"""
Copyright (C) 2014 Bernd Zeimetz <bernd@bzed.de>
Copyright (C) 2014 Bernd Zeimetz <b.zeimetz@conova.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""


from flask import Flask, request, abort, Response
from IPy import IP
from fnmatch import fnmatch

from .grammar import grammar
import requests
from requests.auth import HTTPBasicAuth
import logging
import os
import json
import six

static_favicon = True
try:
    from wand.image import Image
    from StringIO import StringIO
    static_favicon = False
except ImportError:
    pass


configfile_name = 'graphite_aclproxy.conf'

instance_relative_config = False
instance_path = None
if os.path.exists('/etc/carbon/{0!s}'.format(configfile_name )):
    instance_relative_config = True
    instance_path = '/etc/carbon'

app = Flask(__name__.split('.')[0],
            static_url_path='/static',
            instance_relative_config=instance_relative_config,
            instance_path=instance_path
            )
app.config.from_object('graphite_aclproxy.default_settings')

if os.getenv('GRAPHITE_ACLPROXY_SETTINGS'):
    app.config.from_envvar('GRAPHITE_ACLPROXY_SETTINGS')
else:
    app.config.from_pyfile(configfile_name, silent=False)

logging.basicConfig(level=app.config['LOG_LEVEL'])
LOG = logging.getLogger(app.config['LOG_NAME'])

AUTH = app.config['REQUESTS_GRAPHITE_AUTH']
IP_ACL = app.config['IP_ACL']
DYNAMIC_FAVICON_TARGET = app.config['DYNAMIC_FAVICON_TARGET']


@app.route('/favicon.ico')
def favicon():
    if static_favicon:
        return app.send_static_file('favicon.ico')

    # for dynamic fun:
    # width=64&height=64&from=-2hours&graphOnly=true&target=carbon.agents.*.metricsReceived
    favicon_args = {
            'width': 32,
            'height': 32,
            'from': '-2hours',
            'graphOnly': 'true',
            'target': DYNAMIC_FAVICON_TARGET,
            'format': 'png'
            }
    response, headers = upstream_req('/render/', favicon_args)
    response_file = StringIO()
    for data in response():
        response_file.write(data)
    response_file.seek(0)
    image = Image(file=response_file, format='png')
    image.format = 'ico'
    headers['content-type'] = 'image/x-icon'
    return Response(image.make_blob(), headers=headers)


@app.route('/', defaults={'url': ''})
@app.route('/<path:url>')
def root(url):
    LOG.warn('Unknown url: {0!s}'.format(url))
    abort(404)


@app.route('/render/')
def render_proxy():
    """Proxy the render API.
    """
    if not check_render_ip_acl():
        LOG.warn("FailedACL: '%s', '400', '%s'",
                 request.remote_addr,
                 request.query_string
                 )
        abort(400)

    response, headers = upstream_req('/render/',
                                     request.args.to_dict(flat=False)
                                     )
    return Response(response(), headers=headers, status=200)


@app.route('/metrics/find/')
def metrics_proxy():
    """Proxy the render API.
    """
    response, headers = upstream_req('/metrics/find/',
                                     request.args.to_dict(flat=False)
                                     )
    # reponse() is a generator.
    response_data = filter_metrics_ip_acl(
        ''.join([
           x.decode("utf-8") for x in response()
        ]))
    return Response(response_data, headers=headers, status=200)


def upstream_req(path, args):
    if AUTH:
        auth = HTTPBasicAuth(AUTH[0], AUTH[1])
    else:
        auth = None

    url = '{0!s}{1!s}'.format(app.config['REQUESTS_GRAPHITE_URL'], path)
    auth = app.config['REQUESTS_GRAPHITE_AUTH']
    headers = {}
    r = requests.get(url,
                     stream=True,
                     params=args,
                     headers=headers,
                     verify=app.config['REQUESTS_SSL_VERIFY'],
                     auth=auth
                     )
    LOG.info("UpstreamRequest: '%s','%s'", r.status_code, args)

    # abort if status_code != 200
    if r.status_code != 200:
        abort(503, 'graphite render api returned an error')

    r_headers = dict(r.headers)
    headers = {
        'Content-Type': r_headers['Content-Type']
    }

    def resp_generator():
        for chunk in r.iter_content(app.config['REQUESTS_CHUNK_SIZE']):
            yield chunk
    return (resp_generator, headers)


def get_allowed_ip_acl_tokens(remote_ip):
    remote_ip = IP(remote_ip)
    allowed_tokens = []
    for network, acl_tokens in six.iteritems(IP_ACL):
        if remote_ip in IP(network):
            allowed_tokens.extend(acl_tokens)
    return allowed_tokens


def filter_metrics_ip_acl(response):
    filtered_response = []
    remote_ip = request.remote_addr
    allowed_tokens = get_allowed_ip_acl_tokens(remote_ip)
    if not allowed_tokens:
        LOG.warn("No ACLs for %s", remote_ip)
        return []

    filter_tokens = []
    for allowed_token in allowed_tokens:
        token_parts = allowed_token.split('.')
        for i in range(1, len(token_parts) + 1):
            filter_tokens.append('.'.join(token_parts[0:i]))
    # remove duplicates
    filter_tokens = list(set(filter_tokens))

    try:
        response_data = json.loads(response)
        for resp in response_data:
            for filter_token in filter_tokens:
                if fnmatch(resp['id'], filter_token):
                    filtered_response.append(resp)
                    break
        return json.dumps(filtered_response)
    except Exception as err:
        raise
        LOG.warn("FailedRequest: %s (%s) - %s",
                 str(err),
                 request.query_string,
                 response)
        abort(400, 'Failed to parse targets')
    return True


def check_render_ip_acl():
    remote_ip = request.remote_addr
    allowed_tokens = get_allowed_ip_acl_tokens(remote_ip)
    if not allowed_tokens:
        LOG.warn("No ACLs for %s", remote_ip)
        return False

    try:
        if 'target' not in request.args:
            raise ValueError('target missing in query')
        tokens = extractPathExpressions(None, request.args.getlist('target'))
        for token in tokens:
            token_allowed = False
            LOG.debug("evaluated target: %s", token)
            allowed_token = allowed_tokens[0]
            for allowed_token in allowed_tokens:
                if fnmatch(token, allowed_token):
                    LOG.debug("token %s allowed in [%s]",
                              token,
                              allowed_token,
                              )
                    token_allowed = True
                    break
            if not token_allowed:
                LOG.warn("token %s not allowed in [%s]",
                         token,
                         allowed_token)
                return False
    except Exception as err:
        LOG.warn("FailedRequest: %s (%s)", str(err), request.query_string)
        abort(400, 'Failed to parse targets')

    return True


def evaluateScalarTokens(tokens):
    if tokens.number:
        if tokens.number.integer:
            return int(tokens.number.integer)
        if tokens.number.float:
            return float(tokens.number.float)
        if tokens.number.scientific:
            return float(tokens.number.scientific[0])

        raise ValueError("unknown numeric type in target evaluator")

    if tokens.string:
        return tokens.string[1:-1]

    if tokens.boolean:
        return tokens.boolean[0] == 'true'

    if tokens.none:
        return None

    raise ValueError("unknown token in target evaluator")


def extractPathExpressions(requestContext, targets):
    # Returns a list of unique pathExpressions found in the targets list

    pathExpressions = set()

    def extractPathExpression(requestContext, tokens, replacements=None):
        if tokens.template:
            arglist = dict()
            if tokens.template.kwargs:
                arglist.update(dict([(kwarg.argname, evaluateScalarTokens(kwarg.args[0])) for kwarg in tokens.template.kwargs]))
            if tokens.template.args:
                arglist.update(dict([(str(i+1), evaluateScalarTokens(arg)) for i, arg in enumerate(tokens.template.args)]))
            if 'template' in requestContext:
                arglist.update(requestContext['template'])
            extractPathExpression(requestContext, tokens.template, arglist)
        elif tokens.expression:
            extractPathExpression(requestContext, tokens.expression, replacements)
            if tokens.expression.pipedCalls:
                for token in tokens.expression.pipedCalls:
                    extractPathExpression(requestContext, token, replacements)
        elif tokens.pathExpression:
            expression = tokens.pathExpression
            if replacements:
                for name in replacements:
                    if expression != '$'+name:
                        expression = expression.replace('$'+name, str(replacements[name]))
            pathExpressions.add(expression)
        elif tokens.call:
            # if we're prefetching seriesByTag, pass the entire call back as a path expression
            if tokens.call.funcname == 'seriesByTag':
                pathExpressions.add(tokens.call.raw)
            else:
                for a in tokens.call.args:
                    extractPathExpression(requestContext, a, replacements)

    for target in targets:
        if not target:
            continue

        if isinstance(target, six.string_types):
            if not target.strip():
                continue
            target = grammar.parseString(target)
        extractPathExpression(requestContext, target)

    return list(pathExpressions)

