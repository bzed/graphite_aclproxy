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
import logging
import os

static_favicon=True
try:
    from wand.image import Image
    from wand.color import Color
    from StringIO import StringIO
    static_favicon=False
except ImportError:
    pass


configfile_name = 'graphite_aclproxy.conf'

instance_relative_config = False
instance_path = None
if os.path.exists('/etc/carbon/%s' %(configfile_name, )):
    instance_relative_config = True
    instance_path = '/etc/carbon'
    
app = Flask(    __name__.split('.')[0],
                static_url_path='/static',
                instance_relative_config = instance_relative_config,
                instance_path = instance_path
            )
app.config.from_object('graphite_aclproxy.default_settings')

if os.getenv('GRAPHITE_ACLPROXY_SETTINGS'):
    app.config.from_envvar('GRAPHITE_ACLPROXY_SETTINGS')
else:
    app.config.from_pyfile(configfile_name, silent=False)

logging.basicConfig(level=app.config['LOG_LEVEL'])
LOG = logging.getLogger(app.config['LOG_NAME'])

IP_ACL = app.config['IP_ACL']

@app.route('/favicon.ico')
def favicon():
    if static_favicon:
        return app.send_static_file('favicon.ico')

    # for dynamic fun:
    # width=64&height=64&from=-2hours&graphOnly=true&target=carbon.agents.*.metricsReceived
    favicon_args = {
            'width' : 32,
            'height' : 32,
            'from' : '-2hours',
            'graphOnly' : 'true',
            'target' : 'carbon.agents.*.metricsReceived',
            'format' : 'png'
            }
    response, headers = upstream_req(favicon_args)
    response_file=StringIO()
    for data in response():
        response_file.write(data)
    response_file.seek(0)
    image = Image(file=response_file, format='png')
    image.format='ico'
    headers['content-type']='image/x-icon'
    return Response(image.make_blob(), headers=headers)


@app.route('/', defaults={'url': ''})
@app.route('/<path:url>')
def root(url):
    LOG.warn('Unknown url: %s' %(url,))
    abort(404)
 
 
@app.route('/render/')
def proxy():
    """Proxy the render API.
    """
    if not check_ip_acl():
        LOG.warn("FailedACL: '%s', '400', '%s'", request.remote_addr, request.query_string)
        abort(400)

    response, headers = upstream_req(request.args.to_dict(flat=False))
    return Response(response(), headers)

 
 
def upstream_req(args):

    url = '%s/render/' % (app.config['REQUESTS_GRAPHITE_URL'],)
    headers = {}
    r=requests.get(url, stream=True , params = args, headers=headers, verify=app.config['REQUESTS_SSL_VERIFY'])
    LOG.info("UpstreamRequest: '%s','%s'", r.status_code, args)

    # abort if status_code != 200
    if r.status_code != 200:
        if r.status_code >= 300 and r.status_code <= 399:
            abort(503)
        abort(r.status_code)

    r_headers = dict(r.headers)
    headers = {
        'content-type' : r_headers['content-type']
    }
    def resp_generator():
        for chunk in r.iter_content(app.config['REQUESTS_CHUNK_SIZE']):
            yield chunk
    return (resp_generator, headers)

 
 
def check_ip_acl():
    remote_ip = IP(request.remote_addr)
    allowed_tokens = []
    for network, acl_tokens in IP_ACL.iteritems():
        if remote_ip in IP(network):
            allowed_tokens.extend(acl_tokens)
    if not allowed_tokens:
        LOG.warn("No ACLs for %s", remote_ip)
        return False

    try:
        if not request.args.has_key('target'):
            raise ValueError('target missing in query')
        for target in request.args.getlist('target'):
            tokens = grammar.parseString(target)
            for token in _evaluateTokens(tokens):
                token_allowed = False
                LOG.debug("evaluated target: %s", token)
                for allowed_token in allowed_tokens:
                    if fnmatch(token, allowed_token):
                        LOG.warn("token %s allowed in %s [%s]", token, network, allowed_token)
                        token_allowed = True
                        break
                if not token_allowed:
                    return False
    except Exception, e:
        LOG.warn("FailedRequest: %s (%s)", str(e), request.query_string)
        abort(400)

    return True


def _evaluateTokens(tokens):
    if tokens.expression:
        for i in _evaluateTokens(tokens.expression):
            yield i

    elif tokens.pathExpression:
        yield tokens.pathExpression

    elif tokens.call:
        for arg in tokens.call.args:
            for i in _evaluateTokens(arg):
                yield i

        for kwarg in tokens.call.kwargs:
            for i in _evaluateTokens(kwarg.args[0]):
                yield i

