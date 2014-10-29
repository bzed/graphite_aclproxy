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
 
app = Flask(__name__)
app.config.from_object('graphite_aclproxy.default_settings')
app.config.from_object('graphite_aclproxy.local_settings')

logging.basicConfig(level=app.config['LOG_LEVEL'])
LOG = logging.getLogger(app.config['LOG_NAME'])

ACL = app.config['ACL']


@app.route('/', defaults={'url': ''})
@app.route('/<path:url>')
def root(url):
    LOG.warn('Unknown url: %s' %(url,))
    abort(404)
 
 
@app.route('/render/')
def proxy():
    """Proxy the render API.
    """
    if not check_acl():
        LOG.warn("FailedACL: '%s', '400', '%s'", request.remote_addr, request.query_string)
        abort(400)

    r = upstream_req()
    LOG.info("UpstreamRequest: '%s','%s'", r.status_code, request.query_string)

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
        for chunk in r.iter_content(app.config['CHUNK_SIZE']):
            yield chunk
    return Response(resp_generator(), headers = headers)
 
 
def upstream_req():
    url = '%s/render/' % (app.config['GRAPHITE_URL'],)
    headers = {}
    args = request.args.to_dict(flat=False)
    return requests.get(url, stream=True , params = args, headers=headers)
 
 
def check_acl():
    remote_ip = IP(request.remote_addr)
    try:
        if not request.args.has_key('target'):
            raise ValueError('target missing in query')
        for target in request.args.getlist('target'):
            tokens = grammar.parseString(target)
            for token in _evaluateTokens(tokens):
                token_allowed = False
                LOG.debug("evaluated target: %s", token)
                for network, allowed_targets in ACL.iteritems():
                    if remote_ip in IP(network):
                        for allowed_target in allowed_targets:
                            if fnmatch(token, allowed_target):
                                LOG.debug("token %s allowed in %s [%s]", token, network, allowed_target)
                                token_allowed = True
                                break
                    if token_allowed:
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

