import logging

DEBUG = True

LOG_LEVEL = logging.DEBUG
LOG_NAME = 'graphite_aclproxy'

REQUESTS_GRAPHITE_URL = 'http://127.0.0.1/'
REQUESTS_CHUNK_SIZE = 1024
REQUESTS_SSL_VERIFY = True

IP_ACL = {
    '127.0.0.1/32' :   [ 'carbon.*.*.*', 'carbon.*.*.*.*', 'carbon.*.*.*.*.*' ]
}

