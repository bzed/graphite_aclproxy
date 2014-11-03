import logging

DEBUG = True

LOG_LEVEL = logging.DEBUG
LOG_NAME = 'graphite_aclproxy'

GRAPHITE_URL = 'http://127.0.0.1/'
CHUNK_SIZE = 1024

IP_ACL = {
    '127.0.0.1/32' :   [ 'carbon.*.*.*', 'carbon.*.*.*.*', 'carbon.*.*.*.*.*' ]
}

