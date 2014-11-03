#!/usr/bin/python
# -*- coding: utf-8 -*-

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

import sys

try:
    from graphite_aclproxy.proxy import app
except ImportError:
    import os
    sys.path = [os.path.realpath(os.path.dirname(__file__))] + sys.path
    from graphite_aclproxy.proxy import app

app.debug = True

if __name__ == '__main__':
    if len(sys.argv) > 1:
        host, port = sys.argv[1:]
        app.run(host=host, port=int(port))
    else:
        app.run()

