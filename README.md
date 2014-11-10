graphite_aclproxy
=================

The goal of this project is to create a rather simple proxy to enforce ACLs on metrics a given host (user, ....) is allowed to access. It uses the graphite-web grammer to parse targets and extract metric names.

So far only the render API and IP based acls are implemented. So if your project is using /render/ from your graphite-web Serve ronly, the proxy should work instantly by pointing your client to the proxy URL instead of the graphite-web server.

The project is ALPHA software, but works for me. Comments, bug reports and wishes are welcome!

TODOS:
=================

  * Implement user based acls
  * add support for various /metric/ requests
  * add some documentation, better coding style, .....
  * add caching
