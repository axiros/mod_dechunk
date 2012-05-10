mod_dechunk
===========

Apache module which reads all incoming data into memory to replace &#39;Transfer-Encoding: chunked&#39; with a Content-Length
Main use case is to support for chunked request with mod_wsgi in daemon mode.
See here for more details http://groups.google.com/group/modwsgi/browse_thread/thread/464f9c5d31920874
