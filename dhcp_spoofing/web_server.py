#!/usr/bin/env python
"""
Very simple HTTP server in python.

Usage::
    ./dummy-web-server.py [<port>]

Send a GET request::
    curl http://localhost

Send a HEAD request::
    curl -I http://localhost

Send a POST request::
    curl -d "foo=bar&bin=baz" http://localhost

"""

import sys
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer


class HTTPRequestHandler(BaseHTTPRequestHandler):
    def _set_headers(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_GET(self):
        self._set_headers()
        self.wfile.write("<html><body><h1>hi!</h1></body></html>")

    def do_HEAD(self):
        self._set_headers()
        
    def do_POST(self):
        # Doesn't do anything with posted data
        content_length = int(self.headers['Content-Length']) # <--- Gets the size of data
        post_data = self.rfile.read(content_length) # <--- Gets the data itself
        self._set_headers()
        self.wfile.write("<html><body><h1>POST!</h1></body></html>")
        
        
def run(server_class=HTTPServer, handler_class=HTTPRequestHandler, ip_address='', port=80):
    server_address = (ip_address, port)
    httpd = server_class(server_address, handler_class)
    try:
        print("Starting server running forever")
        httpd.serve_forever(poll_interval=2) #2 sec
    except KeyboardInterrupt:
        print("Interrupt handled. Server is DOWN now")
    except Exception as e:
        print("Exception %s", e)
    finally:
        httpd.server_close()
        
        
if __name__ == "__main__":
	argc = len(sys.argv)

	if argc == 2:
		run(ip_address=sys.argv[1])
	elif argc >= 3:
		run(ip_address=sys.argv[1], port=int(sys.argv[2]))
	else:
		run()
