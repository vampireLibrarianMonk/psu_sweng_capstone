from http.server import BaseHTTPRequestHandler, HTTPServer

class EchoServer(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))  # No size limit check (BAD PRACTICE)
        body = self.rfile.read(content_length)

        self.send_response(200)
        self.end_headers()
        self.wfile.write(body)  # Echo the request body

server = HTTPServer(("localhost", 8080), EchoServer)
print("Echo server running on port 8080...")
server.serve_forever()
