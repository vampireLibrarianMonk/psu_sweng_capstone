from http.server import BaseHTTPRequestHandler, HTTPServer

class SimpleAuthServer(BaseHTTPRequestHandler):
    def do_GET(self):
        # Hardcoded credentials (BAD PRACTICE)
        username = "admin"
        password = "12345"

        # Simulate authentication
        if self.headers.get('Authorization') == f"{username}:{password}":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Welcome, admin!")
        else:
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b"Unauthorized")

server = HTTPServer(("localhost", 8080), SimpleAuthServer)
print("Server running on port 8080...")
server.serve_forever()
