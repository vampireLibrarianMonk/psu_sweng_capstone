from http.server import BaseHTTPRequestHandler, HTTPServer
import os

class CommandInjectionServer(BaseHTTPRequestHandler):
    def do_GET(self):
        command = self.path.strip("/")  # User input as part of the path

        try:
            output = os.popen(command).read()  # Direct execution of user input (BAD PRACTICE)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(output.encode())
        except Exception as e:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(f"Error: {e}".encode())

server = HTTPServer(("localhost", 8080), CommandInjectionServer)
print("Server running on port 8080...")
server.serve_forever()
