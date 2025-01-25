from http.server import BaseHTTPRequestHandler, HTTPServer

class FileServer(BaseHTTPRequestHandler):
    def do_GET(self):
        filepath = self.path.strip("/")  # No input sanitization (BAD PRACTICE)

        try:
            with open(filepath, "r") as file:
                content = file.read()
                self.send_response(200)
                self.end_headers()
                self.wfile.write(content.encode())
        except FileNotFoundError:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"File not found")
        except Exception as e:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(f"Error: {e}".encode())

server = HTTPServer(("localhost", 8080), FileServer)
print("File server running on port 8080...")
server.serve_forever()
