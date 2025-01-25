from http.server import BaseHTTPRequestHandler, HTTPServer
import pickle

class DeserializeServer(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        data = self.rfile.read(content_length)

        try:
            # Directly deserializing untrusted input (BAD PRACTICE)
            obj = pickle.loads(data)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(f"Deserialized object: {obj}".encode())
        except Exception as e:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(f"Error: {e}".encode())

server = HTTPServer(("localhost", 8080), DeserializeServer)
print("Deserialization server running on port 8080...")
server.serve_forever()
