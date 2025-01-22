from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse

class XSSVulnerableHandler(BaseHTTPRequestHandler):
    """
    HTTP request handler that is vulnerable to Cross-Site Scripting (XSS) attacks.

    WARNING: This handler echoes user input directly into the HTML response
    without proper sanitization, allowing execution of arbitrary scripts in the
    user's browser.
    """

    def do_GET(self):
        parsed_path = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed_path.query)
        name = query.get('name', [''])[0]

        # Vulnerable HTML response
        response = f"""
        <html>
            <body>
                <h1>Hello, {name}!</h1>
            </body>
        </html>
        """
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(response.encode())

if __name__ == "__main__":
    server_address = ('', 8080)
    httpd = HTTPServer(server_address, XSSVulnerableHandler)
    print("Starting server on port 8080...")
    httpd.serve_forever()
