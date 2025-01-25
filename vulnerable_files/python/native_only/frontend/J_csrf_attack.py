from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse

class CSRFVulnerableHandler(BaseHTTPRequestHandler):
    """
    HTTP request handler that is vulnerable to Cross-Site Request Forgery (CSRF) attacks.

    WARNING: This handler processes state-changing requests without verifying
    the origin or including anti-CSRF tokens, allowing attackers to perform
    unauthorized actions on behalf of authenticated users.
    """

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        params = urllib.parse.parse_qs(post_data.decode())

        # Process the form data (e.g., change user email)
        new_email = params.get('email', [''])[0]
        # In a real application, update the user's email in the database
        print(f"Email changed to: {new_email}")

        # Respond to the client
        response = f"Email has been changed to {new_email}."
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(response.encode())

    def do_GET(self):
        # Serve a simple form for changing email
        response = """
        <html>
            <body>
                <form method="POST" action="/change_email">
                    <label for="email">New Email:</label>
                    <input type="email" id="email" name="email">
                    <input type="submit" value="Change Email">
                </form>
            </body>
        </html>
        """
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(response.encode())

if __name__ == "__main__":
    server_address = ('', 8080)
    httpd = HTTPServer(server_address, CSRFVulnerableHandler)
    print("Starting server on port 8080...")
    httpd.serve_forever()
