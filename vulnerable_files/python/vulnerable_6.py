# Python (Server-Side Template Injection Vulnerability)
from flask import Flask, request, render_template_string

app = Flask(__name__)


@app.route('/')
def index():
    # Retrieve the 'name' parameter from the query string
    user_name = request.args.get('name', 'Guest')

    # Render the greeting message using string formatting
    return render_template_string(f"<h1>Welcome, {user_name}!</h1>")


if __name__ == "__main__":
    app.run(debug=True)
