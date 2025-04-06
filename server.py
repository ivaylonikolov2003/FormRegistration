from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs
from app.auth import register_user


class SimpleHandler(BaseHTTPRequestHandler):
    session_captcha = "AB123"  # For test purposes

    def do_GET(self):
        if self.path == "/register":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            with open("templates/register.html", "r", encoding="utf-8") as f:
                self.wfile.write(f.read().encode())
        elif self.path.startswith("/static/"):
            self.serve_static()
        elif self.path == "/captcha":
            self.serve_captcha()
        else:
            self.send_error(404)

    def do_POST(self):
        if self.path == "/register":
            content_length = int(self.headers["Content-Length"])
            post_data = self.rfile.read(content_length).decode()
            data = parse_qs(post_data)

            first_name = data.get("first_name", [""])[0]
            last_name = data.get("last_name", [""])[0]
            full_name = f"{first_name} {last_name}"

            email = data.get("email", [""])[0]
            password = data.get("password", [""])[0]
            captcha_input = data.get("captcha_input", [""])[0]

            error = register_user(full_name, email, password, captcha_input, self.session_captcha)

            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            if error:
                self.wfile.write(f"<h3>Error: {error}</h3>".encode())
            else:
                self.wfile.write("<h3>Registration successful!</h3>".encode())
    def serve_static(self):
        path = self.path.lstrip("/")
        try:
            with open(path, "rb") as f:
                self.send_response(200)
                if path.endswith(".css"):
                    self.send_header("Content-type", "text/css")
                self.end_headers()
                self.wfile.write(f.read())
        except FileNotFoundError:
            self.send_error(404)

    def serve_captcha(self):
        from app.captcha import generate_captcha_image
        self.send_response(200)
        self.send_header("Content-type", "image/png")
        self.end_headers()
        image_bytes = generate_captcha_image(self.session_captcha)
        self.wfile.write(image_bytes)

if __name__ == "__main__":
    httpd = HTTPServer(("localhost", 8080), SimpleHandler)
    print("Server started at http://localhost:8080")
    httpd.serve_forever()
