from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs
from app.auth import register_user, validate_login, login_user, logout_user
import http.cookies


class SimpleHandler(BaseHTTPRequestHandler):
    session_captcha = "AB123"

    def do_GET(self):
        if self.path == "/register":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            with open("templates/register.html", "r", encoding="utf-8") as f:
                self.wfile.write(f.read().encode())
        elif self.path == "/login":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            with open("templates/login.html", "r", encoding="utf-8") as f:
                self.wfile.write(f.read().encode())
        elif self.path == "/logout":
            self.handle_logout()
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

        elif self.path == "/login":
            content_length = int(self.headers["Content-Length"])
            post_data = self.rfile.read(content_length).decode()
            data = parse_qs(post_data)

            email = data.get("email", [""])[0]
            password = data.get("password", [""])[0]

            error, user = login_user(email, password)

            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()

            if error:
                self.wfile.write(f"<h3>Error: {error}</h3>".encode())
            else:
                self.set_cookie(user["id"])
                self.wfile.write("<h3>Login successful!</h3>".encode())

    def handle_logout(self):
        self.send_response(302)
        self.send_header("Location", "/login")
        self.send_header("Set-Cookie", "user_id=; expires=Thu, 01 Jan 1970 00:00:00 GMT")
        self.end_headers()

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

    def set_cookie(self, user_id):
        cookie = f"user_id={user_id}; Path=/"
        self.send_header("Set-Cookie", cookie)


if __name__ == "__main__":
    httpd = HTTPServer(("localhost", 8080), SimpleHandler)
    print("Server started at http://localhost:8080")
    httpd.serve_forever()
