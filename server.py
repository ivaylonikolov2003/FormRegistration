from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs
from app.auth import register_user, validate_login, login_user, logout_user
from app.captcha import generate_captcha_image
import http.cookies
import random
import string
from app.db import update_user_profile, hash_password


class SimpleHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        if self.path == "/":
            self.send_response(302)
            self.send_header("Location", "/login")
            self.end_headers()

        elif self.path == "/register":
            captcha_code = self.generate_captcha_code()
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.send_header("Set-Cookie", f"captcha_code={captcha_code}; Path=/")
            self.end_headers()
            with open("templates/register.html", "r", encoding="utf-8") as f:
                self.wfile.write(f.read().encode())

        elif self.path == "/login":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            with open("templates/login.html", "r", encoding="utf-8") as f:
                self.wfile.write(f.read().encode())

        elif self.path == "/dashboard":
            if not self.is_authenticated():
                self.send_response(302)
                self.send_header("Location", "/login")
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            with open("templates/dashboard.html", "r", encoding="utf-8") as f:
                self.wfile.write(f.read().encode())

        elif self.path == "/update_profile":
            if not self.is_authenticated():
                self.send_response(302)
                self.send_header("Location", "/login")
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            with open("templates/update_profile.html", "r", encoding="utf-8") as f:
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

            full_name = data.get("name", [""])[0].strip()
            email = data.get("email", [""])[0]
            password = data.get("password", [""])[0]
            captcha_input = data.get("captcha_input", [""])[0]

            session_captcha = self.get_cookie("captcha_code")

            error = register_user(full_name, email, password, captcha_input, session_captcha)

            if error:
                new_captcha_code = self.generate_captcha_code()
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.send_header("Set-Cookie", f"captcha_code={new_captcha_code}; Path=/")
                self.end_headers()

                with open("templates/register.html", "r", encoding="utf-8") as f:
                    html = f.read().replace("<!--ERROR-->", f"<p style='color:red;'>Error: {error}</p>")
                    self.wfile.write(html.encode())
            else:
                self.send_response(302)
                self.send_header("Location", "/login")
                self.end_headers()

        elif self.path == "/login":
            content_length = int(self.headers["Content-Length"])
            post_data = self.rfile.read(content_length).decode()
            data = parse_qs(post_data)

            email = data.get("email", [""])[0]
            password = data.get("password", [""])[0]

            error, user = login_user(email, password)

            if error:
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(f"<h3>Error: {error}</h3>".encode())
            else:
                self.send_response(302)
                self.set_cookie("user_id", user["id"])
                self.send_header("Location", "/dashboard")
                self.end_headers()

        elif self.path == "/update_profile":
            if not self.is_authenticated():
                self.send_response(302)
                self.send_header("Location", "/login")
                self.end_headers()
                return

            content_length = int(self.headers["Content-Length"])
            post_data = self.rfile.read(content_length).decode()
            data = parse_qs(post_data)

            new_name = data.get("name", [""])[0]
            new_password = data.get("password", [""])[0]

            user_id = self.get_cookie("user_id")

            success = update_user_profile(user_id, new_name, hash_password(new_password))

            if success:
                self.send_response(302)
                self.send_header("Set-Cookie", "user_id=; Path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT")
                self.send_header("Location", "/login")
                self.end_headers()
            else:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b"<h3>Error updating profile.</h3>")

    def handle_logout(self):
        self.send_response(302)
        self.send_header("Location", "/login")
        self.send_header("Set-Cookie", "user_id=; Path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT")
        self.end_headers()

    def serve_static(self):
        path = self.path.lstrip("/")
        try:
            with open(path, "rb") as f:
                self.send_response(200)
                if path.endswith(".css"):
                    self.send_header("Content-type", "text/css")
                elif path.endswith(".js"):
                    self.send_header("Content-type", "application/javascript")
                self.end_headers()
                self.wfile.write(f.read())
        except FileNotFoundError:
            self.send_error(404)

    def serve_captcha(self):
        captcha_code = self.get_cookie("captcha_code") or "AB123"
        self.send_response(200)
        self.send_header("Content-type", "image/png")
        self.end_headers()
        image_bytes = generate_captcha_image(captcha_code)
        self.wfile.write(image_bytes)

    def set_cookie(self, key, value):
        cookie = f"{key}={value}; Path=/"
        self.send_header("Set-Cookie", cookie)

    def get_cookie(self, key):
        if "Cookie" in self.headers:
            cookies = http.cookies.SimpleCookie(self.headers["Cookie"])
            if key in cookies:
                return cookies[key].value
        return None

    def is_authenticated(self):
        return self.get_cookie("user_id") is not None

    def generate_captcha_code(self, length=5):
        return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

if __name__ == "__main__":
    httpd = HTTPServer(("localhost", 8080), SimpleHandler)
    print("Server started at http://localhost:8080")
    httpd.serve_forever()
