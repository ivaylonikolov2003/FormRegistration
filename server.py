from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs
from app.auth import register_user, login_user
from app.captcha import generate_captcha_image
from app.db import update_user_profile, hash_password
import http.cookies
import random
import string

class SimpleHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        routes = {
            "/": self.redirect_to_login,
            "/register": self.render_register_page,
            "/login": self.render_login_page,
            "/dashboard": self.render_dashboard_page,
            "/update_profile": self.render_update_profile_page,
            "/logout": self.handle_logout,
            "/captcha": self.serve_captcha
        }

        if self.path in routes:
            routes[self.path]()
        elif self.path.startswith("/static/"):
            self.serve_static()
        else:
            self.send_error(404)

    def do_POST(self):
        if self.path == "/register":
            self.handle_register()
        elif self.path == "/login":
            self.handle_login()
        elif self.path == "/update_profile":
            self.handle_update_profile()
        else:
            self.send_error(404)

    def redirect_to_login(self):
        self.send_response(302)
        self.send_header("Location", "/login")
        self.end_headers()

    def render_register_page(self, error_message=""):
        captcha_code = self.generate_captcha_code()
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.send_header("Set-Cookie", f"captcha_code={captcha_code}; Path=/")
        self.end_headers()

        with open("templates/register.html", "r", encoding="utf-8") as f:
            html = f.read()
            html = html.replace("<!--ERROR-->", f"<p style='color:red;'>{error_message}</p>")
            self.wfile.write(html.encode())

    def render_login_page(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        with open("templates/login.html", "r", encoding="utf-8") as f:
            self.wfile.write(f.read().encode())

    def render_dashboard_page(self):
        if not self.is_authenticated():
            self.redirect_to_login()
            return
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        with open("templates/dashboard.html", "r", encoding="utf-8") as f:
            self.wfile.write(f.read().encode())

    def render_update_profile_page(self):
        if not self.is_authenticated():
            self.redirect_to_login()
            return
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        with open("templates/update_profile.html", "r", encoding="utf-8") as f:
            self.wfile.write(f.read().encode())

    def handle_logout(self):
        self.send_response(302)
        self.send_header("Location", "/login")
        self.send_header("Set-Cookie", "user_id=; Path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT")
        self.end_headers()

    def serve_static(self):
        try:
            with open(self.path.lstrip("/"), "rb") as f:
                self.send_response(200)
                if self.path.endswith(".css"):
                    self.send_header("Content-type", "text/css")
                elif self.path.endswith(".js"):
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
        self.wfile.write(generate_captcha_image(captcha_code))

    def handle_register(self):
        data = self.get_post_data()
        name = data.get("name", "")
        email = data.get("email", "")
        password = data.get("password", "")
        captcha_input = data.get("captcha_input", "")
        session_captcha = self.get_cookie("captcha_code")

        error = register_user(name, email, password, captcha_input, session_captcha)
        if error:
            self.render_register_page(f"Error: {error}")
        else:
            self.send_response(302)
            self.send_header("Location", "/login")
            self.end_headers()

    def handle_login(self):
        data = self.get_post_data()
        email = data.get("email", "")
        password = data.get("password", "")

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

    def handle_update_profile(self):
        if not self.is_authenticated():
            self.redirect_to_login()
            return

        data = self.get_post_data()
        new_name = data.get("name", "")
        new_password = data.get("password", "")
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

    def get_post_data(self):
        content_length = int(self.headers["Content-Length"])
        post_data = self.rfile.read(content_length).decode()
        return {k: v[0] for k, v in parse_qs(post_data).items()}

    def get_cookie(self, key):
        if "Cookie" in self.headers:
            cookies = http.cookies.SimpleCookie(self.headers["Cookie"])
            if key in cookies:
                return cookies[key].value
        return None

    def set_cookie(self, key, value):
        self.send_header("Set-Cookie", f"{key}={value}; Path=/")

    def is_authenticated(self):
        return self.get_cookie("user_id") is not None

    def generate_captcha_code(self, length=5):
        return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

if __name__ == "__main__":
    httpd = HTTPServer(("localhost", 8080), SimpleHandler)
    print("Server started at http://localhost:8080")
    httpd.serve_forever()
