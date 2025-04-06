import re
import hashlib
from app.db import insert_user, get_user_by_email
from app.captcha import validate_captcha

def validate_registration(name, email, password):
    if not re.match(r"^[A-Za-z]{2,}( [A-Za-z]{2,})$", name):
        return "Invalid full name. Please enter first and last name."
    if not re.match(r"^[\w\.-]+@[\w\.-]+\.\w{2,}$", email):
        return "Invalid email"
    if not re.match(r"^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$", password):
        return "Password must be at least 8 characters and include letters and numbers"
    return None


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def validate_login(email, password):
    user = get_user_by_email(email)
    if not user:
        return "User not found", None
    if user['password_hash'] != hash_password(password):
        return "Invalid password", None
    return None, user

def register_user(name, email, password, captcha_input, session_captcha):
    if not validate_captcha(captcha_input, session_captcha):
        return "Invalid CAPTCHA"
    error = validate_registration(name, email, password)
    if error:
        return error
    existing_user = get_user_by_email(email)
    if existing_user:
        return "Email already exists"
    hashed = hash_password(password)
    success = insert_user(name, email, hashed)

    return None if success else "Error registering user"

def login_user(email, password):
    error, user = validate_login(email, password)
    return error, user

def logout_user():
    return "Logged out successfully"
