import re
from app.db import (
    insert_user,
    get_user_by_email,
    hash_password,
    check_password
)
from app.captcha import validate_captcha

def is_valid_registration(name, email, password):
    if not re.match(r"^[A-Za-z]{2,}( [A-Za-z]{2,})$", name):
        return "Invalid full name. Please enter first and last name."

    if not re.match(r"^[\w\.-]+@[\w\.-]+\.\w{2,}$", email):
        return "Invalid email format."

    if not re.match(r"^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$", password):
        return "Password must be at least 8 characters and include both letters and numbers."

    return None

def check_login(email, password):
    user = get_user_by_email(email)
    if not user:
        return "User not found", None

    if not check_password(password, user['password_hash']):
        return "Invalid password", None

    return None, user

def register_user(name, email, password, captcha_input, captcha_expected):
    if not validate_captcha(captcha_input, captcha_expected):
        return "Invalid CAPTCHA"

    error = is_valid_registration(name, email, password)
    if error:
        return error

    if get_user_by_email(email):
        return "Email already exists"

    hashed = hash_password(password)
    success = insert_user(name, email, hashed)

    return None if success else "Error registering user"

def login_user(email, password):
    return check_login(email, password)

def logout_user():
    return "Logged out successfully"
