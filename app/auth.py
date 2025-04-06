import re
import hashlib
from db import insert_user
from captcha import validate_captcha

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

def register_user(name, email, password, captcha_input, session_captcha):
    if not validate_captcha(captcha_input, session_captcha):
        return "Invalid CAPTCHA"
    error = validate_registration(name, email, password)
    if error:
        return error
    hashed = hash_password(password)
    success = insert_user(name, email, hashed)
    return None if success else "Email already exists"
