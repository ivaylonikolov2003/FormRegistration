import unittest
from app.auth import validate_registration, hash_password, validate_login, login_user, logout_user
from app.db import get_user_by_email
from app.captcha import validate_captcha


class TestRegistrationValidation(unittest.TestCase):

    def test_valid_registration(self):
        error = validate_registration("Ivailo Nikolov", "ichocska@example.com", "Pass1234")
        self.assertIsNone(error)

    def test_invalid_name(self):
        error = validate_registration("I", "ichocska@example.com", "Pass1234")
        self.assertEqual(error, "Invalid full name. Please enter first and last name.")

    def test_invalid_email(self):
        error = validate_registration("Ivailo Nikolov", "ichoexample.com", "Pass1234")
        self.assertEqual(error, "Invalid email")

    def test_invalid_password(self):
        error = validate_registration("Ivailo Nikolov", "ichocska@example.com", "password")
        self.assertEqual(error, "Password must be at least 8 characters and include letters and numbers")

class TestPasswordHashing(unittest.TestCase):

    def test_hash_password_consistency(self):
        password1 = hash_password("MySecurePass123")
        password2 = hash_password("MySecurePass123")
        self.assertEqual(password1, password2)

    def test_hash_password_uniqueness(self):
        password1 = hash_password("Password123")
        password2 = hash_password("DifferentPass456")
        self.assertNotEqual(password1, password2)

class TestCaptcha(unittest.TestCase):

    def test_valid_captcha(self):
        self.assertTrue(validate_captcha("aB123", "AB123"))

    def test_invalid_captcha(self):
        self.assertFalse(validate_captcha("xyz", "AB123"))

class TestLogin(unittest.TestCase):

    def test_valid_login(self):
        error, user = validate_login("ichocska@example.com", "Pass1234")
        self.assertIsNone(error)
        self.assertEqual(user['email'], "ichocska@example.com")

    def test_invalid_email(self):
        error, user = validate_login("cskaicho@example.com", "Pass1234")
        self.assertEqual(error, "User not found")
        self.assertIsNone(user)

    def test_invalid_password(self):
        error, user = validate_login("ichocska@example.com", "WrongPass123")
        self.assertEqual(error, "Invalid password")
        self.assertIsNone(user)

class TestLogout(unittest.TestCase):
    def test_logout(self):
        result = logout_user()
        self.assertEqual(result, "Logged out successfully")

if __name__ == "__main__":
    unittest.main()
