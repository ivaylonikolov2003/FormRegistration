import unittest
from app.auth import (
    is_valid_registration, hash_password, check_login,
    login_user, logout_user, register_user
)
from app.db import (
    get_user_by_email, update_user_profile, insert_user,
    get_connection, get_user_by_id, check_password
)
from app.captcha import validate_captcha

def prepare_test_user():
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM users WHERE email = %s", ("ichocska12@example.com",))
        insert_user("Ivailo Nikolov", "ichocska12@example.com", hash_password("Pass1234"), conn)
        conn.commit()
    finally:
        cursor.close()
        conn.close()

class TestRegistrationValidation(unittest.TestCase):
    def test_valid_data(self):
        error = is_valid_registration("Ivailo Nikolov", "ichocska12@example.com", "Pass1234")
        self.assertIsNone(error)

    def test_short_name(self):
        error = is_valid_registration("I", "ichocska12@example.com", "Pass1234")
        self.assertEqual(error, "Invalid full name. Please enter first and last name.")

    def test_bad_email(self):
        error = is_valid_registration("Ivailo Nikolov", "icho12example.com", "Pass1234")
        self.assertEqual(error, "Invalid email format.")

    def test_weak_password(self):
        error = is_valid_registration("Ivailo Nikolov", "ichocska12@example.com", "password")
        self.assertEqual(error, "Password must be at least 8 characters and include both letters and numbers.")

class TestPasswordHashing(unittest.TestCase):
    def test_password_matches_hash(self):
        password = "Test1234"
        hashed = hash_password(password)
        self.assertTrue(check_password(password, hashed))

    def test_different_passwords_different_hashes(self):
        self.assertNotEqual(hash_password("Test1234"), hash_password("Another123"))

class TestCaptcha(unittest.TestCase):
    def test_matching_captcha(self):
        self.assertTrue(validate_captcha("aB123", "AB123"))

    def test_wrong_captcha(self):
        self.assertFalse(validate_captcha("wrong", "AB123"))

class TestLogin(unittest.TestCase):
    def setUp(self):
        prepare_test_user()

    def test_valid_login(self):
        error, user = check_login("ichocska12@example.com", "Pass1234")
        self.assertIsNone(error)
        self.assertEqual(user['email'], "ichocska12@example.com")

    def test_wrong_email(self):
        error, user = check_login("notfound@example.com", "Pass1234")
        self.assertEqual(error, "User not found")
        self.assertIsNone(user)

    def test_wrong_password(self):
        error, user = check_login("ichocska12@example.com", "WrongPass")
        self.assertEqual(error, "Invalid password")
        self.assertIsNone(user)

class TestLogout(unittest.TestCase):
    def test_logout_message(self):
        self.assertEqual(logout_user(), "Logged out successfully")

class TestRegisterUser(unittest.TestCase):
    def setUp(self):
        prepare_test_user()

    def test_email_already_used(self):
        error = register_user("Ivailo Nikolov", "ichocska12@example.com", "Pass1234", "AB123", "AB123")
        self.assertEqual(error, "Email already exists")

    def test_wrong_captcha_input(self):
        error = register_user("Ivailo Nikolov", "ichocska12@example.com", "Pass1234", "WRONG", "AB123")
        self.assertEqual(error, "Invalid CAPTCHA")

class TestLoginUserFunction(unittest.TestCase):
    def test_login_success(self):
        prepare_test_user()
        error, user = login_user("ichocska12@example.com", "Pass1234")
        self.assertIsNone(error)
        self.assertEqual(user['email'], "ichocska12@example.com")

class TestUpdateProfile(unittest.TestCase):
    def setUp(self):
        prepare_test_user()

    def test_valid_update(self):
        user = get_user_by_email("ichocska12@example.com")
        success = update_user_profile(user['id'], "Icho Nikolov", hash_password("NewPass123"))
        self.assertTrue(success)

    def test_invalid_user_id(self):
        success = update_user_profile(-1, "Test", hash_password("AnyPass123"))
        self.assertFalse(success)

class TestGetUserById(unittest.TestCase):
    def test_fetch_user(self):
        prepare_test_user()
        user = get_user_by_email("ichocska12@example.com")
        found = get_user_by_id(user['id'])
        self.assertIsNotNone(found)
        self.assertEqual(found['email'], "ichocska12@example.com")

if __name__ == "__main__":
    unittest.main()
