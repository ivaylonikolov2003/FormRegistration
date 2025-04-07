import unittest
from app.db import (
    get_connection, insert_user, get_user_by_email,
    get_user_by_id, update_user_profile, hash_password, check_password
)

TEST_NAME = "Ivailo Nikolov"
TEST_EMAIL = "ichocska12@example.com"
TEST_PASSWORD = "Pass1234"

def prepare_test_user():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE email = %s", (TEST_EMAIL,))
    conn.commit()

    hashed_password = hash_password(TEST_PASSWORD)
    insert_user(TEST_NAME, TEST_EMAIL, hashed_password)

    cursor.close()
    conn.close()

class TestDatabaseReal(unittest.TestCase):

    def setUp(self):
        prepare_test_user()

    def test_insert_user_duplicate_email(self):
        result = insert_user(TEST_NAME, TEST_EMAIL, hash_password(TEST_PASSWORD))
        self.assertFalse(result)

    def test_get_user_by_email(self):
        user = get_user_by_email(TEST_EMAIL)
        self.assertIsNotNone(user)
        self.assertEqual(user['name'], TEST_NAME)

    def test_get_user_by_id(self):
        user = get_user_by_email(TEST_EMAIL)
        fetched = get_user_by_id(user['id'])
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched['email'], TEST_EMAIL)

    def test_update_user_profile(self):
        user = get_user_by_email(TEST_EMAIL)
        new_name = "Icho Nikolov"
        new_password = hash_password("NewPass123")
        result = update_user_profile(user['id'], new_name, new_password)
        self.assertTrue(result)

        updated_user = get_user_by_id(user['id'])
        self.assertEqual(updated_user['name'], new_name)
        self.assertTrue(check_password("NewPass123", updated_user['password_hash']))

    def test_check_password(self):
        user = get_user_by_email(TEST_EMAIL)
        self.assertTrue(check_password(TEST_PASSWORD, user['password_hash']))
        self.assertFalse(check_password("WrongPassword", user['password_hash']))

if __name__ == "__main__":
    unittest.main()
