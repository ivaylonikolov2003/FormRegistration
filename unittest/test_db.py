import unittest
import mysql.connector
from app.db import get_connection

TEST_TABLE = "users_test"

def create_test_table():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS {TEST_TABLE} (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(100),
            email VARCHAR(100) UNIQUE,
            password_hash VARCHAR(256)
        )
    """)
    conn.commit()
    cursor.close()
    conn.close()

def clear_test_table():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(f"DELETE FROM {TEST_TABLE}")
    conn.commit()
    cursor.close()
    conn.close()

def drop_test_table():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(f"DROP TABLE IF EXISTS {TEST_TABLE}")
    conn.commit()
    cursor.close()
    conn.close()

def insert_user_test(name, email, password_hash):
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            f"INSERT INTO {TEST_TABLE} (name, email, password_hash) VALUES (%s, %s, %s)",
            (name, email, password_hash)
        )
        conn.commit()
        return True
    except mysql.connector.IntegrityError:
        return False
    finally:
        cursor.close()
        conn.close()

class TestDatabase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        create_test_table()

    def setUp(self):
        clear_test_table()

    def test_insert_user_success(self):
        result = insert_user_test("Alice Johnson", "alice@test.com", "hash123")
        self.assertTrue(result)

    def test_insert_user_duplicate_email(self):
        insert_user_test("Alice Johnson", "alice@test.com", "hash123")
        result = insert_user_test("Bob Smith", "alice@test.com", "hash456")
        self.assertFalse(result)

    @classmethod
    def tearDownClass(cls):
        drop_test_table()

if __name__ == "__main__":
    unittest.main()
