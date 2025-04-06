import mysql.connector
import hashlib

def get_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="Ichocska12",
        database="Users"
    )

def insert_user(name, email, password_hash):
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (name, email, password_hash) VALUES (%s, %s, %s)",
            (name, email, password_hash)
        )
        conn.commit()
        return True
    except mysql.connector.IntegrityError:
        return False
    finally:
        cursor.close()
        conn.close()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def get_user_by_email(email):
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        return user
    except Exception as e:
        print(f"Error: {e}")
        return None
    finally:
        cursor.close()
        conn.close()

def validate_login(email, password):
    user = get_user_by_email(email)
    if not user:
        return "User not found", None
    if user['password_hash'] != hash_password(password):
        return "Invalid password", None
    return None, user

def login_user(email, password):
    error, user = validate_login(email, password)
    if error:
        return error, None
    return None, user

def logout_user():
    return "Logged out successfully"
