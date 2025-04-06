import mysql.connector
import bcrypt

def get_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="Ichocska12",
        database="Users"
    )

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def check_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed.encode())

def insert_user(name, email, password_hash, conn=None):
    own_connection = False
    if conn is None:
        conn = get_connection()
        own_connection = True
    try:
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
        if own_connection:
            conn.close()

def get_user_by_email(email):
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE LOWER(email) = LOWER(%s)", (email,))
        user = cursor.fetchone()
        return user
    except Exception as e:
        print(f"Error: {e}")
        return None
    finally:
        cursor.close()
        conn.close()

def get_user_by_id(user_id):
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        return cursor.fetchone()
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
    if not check_password(password, user['password_hash']):
        return "Invalid password", None
    return None, user

def login_user(email, password):
    error, user = validate_login(email, password)
    if error:
        return error, None
    return None, user

def logout_user():
    return "Logged out successfully"

def update_user_profile(user_id, new_name, new_password_hash):
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET name=%s, password_hash=%s WHERE id=%s",
            (new_name, new_password_hash, user_id)
        )
        conn.commit()
        return cursor.rowcount > 0
    except Exception as e:
        print(f"Update error: {e}")
        return False
    finally:
        cursor.close()
        conn.close()
