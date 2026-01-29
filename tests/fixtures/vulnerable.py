# Test fixture: vulnerable Python file
# Intentionally insecure for testing

import hashlib
import os
import subprocess

# CRITICAL: Hardcoded password
db_pass = "my_database_password_123"

# HIGH: SQL injection (Python)
def get_user(cursor, user_id):
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

# HIGH: Command injection (Python)
def run_command(user_input):
    os.system(f"echo {user_input}")

# MEDIUM: Weak crypto MD5
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()
