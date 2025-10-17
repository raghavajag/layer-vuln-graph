import hashlib
import random
import os
import requests
import pickle  # 🚨 Added for insecure deserialization
import sys     # 🚨 Used in new vulnerability

# Vulnerability 1: Use of insecure hash function (MD5)
def generate_file_hash(filename):
    with open(filename, 'rb') as f:
        file_hash = hashlib.md5(f.read()).hexdigest()
    return file_hash

# Vulnerability 2: Use of weak random number generator
def generate_reset_token():
    token = ''.join(random.choice('0123456789ABCDEF') for i in range(16))
    return token

# Vulnerability 3: Hardcoded credentials in code
def connect_to_test_db():
    username = "test_user"
    password = "test_password123"  # Hardcoded credential
    return f"Connected to test DB as {username}"

# Vulnerability 4: Insecure HTTP usage
def fetch_user_data(user_id):
    response = requests.get(f"http://example.com/api/users/{user_id}")
    return response.json()

# Vulnerability 5: Potential path traversal issue
def read_user_file(filename):
    base_dir = "/var/data/user_files/"
    file_path = os.path.join(base_dir, filename)
    try:
        with open(file_path, 'r') as f:
            return f.read()
    except FileNotFoundError:
        return "File not found"

# 🚨 Vulnerability 6: Insecure deserialization of untrusted input
def unsafe_deserialize(data):
    # Deserializing data without validation — dangerous
    return pickle.loads(data)

# 🚨 Vulnerability 7: Command injection via user input (mockup)
def run_system_command(cmd):
    # Unsafely executing shell command with user input
    os.system(f"echo You entered: {cmd}")

# Example usage
if __name__ == "__main__":
    print(f"File hash: {generate_file_hash('example.txt')}")
    print(f"Reset token: {generate_reset_token()}")
    print(connect_to_test_db())
    print(f"User data: {fetch_user_data(123)}")
    print(f"File contents: {read_user_file('notes.txt')}")

    # Simulating vulnerable function calls
    malicious_pickle = pickle.dumps({'exploit': '__import__("os").system("rm -rf /")'})  # For illustration only
    print(f"Deserialized object: {unsafe_deserialize(malicious_pickle)}")

    user_input_command = "rm -rf /"  # Example input
    run_system_command(user_input_command)