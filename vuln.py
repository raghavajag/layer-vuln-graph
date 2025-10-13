import sqlite3
import xml.etree.ElementTree as ET
import pickle
import os
from flask import Flask, request, make_response

app = Flask(__name__)

# --------------------
# Real Endpoints with Vulnerabilities
# --------------------

def sql_injection(user_input):
    conn = sqlite3.connect("test.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{user_input}'"
    cursor.execute(query)
    result = cursor.fetchall()
    conn.close()
    return result

def broken_auth(username, password):
    return username == "adminuser" and password == "xchzdhkrltu"

def store_sensitive_data():
    with open("passwords.txt", "w") as f:
        f.write("admin:Passwo#d@&1957")

def parse_xml(xml_data):
    tree = ET.ElementTree(ET.fromstring(xml_data))
    return tree

@app.route('/access_control', methods=['GET'])
def access_control():
    role = request.args.get('role')
    if role == "admin":
        return "Welcome Admin!"
    return "Access Denied!"

@app.route('/security_misconfig', methods=['GET'])
def security_misconfig():
    response = make_response("Security Misconfiguration Example")
    response.headers['X-Powered-By'] = "Python-Flask"
    return response

@app.route('/xss', methods=['GET'])
def xss_vulnerability():
    user_input = request.args.get('input')
    return f"<html><body>{user_input}</body></html>"

def insecure_deserialization(serialized_data):
    return pickle.loads(serialized_data)

# --------------------
# DEAD CODES WITH VULNERABILITIES
# --------------------

# Dead Vulnerability 1: SQL Injection (never used)
def dead_sql_injection():
    user_input = "' OR '1'='1"
    conn = sqlite3.connect("test.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE username = '{user_input}'")  # vulnerable
    data = cursor.fetchall()
    conn.close()
    return data

# Dead Vulnerability 2: Hardcoded Credentials
def dead_hardcoded_credentials():
    username = "admin"
    password = "SuperSecret123!"  # hardcoded password
    if username == "admin" and password == "SuperSecret123!":
        return True
    return False

# Dead Vulnerability 3: Insecure Deserialization
def dead_insecure_deserialization():
    malicious_data = b"cos\nsystem\n(S'echo vulnerable'\ntR."
    return pickle.loads(malicious_data)  # never called but vulnerable

# Dead Vulnerability 4: Path Traversal
def dead_path_traversal():
    user_file = "../../etc/passwd"
    with open(user_file, "r") as f:
        return f.read()

# Dead Vulnerability 5: XXE via XML parsing
def dead_xxe():
    xml_data = """<?xml version="1.0"?>
    <!DOCTYPE foo [ <!ELEMENT foo ANY >
    <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
    <foo>&xxe;</foo>"""
    ET.fromstring(xml_data)

# Dead Vulnerability 6: Command Injection
def dead_command_injection():
    user_input = "test; rm -rf /"
    os.system("echo " + user_input)  # vulnerable to injection

# --------------------
# Unused Constants / Dummy Declarations
# --------------------

UNUSED_SECRET = "shhh_this_is_a_secret_key_123456"
UNUSED_API_KEY = "AIzaSyD-DeadCode-APIKEY-HERE"

if __name__ == "__main__":
    app.run(debug=True)