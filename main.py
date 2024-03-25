from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3

hostName = "localhost"
serverPort = 8080

# Create SQLite database
conn = sqlite3.connect('totally_not_my_privateKeys.db')
cursor = conn.cursor()

# Table schema/ create keys table if not exists
cursor.execute('''
    CREATE TABLE IF NOT EXISTS keys(
        kid INTEGER PRIMARY KEY AUTOINCREMENT,
        key BLOB NOT NULL,
        exp INTEGER NOT NULL
    )
''')

# Function to generate RSA private key
def generate_private_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

# Function to serialize private key
def serialize(private_key):
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

# Function to deserialize private key
def deserialize(serialized_key):
    return serialization.load_pem_private_key(serialized_key, password=None)

# Function to store private key in db
def save_private_key(private_key, exp):
    serialized_key = serialize(private_key)
    cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (serialized_key, exp))
    conn.commit()

# Function to read private keys from the db
def get_private_keys():
    cursor.execute("SELECT key FROM keys WHERE exp >= ?", (int(datetime.datetime.utcnow().timestamp()),))
    rows = cursor.fetchall()
    private_keys = []
    for row in rows:
        private_key = deserialize(row[0])
        private_keys.append(private_key)
    return private_keys

# Function to convert rsa public key to base64url
def rsa_public_key(public_key):
    numbers = public_key.public_numbers()
    return {
        "alg": "RS256",
        "kty": "RSA",
        "use": "sig",
        "kid": str(numbers.n),
        "n": int_to_base64(numbers.n),
        "e": int_to_base64(numbers.e)
    }

# Function to convert int number to base64url
def int_to_base64(value):
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

class MyServer(BaseHTTPRequestHandler):
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        if parsed_path.path == "/auth":
            headers = {
                "kid": "goodKID"
            }
            token_payload = {
                "user": "username",
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            }
            if 'expired' in params:
                headers["kid"] = "expiredKID"
                private_keys = get_private_keys()
                if private_keys:
                    encoded_jwt = jwt.encode(token_payload, serialize(private_keys[0]), algorithm="RS256", headers=headers)
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(bytes(encoded_jwt, "utf-8"))
                else:
                    self.send_response(500)
                    self.end_headers()
                    self.wfile.write(bytes("No valid private key found", "utf-8"))
            else:
                private_keys = get_private_keys()
                if private_keys:
                    encoded_jwt = jwt.encode(token_payload, serialize(private_keys[0]), algorithm="RS256", headers=headers)
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(bytes(encoded_jwt, "utf-8"))
                else:
                    self.send_response(500)
                    self.end_headers()
                    self.wfile.write(bytes("No valid private key found", "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            private_keys = get_private_keys()
            jwks = {
                "keys": [rsa_public_key(private_key.public_key()) for private_key in private_keys]
            }
            self.wfile.write(bytes(json.dumps(jwks), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return

if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()


