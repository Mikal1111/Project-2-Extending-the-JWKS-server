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
database_name = "totally_not_my_privateKeys.db"


# Create or connect to SQLite database
conn = sqlite3.connect(database_name)
cursor = conn.cursor()


# Create keys table if not exists
cursor.execute('''CREATE TABLE IF NOT EXISTS keys(
                    kid INTEGER PRIMARY KEY AUTOINCREMENT,
                    key BLOB NOT NULL,
                    exp INTEGER NOT NULL)''')
conn.commit()


# Generate private keys if not exists
cursor.execute("SELECT COUNT(*) FROM keys WHERE exp >= ?", (datetime.datetime.utcnow().timestamp(),))
if cursor.fetchone()[0] == 0:
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    expired_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
   
    # Serialize keys to PEM format
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    expired_pem = expired_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
   
    # Insert keys into the database
    cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (pem, (datetime.datetime.utcnow() + datetime.timedelta(hours=1)).timestamp()))
    cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (expired_pem, (datetime.datetime.utcnow() - datetime.timedelta(hours=1)).timestamp()))
    conn.commit()


# Function to retrieve private key from the database
def get_private_key(expired=False):
    if expired:
        cursor.execute("SELECT key FROM keys WHERE exp < ?", (datetime.datetime.utcnow().timestamp(),))
    else:
        cursor.execute("SELECT key FROM keys WHERE exp >= ?", (datetime.datetime.utcnow().timestamp(),))
    result = cursor.fetchone()
    return result[0] if result else None


# Function to generate JWT
def generate_jwt(payload, expired=False):
    key = get_private_key(expired)
    if key:
        headers = {"kid": "goodKID"} if not expired else {"kid": "expiredKID"}
        encoded_jwt = jwt.encode(payload, key, algorithm="RS256", headers=headers)
        return encoded_jwt
    return None


# Function to convert integer to Base64URL-encoded string
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
            token_payload = {"user": "username"}
            if 'expired' in params:
                token_payload["exp"] = datetime.datetime.utcnow() - datetime.timedelta(hours=1)
                jwt_token = generate_jwt(token_payload, expired=True)
            else:
                token_payload["exp"] = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
                jwt_token = generate_jwt(token_payload)
           
            if jwt_token:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(bytes(jwt_token, "utf-8"))
                return


        self.send_response(405)
        self.end_headers()
        return


    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
           
            public_keys = []
            cursor.execute("SELECT key FROM keys WHERE exp >= ?", (datetime.datetime.utcnow().timestamp(),))
            keys = cursor.fetchall()
            for key_data in keys:
                key = serialization.load_pem_private_key(key_data[0], password=None)
                numbers = key.public_key().public_numbers()
                public_keys.append({
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": "goodKID",
                    "n": int_to_base64(numbers.n),
                    "e": int_to_base64(numbers.e)
                })
            jwks = {"keys": public_keys}
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



