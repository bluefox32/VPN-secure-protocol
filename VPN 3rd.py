import socket
import ssl
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
import hashlib
import logging
import threading

# ログ設定
logging.basicConfig(filename='vpn_access.log', level=logging.INFO, format='%(asctime)s %(message)s')

# サーバー証明書と秘密鍵のファイルパス
CERT_FILE = 'path/to/cert.pem'
KEY_FILE = 'path/to/key.pem'

# 公開鍵と秘密鍵の生成
server_private_key = RSA.generate(2048)
server_public_key = server_private_key.publickey()

# ユーザー情報（本番環境では安全な方法で管理）
USER_ID = "user123"
PASSWORD = "securepassword"

def generate_access_identifier():
    """アクセス識別子を生成"""
    return get_random_bytes(16)

def encrypt_user_credentials(user_id, password, access_identifier, public_key):
    """ユーザーIDとパスワードをハッシュ化し、アクセス識別子と組み合わせて暗号化"""
    credentials = f"{user_id}:{password}".encode()
    hashed_credentials = hashlib.sha256(credentials).digest()
    combined_data = hashed_credentials + access_identifier
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_data = cipher_rsa.encrypt(combined_data)
    return encrypted_data

def handle_client(conn, addr):
    """クライアント接続を処理"""
    logging.info(f'Connected by {addr}')
    
    try:
        access_identifier = conn.recv(16)
        encrypted_key = encrypt_user_credentials(USER_ID, PASSWORD, access_identifier, server_public_key)
        
        while True:
            data = conn.recv(1024)
            if not data:
                break
            
            nonce = data[:16]
            ciphertext = data[16:]
            cipher = AES.new(encrypted_key, AES.MODE_GCM, nonce=nonce)
            plaintext = cipher.decrypt(ciphertext)
            
            logging.info(f'Received data from {addr}: {plaintext.decode()}')
            
            response = b'ACK'
            conn.sendall(response)
    except Exception as e:
        logging.error(f'Error with connection {addr}: {str(e)}')
    finally:
        conn.close()

# サーバーの設定
def vpn_server():
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('127.0.0.1', 12345))
    server_socket.listen(5)
    
    with context.wrap_socket(server_socket, server_side=True) as ssock:
        while True:
            conn, addr = ssock.accept()
            threading.Thread(target=handle_client, args=(conn, addr)).start()

# クライアントの設定
def vpn_client():
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    with context.wrap_socket(client_socket, server_hostname='localhost') as ssock:
        ssock.connect(('localhost', 12345))
        
        access_identifier = get_random_bytes(16)
        ssock.sendall(access_identifier)
        
        encrypted_key = encrypt_user_credentials(USER_ID, PASSWORD, access_identifier, server_public_key)
        
        message = b'Hello, Server!'
        nonce = get_random_bytes(16)
        cipher = AES.new(encrypted_key, AES.MODE_GCM, nonce=nonce)
        ciphertext = cipher.encrypt(message)
        
        ssock.sendall(nonce + ciphertext)
        data = ssock.recv(1024)
        logging.info(f'Received from server: {data}')
        
        ssock.close()

# サーバーを起動する場合
# vpn_server()

# クライアントを起動する場合
# vpn_client()