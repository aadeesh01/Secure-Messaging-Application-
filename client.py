import socket, hashlib, threading, os, struct, time
from aes import encrypt_aes128, decrypt_aes128
from dh import generate_dh_keys, compute_shared_key
from hmac_util import generate_hmac, verify_hmac

HOST, PORT = '127.0.0.1', 8080
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.settimeout(60)

try:
    client.connect((HOST, PORT))
except Exception as e:
    print(f"[CLIENT] Connection failed: {e}")
    exit(1)

# Prompt for username and password
username = input("Enter your username: ").strip()
if not username:
    username = "anonymous"
password = input("Enter your password: ").strip()
if not password:
    print("[CLIENT] Password cannot be empty")
    client.close()
    exit(1)
print(f"[CLIENT] Proceeding as {username}")

# Send username and hashed password for authentication
try:
    # Send username
    username_data = username.encode('utf-8')
    client.sendall(struct.pack("!I", len(username_data)) + username_data)
    print(f"[CLIENT] Sent username (length: {len(username_data)} bytes): {username}")

    # Hash the password and send it
    password_data = password.encode('utf-8')
    hashed_password = hashlib.sha256(password_data).hexdigest().encode('utf-8')
    client.sendall(struct.pack("!I", len(hashed_password)) + hashed_password)
    print(f"[CLIENT] Sent hashed password: {hashed_password.decode()}")

    # Receive authentication result
    auth_result = client.recv(7)
    if auth_result != b"SUCCESS":
        print("[CLIENT] Authentication failed")
        client.close()
        exit(1)
    print("[CLIENT] Authentication successful")

except socket.timeout:
    print("[CLIENT] Authentication timed out")
    client.close()
    exit(1)
except socket.error as e:
    print(f"[CLIENT] Socket error during authentication: {e}")
    client.close()
    exit(1)
except Exception as e:
    print(f"[CLIENT] Authentication error: {e}")
    client.close()
    exit(1)

# Diffie-Hellman key exchange with logging
P, G = 23, 5
priv, pub = generate_dh_keys(P, G)
print(f"[CLIENT] Generated private key: {priv}, public key: {pub}")
try:
    pub_data = str(pub).encode()
    client.sendall(struct.pack("!I", len(pub_data)) + pub_data)
    print(f"[CLIENT] Sent public key data (length: {len(pub_data)} bytes): {pub_data.decode()}")
    length_data = client.recv(4)
    if not length_data:
        print("[CLIENT] Failed to receive server public key length: no data")
        client.close()
        exit(1)
    length = struct.unpack("!I", length_data)[0]
    server_pub_data = client.recv(length)
    if not server_pub_data:
        print(f"[CLIENT] Failed to receive server public key: expected {length} bytes, got 0")
        client.close()
        exit(1)
    server_pub = int(server_pub_data.decode())
    print(f"[CLIENT] Received server public key: {server_pub} (length: {length} bytes)")
except socket.timeout:
    print("[CLIENT] Key exchange timed out")
    client.close()
    exit(1)
except socket.error as e:
    print(f"[CLIENT] Socket error during key exchange: {e}")
    client.close()
    exit(1)
except ValueError as e:
    print(f"[CLIENT] Invalid server public key received: {e}")
    client.close()
    exit(1)

shared = compute_shared_key(server_pub, priv, P)
print(f"[CLIENT] Computed shared secret: {shared}")
key = hashlib.sha256(str(shared).encode()).digest()[:16]
print(f"[CLIENT] Derived AES key: {key.hex()}")

def recv_exact(sock, size):
    data = b''
    max_attempts = 3
    attempt = 0
    while len(data) < size and attempt < max_attempts:
        try:
            part = sock.recv(size - len(data))
            if not part:
                return None
            data += part
            print(f"[CLIENT] Received partial data: {len(data)}/{size} bytes")
        except socket.timeout:
            attempt += 1
            print(f"[CLIENT] Receive timed out after {len(data)} bytes (attempt {attempt}/{max_attempts})")
            if attempt == max_attempts or len(data) == 0:
                return None
            time.sleep(2)
        except socket.error as e:
            print(f"[CLIENT] Socket error in recv: {e}")
            return None
    return data if len(data) > 0 else None

def receive():
    while True:
        try:
            length_data = recv_exact(client, 4)
            if not length_data:
                print("[CLIENT] Connection closed by server")
                break
            enc_len = struct.unpack("!I", length_data)[0]
            data = recv_exact(client, enc_len)
            iv = recv_exact(client, 16)
            mac = recv_exact(client, 32)
            if not data or not iv or not mac:
                print("[CLIENT] Incomplete data received")
                break
            print(f"[CLIENT] Received encrypted data: {data.hex()}")
            print(f"[CLIENT] Received IV: {iv.hex()}")
            print(f"[CLIENT] Received HMAC: {mac.hex()}")
            if not verify_hmac(key, data, mac):
                print("[!] HMAC check failed")
                continue
            print(f"[CLIENT] Attempting decryption with key: {key.hex()}, IV: {iv.hex()}, data: {data.hex()}")
            msg = decrypt_aes128(key, iv, data)
            if not msg:
                print("[CLIENT] Decryption failed: empty or invalid message")
                continue
            try:
                decoded_msg = msg.decode('utf-8', errors='replace')
                print(f"\n[RECV]: {decoded_msg}")
            except UnicodeDecodeError as e:
                print(f"[CLIENT] Decoding error: {e}, raw message: {msg.hex()}")
        except Exception as e:
            print(f"[CLIENT] Receive error: {e}")
            break

threading.Thread(target=receive, daemon=True).start()

while True:
    try:
        msg = input(f"{username}: ").strip().encode('utf-8')
        if not msg:
            continue
        iv = os.urandom(16)
        enc = encrypt_aes128(key, iv, msg)
        mac = generate_hmac(key, enc)
        print(f"[CLIENT] Sending encrypted data: {enc.hex()}")
        print(f"[CLIENT] Sending IV: {iv.hex()}")
        print(f"[CLIENT] Sending HMAC: {mac.hex()}")
        client.sendall(struct.pack("!I", len(enc)))
        client.sendall(enc)
        client.sendall(iv)
        client.sendall(mac)
    except KeyboardInterrupt:
        print("\n[CLIENT] Exiting")
        client.close()
        break
    except socket.error as e:
        print(f"[CLIENT] Socket error: {e}")
        client.close()
        break
    except Exception as e:
        print(f"[CLIENT] Error: {e}")
        client.close()
        break