import socket, threading, hashlib, os, struct, time
from aes import encrypt_aes128, decrypt_aes128
from dh import generate_dh_keys, compute_shared_key
from hmac_util import generate_hmac, verify_hmac

HOST, PORT = '127.0.0.1', 8080
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.settimeout(60)
server.bind((HOST, PORT))
server.listen()
print(f"[SERVER] Listening on {HOST}:{PORT}")

# Store user credentials (username: hashed password)
users = {
    "alice": hashlib.sha256("alice123".encode()).hexdigest(),
    "bob": hashlib.sha256("bob123".encode()).hexdigest(),
}

clients = {}
keys = {}
usernames = {}
P, G = 23, 5
client_counter = 0

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
            print(f"[SERVER] Received partial data: {len(data)}/{size} bytes")
        except socket.timeout:
            attempt += 1
            print(f"[SERVER] Receive timed out after {len(data)} bytes (attempt {attempt}/{max_attempts})")
            if attempt == max_attempts or len(data) == 0:
                return None
            time.sleep(2)
        except socket.error as e:
            print(f"[SERVER] Socket error in recv: {e}")
            return None
    return data if len(data) > 0 else None

def handle_client(conn, addr):
    global client_counter

    # Authenticate the client
    try:
        # Receive username length and username
        username_len_data = recv_exact(conn, 4)
        if not username_len_data:
            print(f"[SERVER] Failed to receive username length from {addr}: no data")
            conn.close()
            return
        username_len = struct.unpack("!I", username_len_data)[0]
        username_data = recv_exact(conn, username_len)
        if not username_data:
            print(f"[SERVER] Failed to receive username from {addr}: expected {username_len} bytes, got 0")
            conn.close()
            return
        username = username_data.decode('utf-8')
        print(f"[SERVER] Received username from {addr}: {username}")

        # Receive hashed password length and hashed password
        hashed_pwd_len_data = recv_exact(conn, 4)
        if not hashed_pwd_len_data:
            print(f"[SERVER] Failed to receive hashed password length from {addr}: no data")
            conn.close()
            return
        hashed_pwd_len = struct.unpack("!I", hashed_pwd_len_data)[0]
        hashed_pwd = recv_exact(conn, hashed_pwd_len)
        if not hashed_pwd:
            print(f"[SERVER] Failed to receive hashed password from {addr}")
            conn.close()
            return
        received_hash = hashed_pwd.decode('utf-8')
        print(f"[SERVER] Received hashed password from {username}: {received_hash}")

        # Verify credentials
        if username not in users:
            print(f"[SERVER] Authentication failed for {username}: unknown user")
            conn.sendall(b"FAIL")
            conn.close()
            return
        print(f"[SERVER] Expected hash for {username}: {users[username]}")
        print(f"[SERVER] Received hash: {received_hash}")
        if received_hash != users[username]:
            print(f"[SERVER] Authentication failed for {username}: incorrect password")
            conn.sendall(b"FAIL")
            conn.close()
            return

        # Authentication successful
        print(f"[SERVER] Authentication successful for {username}")
        conn.sendall(b"SUCCESS")

    except Exception as e:
        print(f"[SERVER] Authentication error for {addr}: {e}")
        conn.sendall(b"FAIL")
        conn.close()
        return

    # Proceed with Diffie-Hellman key exchange
    client_counter += 1
    print(f"[+] {addr} connected as {username}")

    conn.settimeout(60)
    priv, pub = generate_dh_keys(P, G)
    print(f"[SERVER] Generated private key: {priv}, public key: {pub}")
    try:
        length_data = recv_exact(conn, 4)
        if not length_data:
            print(f"[SERVER] Failed to receive public key length from {username}@{addr}: no data")
            conn.close()
            return
        length = struct.unpack("!I", length_data)[0]
        print(f"[SERVER] Expected public key length: {length} bytes")
        client_pub_data = recv_exact(conn, length)
        if not client_pub_data:
            print(f"[SERVER] Failed to receive client public key from {username}@{addr}: expected {length} bytes, got 0")
            conn.close()
            return
        client_pub = int(client_pub_data.decode())
        print(f"[SERVER] Received client public key: {client_pub} (length: {length} bytes)")
        pub_data = str(pub).encode()
        conn.sendall(struct.pack("!I", len(pub_data)) + pub_data)
        print(f"[SERVER] Sent public key data (length: {len(pub_data)} bytes): {pub_data.decode()}")
    except socket.timeout:
        print(f"[SERVER] Key exchange timed out for {username}@{addr}")
        conn.close()
        return
    except socket.error as e:
        print(f"[SERVER] Socket error during key exchange for {username}@{addr}: {e}")
        conn.close()
        return
    except ValueError as e:
        print(f"[SERVER] Invalid client public key received from {username}@{addr}: {e}")
        conn.close()
        return

    shared = compute_shared_key(client_pub, priv, P)
    print(f"[SERVER] Computed shared secret: {shared}")
    key = hashlib.sha256(str(shared).encode()).digest()[:16]
    print(f"[SERVER] Derived AES key: {key.hex()}")
    keys[conn] = key
    clients[conn] = addr
    usernames[conn] = username

    while True:
        try:
            length_data = recv_exact(conn, 4)
            if not length_data:
                print(f"[SERVER] Connection closed by {username}@{addr}")
                break
            enc_len = struct.unpack("!I", length_data)[0]
            data = recv_exact(conn, enc_len)
            iv = recv_exact(conn, 16)
            mac = recv_exact(conn, 32)
            if not data or not iv or not mac:
                print(f"[SERVER] Incomplete data received from {username}@{addr}")
                continue
            print(f"[SERVER] Received encrypted data from {username}: {data.hex()}")
            print(f"[SERVER] Received IV: {iv.hex()}")
            print(f"[SERVER] Received HMAC: {mac.hex()}")
            if not verify_hmac(key, data, mac):
                print(f"[SERVER] HMAC check failed for {username}")
                continue
            try:
                print(f"[SERVER] Attempting decryption with key: {key.hex()}, IV: {iv.hex()}, data: {data.hex()}")
                msg = decrypt_aes128(key, iv, data)
                if not msg:
                    print(f"[SERVER] Decryption failed: empty message for {username}")
                    continue
                decoded_msg = msg.decode('utf-8', errors='replace')
                print(f"[{username}@{addr}] {decoded_msg}")
            except UnicodeDecodeError as e:
                print(f"[SERVER] Decoding error for {username}: {e}, raw message: {msg.hex() if msg else 'None'}")
                continue
            except Exception as e:
                print(f"[SERVER] Decryption error for {username}: {e}, raw data: {data.hex()}")
                continue
            # Forward to other clients
            for c in list(clients.keys()):
                if c != conn:
                    try:
                        iv2 = os.urandom(16)
                        enc = encrypt_aes128(keys[c], iv2, msg)
                        mac2 = generate_hmac(keys[c], enc)
                        print(f"[SERVER] Forwarding to {usernames[c]}: encrypted data: {enc.hex()}")
                        print(f"[SERVER] Forwarding IV: {iv2.hex()}")
                        print(f"[SERVER] Forwarding HMAC: {mac2.hex()}")
                        c.sendall(struct.pack("!I", len(enc)))
                        c.sendall(enc)
                        c.sendall(iv2)
                        c.sendall(mac2)
                    except socket.error as e:
                        print(f"[SERVER] Error forwarding to {usernames[c]}: {e}")
                        c.close()
                        del clients[c], keys[c], usernames[c]
                        print(f"[-] {usernames[c]}@{clients[c]} disconnected due to error")
        except socket.error as e:
            print(f"[SERVER] Socket error for {username}@{addr}: {e}")
            break
        except Exception as e:
            print(f"[SERVER] Error for {username}@{addr}: {e}")
            break
    conn.close()
    if conn in clients:
        del clients[conn], keys[conn], usernames[conn]
    print(f"[-] {username}@{addr} disconnected")

while True:
    try:
        conn, addr = server.accept()
        print(f"[SERVER] Accepted connection from {addr}")
        threading.Thread(target=handle_client, args=(conn, addr)).start()
    except socket.timeout:
        print("[SERVER] Accept timed out, continuing to listen")
    except Exception as e:
        print(f"[SERVER] Accept error: {e}")