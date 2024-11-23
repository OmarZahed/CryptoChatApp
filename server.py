import socket
import threading
import rsa
import bcrypt
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

# Global dictionaries to keep track of clients
clients = {}
usernames = {}
client_keys = {}  # Store AES keys for each client
client_public_keys = {}  # Store each client's public RSA key


# Function to handle individual client connections
def handle_client(conn, addr):
    print(f"[NEW CONNECTION] {addr} connected.")
    conn.send("Welcome! Please type 'signup' to register or 'login' to log in: ".encode())

    authenticated = False
    username = ""

    while not authenticated:
        try:
            credentials = conn.recv(1024).decode().strip().lower()
            print(f"[DEBUG] Received credentials action: {credentials}")
            if credentials == "signup":
                conn.send("Enter a username: ".encode())
                username = conn.recv(1024).decode().strip()
                print(f"[DEBUG] Signup username received: {username}")

                conn.send("Enter a password: ".encode())
                password = conn.recv(1024).decode().strip()
                print(f"[DEBUG] Signup password received for username {username}")

                # Hash the password using bcrypt
                hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

                # Store the username and hashed password in the cred.txt file
                with open("cred.txt", "a") as f:
                    f.write(f"{username} {hashed_password.decode()}\n")

                # Generate RSA key pair for the client and save them
                public_key, private_key = rsa.newkeys(2048)
                with open(f"{username}_public_key.pem", "wb") as pub_file:
                    pub_file.write(public_key.save_pkcs1())
                with open(f"{username}_private_key.pem", "wb") as priv_file:
                    priv_file.write(private_key.save_pkcs1())
                print(f"[INFO] Generated and saved RSA key pair for {username}")

                conn.send("Signup successful. Please type 'login' to log in now.\n".encode())
                print(f"[INFO] User {username} signed up successfully.")
            elif credentials == "login":
                conn.send("Enter your username: ".encode())
                username = conn.recv(1024).decode().strip()
                print(f"[DEBUG] Login username received: {username}")

                conn.send("Enter your password: ".encode())
                password = conn.recv(1024).decode().strip()
                print(f"[DEBUG] Login password received for username {username}")

                authenticated = False

                # Read the credentials file to verify username and password
                with open("cred.txt", "r") as f:
                    lines = f.readlines()
                    for line in lines:
                        stored_username, stored_hashed_password = line.strip().split(maxsplit=1)
                        if stored_username == username:
                            # Verify the hashed password
                            if bcrypt.checkpw(password.encode(), stored_hashed_password.encode()):
                                authenticated = True
                                print(f"[INFO] User {username} authenticated successfully.")
                                break

                if authenticated:
                    conn.send(f"Login successful! Welcome, {username}.\n".encode())
                else:
                    conn.send("Invalid credentials. Try again.\n".encode())
                    print(f"[WARN] Failed login attempt for username {username}")
            else:
                conn.send("Invalid option. Please type 'signup' or 'login': ".encode())
        except Exception as e:
            print(f"[ERROR] {e}")
            conn.close()
            return

    # Receive and store the client's public key
    client_public_key_data = conn.recv(1024)
    client_public_key = rsa.PublicKey.load_pkcs1(client_public_key_data)
    client_public_keys[username] = client_public_key
    print(f"[INFO] Received public key from {username}.")

    # Save the received public key for verification
    with open(f"{username}_received_public_key.pem", "wb") as pub_file:
        pub_file.write(client_public_key.save_pkcs1())
    print(f"[INFO] Saved received public key for {username}")

    # Generate AES session key for this client
    aes_key = os.urandom(16)  # AES-128
    encrypted_aes_key = rsa.encrypt(aes_key, client_public_key)
    conn.send(encrypted_aes_key)  # Send the encrypted AES key to the client
    client_keys[conn] = aes_key
    print(f"[INFO] AES session key exchanged with {username}.")

    # Store the client connection and username
    usernames[conn] = username
    clients[username] = conn
    print(f"[INFO] User {username} added to active clients.")

    broadcast(f"{username} has joined the chat!", conn)

    # Client interaction loop
    while True:
        try:
            encrypted_message = conn.recv(1024)
            if encrypted_message:
                aes_key = client_keys[conn]
                try:
                    cipher = AES.new(aes_key, AES.MODE_CBC, iv=encrypted_message[:16])
                    message = unpad(cipher.decrypt(encrypted_message[16:]), AES.block_size).decode()
                    print(f"[DEBUG] Message received from {username}: {message}")
                    broadcast(f"{username}: {message}", conn)
                except (ValueError, KeyError) as e:
                    print(f"[ERROR] Decryption failed: {e}")
            else:
                print(f"[WARN] Empty message received from {username}. Removing client.")
                remove_client(conn)
                break
        except Exception as e:
            print(f"[ERROR] {e}")
            remove_client(conn)
            break


# Function to broadcast messages to all clients except the sender
def broadcast(message, sender_conn):
    print(f"[BROADCAST] Broadcasting message: {message}")
    for client_conn in clients.values():
        if client_conn != sender_conn:
            try:
                aes_key = client_keys[client_conn]
                iv = os.urandom(16)
                cipher = AES.new(aes_key, AES.MODE_CBC, iv)
                encrypted_message = iv + cipher.encrypt(pad(message.encode(), AES.block_size))
                client_conn.send(encrypted_message)
                print(f"[DEBUG] Message sent to {usernames[client_conn]}")
            except Exception as e:
                print(f"[ERROR] {e}")
                remove_client(client_conn)


# Function to remove client from the list
def remove_client(conn):
    username = usernames.get(conn)
    if username:
        print(f"[DISCONNECT] {username} has left the chat.")
        broadcast(f"{username} has left the chat.", conn)
        del clients[username]
        del usernames[conn]
        del client_keys[conn]
        conn.close()
        print(f"[INFO] Connection with {username} closed and removed from active clients.")


# Main function to accept connections
def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', 8081))
    server.listen()
    print("[SERVER STARTED] Waiting for connections...")

    while True:
        conn, addr = server.accept()
        print(f"[INFO] Accepted connection from {addr}")
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()
        print(f"[ACTIVE CONNECTIONS] {threading.active_count() - 1}")


if __name__ == "__main__":
    main()
