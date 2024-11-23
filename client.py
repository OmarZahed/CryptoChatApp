import socket
import threading
import rsa
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

# Generate RSA key pair for the client
(public_key, private_key) = rsa.newkeys(2048)

# Function to receive messages from the server
def receive_messages(sock, aes_key):
    while True:
        try:
            encrypted_message = sock.recv(1024)
            if encrypted_message:
                iv = encrypted_message[:16]
                cipher = AES.new(aes_key, AES.MODE_CBC, iv)
                decrypted_message = unpad(cipher.decrypt(encrypted_message[16:]), AES.block_size).decode()
                print(f"\r{decrypted_message}\n>> ", end="")
            else:
                print("\nDisconnected from chat server")
                sock.close()
                break
        except Exception as e:
            print(f"[ERROR] {e}")
            sock.close()
            break

# Main function for client connection
def main():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('127.0.0.1', 8081))

    # Handle login/signup
    print(client.recv(1024).decode())  # Welcome message
    while True:
        action = input(">> ")
        client.send(action.encode())

        if action == "signup":
            print(client.recv(1024).decode())  # Enter a username
            username = input(">> ")
            client.send(username.encode())

            print(client.recv(1024).decode())  # Enter a password
            password = input(">> ")
            client.send(password.encode())

            print(client.recv(1024).decode())  # Signup successful
        elif action == "login":
            print(client.recv(1024).decode())  # Enter username
            username = input(">> ")
            client.send(username.encode())

            print(client.recv(1024).decode())  # Enter password
            password = input(">> ")
            client.send(password.encode())

            login_response = client.recv(1024).decode()
            print(login_response)
            if "Login successful" in login_response:
                break
        else:
            print(client.recv(1024).decode())  # Invalid option

    # Send the client's public key to the server
    client.send(public_key.save_pkcs1())

    # Receive the encrypted AES key from the server
    encrypted_aes_key = client.recv(256)
    try:
        aes_key = rsa.decrypt(encrypted_aes_key, private_key)
    except rsa.DecryptionError as e:
        print("[ERROR] AES key decryption failed:", e)
        client.close()
        return

    print("[INFO] Successfully received and decrypted the AES key.")

    # Start thread to receive messages from server
    threading.Thread(target=receive_messages, args=(client, aes_key), daemon=True).start()

    # Main loop for sending messages
    while True:
        try:
            message = input(">> ")
            if message.lower() == 'quit':
                client.close()
                break

            # Encrypt the message with AES and send
            iv = os.urandom(16)
            cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            encrypted_message = iv + cipher.encrypt(pad(message.encode(), AES.block_size))
            client.send(encrypted_message)

        except Exception as e:
            print(f"[ERROR] {e}")
            client.close()
            break

if __name__ == "__main__":
    main()
