import tkinter as tk
from tkinter import scrolledtext, messagebox
import threading
import client
import rsa
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
import socket
import time

class ClientGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("Secure Chat Client")
        self.master.geometry("500x600")

        self.client_socket = None
        self.aes_key = None

        # Login Frame
        self.login_frame = tk.Frame(master)
        self.login_frame.pack(pady=10)

        tk.Label(self.login_frame, text="Username:").grid(row=0, column=0, padx=5, pady=5)
        self.username_entry = tk.Entry(self.login_frame)
        self.username_entry.grid(row=0, column=1, padx=5, pady=5)

        tk.Label(self.login_frame, text="Password:").grid(row=1, column=0, padx=5, pady=5)
        self.password_entry = tk.Entry(self.login_frame, show="*")
        self.password_entry.grid(row=1, column=1, padx=5, pady=5)

        self.signup_button = tk.Button(self.login_frame, text="Sign Up", command=self.signup)
        self.signup_button.grid(row=2, column=0, pady=10)

        self.login_button = tk.Button(self.login_frame, text="Login", command=self.login)
        self.login_button.grid(row=2, column=1, pady=10)

        # Chat Frame
        self.chat_frame = tk.Frame(master)

        self.chat_text_area = scrolledtext.ScrolledText(self.chat_frame, wrap=tk.WORD, width=60, height=20, state='disabled')
        self.chat_text_area.pack(padx=10, pady=10)

        self.message_entry = tk.Entry(self.chat_frame, width=40)
        self.message_entry.pack(side=tk.LEFT, padx=10, pady=10)

        self.send_button = tk.Button(self.chat_frame, text="Send", command=self.send_message)
        self.send_button.pack(side=tk.RIGHT, padx=10, pady=10)

        self.public_key, self.private_key = rsa.newkeys(2048)

    def signup(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        if username and password:
            try:
                self.connect_to_server()
                self.client_socket.send(b"signup")
                time.sleep(0.1)
                self.client_socket.recv(1024)  # Receive prompt
                self.client_socket.send(username.encode())
                time.sleep(0.1)
                self.client_socket.recv(1024)  # Receive prompt
                self.client_socket.send(password.encode())
                time.sleep(0.1)
                response = self.client_socket.recv(1024).decode()
                messagebox.showinfo("Sign Up", response)
                self.client_socket.close()
            except Exception as e:
                messagebox.showerror("Error", str(e))
        else:
            messagebox.showwarning("Warning", "Please enter both username and password.")

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        if username and password:
            try:
                self.connect_to_server()
                self.client_socket.send(b"login")
                time.sleep(0.1)
                self.client_socket.recv(1024)  # Receive prompt
                self.client_socket.send(username.encode())
                time.sleep(0.1)
                self.client_socket.recv(1024)  # Receive prompt
                self.client_socket.send(password.encode())
                time.sleep(0.1)
                response = self.client_socket.recv(1024).decode()
                if "Login successful" in response:
                    messagebox.showinfo("Login", response)
                    self.start_chat()
                else:
                    messagebox.showerror("Login Failed", response)
                    self.client_socket.close()
            except Exception as e:
                messagebox.showerror("Error", str(e))
        else:
            messagebox.showwarning("Warning", "Please enter both username and password.")

    def connect_to_server(self):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect(('127.0.0.1', 8081))

    def start_chat(self):
        self.login_frame.pack_forget()
        self.chat_frame.pack(pady=10)


        self.client_socket.send(self.public_key.save_pkcs1())


        encrypted_aes_key = self.client_socket.recv(256)
        self.aes_key = rsa.decrypt(encrypted_aes_key, self.private_key)

        # Start thread to receive messages
        threading.Thread(target=self.receive_messages, daemon=True).start()

    def receive_messages(self):
        while True:
            try:
                encrypted_message = self.client_socket.recv(1024)
                if encrypted_message:
                    iv = encrypted_message[:16]
                    cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
                    decrypted_message = unpad(cipher.decrypt(encrypted_message[16:]), AES.block_size).decode()
                    self.chat_text_area.config(state='normal')
                    self.chat_text_area.insert(tk.END, decrypted_message + '\n')
                    self.chat_text_area.config(state='disabled')
                    self.chat_text_area.yview(tk.END)
                else:
                    self.client_socket.close()
                    break
            except Exception as e:
                messagebox.showerror("Error", str(e))
                self.client_socket.close()
                break

    def send_message(self):
        message = self.message_entry.get()
        if message:
            try:
                iv = os.urandom(16)
                cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
                encrypted_message = iv + cipher.encrypt(pad(message.encode(), AES.block_size))
                self.client_socket.send(encrypted_message)
                self.message_entry.delete(0, tk.END)

                # Display the sent message in the chat area
                self.chat_text_area.config(state='normal')
                self.chat_text_area.insert(tk.END, "You: " + message + '\n')
                self.chat_text_area.config(state='disabled')
                self.chat_text_area.yview(tk.END)
            except Exception as e:
                messagebox.showerror("Error", str(e))
                self.client_socket.close()

if __name__ == "__main__":
    root = tk.Tk()
    client_gui = ClientGUI(root)
    root.mainloop()
