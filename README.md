# CryptoChatApp
# CRYPTOGRAPHY CW1: SecureChat

## Introduction
**SecureChat** is a cryptographic client-server application designed to ensure secure communication and user authentication using a combination of RSA, AES, and bcrypt cryptographic techniques. The project focuses on confidentiality, integrity, and authentication of data for secure real-time messaging.

## Features
- **User Authentication**: Secure sign-up and login with password hashing.
- **End-to-End Encryption**: Secure communication between client and server.
- **Key Exchange**: RSA-based secure AES session key delivery.
- **Real-Time Messaging**: Encrypted and decrypted communication using AES.

## Architecture
### Server
- Manages user authentication.
- Distributes AES session keys via RSA encryption.
- Broadcasts encrypted messages to clients.

### Client
- Handles user authentication (sign-up/login).
- Exchanges RSA public keys for secure communication.
- Sends and receives encrypted messages using AES.

## Cryptographic Techniques
1. **RSA**: Asymmetric encryption for secure key exchange.
2. **AES**: Symmetric encryption for real-time communication.
3. **bcrypt**: Password hashing with salting for user authentication.

## Implementation Highlights
### Key Exchange
- RSA is used to securely transfer AES session keys from the server to the client.

### Messaging
- AES (CBC mode) encrypts and decrypts all chat messages.
- Unique Initialization Vectors (IVs) ensure ciphertext uniqueness.

### Password Security
- bcrypt hashes passwords during signup and verifies them during login.

## Security Analysis
### Strengths
- **End-to-End Encryption**: Ensures secure communication.
- **Secure Authentication**: Passwords are hashed using bcrypt.
- **Key Exchange**: RSA prevents interception of AES keys.

### Potential Improvements
- Add Public Key Infrastructure (PKI) for enhanced RSA security.
- Use TLS for additional communication security.

## Unit Testing
### Tested Components
- RSA key generation and encryption/decryption.
- AES encryption and decryption workflows.
- bcrypt hashing and password verification.
- Client-server communication.

### Observations
- Encryption and decryption performed as expected.
- bcrypt effectively secured passwords.
- Server handled multiple client connections efficiently.

## Conclusion
**SecureChat** demonstrates the application of cryptographic techniques for secure communication. With further enhancements like PKI and TLS, it can provide even greater resilience against attacks.

---
