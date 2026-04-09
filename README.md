# SecureChat — TLS-like Secure Communication System

## Project Summary

SecureChat is a full-stack, security-focused application that implements a simplified version of the Transport Layer Security (TLS) protocol. The system demonstrates how secure communication is established and maintained between a client and server over an untrusted network.

This project was developed as part of a Software and Computer Security course to provide hands-on experience with cryptographic protocols, secure system design, and real-world attack mitigation techniques.

---

## Key Highlights

- Designed and implemented a **TLS-like secure communication protocol** from scratch
- Implemented **end-to-end encrypted messaging** using AES-256-GCM
- Built **secure handshake mechanism** using RSA (2048-bit) and HKDF-SHA256
- Developed **real-time web application (Flask + JavaScript Web Crypto API)**
- Implemented protection against:
  - Man-in-the-middle (MITM) attacks
  - Ciphertext tampering
  - Replay attacks
- Performed **network-level validation using Wireshark** to confirm zero plaintext leakage
- Built modular backend with session management, cryptographic utilities, and secure API endpoints

---

## Core Security Concepts Implemented

### Authentication

- Server identity verified using **SHA-256 fingerprint pinning**
- Prevents impersonation and MITM attacks

### Confidentiality

- All messages encrypted using **AES-256-GCM**
- Ensures data cannot be read by third parties

### Integrity

- AES-GCM authentication tags detect any modification of ciphertext
- Tampered messages are automatically rejected

### Replay Protection

- Monotonic **sequence numbers** prevent reuse of captured messages

---

## System Architecture

```
Client (Browser / Python)
        ↓
Encrypted API Requests (HTTP)
        ↓
Flask Server
        ↓
Crypto Layer (RSA, HKDF, AES-GCM)
        ↓
Session Manager
```

### Components:

- **Client (Frontend):**
  - JavaScript (Web Crypto API)
  - Handles encryption, fingerprint verification, and communication

- **Server (Backend):**
  - Python Flask
  - Handles handshake, decryption, validation, and response generation

---

## Protocol Design

### Handshake Phase

1. Server generates RSA key pair and sends public key + fingerprint
2. Client verifies fingerprint (authentication)
3. Client generates premaster secret and encrypts using RSA
4. Both derive symmetric session keys using HKDF

### Secure Communication Phase

- Messages encrypted using AES-256-GCM
- Each message includes:
  - Nonce (random value for uniqueness)
  - Sequence number (replay protection)
  - Ciphertext

---

## Security Testing

### Tamper Test

- Modifies ciphertext before transmission
- AES-GCM detects mismatch → message rejected

### Replay Test

- Resends previously valid message
- Server detects duplicate sequence number → blocked

### Wrong Fingerprint Test

- Uses incorrect server identity
- Client aborts handshake → connection rejected

### Wireshark Analysis

- Captured network traffic shows only encrypted data
- No plaintext messages found → confirms confidentiality

---

## Technologies Used

- **Backend:** Python, Flask
- **Frontend:** HTML, CSS, JavaScript (Web Crypto API)
- **Cryptography:** RSA, AES-256-GCM, HKDF-SHA256
- **Networking:** HTTP APIs
- **Tools:** Wireshark

---

## How to Run

### 1. Install dependencies

```
pip install -r requirements.txt
```

### 2. Start server

```
python app.py
```

### 3. Open browser

```
http://127.0.0.1:5000
```

---

## 🔬 Wireshark

Filter:

```
tcp.port == 5000
```

Search:

```
Hello from SecureChat client
```

---

## Learning Outcomes

- Deep understanding of TLS protocol design
- Hands-on implementation of cryptographic algorithms
- Experience with secure API design and testing
- Practical exposure to real-world attack scenarios
- Network traffic analysis using Wireshark

---

## Disclaimer

This project is intended for educational purposes and does not replace production-grade TLS implementations.
