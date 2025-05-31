# CLI E2EE Chat Application — System Architecture & Implementation Plan

---

## 🏗️ System Architecture & Key Flows

### 1. User Authentication & Login
- Client prompts user for username & password (or key-based auth).
- Client sends login request to server.
- Server authenticates user.
- Server responds with:
  - User’s unread messages metadata & content.
  - List of current active connections.

---

### 2. Connection Request Flow (Public Key Exchange)
- User A wants to chat with User B.
- User A sends connection request to server with their public key + User B’s ID.
- Server stores this request as **pending** and forwards the request to User B (if online).
- User B’s client displays incoming connection request:  
  “User A wants to connect. Accept? [Y/n]”
- User B accepts or denies:
  - If **accepted**, server updates connection state to **accepted** for both.
  - If **denied**, server deletes or marks request denied.
- Once connected, both users have each other’s public keys saved locally for encryption.

---

### 3. Message Sending and Receiving
- When user sends a message to a connected peer:
  - Message is encrypted with shared key (derived from public keys).
  - Encrypted message sent to server with recipient info.
- Server stores the message and forwards it to recipient if online.
- Recipient decrypts message on receiving.
- Server tracks if message was delivered/read to update unread counts.

---

### 4. Unread Messages
- On login, server sends all unread messages to the client.
- Client shows unread messages grouped by sender.
- Client sends “read receipts” to server when user reads messages.

---

### 5. Client Data Storage
- Store locally:
  - User’s own private key (securely!)
  - List of connected users (with public keys)
  - Session keys for each connection
  - Chat history (optional for offline access)

---

## 📋 Next Steps & Suggestions for Implementation

### Step 1: Basic CLI + Login + Unread Message Retrieval
- Set up the **server** with user authentication and message storage.
- Create the **client** that logs in and fetches unread messages.

### Step 2: Connection Request & Approval Flow
- Implement connection request messages.
- Client UI for accepting/denying requests.
- Store connections server and client side.

### Step 3: E2EE Messaging
- Use cryptographic library (e.g., `crypto/ed25519`, `golang.org/x/crypto/curve25519`) for keys.
- Implement key exchange and shared key derivation.
- Encrypt/decrypt messages on client side.

### Step 4: Maintain connections & message sync
- Update server to store connections, message statuses.
- Client maintains local state and connection list.

---
