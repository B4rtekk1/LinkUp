# LinkUp - Secure WebSocket Chat Application

## Overview

LinkUp is a secure WebSocket-based chat application written in Go. It consists of a server (`main.go`) that handles user registration and real-time messaging, and a console-based client (`client.go`) for interacting with the server via a command-line interface (CMD). The server supports multiple simultaneous WebSocket connections, user registration via HTTP, and message broadcasting with AES-GCM encryption for end-to-end security. Clients must authenticate with a username and password before sending messages, ensuring only registered users can participate in the chat. The console client also supports user registration directly from the command line and displays the sender's username for each received message.

This project is ideal for learning about WebSocket communication, secure message encryption, SQLite-based user management, and authentication mechanisms. It can be extended for use cases like real-time chat applications or multiplayer games.

## Features

- **User Registration**: Register users via HTTP POST to `/register` or directly from the console client, with usernames and passwords stored securely in a SQLite database with bcrypt-hashed passwords.
- **User Authentication**: Clients must authenticate with a username and password upon WebSocket connection to send messages.
- **Sender Identification**: Each received message displays the sender's username (e.g., `Received from Bartekbk: Hello, world!`).
- **WebSocket Communication**: Supports multiple clients over `ws://` (HTTP) or `wss://` (HTTPS) with real-time message broadcasting.
- **End-to-End Encryption**: Messages are encrypted and decrypted using AES-GCM with a shared 32-byte key.
- **Thread-Safe Client Management**: Uses a mutex to safely manage connected clients.
- **Console Client**: A command-line client (`client.go`) for registering, logging in, and sending/receiving messages via CMD.
- **Configurable Server**: Supports HTTP/HTTPS, custom ports, and TLS certificates via command-line flags.
- **Error Logging**: Detailed logging for debugging connection, encryption, authentication, and database issues.

## Prerequisites

- **Go**: Version 1.16 or higher ([Install Go](https://go.dev/doc/install)).
- **Dependencies**:
  - `github.com/gorilla/websocket`: For WebSocket communication.
  - `github.com/joho/godotenv`: For loading environment variables.
  - `github.com/mattn/go-sqlite3`: For SQLite database support.
  - `golang.org/x/crypto/bcrypt`: For password hashing.
- **OpenSSL** (optional): For generating self-signed TLS certificates for testing HTTPS.
- **Environment File**: A `.env` file with a 32-byte `AES_KEY` for message encryption.

## Installation

1. **Clone or create the project directory**:
   Create a directory for the project and place `main.go` and `client.go` in it.

2. **Initialize a Go module**:

   ```bash
   go mod init linkup
   ```

3. **Install dependencies**:

   ```bash
   go get github.com/gorilla/websocket
   go get github.com/joho/godotenv
   go get github.com/mattn/go-sqlite3
   go get golang.org/x/crypto/bcrypt
   ```

4. **Create a `.env` file**:

   In the project directory, create a `.env` file with a 32-byte AES key:

   ```env
   AES_KEY=6v7zX8k9p3qW2rT5mY1nJ4hL8gF2dC0a
   ```

   To generate a random key:

   ```bash
   openssl rand -base64 32
   ```

5. **Generate SSL/TLS certificates (optional, for HTTPS)**:
   For local testing with HTTPS:

   ```bash
   openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
   ```

## Usage

### Running the Server

1. **Start the server**:
   - **Without HTTPS (recommended for local testing)**:

     ```bash
     go run main.go -port=8080 -https=false
     ```

   - **With HTTPS**:

     ```bash
     go run main.go -port=8080 -https=true -cert=cert.pem -key=key.pem
     ```

   - The server will listen on `http://localhost:8080` (or `https://localhost:8080` for HTTPS).
   - Logs will confirm database initialization and server startup.

2. **Available endpoints**:
   - `POST /register`: Register a new user with a JSON body `{ "username": "user", "password": "pass" }`.
   - `WebSocket /ws`: Connect to the WebSocket server for real-time messaging (requires authentication).

### Running the Console Client

1. **Start the client**:
   In a separate terminal, run:

   ```bash
   go run client.go
   ```

   - Ensure the `.env` file with the same `AES_KEY` is present in the client directory.
   - The client will prompt to choose between registration and login.

2. **Registering a user**:
   - When prompted with `Do you want to register a new account? (yes/no):`, enter `yes` or `y`.
   - Enter a username and password for registration.
   - If registration is successful, you will see `User registered successfully`, and the client will proceed to authentication with the same credentials.
   - If the username is already taken, the client will exit with an error (e.g., `Registration failed: User already exists`).

3. **Logging in**:
   - If you choose `no` at the registration prompt, enter a username and password for login.
   - If authentication fails, the client will exit with an error (e.g., `Authentication failed: invalid username or password`).
   - On success, you will see `Authentication successful`.

4. **Sending messages**:
   - Type a message and press Enter to send it (e.g., `Hello, world!`).
   - Messages are encrypted with AES-GCM and broadcast to all connected clients.
   - Type `exit` to quit the client.

5. **Receiving messages**:
   - Received messages are decrypted and displayed with the sender's username (e.g., `Received from Bartekbk: Hello, world!`).

### Testing with Postman

1. **Register a user**:
   - Create a POST request to `http://localhost:8080/register`.
   - Set headers: `Content-Type: application/json`.
   - Body (raw JSON):

     ```json
     {
         "username": "testuser",
         "password": "testpassword123"
     }
     ```

   - Expected response: `201 Created` with `User registered successfully`.

2. **Test WebSocket**:
   - Create a WebSocket request in Postman to `ws://localhost:8080/ws`.
   - Send an authentication message (JSON) immediately after connecting:

     ```json
     {
         "username": "testuser",
         "password": "testpassword123"
     }
     ```

   - If authentication succeeds, you will receive `Authentication successful`.
   - Send AES-GCM encrypted messages in JSON format `{ "username": "testuser", "content": "Hello" }` (or test with the console client for simplicity).

### Example Usage

1. Start the server:

   ```bash
   go run main.go -port=8080 -https=false
   ```

2. Start a client in a terminal:

   ```bash
   go run client.go
   ```

3. Register a new user:

   ```
   Do you want to register a new account? (yes/no): y
   Enter username for registration: Bartekbk
   Enter password for registration: P@ssword
   User registered successfully
   Connected to WebSocket server
   Authentication successful
   Enter messages to send (type 'exit' to quit):
   >
   ```

4. Start another client and register or log in with a different user (e.g., `testuser2`):

   ```
   Do you want to register a new account? (yes/no): y
   Enter username for registration: testuser2
   Enter password for registration: Test123
   User registered successfully
   Connected to WebSocket server
   Authentication successful
   Enter messages to send (type 'exit' to quit):
   >
   ```

5. In the first client, send a message:

   ```
   > Hello from Bartekbk!
   Sent: Hello from Bartekbk!
   ```

6. The second client should receive:

   ```
   Received from Bartekbk: Hello from Bartekbk!
   ```

## Project Structure

```
linkup/
├── main.go        # WebSocket server with user registration and message broadcasting
├── client.go      # Console-based WebSocket client with registration and authentication
├── go.mod         # Go module file with dependencies
├── .env           # Environment file with AES_KEY
├── users.db       # SQLite database for user data (created automatically)
├── cert.pem       # SSL/TLS certificate (optional, for HTTPS)
└── key.pem        # SSL/TLS private key (optional, for HTTPS)
```

## Production Notes

- **TLS Certificates**: For production, use certificates from a trusted CA like Let's Encrypt:

  ```bash
  sudo apt update
  sudo apt install certbot
  sudo certbot certonly --standalone -d yourdomain.com
  go run main.go -port=443 -https=true -cert=/etc/letsencrypt/live/yourdomain.com/fullchain.pem -key=/etc/letsencrypt/live/yourdomain.com/privkey.pem
  ```

- **Security**:
  - Restrict WebSocket origins in `upgrader.CheckOrigin` for production.
  - Use a secure key exchange mechanism instead of a hardcoded `AES_KEY`.
  - Regularly back up the `users.db` database.
  - Implement rate limiting for `/register` to prevent abuse.
- **Scalability**: Use a more robust database (e.g., PostgreSQL) for large-scale deployments.

## Troubleshooting

- **Database Issues**:
  - Ensure the program has write permissions in the project directory for `users.db`.
  - Check logs for database errors and verify SQLite installation (`go get github.com/mattn/go-sqlite3`).
- **WebSocket Connection Errors**:
  - Verify the server is running and the port (default 8080) is not blocked.
  - Use `ws://localhost:8080/ws` for HTTP or `wss://localhost:8080/ws` for HTTPS.
- **Authentication Errors**:
  - Ensure the username and password match a registered user in the database.
  - Check server logs for authentication failures.
- **Registration Errors**:
  - If registration fails, check for errors like `User already exists` or network issues.
  - Ensure the server is running and accessible at `http://localhost:8080/register`.
- **Encryption Errors**:
  - Ensure the `AES_KEY` in the client and server `.env` files is identical and 32 bytes long.
  - If testing without encryption, temporarily modify `handleConnections` and `handleMessages` in `main.go` to bypass AES-GCM.
- **Client Disconnections**:
  - The server automatically removes disconnected clients. Check logs for `Read error` or `Write error`.

## Extending the Project

- **JWT Authentication**: Replace the current authentication with JWT tokens for stateless verification.
- **Mobile Client**: Create a mobile app using Flutter or React Native to connect to the server.
- **Game Logic**: Extend the server to support multiplayer games like Tic-Tac-Toe by processing structured JSON messages.
- **Message Persistence**: Store messages in the database for chat history.
