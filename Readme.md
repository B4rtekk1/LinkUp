# LinkUp

## Overview

This is a secure WebSocket-based chat server written in Go. It allows multiple clients to connect via WebSocket, send messages, and broadcast them to all connected clients. The server supports real-time communication with transport-layer encryption (TLS) and optional application-layer encryption (AES-GCM). It can be extended for use cases like multiplayer games or chat applications.

## Features

- Supports multiple simultaneous WebSocket connections over secure `wss://` protocol.
- Broadcasts messages received from one client to all connected clients.
- Handles client disconnections gracefully.
- Configurable server port and SSL/TLS certificate paths via command-line arguments.
- Thread-safe management of clients using a mutex.
- Transport-layer encryption using HTTPS/TLS for WebSocket connections (`wss://`).
- Optional application-layer encryption using AES-GCM for end-to-end message security.

## Prerequisites

- **Go**: Version 1.16 or higher.
- **Gorilla WebSocket**: A Go library for WebSocket communication.
- **SSL/TLS Certificates**: Required for HTTPS/WSS support (self-signed or from a trusted CA like Let's Encrypt).
- **OpenSSL** (optional): For generating self-signed certificates for testing.

## Installation

1. **Clone or create the project directory**:
   Create a directory for the project and place the `main.go` file in it.

2. **Initialize a Go module**:
   Run the following command to initialize a Go module:

   ```bash
   go mod init websocket-chat
   ```

3. **Install dependencies**:
   Install the Gorilla WebSocket library:

   ```bash
   go get github.com/gorilla/websocket
   ```

4. **Generate SSL/TLS certificates (for testing)**:
   For local development, generate self-signed certificates using OpenSSL:

   ```bash
   openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
   ```

   For production, obtain certificates from a trusted Certificate Authority (e.g., Let's Encrypt).

## Usage

1. **Run the server**:
   Start the server with HTTPS support, specifying the port and paths to the SSL/TLS certificate and key files:

   ```bash
   go run main.go -port=8080 -cert=cert.pem -key=key.pem
   ```

   If no custom port or certificate paths are specified, the server defaults to port 8080 and expects `cert.pem` and `key.pem` in the project directory.

2. **Connect clients**:
   Clients must connect to the server using the secure WebSocket protocol at `wss://localhost:<port>/ws`, where `<port>` is the port specified when starting the server (default: 8080).
   - Example WebSocket URL: `wss://localhost:8080/ws`
   - Clients can be implemented in any language or framework that supports WebSocket, such as JavaScript (for browser-based clients) or Go.

3. **Sending messages**:
   - Clients send messages to the server via the WebSocket connection.
   - If application-layer encryption is enabled, messages must be encrypted with AES-GCM using the shared key (see [Example Client](#example-client)).
   - The server broadcasts each received message to all connected clients (decrypting and re-encrypting if application-layer encryption is used).

4. **Example client**:
   A simple client can be implemented in JavaScript for a browser-based interface or in Go for a console-based client. See the [Example Client](#example-client) section for details.

## Example Client

Below is an example of a JavaScript client that connects to the server using `wss://` and supports optional AES-GCM encryption for messages:

```html
<!DOCTYPE html>
<html>
<head>
    <title>Secure WebSocket Chat Client</title>
</head>
<body>
    <input id="message" type="text" placeholder="Type a message">
    <button onclick="sendMessage()">Send</button>
    <div id="messages"></div>
    <script>
        // AES-GCM encryption/decryption functions
        async function encryptMessage(message, key) {
            const encoded = new TextEncoder().encode(message);
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const cryptoKey = await crypto.subtle.importKey("raw", key, { name: "AES-GCM" }, false, ["encrypt"]);
            const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, cryptoKey, encoded);
            return new Uint8Array([...iv, ...new Uint8Array(encrypted)]);
        }

        async function decryptMessage(ciphertext, key) {
            const cryptoKey = await crypto.subtle.importKey("raw", key, { name: "AES-GCM" }, false, ["decrypt"]);
            const iv = ciphertext.slice(0, 12);
            const data = ciphertext.slice(12);
            const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, cryptoKey, data);
            return new TextDecoder().decode(decrypted);
        }

        const key = new TextEncoder().encode("examplekey1234567890123456789012"); // Must match server key
        const ws = new WebSocket("wss://localhost:8080/ws");

        ws.onopen = function() {
            console.log("Connected to WebSocket server");
        };

        ws.onmessage = async function(event) {
            const messages = document.getElementById("messages");
            let message = event.data;
            // If using application-layer encryption, decrypt the message
            if (typeof event.data !== "string") {
                message = await decryptMessage(new Uint8Array(await event.data.arrayBuffer()), key);
            }
            messages.innerHTML += `<p>${message}</p>`;
        };

        async function sendMessage() {
            const input = document.getElementById("message");
            let message = input.value;
            // If using application-layer encryption, encrypt the message
            const encryptedMessage = await encryptMessage(message, key);
            ws.send(encryptedMessage);
            input.value = "";
        }
    </script>
</body>
</html>
```

Save this as `index.html`, serve it with a simple HTTPS server (e.g., using Node.js with `https` module or a reverse proxy like Nginx), and open it in a browser to connect to the WebSocket server. Note: If using self-signed certificates, you may need to accept a security warning in the browser.

## Project Structure

- `main.go`: The main server code that handles secure WebSocket connections and message broadcasting with optional AES-GCM encryption.
- `go.mod`: Go module file containing dependencies (created after running `go mod init`).
- `cert.pem`: SSL/TLS certificate file (required for HTTPS/WSS).
- `key.pem`: SSL/TLS private key file (required for HTTPS/WSS).

## Notes

- **Security**:
  - The server uses HTTPS/TLS (`wss://`) for transport-layer encryption, ensuring all WebSocket communication is encrypted.
  - Optional application-layer encryption (AES-GCM) provides end-to-end security but requires clients to use the same encryption key.
  - The WebSocket server allows connections from any origin (`CheckOrigin` returns `true`). For production, restrict allowed origins to prevent unauthorized access.
  - The AES key is hardcoded for simplicity. In production, use a secure key exchange mechanism (e.g., Diffie-Hellman).
- **Error Handling**: The server logs errors for connection upgrades, message reading, writing, and encryption/decryption. Ensure proper monitoring in a production environment.
- **Extending for Tic-Tac-Toe**: The server can be extended to support a multiplayer Tic-Tac-Toe game by adding game logic to process structured messages (e.g., JSON with row, column, and player data).

## Troubleshooting

- **Connection Errors**: Ensure the server is running, the port is not blocked, and the SSL/TLS certificates are valid. If using self-signed certificates, accept the security warning in the browser.
- **Dependency Issues**: Verify that the `github.com/gorilla/websocket` package is installed correctly by running `go mod tidy`.
- **Client Disconnections**: The server automatically removes disconnected clients. If a client fails to receive messages, check for network issues or ensure the client handles WebSocket reconnection properly.
- **Encryption Errors**: If using application-layer encryption, ensure the client and server use the same AES key and that the key is 32 bytes long (for AES-256).

## License

This project is unlicensed and provided as-is for educational purposes.