# LinkUp

## Overview

This is a simple WebSocket-based chat server written in Go. It allows multiple clients to connect via WebSocket, send messages, and broadcast them to all connected clients. The server is designed to handle real-time communication and can be extended for use cases like multiplayer games or chat applications.

## Features

- Supports multiple simultaneous WebSocket connections.
- Broadcasts messages received from one client to all connected clients.
- Handles client disconnections gracefully.
- Configurable server port via command-line argument.
- Thread-safe management of clients using a mutex.

## Prerequisites

- **Go**: Version 1.16 or higher.
- **Gorilla WebSocket**: A Go library for WebSocket communication.

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

## Usage

1. **Run the server**:
   Use the following command to start the server on the default port (8080):

   ```bash
   go run main.go
   ```

   To specify a custom port, use the `-port` flag:

   ```bash
   go run main.go -port=9090
   ```

2. **Connect clients**:
   Clients can connect to the server using the WebSocket protocol at `ws://localhost:<port>/ws`, where `<port>` is the port specified when starting the server (default: 8080).
   - Example WebSocket URL: `ws://localhost:8080/ws`
   - Clients can be implemented in any language or framework that supports WebSocket, such as JavaScript (for browser-based clients) or Go.

3. **Sending messages**:
   - Clients send messages to the server via the WebSocket connection.
   - The server broadcasts each received message to all connected clients.

4. **Example client**:
   A simple client can be implemented in JavaScript for a browser-based interface or in Go for a console-based client. See the [Example Client](#example-client) section for details.

## Example Client

Below is an example of how to connect to the server using a JavaScript client in a browser:

```html
<!DOCTYPE html>
<html>
<head>
    <title>WebSocket Chat Client</title>
</head>
<body>
    <input id="message" type="text" placeholder="Type a message">
    <button onclick="sendMessage()">Send</button>
    <div id="messages"></div>
    <script>
        const ws = new WebSocket("ws://localhost:8080/ws");
        ws.onmessage = function(event) {
            const messages = document.getElementById("messages");
            messages.innerHTML += `<p>${event.data}</p>`;
        };
        function sendMessage() {
            const input = document.getElementById("message");
            ws.send(input.value);
            input.value = "";
        }
    </script>
</body>
</html>
```

Save this as `index.html`, serve it with a simple HTTP server (e.g., `python -m http.server`), and open it in a browser to connect to the WebSocket server.

## Project Structure

- `main.go`: The main server code that handles WebSocket connections and message broadcasting.
- `go.mod`: Go module file containing dependencies (created after running `go mod init`).

## Notes

- **Security**: The WebSocket server allows connections from any origin (`CheckOrigin` returns `true`). For production, restrict allowed origins to prevent unauthorized access.
- **Error Handling**: The server logs errors for connection upgrades, message reading, and writing. Ensure proper monitoring in a production environment.
- **Extending for Tic-Tic-Toe**: This server can be extended to support a multiplayer Tic-Tac-Toe game by adding game logic to process structured messages (e.g., JSON with row, column, and player data).

## Troubleshooting

- **Connection Errors**: Ensure the server is running and the port is not blocked by another application.
- **Dependency Issues**: Verify that the `github.com/gorilla/websocket` package is installed correctly by running `go mod tidy`.
- **Client Disconnections**: The server automatically removes disconnected clients. If a client fails to receive messages, check for network issues or ensure the client handles WebSocket reconnection properly.

## License

This project is unlicensed and provided as-is for educational purposes.
