package main

import (
	"flag"
	"fmt"
	"net/http"
	"strconv"
	"sync"

	"github.com/gorilla/websocket"
)

/*
Client represents a single WebSocket client connection.

Fields:
  - conn: The WebSocket connection to the client.
  - send: A channel for sending messages to the client.
*/
type Client struct {
	conn *websocket.Conn // WebSocket connection with the client
	send chan []byte     // Channel for sending messages to the client
}

/*
Global variables:

  - clients: A map holding all currently connected clients.
  - broadcast: A channel where incoming messages are placed to be broadcasted to all clients.
  - upgrader: Configuration to upgrade an HTTP connection to a WebSocket connection.
  - mu: Mutex to safely access shared resources like the clients map.
*/
var clients = make(map[*Client]bool)
var broadcast = make(chan []byte)
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		// Allow connections from any origin (for development purposes)
		return true
	},
}
var mu sync.Mutex

/*
main is the entry point of the application.

It sets up the HTTP route for WebSocket connections and starts the server.
It also starts a goroutine to handle broadcasting messages to all clients.
*/
func main() {
	port := flag.Int("port", 8080, "Port to run the WebSocket server on")
	flag.Usage = func() {
		fmt.Println("Usage: msg [-port PORT]")
		flag.PrintDefaults()
	}
	flag.Parse()

	// Handle WebSocket requests at the /ws endpoint
	http.HandleFunc("/ws", handleConnections)

	// Start a separate goroutine to handle incoming messages
	go handleMessages()

	fmt.Printf("Server running on http://localhost:%s\n", *port)
	// Start the HTTP server on port specified by the user or default to 8080
	err := http.ListenAndServe(":"+strconv.Itoa(*port), nil)
	if err != nil {
		fmt.Println("Error starting server:", err)
		return
	}
}

/*
handleConnections upgrades an HTTP connection to a WebSocket connection and registers a new client.

It continuously reads messages from the client and sends them to the broadcast channel.
When the client disconnects, it removes the client from the clients map.
*/
func handleConnections(w http.ResponseWriter, r *http.Request) {
	// Upgrade the HTTP connection to WebSocket
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		fmt.Println("Upgrade error:", err)
		return
	}
	defer ws.Close() // Ensure connection is closed when function exits

	// Create a new client
	client := &Client{conn: ws, send: make(chan []byte)}

	// Add the new client to the clients map
	mu.Lock()
	clients[client] = true
	mu.Unlock()

	// Start a goroutine to write messages to the client
	go writeMessages(client)

	// Continuously read messages from the client
	for {
		_, msg, err := ws.ReadMessage()
		if err != nil {
			fmt.Println("Read error:", err)
			break
		}
		// Send the received message to the broadcast channel
		broadcast <- msg
	}

	// Remove the client from the map when they disconnect
	mu.Lock()
	delete(clients, client)
	mu.Unlock()
}

/*
handleMessages listens for messages on the broadcast channel and sends them to all connected clients.

If a client's send channel is blocked or closed, the client is removed from the clients map.
*/
func handleMessages() {
	for {
		// Wait for a message to broadcast
		msg := <-broadcast
		mu.Lock()
		for client := range clients {
			select {
			case client.send <- msg: // Send message to the client
			default: // If sending fails, remove the client
				close(client.send)
				delete(clients, client)
			}
		}
		mu.Unlock()
	}
}

/*
writeMessages continuously sends messages from the client's send channel over the WebSocket.

If there is an error while sending a message, the connection is closed and the loop exits.
*/
func writeMessages(client *Client) {
	for msg := range client.send {
		err := client.conn.WriteMessage(websocket.TextMessage, msg)
		if err != nil {
			fmt.Println("Write error:", err)
			client.conn.Close()
			break
		}
	}
}
