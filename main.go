package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
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
  - aesKey: Shared AES key for message encryption (hardcoded for simplicity).
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
var aesKey = []byte("examplekey1234567890123456789012") // 32-byte key for AES-256

/*
encryptMessage encrypts a message using AES-GCM with the provided key.
*/
func encryptMessage(message []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, message, nil), nil
}

/*
decryptMessage decrypts a message encrypted with AES-GCM using the provided key.
*/
func decryptMessage(ciphertext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

/*
main is the entry point of the application.

It sets up the HTTP route for WebSocket connections and starts the server with or without TLS based on the -https flag.
It also starts a goroutine to handle broadcasting messages to all clients.
*/
func main() {
	port := flag.Int("port", 8080, "Port to run the WebSocket server on")
	certFile := flag.String("cert", "cert.pem", "Path to SSL certificate file")
	keyFile := flag.String("key", "key.pem", "Path to SSL key file")
	useHTTPS := flag.Bool("https", false, "Enable HTTPS/WSS (requires cert and key files)")
	flag.Usage = func() {
		fmt.Println("Usage: msg [-port PORT] [-https] [-cert CERT_FILE] [-key KEY_FILE]")
		flag.PrintDefaults()
	}
	flag.Parse()

	// Handle WebSocket requests at the /ws endpoint
	http.HandleFunc("/ws", handleConnections)

	// Start a separate goroutine to handle incoming messages
	go handleMessages()

	// Determine the protocol (http or https) based on the -https flag
	protocol := "http"
	if *useHTTPS {
		protocol = "https"
	}
	fmt.Printf("Server running on %s://localhost:%d\n", protocol, *port)

	// Start the server with or without TLS
	if *useHTTPS {
		err := http.ListenAndServeTLS(":"+strconv.Itoa(*port), *certFile, *keyFile, nil)
		if err != nil {
			fmt.Println("Error starting HTTPS server:", err)
			return
		}
	} else {
		err := http.ListenAndServe(":"+strconv.Itoa(*port), nil)
		if err != nil {
			fmt.Println("Error starting HTTP server:", err)
			return
		}
	}
}

/*
handleConnections upgrades an HTTP connection to a WebSocket connection and registers a new client.

It continuously reads messages from the client, decrypts them, and sends them to the broadcast channel.
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
		// Decrypt the received message
		decryptedMsg, err := decryptMessage(msg, aesKey)
		if err != nil {
			fmt.Println("Decryption error:", err)
			continue
		}
		// Send the decrypted message to the broadcast channel
		broadcast <- decryptedMsg
	}

	// Remove the client from the map when they disconnect
	mu.Lock()
	delete(clients, client)
	mu.Unlock()
}

/*
handleMessages listens for messages on the broadcast channel, encrypts them, and sends them to all connected clients.

If a client's send channel is blocked or closed, the client is removed from the clients map.
*/
func handleMessages() {
	for {
		// Wait for a message to broadcast
		msg := <-broadcast
		// Encrypt the message before broadcasting
		encryptedMsg, err := encryptMessage(msg, aesKey)
		if err != nil {
			fmt.Println("Encryption error:", err)
			continue
		}
		mu.Lock()
		for client := range clients {
			select {
			case client.send <- encryptedMsg: // Send encrypted message to the client
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
		err := client.conn.WriteMessage(websocket.BinaryMessage, msg) // Use BinaryMessage
		if err != nil {
			fmt.Println("Write error:", err)
			client.conn.Close()
			break
		}
	}
}
