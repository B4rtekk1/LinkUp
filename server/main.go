package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"sync"

	"github.com/gorilla/websocket"
	"github.com/joho/godotenv"
	_ "github.com/mattn/go-sqlite3" // SQLite driver for database operations
	"golang.org/x/crypto/bcrypt"
)

// users is an in-memory store for usernames and hashed passwords.
// Note: This is not used in the current implementation, as user data is stored in the SQLite database.
var users = make(map[string]string)

// db is the global SQLite database connection used for user management.
var db *sql.DB

// initDB initializes the SQLite database and creates the users table if it doesn't exist.
// It logs the current working directory and any errors during database setup.
// The database file is created as `users.db` in the current working directory.
func initDB() {
	var err error
	log.Println("Attempting to open database ./users.db")
	// Log current working directory for debugging
	dir, err := os.Getwd()
	if err != nil {
		log.Fatalf("Failed to get current working directory: %v", err)
	}
	log.Println("Current working directory:", dir)

	// Open SQLite database
	db, err = sql.Open("sqlite3", "./users.db")
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	log.Println("Database opened successfully")

	// Create users table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE,
			password TEXT
		)
	`)
	if err != nil {
		log.Fatalf("Failed to create users table: %v", err)
	}
	log.Println("Users table created successfully")
}

// RegisterRequest represents the structure of a user registration request in JSON format.
type RegisterRequest struct {
	Username string `json:"username"` // The username of the user
	Password string `json:"password"` // The password to be hashed and stored
}

// AuthMessage represents the structure of an authentication message sent by clients.
type AuthMessage struct {
	Username string `json:"username"` // The username for authentication
	Password string `json:"password"` // The password for authentication
}

// Message represents the structure of a chat message with sender information.
type Message struct {
	Username string `json:"username"` // The username of the sender
	Content  string `json:"content"`  // The content of the message
}

// registerHandler handles HTTP POST requests for user registration.
// It expects a JSON body with username and password fields.
// If the user already exists, it returns a 409 Conflict error.
// On success, it hashes the password using bcrypt and stores the user in the database.
// Returns 201 Created on successful registration.
func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	var exists int
	// Check if the user already exists in the database
	err := db.QueryRow("SELECT COUNT(*) FROM users WHERE username = ?", req.Username).Scan(&exists)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	if exists > 0 {
		http.Error(w, "User already exists", http.StatusConflict)
		return
	}

	// Hash the password using bcrypt
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Error hashing password", http.StatusInternalServerError)
		return
	}

	// Insert user into database
	_, err = db.Exec("INSERT INTO users (username, password) VALUES (?, ?)", req.Username, string(hashedPassword))
	if err != nil {
		http.Error(w, "Error inserting user into database", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("User registered successfully"))
}

// Client represents a single WebSocket client connection.
type Client struct {
	conn     *websocket.Conn // WebSocket connection to the client
	send     chan []byte     // Channel for sending messages to the client
	username string          // Authenticated username of the client
}

// Global variables:
// clients: Map of all connected WebSocket clients, mapping Client pointers to a boolean flag.
// broadcast: Channel for broadcasting messages to all connected clients.
// upgrader: Configures HTTP to WebSocket connection upgrades with permissive origin checking.
// mu: Mutex for thread-safe access to the clients map.
// aesKey: Shared AES key for message encryption (32 bytes for AES-256).
var clients = make(map[*Client]bool)
var broadcast = make(chan []byte)
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow connections from any origin (for development only)
	},
}
var mu sync.Mutex
var aesKey []byte

// encryptMessage encrypts a message using AES-GCM with the provided key.
// It generates a random nonce and returns the encrypted message with the nonce prepended.
// Returns an error if encryption fails.
func encryptMessage(message []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %v", err)
	}

	return gcm.Seal(nonce, nonce, message, nil), nil
}

// decryptMessage decrypts a message encrypted with AES-GCM using the provided key.
// The input must include the nonce prepended to the ciphertext.
// Returns the decrypted message or an error if decryption fails.
func decryptMessage(ciphertext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// authenticateUser verifies the provided username and password against the database.
// Returns true if authentication is successful, false otherwise, along with an error if applicable.
func authenticateUser(username, password string) (bool, error) {
	var hashedPassword string
	err := db.QueryRow("SELECT password FROM users WHERE username = ?", username).Scan(&hashedPassword)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("database error: %v", err)
	}

	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		return false, nil
	}
	return true, nil
}

// main is the entry point of the application.
// It loads environment variables from a .env file, initializes the SQLite database,
// sets up HTTP routes for WebSocket (/ws) and registration (/register),
// and starts the server with or without TLS based on the -https flag.
func main() {
	// Load environment variables from .env file
	err := godotenv.Load("../.env")
	if err != nil {
		log.Println("No .env file found, using default or environment variables")
	}

	// Initialize database
	initDB()

	// Ensure database connection is closed on exit
	defer func() {
		if db != nil {
			db.Close()
			log.Println("Database connection closed")
		}
	}()

	// Load AES key from environment variable
	aesKey = []byte(os.Getenv("AES_KEY"))
	log.Printf("AES_KEY: %s (length: %d bytes)", aesKey, len(aesKey))
	if len(aesKey) != 32 {
		log.Fatal("AES_KEY must be 32 bytes for AES-256")
	}

	// Parse command-line flags
	port := flag.Int("port", 8080, "Port to run the WebSocket server on")
	certFile := flag.String("cert", "cert.pem", "Path to SSL certificate file")
	keyFile := flag.String("key", "key.pem", "Path to SSL key file")
	useHTTPS := flag.Bool("https", false, "Enable HTTPS/WSS (requires cert and key files)")
	flag.Usage = func() {
		fmt.Println("Usage: msg [-port PORT] [-https] [-cert CERT_FILE] [-key KEY_FILE]")
		flag.PrintDefaults()
	}
	flag.Parse()

	// Set up HTTP handlers
	http.HandleFunc("/ws", handleConnections)
	http.HandleFunc("/register", registerHandler)

	// Start message broadcasting goroutine
	go handleMessages()

	// Start server
	protocol := "http"
	if *useHTTPS {
		protocol = "https"
	}
	log.Printf("Starting server on %s://localhost:%d", protocol, *port)

	if *useHTTPS {
		err := http.ListenAndServeTLS(":"+strconv.Itoa(*port), *certFile, *keyFile, nil)
		if err != nil {
			log.Fatalf("Error starting HTTPS server: %v", err)
		}
	} else {
		err := http.ListenAndServe(":"+strconv.Itoa(*port), nil)
		if err != nil {
			log.Fatalf("Error starting HTTP server: %v", err)
		}
	}
}

// handleConnections upgrades an HTTP connection to a WebSocket connection and manages client communication.
// It requires clients to send an authentication message (JSON with username and password) upon connection.
// If authentication fails, the connection is closed.
// On successful authentication, it reads messages, attaches the username, and sends them to the broadcast channel.
// When the client disconnects, it removes the client from the clients map and closes the connection.
func handleConnections(w http.ResponseWriter, r *http.Request) {
	log.Println("New WebSocket connection attempt")
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Upgrade error: %v", err)
		return
	}
	defer ws.Close()

	// Read authentication message
	_, authMsg, err := ws.ReadMessage()
	if err != nil {
		log.Printf("Authentication read error: %v", err)
		ws.WriteMessage(websocket.TextMessage, []byte("Authentication failed: unable to read credentials"))
		return
	}

	var auth AuthMessage
	if err := json.Unmarshal(authMsg, &auth); err != nil {
		log.Printf("Authentication parse error: %v", err)
		ws.WriteMessage(websocket.TextMessage, []byte("Authentication failed: invalid credentials format"))
		return
	}

	// Verify credentials
	authenticated, err := authenticateUser(auth.Username, auth.Password)
	if err != nil {
		log.Printf("Authentication error: %v", err)
		ws.WriteMessage(websocket.TextMessage, []byte("Authentication failed: server error"))
		return
	}
	if !authenticated {
		log.Printf("Authentication failed for user: %s", auth.Username)
		ws.WriteMessage(websocket.TextMessage, []byte("Authentication failed: invalid username or password"))
		return
	}

	client := &Client{conn: ws, send: make(chan []byte), username: auth.Username}
	defer close(client.send)

	mu.Lock()
	clients[client] = true
	mu.Unlock()
	log.Printf("New WebSocket client connected: %s", auth.Username)

	go writeMessages(client)

	// Notify client of successful authentication
	err = ws.WriteMessage(websocket.TextMessage, []byte("Authentication successful"))
	if err != nil {
		log.Printf("Write error: %v", err)
		return
	}

	for {
		_, msg, err := ws.ReadMessage()
		if err != nil {
			log.Printf("Read error for %s: %v", client.username, err)
			break
		}
		log.Printf("Received message from %s, decrypting...", client.username)
		decryptedMsg, err := decryptMessage(msg, aesKey)
		if err != nil {
			log.Printf("Decryption error: %v", err)
			continue
		}
		log.Println("Message decrypted successfully")

		// Create message with username and content
		message := Message{
			Username: client.username,
			Content:  string(decryptedMsg),
		}
		messageJSON, err := json.Marshal(message)
		if err != nil {
			log.Printf("Failed to marshal message: %v", err)
			continue
		}
		broadcast <- messageJSON
	}

	mu.Lock()
	delete(clients, client)
	mu.Unlock()
	log.Printf("Client disconnected: %s", client.username)
}

// handleMessages listens for messages on the broadcast channel and sends encrypted messages to all clients.
// It encrypts each message using AES-GCM before broadcasting.
// If a client's send channel is blocked or closed, the client is removed from the clients map.
func handleMessages() {
	for {
		msg := <-broadcast
		log.Println("Broadcasting message to all clients")
		encryptedMsg, err := encryptMessage(msg, aesKey)
		if err != nil {
			log.Printf("Encryption error: %v", err)
			continue
		}
		mu.Lock()
		for client := range clients {
			select {
			case client.send <- encryptedMsg:
				log.Printf("Message sent to client: %s", client.username)
			default:
				log.Printf("Client disconnected, removing from clients: %s", client.username)
				close(client.send)
				delete(clients, client)
			}
		}
		mu.Unlock()
	}
}

// writeMessages sends messages from the client's send channel over the WebSocket connection.
// If an error occurs while sending a message, the connection is closed and the loop exits.
func writeMessages(client *Client) {
	for msg := range client.send {
		err := client.conn.WriteMessage(websocket.BinaryMessage, msg)
		if err != nil {
			log.Printf("Write error for %s: %v", client.username, err)
			client.conn.Close()
			break
		}
		log.Printf("Message written to client: %s", client.username)
	}
}
