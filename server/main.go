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
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

// users is an in-memory store for usernames and hashed passwords.
// Deprecated: Not used; user data is stored in the SQLite database.
var users = make(map[string]string)

// db is the global SQLite database connection for user management.
var db *sql.DB

// initDB initializes the SQLite database and creates the users table if it doesn't exist.
// It logs the current working directory and any errors during setup.
// The database file is created as `users.db` in the current directory.
func initDB() {
	var err error
	log.Println("Attempting to open database ./users.db")
	dir, err := os.Getwd()
	if err != nil {
		log.Fatalf("Failed to get current working directory: %v", err)
	}
	log.Println("Current working directory:", dir)

	db, err = sql.Open("sqlite3", "./users.db")
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	log.Println("Database opened successfully")

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

// RegisterRequest represents a user registration request in JSON format.
type RegisterRequest struct {
	Username string `json:"username"` // The username for registration
	Password string `json:"password"` // The password to be hashed
}

// AuthMessage represents an authentication message sent by clients.
type AuthMessage struct {
	Username string `json:"username"` // The username for authentication
	Password string `json:"password"` // The password for authentication
}

// Message represents a chat message with sender information.
type Message struct {
	Username string `json:"username"` // The sender's username
	Content  string `json:"content"`  // The message content
}

// registerHandler handles HTTP POST requests to register a new user.
// It expects a JSON body with username and password.
// If the username exists, it returns 409 Conflict.
// On success, it hashes the password with bcrypt, stores the user in the database, and returns 201 Created.
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
	if err := db.QueryRow("SELECT COUNT(*) FROM users WHERE username = ?", req.Username).Scan(&exists); err != nil {
		log.Printf("Database error checking user existence: %v", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	if exists > 0 {
		http.Error(w, "User already exists", http.StatusConflict)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Error hashing password: %v", err)
		http.Error(w, "Error hashing password", http.StatusInternalServerError)
		return
	}

	tx, err := db.Begin()
	if err != nil {
		log.Printf("Error starting transaction: %v", err)
		http.Error(w, "Error starting transaction", http.StatusInternalServerError)
		return
	}

	_, err = tx.Exec("INSERT INTO users (username, password) VALUES (?, ?)", req.Username, string(hashedPassword))
	if err != nil {
		tx.Rollback()
		log.Printf("Error inserting user into database: %v", err)
		http.Error(w, "Error inserting user into database", http.StatusInternalServerError)
		return
	}

	if err := tx.Commit(); err != nil {
		log.Printf("Error committing transaction: %v", err)
		http.Error(w, "Error committing transaction", http.StatusInternalServerError)
		return
	}

	log.Printf("User %s registered successfully", req.Username)
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("User registered successfully"))
}

// Client represents a WebSocket client connection.
type Client struct {
	conn     *websocket.Conn // WebSocket connection
	send     chan []byte     // Channel for sending messages
	username string          // Authenticated username
}

// clients is a map of connected WebSocket clients.
var clients = make(map[*Client]bool)

// broadcast is a channel for broadcasting messages to all clients.
var broadcast = make(chan []byte)

// upgrader configures HTTP to WebSocket upgrades.
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all origins (development only)
	},
}

// mu provides thread-safe access to the clients map.
var mu sync.Mutex

// aesKey is the shared AES-256 key for message encryption.
var aesKey []byte

// encryptMessage encrypts a message using AES-GCM with the provided key.
// It prepends a random nonce to the ciphertext.
// Returns the encrypted message or an error.
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

// decryptMessage decrypts an AES-GCM encrypted message with the provided key.
// The input must include the nonce prepended to the ciphertext.
// Returns the decrypted message or an error.
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

// authenticateUser verifies a username and password against the database.
// Returns true if credentials are valid, false otherwise, with an error for database issues.
func authenticateUser(username, password string) (bool, error) {
	var hashedPassword string
	err := db.QueryRow("SELECT password FROM users WHERE username = ?", username).Scan(&hashedPassword)
	if err == sql.ErrNoRows {
		log.Printf("Authentication failed: user %s not found", username)
		return false, nil
	}
	if err != nil {
		log.Printf("Authentication database error: %v", err)
		return false, fmt.Errorf("database error: %v", err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password)); err != nil {
		log.Printf("Authentication failed: password mismatch for user %s", username)
		return false, nil
	}

	log.Printf("Authentication successful for user %s", username)
	return true, nil
}

// main initializes the server, loads environment variables, sets up the database,
// configures HTTP routes, and starts the server with or without TLS.
func main() {
	err := godotenv.Load("../.env")
	if err != nil {
		log.Println("No .env file found, using default or environment variables")
	}

	initDB()
	defer func() {
		if db != nil {
			db.Close()
			log.Println("Database connection closed")
		}
	}()

	aesKey = []byte(os.Getenv("AES_KEY"))
	log.Printf("AES_KEY: %s (length: %d bytes)", aesKey, len(aesKey))
	if len(aesKey) != 32 {
		log.Fatal("AES_KEY must be 32 bytes for AES-256")
	}

	port := flag.Int("port", 8080, "Port for the WebSocket server")
	certFile := flag.String("cert", "cert.pem", "Path to SSL certificate file")
	keyFile := flag.String("key", "key.pem", "Path to SSL key file")
	useHTTPS := flag.Bool("https", false, "Enable HTTPS/WSS")
	flag.Usage = func() {
		fmt.Println("Usage: msg [-port PORT] [-https] [-cert CERT_FILE] [-key KEY_FILE]")
		flag.PrintDefaults()
	}
	flag.Parse()

	http.HandleFunc("/ws", handleConnections)
	http.HandleFunc("/register", registerHandler)
	go handleMessages()

	protocol := "http"
	if *useHTTPS {
		protocol = "https"
	}
	log.Printf("Starting server on %s://localhost:%d", protocol, *port)

	if *useHTTPS {
		if err := http.ListenAndServeTLS(":"+strconv.Itoa(*port), *certFile, *keyFile, nil); err != nil {
			log.Fatalf("Error starting HTTPS server: %v", err)
		}
	} else {
		if err := http.ListenAndServe(":"+strconv.Itoa(*port), nil); err != nil {
			log.Fatalf("Error starting HTTP server: %v", err)
		}
	}
}

// handleConnections upgrades HTTP requests to WebSocket connections and manages client communication.
// Clients must send a JSON authentication message upon connection.
// On successful authentication, it reads messages, attaches the username, and broadcasts them.
// Disconnects are handled by removing the client from the clients map.
func handleConnections(w http.ResponseWriter, r *http.Request) {
	log.Println("New WebSocket connection attempt")
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Upgrade error: %v", err)
		return
	}
	defer ws.Close()

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

	if err := ws.WriteMessage(websocket.TextMessage, []byte("Authentication successful")); err != nil {
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

// handleMessages broadcasts messages from the broadcast channel to all clients.
// Messages are encrypted with AES-GCM before sending.
// Disconnected clients are removed from the clients map.
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
// If a write error occurs, the connection is closed.
func writeMessages(client *Client) {
	for msg := range client.send {
		if err := client.conn.WriteMessage(websocket.BinaryMessage, msg); err != nil {
			log.Printf("Write error for %s: %v", client.username, err)
			client.conn.Close()
			break
		}
		log.Printf("Message written to client: %s", client.username)
	}
}
