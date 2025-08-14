package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/gorilla/websocket"
	"github.com/joho/godotenv"
)

// aesKey holds the AES-256 key for encryption and decryption of WebSocket messages.
// It must match the key used by the server (loaded from the AES_KEY environment variable).
var aesKey []byte

// AuthMessage represents the structure of an authentication message sent to the server.
type AuthMessage struct {
	Username string `json:"username"` // The username for authentication
	Password string `json:"password"` // The password for authentication
}

// RegisterRequest represents the structure of a user registration request.
type RegisterRequest struct {
	Username string `json:"username"` // The username for registration
	Password string `json:"password"` // The password for registration
}

// Message represents the structure of a chat message with sender information.
type Message struct {
	Username string `json:"username"` // The username of the sender
	Content  string `json:"content"`  // The content of the message
}

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

// registerUser sends an HTTP POST request to the server's /register endpoint to create a new user.
// Returns an error if the registration fails.
func registerUser(username, password, serverURL string) error {
	reqBody, err := json.Marshal(RegisterRequest{Username: username, Password: password})
	if err != nil {
		return fmt.Errorf("failed to marshal registration request: %v", err)
	}

	resp, err := http.Post(serverURL+"/register", "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		return fmt.Errorf("failed to send registration request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("registration failed: %s (%s)", resp.Status, string(body))
	}

	return nil
}

// main is the entry point of the WebSocket client.
// It loads environment variables, prompts the user to register or log in,
// sends a registration request if needed, connects to the WebSocket server at ws://localhost:8080/ws,
// sends an authentication message, and, if authenticated, allows sending and receiving messages.
// The client exits when the user types "exit".
func main() {
	// Load environment variables from .env file
	err := godotenv.Load("../.env")
	if err != nil {
		log.Println("No .env file found, using default or environment variables")
	}

	// Load AES key from environment variable
	aesKey = []byte(os.Getenv("AES_KEY"))
	log.Printf("AES_KEY: %s (length: %d bytes)", aesKey, len(aesKey))
	if len(aesKey) != 32 {
		log.Fatal("AES_KEY must be 32 bytes for AES-256")
	}
	log.Println("AES_KEY loaded successfully")

	// Prompt for registration or login
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Do you want to register a new account? (yes/no): ")
	choice, err := reader.ReadString('\n')
	if err != nil {
		log.Fatalf("Failed to read choice: %v", err)
	}
	choice = strings.TrimSpace(strings.ToLower(choice))

	var username, password string
	serverURL := "http://localhost:8080"

	// Handle registration
	if choice == "yes" || choice == "y" {
		fmt.Print("Enter username for registration: ")
		username, err = reader.ReadString('\n')
		if err != nil {
			log.Fatalf("Failed to read username: %v", err)
		}
		username = strings.TrimSpace(username)

		fmt.Print("Enter password for registration: ")
		password, err = reader.ReadString('\n')
		if err != nil {
			log.Fatalf("Failed to read password: %v", err)
		}
		password = strings.TrimSpace(password)

		// Register the user
		err = registerUser(username, password, serverURL)
		if err != nil {
			log.Fatalf("Registration failed: %v", err)
		}
		fmt.Println("User registered successfully")
	} else {
		// Prompt for authentication
		fmt.Print("Enter username for login: ")
		username, err = reader.ReadString('\n')
		if err != nil {
			log.Fatalf("Failed to read username: %v", err)
		}
		username = strings.TrimSpace(username)

		fmt.Print("Enter password for login: ")
		password, err = reader.ReadString('\n')
		if err != nil {
			log.Fatalf("Failed to read password: %v", err)
		}
		password = strings.TrimSpace(password)
	}

	// Connect to WebSocket server
	wsURL := "ws://localhost:8080/ws"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		log.Fatalf("Failed to connect to WebSocket server: %v", err)
	}
	defer conn.Close()
	log.Println("Connected to WebSocket server")

	// Send authentication message
	auth := AuthMessage{Username: username, Password: password}
	authJSON, err := json.Marshal(auth)
	if err != nil {
		log.Fatalf("Failed to marshal authentication message: %v", err)
	}
	err = conn.WriteMessage(websocket.TextMessage, authJSON)
	if err != nil {
		log.Fatalf("Failed to send authentication message: %v", err)
	}

	// Read authentication response
	_, authResponse, err := conn.ReadMessage()
	if err != nil {
		log.Fatalf("Failed to read authentication response: %v", err)
	}
	if string(authResponse) != "Authentication successful" {
		log.Fatalf("Authentication failed: %s", string(authResponse))
	}
	fmt.Println("Authentication successful")

	// Start goroutine to read messages from the server
	go func() {
		for {
			_, message, err := conn.ReadMessage()
			if err != nil {
				log.Printf("Read error: %v", err)
				return
			}
			// Decrypt the received message
			decrypted, err := decryptMessage(message, aesKey)
			if err != nil {
				log.Printf("Decryption error: %v", err)
				continue
			}
			// Parse the message as JSON
			var msg Message
			if err := json.Unmarshal(decrypted, &msg); err != nil {
				log.Printf("Failed to parse message: %v", err)
				continue
			}
			fmt.Printf("%s: %s\n", msg.Username, msg.Content)
		}
	}()

	// Read input from console and send messages
	fmt.Println("Enter messages to send (type 'exit' to quit):")
	for {
		fmt.Print("> ")
		message, err := reader.ReadString('\n')
		if err != nil {
			log.Printf("Input error: %v", err)
			return
		}
		message = strings.TrimSpace(message)
		if message == "exit" {
			break
		}
		if message == "" {
			continue
		}

		// Encrypt the message
		encrypted, err := encryptMessage([]byte(message), aesKey)
		if err != nil {
			log.Printf("Encryption error: %v", err)
			continue
		}

		// Send the encrypted message
		err = conn.WriteMessage(websocket.BinaryMessage, encrypted)
		if err != nil {
			log.Printf("Write error: %v", err)
			return
		}
		fmt.Printf("Sent: %s\n", message)
	}
}
