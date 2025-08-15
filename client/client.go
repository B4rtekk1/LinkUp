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
	"syscall"

	"github.com/gorilla/websocket"
	"github.com/joho/godotenv"
	"golang.org/x/term"
)

// aesKey holds the AES-256 key for encrypting and decrypting WebSocket messages.
// It must match the server's key, loaded from the AES_KEY environment variable.
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

// Message represents a chat message with sender information.
type Message struct {
	Username string `json:"username"` // The sender's username
	Content  string `json:"content"`  // The message content
}

// encryptMessage encrypts a message using AES-GCM with the provided key.
// It generates a random nonce and prepends it to the ciphertext.
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

// registerUser sends an HTTP POST request to the server's /register endpoint to create a new user.
// Returns an error if registration fails.
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
// It loads environment variables, prompts for registration or login,
// sends a registration request if needed, connects to the WebSocket server,
// authenticates, and enables sending/receiving messages.
// Exits when the user types "exit".
func main() {
	err := godotenv.Load("../.env")
	if err != nil {
		log.Println("No .env file found, using default or environment variables")
	}

	aesKey = []byte(os.Getenv("AES_KEY"))
	log.Printf("AES_KEY: %s (length: %d bytes)", aesKey, len(aesKey))
	if len(aesKey) != 32 {
		log.Fatal("AES_KEY must be 32 bytes for AES-256")
	}
	log.Println("AES_KEY loaded successfully")

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Do you want to register a new account? (yes/no): ")
	choice, err := reader.ReadString('\n')
	if err != nil {
		log.Fatalf("Failed to read choice: %v", err)
	}
	choice = strings.TrimSpace(strings.ToLower(choice))

	var username, password string
	serverURL := "http://localhost:8080"

	if choice == "yes" || choice == "y" {
		fmt.Print("Enter username for registration: ")
		username, err = reader.ReadString('\n')
		if err != nil {
			log.Fatalf("Failed to read username: %v", err)
		}
		username = strings.TrimSpace(username)

		fmt.Print("Enter password for registration: ")
		passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			log.Fatalf("Failed to read password: %v", err)
		}
		password = strings.TrimSpace(string(passwordBytes))

		fmt.Print("\nConfirm password for registration: ")
		confirmPasswordBytes, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			log.Fatalf("Failed to read confirm password: %v", err)
		}
		confirmPassword := strings.TrimSpace(string(confirmPasswordBytes))

		if confirmPassword != password {
			log.Fatal("Passwords do not match")
			os.Exit(1)
		}

		err = registerUser(username, password, serverURL)
		if err != nil {
			log.Fatalf("Registration failed: %v", err)
		}
		fmt.Println("User registered successfully")
		// Optional: Uncomment for testing if server-side transaction fix is insufficient
		// time.Sleep(1 * time.Second)
	} else {
		fmt.Print("Enter username for login: ")
		username, err = reader.ReadString('\n')
		if err != nil {
			log.Fatalf("Failed to read username: %v", err)
		}
		username = strings.TrimSpace(username)

		fmt.Print("Enter password for login: ")
		passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			log.Fatalf("Failed to read password: %v", err)
		}
		password = strings.TrimSpace(string(passwordBytes))
	}

	wsURL := "ws://localhost:8080/ws"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		log.Fatalf("Failed to connect to WebSocket server: %v", err)
	}
	defer conn.Close()
	log.Println("Connected to WebSocket server")

	auth := AuthMessage{Username: username, Password: password}
	authJSON, err := json.Marshal(auth)
	if err != nil {
		log.Fatalf("Failed to marshal authentication message: %v", err)
	}
	err = conn.WriteMessage(websocket.TextMessage, authJSON)
	if err != nil {
		log.Fatalf("Failed to send authentication message: %v", err)
	}

	_, authResponse, err := conn.ReadMessage()
	if err != nil {
		log.Fatalf("Failed to read authentication response: %v", err)
	}
	if string(authResponse) != "Authentication successful" {
		log.Fatalf("Authentication failed: %s", string(authResponse))
	}
	fmt.Println("Authentication successful")

	go func() {
		for {
			_, message, err := conn.ReadMessage()
			if err != nil {
				log.Printf("Read error: %v", err)
				return
			}
			decrypted, err := decryptMessage(message, aesKey)
			if err != nil {
				log.Printf("Decryption error: %v", err)
				continue
			}
			var msg Message
			if err := json.Unmarshal(decrypted, &msg); err != nil {
				log.Printf("Failed to parse message: %v", err)
				continue
			}
			fmt.Printf("%s: %s\n", msg.Username, msg.Content)
		}
	}()

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

		encrypted, err := encryptMessage([]byte(message), aesKey)
		if err != nil {
			log.Printf("Encryption error: %v", err)
			continue
		}

		err = conn.WriteMessage(websocket.BinaryMessage, encrypted)
		if err != nil {
			log.Printf("Write error: %v", err)
			return
		}
		fmt.Printf("Sent: %s\n", message)
	}
}
