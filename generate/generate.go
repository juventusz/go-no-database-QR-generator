package generate

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/google/uuid"
	"github.com/skip2/go-qrcode"
)

type QRPayload struct {
	ID      string `json:"id"`
	Created int64  `json:"created"`
	Type    string `json:"type,omitempty"`
}

// Generate a unique ID
func generateID() string {
	return uuid.New().String()
}

// Encrypt data using AES-256-GCM
func encrypt(plaintext []byte, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)
	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

// Create QR code with encrypted data
func CreateEncryptedQRCode(key []byte, outputFile string) (string, error) {
	payload := QRPayload{
		ID:      generateID(),
		Created: time.Now().Unix(),
		Type:    "access",
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	encryptedData, err := encrypt(jsonData, key)
	if err != nil {
		return "", err
	}

	return encryptedData, qrcode.WriteFile(encryptedData, qrcode.Medium, 256, outputFile)
}

// validateEncryptedQR checks if the QR content is valid by attempting decryption and JSON parsing.
func ValidateEncryptedQR(encodedCiphertext string, key []byte) (bool, *QRPayload, error) {
	// Decode base64 URL encoding
	ciphertext, err := base64.URLEncoding.DecodeString(encodedCiphertext)
	if err != nil {
		return false, nil, fmt.Errorf("base64 decode failed: %w", err)
	}

	// Prepare AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return false, nil, fmt.Errorf("AES cipher creation failed: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return false, nil, fmt.Errorf("GCM setup failed: %w", err)
	}

	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return false, nil, errors.New("ciphertext too short")
	}

	nonce := ciphertext[:nonceSize]
	encryptedData := ciphertext[nonceSize:]

	// Decrypt the data
	plaintext, err := aesGCM.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return false, nil, fmt.Errorf("decryption failed: %w", err)
	}

	// Parse the JSON into QRPayload
	var payload QRPayload
	err = json.Unmarshal(plaintext, &payload)
	if err != nil {
		return false, nil, fmt.Errorf("JSON unmarshal failed: %w", err)
	}

	return true, &payload, nil
}
