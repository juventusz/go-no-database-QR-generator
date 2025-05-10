package main

import (
	"fmt"
	"go-no-database-QR-generator/generate"
)

func main() {
	sample32byteKey := "samplekey12345678901234567890123" // 32 bytes for AES-256

	data, err := generate.CreateEncryptedQRCode([]byte(sample32byteKey), "encrypted_qr.png")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("Encrypted QR code data:", data)

	// Validate the QR code
	valid, payload, err := generate.ValidateEncryptedQR(data, []byte(sample32byteKey))
	if err != nil {
		fmt.Println("Error validating QR code:", err)
		return
	}
	if valid {
		fmt.Println("QR code is valid. Payload:", payload)
	} else {
		fmt.Println("QR code is invalid.")
	}
}
