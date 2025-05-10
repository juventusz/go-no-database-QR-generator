package generate

import (
	"reflect"
	"testing"
)

func TestCreateEncryptedQRCode(t *testing.T) {
	type args struct {
		key        []byte
		outputFile string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Valid key and output file",
			args: args{
				key:        []byte("samplekey12345678901234567890123"), // 32 bytes for AES-256
				outputFile: "test_qr.png",
			},
			wantErr: false,
		},
		{
			name: "Invalid key length",
			args: args{
				key:        []byte("shortkey"), // Invalid key length
				outputFile: "test_qr.png",
			},
			wantErr: true,
		},
		{
			name: "Empty output file",
			args: args{
				key:        []byte("samplekey12345678901234567890123"), // 32 bytes for AES-256
				outputFile: "",
			},
			wantErr: true,
		},
		{
			name: "Invalid key (nil)",
			args: args{
				key:        nil, // Invalid key
				outputFile: "test_qr.png",
			},
			wantErr: true,
		},
		{
			name: "Invalid output file path",
			args: args{
				key:        []byte("samplekey12345678901234567890123"), // 32 bytes for AES-256
				outputFile: "/invalid/path/test_qr.png",                // Invalid path
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := CreateEncryptedQRCode(tt.args.key, tt.args.outputFile)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateEncryptedQRCode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestValidateEncryptedQR(t *testing.T) {
	type args struct {
		encodedCiphertext string
		key               []byte
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		want1   *QRPayload
		wantErr bool
	}{
		{
			name: "Valid QR code",
			args: args{
				encodedCiphertext: "5CdzP2Ew6PEWz4YDOi0fUd5ejyfJUpGidyBuLvvwE4lebUdn6nFBziMiznKQGwwwJhmGQcpOajPj_fkCnxdfok1xTo8hkZfvmcbPWV0IWhWz5SL2HO77xdYcWR1XVnpviLfeGUhWrMG1rR138_M=",
				key:               []byte("samplekey12345678901234567890123"), // 32 bytes for AES-256
			},
			want:    true,
			want1:   &QRPayload{ID: "f34135a1-2fa0-4fe3-9f79-4796e0b2c7d9", Created: 1746801058, Type: "access"},
			wantErr: false,
		},
		{
			name: "Invalid QR code",
			args: args{
				encodedCiphertext: "invalid_encoded_ciphertext",
				key:               []byte("samplekey12345678901234567890123"), // 32 bytes for AES-256
			},
			want:    false,
			want1:   nil,
			wantErr: true,
		},
		{
			name: "Empty encoded ciphertext",
			args: args{
				encodedCiphertext: "",
				key:               []byte("samplekey12345678901234567890123"), // 32 bytes for AES-256
			},
			want:    false,
			want1:   nil,
			wantErr: true,
		},
		{
			name: "Invalid key length",
			args: args{
				encodedCiphertext: "5CdzP2Ew6PEWz4YDOi0fUd5ejyfJUpGidyBuLvvwE4lebUdn6nFBziMiznKQGwwwJhmGQcpOajPj_fkCnxdfok1xTo8hkZfvmcbPWV0IWhWz5SL2HO77xdYcWR1XVnpviLfeGUhWrMG1rR138_M=",
				key:               []byte("shortkey"), // Invalid key length
			},
			want:    false,
			want1:   nil,
			wantErr: true,
		},
		{
			name: "Nil key",
			args: args{
				encodedCiphertext: "valid_encoded_ciphertext",
				key:               nil, // Invalid key
			},
			want:    false,
			want1:   nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, err := ValidateEncryptedQR(tt.args.encodedCiphertext, tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateEncryptedQR() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ValidateEncryptedQR() got = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("ValidateEncryptedQR() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}
