package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type MFAEntry struct {
	Account string `json:"account"`
	Name    string `json:"name"`
	Secret  string `json:"secret"`
	Period  int    `json:"period"`
}

type MFAStorage struct {
	Entries []MFAEntry `json:"entries"`
}

func getConfigPath() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %v", err)
	}

	configDir := filepath.Join(homeDir, ".config", "mfa")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create config directory: %v", err)
	}

	return filepath.Join(configDir, "secrets.json"), nil
}

func loadMFAStorage() (*MFAStorage, error) {
	configPath, err := getConfigPath()
	if err != nil {
		return nil, err
	}

	storage := &MFAStorage{Entries: []MFAEntry{}}

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return storage, nil
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	if len(data) == 0 {
		return storage, nil
	}

	if err := json.Unmarshal(data, storage); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %v", err)
	}

	return storage, nil
}

func saveMFAStorage(storage *MFAStorage) error {
	configPath, err := getConfigPath()
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(storage, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %v", err)
	}

	if err := os.WriteFile(configPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %v", err)
	}

	return nil
}

func cleanSecret(secret string) string {
	// Remove all non-base32 characters (spaces, hyphens, etc.)
	// Base32 alphabet: A-Z, 2-7
	var cleaned strings.Builder
	secret = strings.ToUpper(secret)
	
	for _, char := range secret {
		if (char >= 'A' && char <= 'Z') || (char >= '2' && char <= '7') {
			cleaned.WriteRune(char)
		}
	}
	
	result := cleaned.String()
	
	// Add proper base32 padding
	switch len(result) % 8 {
	case 2:
		result += "======"
	case 4:
		result += "===="
	case 5:
		result += "==="
	case 7:
		result += "="
	}
	
	return result
}

func generateTOTPWithOffset(secret string, period int, timeOffset int64) (string, int, error) {
	// Clean the secret key
	cleanedSecret := cleanSecret(secret)
	
	// Debug: print cleaned secret
	fmt.Printf("Debug: Original secret: %s\n", secret)
	fmt.Printf("Debug: Cleaned secret: %s\n", cleanedSecret)
	
	// Decode base32 secret
	key, err := base32.StdEncoding.DecodeString(cleanedSecret)
	if err != nil {
		return "", 0, fmt.Errorf("invalid secret key after cleaning: %v", err)
	}
	
	// Debug: print decoded key
	fmt.Printf("Debug: Decoded key (hex): %s\n", hex.EncodeToString(key))

	// Get current Unix timestamp with offset
	now := time.Now().Unix() + timeOffset
	
	// Calculate time counter (T = (Current Unix time - T0) / X)
	// T0 = 0 (Unix epoch), X = period (typically 30)
	counter := now / int64(period)
	
	// Calculate remaining time in current period
	remaining := period - int(now%int64(period))
	
	// Debug: print time calculations
	currentTime := time.Unix(now, 0)
	fmt.Printf("Debug: Current time: %s\n", currentTime.Format("2006-01-02 15:04:05 UTC"))
	fmt.Printf("Debug: Current Unix time: %d (offset: %d)\n", now, timeOffset)
	fmt.Printf("Debug: Time counter: %d\n", counter)
	fmt.Printf("Debug: Remaining seconds: %d\n", remaining)

	// Convert counter to 8-byte big-endian byte array
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(counter))
	
	// Debug: print counter bytes
	fmt.Printf("Debug: Counter bytes (hex): %s\n", hex.EncodeToString(buf))

	// Generate HMAC-SHA1 hash
	h := hmac.New(sha1.New, key)
	h.Write(buf)
	hash := h.Sum(nil)
	
	// Debug: print hash
	fmt.Printf("Debug: HMAC-SHA1 hash (hex): %s\n", hex.EncodeToString(hash))

	// Dynamic truncation (RFC 4226, Section 5.3)
	// Take the last 4 bits of the hash as offset
	offset := int(hash[len(hash)-1] & 0x0f)
	
	// Debug: print offset
	fmt.Printf("Debug: Offset: %d\n", offset)
	
	// Extract 4 bytes starting from offset
	truncatedHash := binary.BigEndian.Uint32(hash[offset:offset+4])
	
	// Clear the most significant bit to ensure positive number
	truncatedHash &= 0x7fffffff
	
	// Debug: print truncated hash
	fmt.Printf("Debug: Truncated hash: %d\n", truncatedHash)
	
	// Generate 6-digit code
	otp := fmt.Sprintf("%06d", truncatedHash%1000000)
	
	// Debug: print final OTP
	fmt.Printf("Debug: Generated OTP: %s\n", otp)
	
	return otp, remaining, nil
}

func generateTOTP(secret string, period int) (string, int, error) {
	return generateTOTPWithOffset(secret, period, 0)
}

// Generate multiple TOTP codes with time offsets to help with synchronization
func generateTOTPCodes(secret string, period int) error {
	fmt.Println("=== Generating TOTP codes with different time offsets ===")
	
	offsets := []int64{-60, -30, 0, 30, 60} // -2min, -1min, current, +1min, +2min
	
	for _, offset := range offsets {
		fmt.Printf("\n--- Time offset: %+d seconds ---\n", offset)
		code, remaining, err := generateTOTPWithOffset(secret, period, offset)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			continue
		}
		
		adjustedTime := time.Now().Add(time.Duration(offset) * time.Second)
		fmt.Printf("Time: %s\n", adjustedTime.Format("15:04:05"))
		fmt.Printf("Code: %s (valid for %d seconds)\n", code, remaining)
	}
	
	fmt.Println("=========================================================")
	return nil
}

// Test function with RFC 6238 test vectors
func testTOTP() {
	// RFC 6238 test vector
	testSecret := "12345678901234567890" // ASCII string
	testPeriod := 30
	
	fmt.Println("=== Testing with RFC 6238 test vector ===")
	
	// Convert ASCII to bytes, then to base32 for our function
	testSecretBytes := []byte(testSecret)
	testSecretBase32 := base32.StdEncoding.EncodeToString(testSecretBytes)
	
	fmt.Printf("Test secret (ASCII): %s\n", testSecret)
	fmt.Printf("Test secret (Base32): %s\n", testSecretBase32)
	
	// Test with specific timestamp from RFC 6238: 59 seconds -> should give 94287082
	testTime := int64(59)
	testCounter := testTime / int64(testPeriod)
	
	fmt.Printf("Test time: %d, Counter: %d\n", testTime, testCounter)
	
	// Manual calculation for test
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(testCounter))
	
	h := hmac.New(sha1.New, testSecretBytes)
	h.Write(buf)
	hash := h.Sum(nil)
	
	offset := int(hash[len(hash)-1] & 0x0f)
	truncatedHash := binary.BigEndian.Uint32(hash[offset:offset+4])
	truncatedHash &= 0x7fffffff
	expectedOTP := fmt.Sprintf("%06d", truncatedHash%1000000)
	
	fmt.Printf("Expected OTP for T=1: %s (should be 287082 or 94287082)\n", expectedOTP)
	fmt.Println("==========================================")
}

func SetupMFA(account, name, secret string, period int) error {
	// Run test first
	testTOTP()
	
	// Validate the secret by trying to generate a code
	_, _, err := generateTOTP(secret, period)
	if err != nil {
		return fmt.Errorf("invalid secret key - cannot generate TOTP: %v", err)
	}

	storage, err := loadMFAStorage()
	if err != nil {
		return err
	}

	// Check if entry already exists and update it
	for i, entry := range storage.Entries {
		if entry.Account == account && entry.Name == name {
			storage.Entries[i] = MFAEntry{
				Account: account,
				Name:    name,
				Secret:  secret,
				Period:  period,
			}
			return saveMFAStorage(storage)
		}
	}

	// Add new entry
	newEntry := MFAEntry{
		Account: account,
		Name:    name,
		Secret:  secret,
		Period:  period,
	}

	storage.Entries = append(storage.Entries, newEntry)
	return saveMFAStorage(storage)
}

func ListMFA() ([]MFAEntry, error) {
	storage, err := loadMFAStorage()
	if err != nil {
		return nil, err
	}

	return storage.Entries, nil
}

func GenerateMFA(account, name string) (string, int, error) {
	storage, err := loadMFAStorage()
	if err != nil {
		return "", 0, err
	}

	// Find the matching entry
	for _, entry := range storage.Entries {
		if entry.Account == account && entry.Name == name {
			// Generate multiple codes with time offsets for debugging
			fmt.Printf("\n=== Debugging codes for %s (%s) ===\n", name, account)
			generateTOTPCodes(entry.Secret, entry.Period)
			
			code, remaining, err := generateTOTP(entry.Secret, entry.Period)
			if err != nil {
				return "", 0, fmt.Errorf("failed to generate TOTP: %v", err)
			}
			return code, remaining, nil
		}
	}

	return "", 0, fmt.Errorf("MFA entry not found for account '%s' and name '%s'", account, name)
}
