package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
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
	// Remove spaces and convert to uppercase for base32 decoding
	return strings.ToUpper(strings.ReplaceAll(secret, " ", ""))
}

func generateTOTP(secret string, period int) (string, int, error) {
	// Clean the secret key
	cleanedSecret := cleanSecret(secret)
	
	// Decode base32 secret
	key, err := base32.StdEncoding.DecodeString(cleanedSecret)
	if err != nil {
		return "", 0, fmt.Errorf("invalid secret key: %v", err)
	}

	// Calculate time counter
	now := time.Now().Unix()
	counter := now / int64(period)
	
	// Calculate remaining time
	remaining := period - int(now%int64(period))

	// Convert counter to bytes
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(counter))

	// Generate HMAC-SHA1
	h := hmac.New(sha1.New, key)
	h.Write(buf)
	hash := h.Sum(nil)

	// Dynamic truncation
	offset := hash[19] & 0x0f
	code := binary.BigEndian.Uint32(hash[offset:offset+4]) & 0x7fffffff
	
	// Generate 6-digit code
	otp := fmt.Sprintf("%06d", code%1000000)
	
	return otp, remaining, nil
}

func SetupMFA(account, name, secret string, period int) error {
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
			code, remaining, err := generateTOTP(entry.Secret, entry.Period)
			if err != nil {
				return "", 0, fmt.Errorf("failed to generate TOTP: %v", err)
			}
			return code, remaining, nil
		}
	}

	return "", 0, fmt.Errorf("MFA entry not found for account '%s' and name '%s'", account, name)
}
