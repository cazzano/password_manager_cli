package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
)

type PasswordEntry struct {
	Name     string `json:"name"`
	Account  string `json:"account"`
	Password string `json:"password"`
	Length   int    `json:"length"`
	Config   string `json:"config"` // Store what character types were used
}

type PasswordStorage struct {
	Entries []PasswordEntry `json:"entries"`
}

func getPasswordConfigPath() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %v", err)
	}

	configDir := filepath.Join(homeDir, ".config", "pass")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create config directory: %v", err)
	}

	return filepath.Join(configDir, "passwords.json"), nil
}

func loadPasswordStorage() (*PasswordStorage, error) {
	configPath, err := getPasswordConfigPath()
	if err != nil {
		return nil, err
	}

	storage := &PasswordStorage{Entries: []PasswordEntry{}}

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return storage, nil
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read password config file: %v", err)
	}

	if len(data) == 0 {
		return storage, nil
	}

	if err := json.Unmarshal(data, storage); err != nil {
		return nil, fmt.Errorf("failed to parse password config file: %v", err)
	}

	return storage, nil
}

func savePasswordStorage(storage *PasswordStorage) error {
	configPath, err := getPasswordConfigPath()
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(storage, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal password config: %v", err)
	}

	if err := os.WriteFile(configPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write password config file: %v", err)
	}

	return nil
}

func generatePassword(length int, useSmallAlpha, useLargeAlpha, useDigits bool, specialChars string) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("password length must be greater than 0")
	}

	var charset string
	var configParts []string

	// Build character set based on flags
	if useSmallAlpha {
		charset += "abcdefghijklmnopqrstuvwxyz"
		configParts = append(configParts, "lowercase")
	}
	if useLargeAlpha {
		charset += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		configParts = append(configParts, "uppercase")
	}
	if useDigits {
		charset += "0123456789"
		configParts = append(configParts, "digits")
	}
	if specialChars != "" {
		charset += specialChars
		configParts = append(configParts, fmt.Sprintf("special(%s)", specialChars))
	}

	// Debug: Print what's being used for password generation
	fmt.Printf("Debug: Using charset: %s\n", charset)
	fmt.Printf("Debug: Special chars: '%s'\n", specialChars)
	fmt.Printf("Debug: Config parts: %v\n", configParts)

	// If no character types specified, use all by default
	if charset == "" {
		charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?"
		configParts = []string{"all"}
	}

	if len(charset) == 0 {
		return "", fmt.Errorf("no characters available for password generation")
	}

	// Generate password
	password := make([]byte, length)
	charsetLen := big.NewInt(int64(len(charset)))

	for i := 0; i < length; i++ {
		randomIndex, err := rand.Int(rand.Reader, charsetLen)
		if err != nil {
			return "", fmt.Errorf("failed to generate random number: %v", err)
		}
		password[i] = charset[randomIndex.Int64()]
	}

	return string(password), nil
}

func AddPassword(name, account string, length int, useSmallAlpha, useLargeAlpha, useDigits bool, specialChars string) error {
	if name == "" || account == "" {
		return fmt.Errorf("name and account are required")
	}

	// Generate password
	password, err := generatePassword(length, useSmallAlpha, useLargeAlpha, useDigits, specialChars)
	if err != nil {
		return fmt.Errorf("failed to generate password: %v", err)
	}

	// Build config string for storage
	var configParts []string
	if useSmallAlpha {
		configParts = append(configParts, "lowercase")
	}
	if useLargeAlpha {
		configParts = append(configParts, "uppercase")
	}
	if useDigits {
		configParts = append(configParts, "digits")
	}
	if specialChars != "" {
		configParts = append(configParts, fmt.Sprintf("special(%s)", specialChars))
	}
	
	config := strings.Join(configParts, ", ")
	if config == "" {
		config = "all (default)"
	}

	storage, err := loadPasswordStorage()
	if err != nil {
		return err
	}

	// Check if entry already exists and update it
	for i, entry := range storage.Entries {
		if entry.Name == name && entry.Account == account {
			storage.Entries[i] = PasswordEntry{
				Name:     name,
				Account:  account,
				Password: password,
				Length:   length,
				Config:   config,
			}
			fmt.Printf("Password updated for %s (%s): %s\n", name, account, password)
			return savePasswordStorage(storage)
		}
	}

	// Add new entry
	newEntry := PasswordEntry{
		Name:     name,
		Account:  account,
		Password: password,
		Length:   length,
		Config:   config,
	}

	storage.Entries = append(storage.Entries, newEntry)
	fmt.Printf("Password generated for %s (%s): %s\n", name, account, password)
	return savePasswordStorage(storage)
}

func GetPasswords() error {
	storage, err := loadPasswordStorage()
	if err != nil {
		return fmt.Errorf("error loading passwords: %v", err)
	}

	if len(storage.Entries) == 0 {
		fmt.Println("No passwords found")
		return nil
	}

	fmt.Println("Stored Passwords:")
	fmt.Println("=================")
	for i, entry := range storage.Entries {
		fmt.Printf("%d. Name: %s\n", i+1, entry.Name)
		fmt.Printf("   Account: %s\n", entry.Account)
		fmt.Printf("   Password: %s\n", entry.Password)
		fmt.Printf("   Length: %d characters\n", entry.Length)
		fmt.Printf("   Config: %s\n", entry.Config)
		fmt.Println()
	}

	return nil
}
