package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
)

type MPINEntry struct {
	Name    string `json:"name"`
	Account string `json:"account"`
	PIN     string `json:"pin"`
}

type MPINConfig struct {
	Entries []MPINEntry `json:"entries"`
}

func getMPINConfigPath() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %v", err)
	}

	configDir := filepath.Join(homeDir, ".config", "mpin")
	err = os.MkdirAll(configDir, 0755)
	if err != nil {
		return "", fmt.Errorf("failed to create config directory: %v", err)
	}

	return filepath.Join(configDir, "pins.json"), nil
}

func loadMPINConfig() (*MPINConfig, error) {
	configPath, err := getMPINConfigPath()
	if err != nil {
		return nil, err
	}

	config := &MPINConfig{
		Entries: []MPINEntry{},
	}

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return config, nil
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	err = json.Unmarshal(data, config)
	if err != nil {
		return nil, fmt.Errorf("failed to parse config file: %v", err)
	}

	return config, nil
}

func saveMPINConfig(config *MPINConfig) error {
	configPath, err := getMPINConfigPath()
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %v", err)
	}

	err = os.WriteFile(configPath, data, 0600)
	if err != nil {
		return fmt.Errorf("failed to write config file: %v", err)
	}

	return nil
}

func generateMPIN(length int) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("PIN length must be positive")
	}

	pin := make([]byte, length)
	for i := 0; i < length; i++ {
		digit, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			return "", fmt.Errorf("failed to generate random digit: %v", err)
		}
		pin[i] = byte('0' + digit.Int64())
	}

	return string(pin), nil
}

func AddMPIN(name, account string, length int) error {
	if name == "" || account == "" {
		return fmt.Errorf("name and account cannot be empty")
	}

	if length <= 0 {
		return fmt.Errorf("PIN length must be positive")
	}

	config, err := loadMPINConfig()
	if err != nil {
		return err
	}

	// Check if entry already exists
	for i, entry := range config.Entries {
		if entry.Name == name && entry.Account == account {
			// Update existing entry
			pin, err := generateMPIN(length)
			if err != nil {
				return err
			}
			config.Entries[i].PIN = pin
			err = saveMPINConfig(config)
			if err != nil {
				return err
			}
			fmt.Printf("MPIN updated for %s (%s): %s\n", name, account, pin)
			return nil
		}
	}

	// Generate new PIN
	pin, err := generateMPIN(length)
	if err != nil {
		return err
	}

	// Add new entry
	newEntry := MPINEntry{
		Name:    name,
		Account: account,
		PIN:     pin,
	}

	config.Entries = append(config.Entries, newEntry)

	err = saveMPINConfig(config)
	if err != nil {
		return err
	}

	fmt.Printf("MPIN generated for %s (%s): %s\n", name, account, pin)
	return nil
}

func GetMPIN(name, account string) error {
	if name == "" || account == "" {
		return fmt.Errorf("name and account cannot be empty")
	}

	config, err := loadMPINConfig()
	if err != nil {
		return err
	}

	// Search for the entry
	for _, entry := range config.Entries {
		if entry.Name == name && entry.Account == account {
			fmt.Printf("MPIN for %s (%s): %s\n", name, account, entry.PIN)
			return nil
		}
	}

	return fmt.Errorf("MPIN not found for %s (%s)", name, account)
}

func ListMPINs() error {
	config, err := loadMPINConfig()
	if err != nil {
		return err
	}

	if len(config.Entries) == 0 {
		fmt.Println("No MPIN entries found")
		return nil
	}

	fmt.Println("MPIN Entries:")
	for _, entry := range config.Entries {
		fmt.Printf("  Name: %s, Account: %s, PIN: %s\n", entry.Name, entry.Account, entry.PIN)
	}

	return nil
}
