package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "setup-mfa":
		handleSetupMFA()
	case "list":
		handleList()
	case "generate":
		handleGenerate()
	case "add-pass":
		handleAddPassword()
	case "get-pass":
		handleGetPasswords()
	case "add-mpin":
		handleAddMPIN()
	case "get-mpin":
		handleGetMPIN()
	case "list-mpin":
		handleListMPINs()
	default:
		fmt.Printf("Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

func handleSetupMFA() {
	fs := flag.NewFlagSet("setup-mfa", flag.ExitOnError)
	account := fs.String("account", "", "Account name (required)")
	name := fs.String("name", "", "Name/email (required)")
	key := fs.String("k", "", "Secret key (required)")
	seconds := fs.Int("s", 30, "Time step in seconds (default: 30)")

	fs.Parse(os.Args[2:])

	if *account == "" || *name == "" || *key == "" {
		fmt.Println("Error: --account, --name, and -k are required")
		fs.Usage()
		os.Exit(1)
	}

	err := SetupMFA(*account, *name, *key, *seconds)
	if err != nil {
		fmt.Printf("Error setting up MFA: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("MFA setup successful for %s (%s)\n", *name, *account)
}

func handleList() {
	entries, err := ListMFA()
	if err != nil {
		fmt.Printf("Error listing MFA entries: %v\n", err)
		os.Exit(1)
	}

	if len(entries) == 0 {
		fmt.Println("No MFA entries found")
		return
	}

	fmt.Println("MFA Accounts:")
	for _, entry := range entries {
		fmt.Printf("  Account: %s, Name: %s, Period: %ds\n", 
			entry.Account, entry.Name, entry.Period)
	}
}

func handleGenerate() {
	fs := flag.NewFlagSet("generate", flag.ExitOnError)
	account := fs.String("account", "", "Account name (required)")
	name := fs.String("name", "", "Name/email (required)")

	fs.Parse(os.Args[2:])

	if *account == "" || *name == "" {
		fmt.Println("Error: --account and --name are required")
		fs.Usage()
		os.Exit(1)
	}

	code, remaining, err := GenerateMFA(*account, *name)
	if err != nil {
		fmt.Printf("Error generating MFA code: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("MFA Code: %s (valid for %d seconds)\n", code, remaining)
}

func handleAddPassword() {
	fs := flag.NewFlagSet("add-pass", flag.ExitOnError)
	length := fs.Int("l", 16, "Password length (default: 16)")
	smallAlpha := fs.Bool("a", false, "Include lowercase letters")
	largeAlpha := fs.Bool("A", false, "Include uppercase letters")
	digits := fs.Bool("d", false, "Include digits")
	specialChars := fs.String("s", "", "Special characters to include (use 'default' for common special chars or provide custom)")
	name := fs.String("name", "", "Name/service (required)")
	account := fs.String("account", "", "Account/username (required)")

	fs.Parse(os.Args[2:])

	if *name == "" || *account == "" {
		fmt.Println("Error: --name and --account are required")
		fs.Usage()
		os.Exit(1)
	}

	// Handle special characters logic - THIS IS THE FIX
	actualSpecialChars := *specialChars
	if *specialChars == "default" {
		actualSpecialChars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
	}
	
	// If no character type flags are specified at all, use all character types with default special chars
	if !*smallAlpha && !*largeAlpha && !*digits && *specialChars == "" {
		*smallAlpha = true
		*largeAlpha = true  
		*digits = true
		actualSpecialChars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
	}

	err := AddPassword(*name, *account, *length, *smallAlpha, *largeAlpha, *digits, actualSpecialChars)
	if err != nil {
		fmt.Printf("Error generating password: %v\n", err)
		os.Exit(1)
	}
}

func handleGetPasswords() {
	err := GetPasswords()
	if err != nil {
		fmt.Printf("Error retrieving passwords: %v\n", err)
		os.Exit(1)
	}
}

func handleAddMPIN() {
	fs := flag.NewFlagSet("add-mpin", flag.ExitOnError)
	length := fs.Int("l", 4, "MPIN length (default: 4)")
	name := fs.String("name", "", "Name/service (required)")
	account := fs.String("account", "", "Account/username (required)")

	fs.Parse(os.Args[2:])

	if *name == "" || *account == "" {
		fmt.Println("Error: --name and --account are required")
		fs.Usage()
		os.Exit(1)
	}

	err := AddMPIN(*name, *account, *length)
	if err != nil {
		fmt.Printf("Error adding MPIN: %v\n", err)
		os.Exit(1)
	}
}

func handleGetMPIN() {
	fs := flag.NewFlagSet("get-mpin", flag.ExitOnError)
	name := fs.String("name", "", "Name/service (required)")
	account := fs.String("account", "", "Account/username (required)")

	fs.Parse(os.Args[2:])

	if *name == "" || *account == "" {
		fmt.Println("Error: --name and --account are required")
		fs.Usage()
		os.Exit(1)
	}

	err := GetMPIN(*name, *account)
	if err != nil {
		fmt.Printf("Error retrieving MPIN: %v\n", err)
		os.Exit(1)
	}
}

func handleListMPINs() {
	err := ListMPINs()
	if err != nil {
		fmt.Printf("Error listing MPINs: %v\n", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Usage:")
	fmt.Println("  ./main setup-mfa --account <account> --name <name> -k <secret_key> [-s <seconds>]")
	fmt.Println("  ./main list")
	fmt.Println("  ./main generate --account <account> --name <name>")
	fmt.Println("  ./main add-pass --name <service> --account <username> [-l <length>] [-a] [-A] [-d] [-s <special_chars>]")
	fmt.Println("  ./main get-pass")
	fmt.Println("  ./main add-mpin --name <service> --account <username> [-l <length>]")
	fmt.Println("  ./main get-mpin --name <service> --account <username>")
	fmt.Println("  ./main list-mpin")
	fmt.Println()
	fmt.Println("MFA Examples:")
	fmt.Println("  ./main setup-mfa --account google --name dummy@gmail.com -k \"rfg3 oi7l zdiy 2yha sypa gdm6 g3qa d3pc\" -s 30")
	fmt.Println("  ./main list")
	fmt.Println("  ./main generate --account google --name dummy@gmail.com")
	fmt.Println()
	fmt.Println("Password Examples:")
	fmt.Println("  ./main add-pass --name google --account dummy@gmail.com -l 20 -a -A -d -s default")
	fmt.Println("  ./main add-pass --name github --account myuser -l 16 -s \"!@#$\"")
	fmt.Println("  ./main add-pass --name twitter --account handle -a -A -d")
	fmt.Println("  ./main get-pass")
	fmt.Println()
	fmt.Println("MPIN Examples:")
	fmt.Println("  ./main add-mpin --name google --account dummy@gmail.com -l 4")
	fmt.Println("  ./main add-mpin --name bank --account myaccount -l 6")
	fmt.Println("  ./main get-mpin --name google --account dummy@gmail.com")
	fmt.Println("  ./main list-mpin")
	fmt.Println()
	fmt.Println("Password Flags:")
	fmt.Println("  -l: Password length (default: 16)")
	fmt.Println("  -a: Include lowercase letters")
	fmt.Println("  -A: Include uppercase letters") 
	fmt.Println("  -d: Include digits")
	fmt.Println("  -s: Special characters - use 'default' for common special chars or provide custom like \"!@#$\"")
	fmt.Println("      If not specified with other flags, no special characters will be used")
	fmt.Println()
	fmt.Println("MPIN Flags:")
	fmt.Println("  -l: MPIN length (default: 4)")
}
