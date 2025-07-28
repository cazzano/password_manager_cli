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

func printUsage() {
	fmt.Println("Usage:")
	fmt.Println("  ./main setup-mfa --account <account> --name <name> -k <secret_key> [-s <seconds>]")
	fmt.Println("  ./main list")
	fmt.Println("  ./main generate --account <account> --name <name>")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  ./main setup-mfa --account google --name dummy@gmail.com -k \"rfg3 oi7l zdiy 2yha sypa gdm6 g3qa d3pc\" -s 30")
	fmt.Println("  ./main list")
	fmt.Println("  ./main generate --account google --name dummy@gmail.com")
}
