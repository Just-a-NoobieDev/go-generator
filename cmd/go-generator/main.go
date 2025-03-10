package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/Just-A-NoobieDev/go-generator/internal/generator"
)

const helpText = `
Go Project Generator - A modern web application generator

Usage:
  go-generator [flags]
  go-generator [command]

Available Commands:
  help        Show help for go-generator
  version     Show go-generator version

Flags:
  -n, --name string      Project name
  -r, --router string    Router type (chi, std, gin, echo)
  -d, --database string  Database type (sqlc, gorm, mongodb)
  -i, --interactive     Interactive mode
      --ws              Include WebSocket support
      --jwt             Include JWT authentication
      --redis           Include Redis support
      --swagger         Include Swagger documentation
      --tests           Include test files

Router Types:
  chi    - Chi router (lightweight and fast)
  std    - Standard library net/http
  gin    - Gin web framework (feature-rich)
  echo   - Echo framework (high performance)

Database Types:
  sqlc     - PostgreSQL with SQLC (type-safe SQL)
  gorm     - PostgreSQL with GORM (full-featured ORM)
  mongodb  - MongoDB (using official Go driver)

Examples:
  # Create a new project with Chi router and SQLC
  go-generator -n myapp -r chi -d sqlc

  # Create a new project with Gin, GORM, and additional features
  go-generator -n myapp -r gin -d gorm --jwt --redis --swagger

  # Interactive mode
  go-generator -i

  # Show help
  go-generator help
`

const version = "v0.1.0"

func main() {
	// Check for commands first
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "help", "--help", "-h":
			fmt.Print(helpText)
			os.Exit(0)
		case "version", "--version", "-v":
			fmt.Printf("go-generator %s\n", version)
			os.Exit(0)
		}
	}

	// Command-line flags
	var (
		name        string
		router      string
		database    string
		websocket   bool
		jwt         bool
		redis       bool
		swagger     bool
		tests       bool
		interactive bool
	)

	// Define flags
	flag.StringVar(&name, "n", "", "Project name")
	flag.StringVar(&name, "name", "", "Project name")
	flag.StringVar(&router, "r", "", "Router type (chi, std, gin, echo)")
	flag.StringVar(&router, "router", "", "Router type (chi, std, gin, echo)")
	flag.StringVar(&database, "d", "", "Database type (sqlc, gorm, mongodb)")
	flag.StringVar(&database, "database", "", "Database type (sqlc, gorm, mongodb)")
	flag.BoolVar(&websocket, "ws", false, "Include WebSocket support")
	flag.BoolVar(&jwt, "jwt", false, "Include JWT authentication")
	flag.BoolVar(&redis, "redis", false, "Include Redis support")
	flag.BoolVar(&swagger, "swagger", false, "Include Swagger documentation")
	flag.BoolVar(&tests, "tests", false, "Include test files")
	flag.BoolVar(&interactive, "i", false, "Interactive mode")
	flag.BoolVar(&interactive, "interactive", false, "Interactive mode")

	flag.Usage = func() {
		fmt.Print(helpText)
	}

	flag.Parse()

	var config generator.ProjectConfig
	var err error

	if interactive || (name == "" && router == "" && database == "") {
		config, err = getProjectConfigInteractive()
	} else {
		config, err = getProjectConfigFromFlags(name, router, database, websocket, jwt, redis, swagger, tests)
	}

	if err != nil {
		fmt.Printf("Error getting project configuration: %v\n", err)
		os.Exit(1)
	}

	gen := generator.New(config)
	if err := gen.Generate(); err != nil {
		fmt.Printf("Error generating project: %v\n", err)
		os.Exit(1)
	}

	// Print success message with next steps
	fmt.Printf("\nProject %s created successfully!\n", config.Name)
	fmt.Printf("\nNext steps:\n")
	fmt.Printf("  cd %s\n", config.Name)
	fmt.Printf("  make install-tools    # Install required tools\n")
	fmt.Printf("  make docker-up        # Start the development environment\n")
	fmt.Printf("  make dev             # Run the application with live reload\n")
}

func getProjectConfigFromFlags(name, router, database string, websocket, jwt, redis, swagger, tests bool) (generator.ProjectConfig, error) {
	if name == "" {
		return generator.ProjectConfig{}, fmt.Errorf("project name is required")
	}

	var routerType generator.RouterType
	switch strings.ToLower(router) {
	case "chi":
		routerType = generator.RouterChi
	case "std":
		routerType = generator.RouterStd
	case "gin":
		routerType = generator.RouterGin
	case "echo":
		routerType = generator.RouterEcho
	default:
		return generator.ProjectConfig{}, fmt.Errorf("invalid router type: %s", router)
	}

	var dbType generator.DatabaseType
	switch strings.ToLower(database) {
	case "sqlc":
		dbType = generator.DatabaseSQLC
	case "gorm":
		dbType = generator.DatabaseGORM
	case "mongodb":
		dbType = generator.DatabaseMongoDB
	default:
		return generator.ProjectConfig{}, fmt.Errorf("invalid database type: %s", database)
	}

	return generator.ProjectConfig{
		Name:             name,
		Router:           routerType,
		Database:         dbType,
		IncludeWebSocket: websocket,
		IncludeJWT:      jwt,
		IncludeRedis:    redis,
		IncludeSwagger:   swagger,
		IncludeTests:    tests,
		ModulePath:      name,
	}, nil
}

func getProjectConfigInteractive() (generator.ProjectConfig, error) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Enter project name: ")
	name, err := reader.ReadString('\n')
	if err != nil {
		return generator.ProjectConfig{}, fmt.Errorf("error reading project name: %v", err)
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return generator.ProjectConfig{}, fmt.Errorf("project name cannot be empty")
	}

	// Generate module path from project name
	modulePath := name

	fmt.Println("\nSelect Router:")
	fmt.Println("1. Chi (lightweight and fast)")
	fmt.Println("2. Standard library net/http")
	fmt.Println("3. Gin (feature-rich web framework)")
	fmt.Println("4. Echo (high performance, minimalist)")
	fmt.Print("Enter choice (1-4): ")
	routerChoice, err := reader.ReadString('\n')
	if err != nil {
		return generator.ProjectConfig{}, fmt.Errorf("error reading router choice: %v", err)
	}
	routerChoice = strings.TrimSpace(routerChoice)

	var routerType generator.RouterType
	switch routerChoice {
	case "1":
		routerType = generator.RouterChi
	case "2":
		routerType = generator.RouterStd
	case "3":
		routerType = generator.RouterGin
	case "4":
		routerType = generator.RouterEcho
	default:
		return generator.ProjectConfig{}, fmt.Errorf("invalid router choice")
	}

	fmt.Println("\nSelect Database:")
	fmt.Println("1. PostgreSQL with SQLC (type-safe SQL)")
	fmt.Println("2. PostgreSQL with GORM (full-featured ORM)")
	fmt.Println("3. MongoDB (using official Go driver)")
	fmt.Print("Enter choice (1-3): ")
	dbChoice, err := reader.ReadString('\n')
	if err != nil {
		return generator.ProjectConfig{}, fmt.Errorf("error reading database choice: %v", err)
	}
	dbChoice = strings.TrimSpace(dbChoice)

	var dbType generator.DatabaseType
	switch dbChoice {
	case "1":
		dbType = generator.DatabaseSQLC
	case "2":
		dbType = generator.DatabaseGORM
	case "3":
		dbType = generator.DatabaseMongoDB
	default:
		return generator.ProjectConfig{}, fmt.Errorf("invalid database choice")
	}

	fmt.Print("\nInclude WebSocket support? (y/n): ")
	wsSupport, err := reader.ReadString('\n')
	if err != nil {
		return generator.ProjectConfig{}, fmt.Errorf("error reading WebSocket support: %v", err)
	}

	fmt.Print("Include JWT authentication? (y/n): ")
	jwtSupport, err := reader.ReadString('\n')
	if err != nil {
		return generator.ProjectConfig{}, fmt.Errorf("error reading JWT support: %v", err)
	}

	fmt.Print("Include Redis for caching? (y/n): ")
	redisSupport, err := reader.ReadString('\n')
	if err != nil {
		return generator.ProjectConfig{}, fmt.Errorf("error reading Redis support: %v", err)
	}

	fmt.Print("Include Swagger documentation? (y/n): ")
	swaggerSupport, err := reader.ReadString('\n')
	if err != nil {
		return generator.ProjectConfig{}, fmt.Errorf("error reading Swagger support: %v", err)
	}

	fmt.Print("Include test files? (y/n): ")
	testsSupport, err := reader.ReadString('\n')
	if err != nil {
		return generator.ProjectConfig{}, fmt.Errorf("error reading tests support: %v", err)
	}

	return generator.ProjectConfig{
		Name:             name,
		Router:           routerType,
		Database:         dbType,
		IncludeWebSocket: strings.ToLower(strings.TrimSpace(wsSupport)) == "y",
		IncludeJWT:      strings.ToLower(strings.TrimSpace(jwtSupport)) == "y",
		IncludeRedis:    strings.ToLower(strings.TrimSpace(redisSupport)) == "y",
		IncludeSwagger:  strings.ToLower(strings.TrimSpace(swaggerSupport)) == "y",
		IncludeTests:    strings.ToLower(strings.TrimSpace(testsSupport)) == "y",
		ModulePath:      modulePath,
	}, nil
} 