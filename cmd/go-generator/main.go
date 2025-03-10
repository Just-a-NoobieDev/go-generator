package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/Just-A-NoobieDev/go-generator/internal/generator"
)

func main() {
	config, err := getProjectConfig()
	if err != nil {
		fmt.Printf("Error getting project configuration: %v\n", err)
		os.Exit(1)
	}

	gen := generator.New(config)
	if err := gen.Generate(); err != nil {
		fmt.Printf("Error generating project: %v\n", err)
		os.Exit(1)
	}
}

func getProjectConfig() (generator.ProjectConfig, error) {
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

	fmt.Print("Include WebSocket support? (y/n): ")
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

	fmt.Print("Enter Go module path (e.g., github.com/username/project): ")
	modulePath, err := reader.ReadString('\n')
	if err != nil {
		return generator.ProjectConfig{}, fmt.Errorf("error reading module path: %v", err)
	}
	modulePath = strings.TrimSpace(modulePath)
	if modulePath == "" {
		return generator.ProjectConfig{}, fmt.Errorf("module path cannot be empty")
	}

	return generator.ProjectConfig{
		Name:             name,
		IncludeWebSocket: strings.ToLower(strings.TrimSpace(wsSupport)) == "y",
		IncludeJWT:      strings.ToLower(strings.TrimSpace(jwtSupport)) == "y",
		IncludeRedis:    strings.ToLower(strings.TrimSpace(redisSupport)) == "y",
		IncludeSwagger:  strings.ToLower(strings.TrimSpace(swaggerSupport)) == "y",
		IncludeTests:    strings.ToLower(strings.TrimSpace(testsSupport)) == "y",
		ModulePath:      modulePath,
	}, nil
} 