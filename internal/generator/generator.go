package generator

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// RouterType defines the type of router to use
type RouterType string

const (
	RouterChi     RouterType = "chi"
	RouterStd     RouterType = "std"
	RouterGin     RouterType = "gin"
	RouterEcho    RouterType = "echo"
)

// DatabaseType defines the type of database access to use
type DatabaseType string

const (
	DatabaseSQLC    DatabaseType = "sqlc"
	DatabaseGORM    DatabaseType = "gorm"
	DatabaseMongoDB DatabaseType = "mongodb"
)

// ProjectConfig holds the configuration for project generation
type ProjectConfig struct {
	Name              string
	IncludeWebSocket  bool
	IncludeJWT        bool
	IncludeRedis      bool
	ModulePath        string
	IncludeSwagger    bool
	IncludeTests      bool
	Router            RouterType
	Database          DatabaseType
}

// Generator handles project generation
type Generator struct {
	config ProjectConfig
}

// New creates a new Generator instance
func New(config ProjectConfig) *Generator {
	return &Generator{
		config: config,
	}
}

// Generate creates a new project based on the configuration
func (g *Generator) Generate() error {
	// Create project directory structure
	if err := g.createDirectories(); err != nil {
		return err
	}

	// Generate files
	generators := []func() error{
		g.generateGoMod,
		g.generateDockerfile,
		g.generateDockerCompose,
		g.generateAirConfig,
		g.generateMakefile,
		g.generateGitignore,
		g.generateMainGo,
		g.generateEnvFile,
		g.generateReadme,
		g.generateCommonMiddleware,
	}

	// Add database-specific generators
	switch g.config.Database {
	case DatabaseSQLC:
		generators = append(generators, g.generateSQLCConfig)
	case DatabaseMongoDB:
		generators = append(generators, g.generateMongoDBConfig)
	}

	if g.config.IncludeJWT {
		generators = append(generators, g.generateAuthFiles)
	}

	if g.config.IncludeWebSocket {
		generators = append(generators, g.generateWebSocketFiles)
	}

	if g.config.IncludeRedis {
		generators = append(generators, g.generateRedisFiles)
	}

	if g.config.IncludeSwagger {
		generators = append(generators, g.generateSwaggerFiles)
	}

	// Execute all generators
	for _, generator := range generators {
		if err := generator(); err != nil {
			return err
		}
	}

	// Generate example Todo API files
	if err := g.generateTodoAPI(); err != nil {
		return fmt.Errorf("error generating Todo API files: %v", err)
	}

	// Execute post-generation commands
	if err := g.executePostGenerationCommands(); err != nil {
		return fmt.Errorf("failed to execute post-generation commands: %v", err)
	}

	fmt.Printf("\nProject %s created successfully!\n", g.config.Name)
	fmt.Println("\nNext steps:")
	fmt.Println("1. cd", g.config.Name)
	fmt.Println("2. make install-tools")
	fmt.Println("3. make docker-up")
	fmt.Println("4. make migrate-up")
	fmt.Println("5. make dev")

	return nil
}

func (g *Generator) createDirectories() error {
	dirs := []string{
		"cmd/server",
		"internal/api/handlers",
		"internal/api/middleware",
		"internal/api/routes",
		"internal/api/types",
		"internal/config",
		"internal/db/migrations",
		"internal/db/queries",
		"internal/db/sqlc",
		"internal/domain",
		"internal/repository",
		"internal/service",
		"pkg/utils",
		"scripts",
		"docs",
	}

	if g.config.IncludeWebSocket {
		dirs = append(dirs, "internal/websocket")
	}

	if g.config.IncludeTests {
		dirs = append(dirs, "tests/integration", "tests/unit")
	}

	for _, dir := range dirs {
		err := os.MkdirAll(filepath.Join(g.config.Name, dir), 0755)
		if err != nil {
			return fmt.Errorf("error creating directory %s: %v", dir, err)
		}
	}

	return nil
}

func (g *Generator) executePostGenerationCommands() error {
	// Change to the project directory
	err := os.Chdir(g.config.Name)
	if err != nil {
		return fmt.Errorf("failed to change to project directory: %v", err)
	}

	// Initialize git repository
	if err := exec.Command("git", "init").Run(); err != nil {
		return fmt.Errorf("failed to initialize git repository: %v", err)
	}

	// Initialize go module
	if err := exec.Command("go", "mod", "tidy").Run(); err != nil {
		return fmt.Errorf("failed to run go mod tidy: %v", err)
	}

	// Generate SQLC code if using SQLC
	if g.config.Database == DatabaseSQLC {
		if err := exec.Command("sqlc", "generate").Run(); err != nil {
			return fmt.Errorf("failed to generate SQLC code: %v", err)
		}
	}

	// Install required tools
	if err := exec.Command("make", "install-tools").Run(); err != nil {
		return fmt.Errorf("failed to install tools: %v", err)
	}

	return nil
} 