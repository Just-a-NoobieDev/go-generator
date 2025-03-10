package generator

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func (g *Generator) generateGoMod() error {
	content := fmt.Sprintf(`module %s

go 1.22

require (`, g.config.Name)

	// Add router-specific dependencies
	switch g.config.Router {
	case RouterChi:
		content += `
	github.com/go-chi/chi/v5 v5.0.11
	github.com/go-chi/cors v1.2.1`
	case RouterGin:
		content += `
	github.com/gin-gonic/gin v1.9.1
	github.com/gin-contrib/cors v1.5.0`
	case RouterEcho:
		content += `
	github.com/labstack/echo/v4 v4.11.4
	github.com/labstack/gommon v0.4.2`
	}

	// Add common dependencies
	content += `
	github.com/golang-migrate/migrate/v4 v4.17.0
	github.com/google/uuid v1.6.0
	github.com/joho/godotenv v1.5.1`

	// Add database-specific dependencies
	switch g.config.Database {
	case DatabaseGORM:
		content += `
	gorm.io/gorm v1.25.7
	gorm.io/driver/postgres v1.5.6`
	case DatabaseSQLC:
		content += `
	github.com/jackc/pgx/v5 v5.5.2`
	case DatabaseMongoDB:
		content += `
	go.mongodb.org/mongo-driver v1.14.0`
	}

	if g.config.IncludeJWT {
		content += `
	github.com/golang-jwt/jwt/v5 v5.0.0`
	}

	if g.config.IncludeRedis {
		content += `
	github.com/redis/go-redis/v9 v9.4.0`
	}

	if g.config.IncludeWebSocket {
		content += `
	github.com/gorilla/websocket v1.5.1`
	}

	if g.config.IncludeSwagger {
		content += `
	github.com/swaggo/swag v1.16.3
	github.com/swaggo/http-swagger v1.3.4`
	}

	content += `
)`

	return g.writeFile("go.mod", content)
}

func (g *Generator) generateDockerfile() error {
	content := `# Build stage
FROM golang:1.22-alpine AS builder

WORKDIR /app

# Install git and build-base (gcc, etc.)
RUN apk add --no-cache git build-base

# Install Air for live reloading
RUN go install github.com/cosmtrek/air@latest

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy the source code
COPY . .

# Build the application
RUN go build -o main ./cmd/server

# Final stage
FROM alpine:latest

WORKDIR /app

# Install necessary runtime dependencies
RUN apk add --no-cache ca-certificates tzdata

# Copy the binary from builder
COPY --from=builder /app/main .
COPY --from=builder /go/bin/air /usr/local/bin/air
COPY .air.toml .

# Copy migrations and any other necessary files
COPY internal/db/migrations ./internal/db/migrations

# Set environment variables
ENV GO_ENV=development

# Expose the application port
EXPOSE 8080

# Use Air for development
CMD ["air"]`

	return g.writeFile("Dockerfile", content)
}

func (g *Generator) generateDockerCompose() error {
	content := `version: '3.8'

services:
  app:
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      - "8080:8080"
    environment:
      - DB_HOST=postgres
      - DB_PORT=5432
      - DB_USER=postgres
      - DB_PASSWORD=postgres
      - DB_NAME=app_db
      - DB_SSL_MODE=disable
      - JWT_SECRET=your_jwt_secret_here
      - ENVIRONMENT=development
    volumes:
      - .:/app
    depends_on:
      - postgres
    networks:
      - app-network

  postgres:
    image: postgis/postgis:15-3.3
    environment:
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=postgres
      - POSTGRES_DB=app_db
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
    networks:
      - app-network

  pgadmin:
    image: dpage/pgadmin4
    environment:
      - PGADMIN_DEFAULT_EMAIL=admin@admin.com
      - PGADMIN_DEFAULT_PASSWORD=admin
    ports:
      - "5050:80"
    depends_on:
      - postgres
    networks:
      - app-network`

	if g.config.IncludeRedis {
		content += `

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    networks:
      - app-network`
	}

	content += `

volumes:
  postgres_data:`

	if g.config.IncludeRedis {
		content += `
  redis_data:`
	}

	content += `

networks:
  app-network:
    driver: bridge`

	return g.writeFile("docker-compose.yml", content)
}

func (g *Generator) generateAirConfig() error {
	content := `root = "."
testdata_dir = "testdata"
tmp_dir = "tmp"

[build]
  args_bin = []
  bin = "./tmp/main"
  cmd = "go build -o ./tmp/main ./cmd/server"
  delay = 1000
  exclude_dir = ["assets", "tmp", "vendor", "testdata"]
  exclude_file = []
  exclude_regex = ["_test.go"]
  exclude_unchanged = false
  follow_symlink = false
  full_bin = ""
  include_dir = []
  include_ext = ["go", "tpl", "tmpl", "html"]
  include_file = []
  kill_delay = "0s"
  log = "build-errors.log"
  poll = false
  poll_interval = 0
  rerun = false
  rerun_delay = 500
  send_interrupt = false
  stop_on_error = true

[color]
  app = ""
  build = "yellow"
  main = "magenta"
  runner = "green"
  watcher = "cyan"

[log]
  main_only = false
  time = false

[misc]
  clean_on_exit = false

[screen]
  clear_on_rebuild = false
  keep_scroll = true`

	return g.writeFile(".air.toml", content)
}

func (g *Generator) generateMakefile() error {
	content := `.PHONY: build run test clean docker-build docker-up docker-down migrate-up migrate-down

# Go commands
build:
	go build -o bin/server ./cmd/server

run:
	go run ./cmd/server

test:
	go test -v ./...

clean:
	rm -rf bin/
	rm -rf tmp/

# Docker commands
docker-build:
	docker-compose build

docker-up:
	docker-compose up -d

docker-down:
	docker-compose down

# Database commands
migrate-up:
	migrate -path internal/db/migrations -database "postgresql://postgres:postgres@localhost:5432/app_db?sslmode=disable" up

migrate-down:
	migrate -path internal/db/migrations -database "postgresql://postgres:postgres@localhost:5432/app_db?sslmode=disable" down

# Development commands
dev:
	air

# SQLC commands
sqlc:
	sqlc generate

# Install tools
install-tools:
	go install github.com/cosmtrek/air@latest
	go install github.com/kyleconroy/sqlc/cmd/sqlc@latest
	go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest`

	if g.config.IncludeSwagger {
		content += `
	go install github.com/swaggo/swag/cmd/swag@latest`
	}

	content += `

# Help
help:
	@echo "Available commands:"
	@echo "  build         - Build the application"
	@echo "  run          - Run the application"
	@echo "  test         - Run tests"
	@echo "  clean        - Clean build artifacts"
	@echo "  docker-build - Build Docker images"
	@echo "  docker-up    - Start Docker containers"
	@echo "  docker-down  - Stop Docker containers"
	@echo "  migrate-up   - Run database migrations"
	@echo "  migrate-down - Rollback database migrations"
	@echo "  dev          - Run with live reload"
	@echo "  sqlc         - Generate SQLC code"`

	return g.writeFile("Makefile", content)
}

func (g *Generator) generateGitignore() error {
	content := `# Binaries for programs and plugins
*.exe
*.exe~
*.dll
*.so
*.dylib
bin/
tmp/

# Test binary, built with 'go test -c'
*.test

# Output of the go coverage tool, specifically when used with LiteIDE
*.out

# Dependency directories (remove the comment below to include it)
vendor/

# Go workspace file
go.work

# Environment variables
.env

# IDE specific files
.idea/
.vscode/
*.swp
*.swo

# OS generated files
.DS_Store
.DS_Store?
._*
.Spotlight-V100
.Trashes
ehthumbs.db
Thumbs.db

# Air temporary files
tmp/`

	return g.writeFile(".gitignore", content)
}

func (g *Generator) generateMainGo() error {
	var content string

	switch g.config.Router {
	case RouterChi:
		content = fmt.Sprintf(`package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"%s/internal/api/routes"
)

func main() {
	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:          300,
	}))

	// Routes
	routes.SetupRoutes(r)

	srv := &http.Server{
		Addr:    ":8080",
		Handler: r,
	}

	// Server run context
	serverCtx, serverStopCtx := context.WithCancel(context.Background())

	// Listen for syscall signals for process to interrupt/quit
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	go func() {
		<-sig

		// Shutdown signal with grace period of 30 seconds
		shutdownCtx, _ := context.WithTimeout(serverCtx, 30*time.Second)

		go func() {
			<-shutdownCtx.Done()
			if shutdownCtx.Err() == context.DeadlineExceeded {
				log.Fatal("graceful shutdown timed out.. forcing exit.")
			}
		}()

		// Trigger graceful shutdown
		err := srv.Shutdown(shutdownCtx)
		if err != nil {
			log.Fatal(err)
		}
		serverStopCtx()
	}()

	// Run the server
	fmt.Println("Server is running on port 8080")
	err := srv.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}

	// Wait for server context to be stopped
	<-serverCtx.Done()
}`, g.config.ModulePath)

	case RouterGin:
		content = fmt.Sprintf(`package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"%s/internal/api/routes"
)

func main() {
	r := gin.Default()

	// Middleware
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Accept", "Authorization", "Content-Type"},
		ExposeHeaders:    []string{"Link"},
		AllowCredentials: true,
		MaxAge:          300 * time.Second,
	}))

	// Routes
	routes.SetupRoutes(r)

	srv := &http.Server{
		Addr:    ":8080",
		Handler: r,
	}

	// Server run context
	serverCtx, serverStopCtx := context.WithCancel(context.Background())

	// Listen for syscall signals for process to interrupt/quit
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	go func() {
		<-sig

		// Shutdown signal with grace period of 30 seconds
		shutdownCtx, _ := context.WithTimeout(serverCtx, 30*time.Second)

		go func() {
			<-shutdownCtx.Done()
			if shutdownCtx.Err() == context.DeadlineExceeded {
				log.Fatal("graceful shutdown timed out.. forcing exit.")
			}
		}()

		// Trigger graceful shutdown
		err := srv.Shutdown(shutdownCtx)
		if err != nil {
			log.Fatal(err)
		}
		serverStopCtx()
	}()

	// Run the server
	fmt.Println("Server is running on port 8080")
	err := srv.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}

	// Wait for server context to be stopped
	<-serverCtx.Done()
}`, g.config.ModulePath)

	case RouterEcho:
		content = fmt.Sprintf(`package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"%s/internal/api/routes"
)

func main() {
	e := echo.New()

	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"*"},
		AllowMethods: []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodOptions},
		AllowHeaders: []string{echo.HeaderAccept, echo.HeaderAuthorization, echo.HeaderContentType},
		MaxAge:      300,
	}))

	// Routes
	routes.SetupRoutes(e)

	// Server configuration
	srv := &http.Server{
		Addr:    ":8080",
		Handler: e,
	}

	// Server run context
	serverCtx, serverStopCtx := context.WithCancel(context.Background())

	// Listen for syscall signals for process to interrupt/quit
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	go func() {
		<-sig

		// Shutdown signal with grace period of 30 seconds
		shutdownCtx, _ := context.WithTimeout(serverCtx, 30*time.Second)

		go func() {
			<-shutdownCtx.Done()
			if shutdownCtx.Err() == context.DeadlineExceeded {
				log.Fatal("graceful shutdown timed out.. forcing exit.")
			}
		}()

		// Trigger graceful shutdown
		err := e.Shutdown(shutdownCtx)
		if err != nil {
			log.Fatal(err)
		}
		serverStopCtx()
	}()

	// Run the server
	fmt.Println("Server is running on port 8080")
	err := srv.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}

	// Wait for server context to be stopped
	<-serverCtx.Done()
}`, g.config.ModulePath)

	default: // Standard library
		content = fmt.Sprintf(`package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"%s/internal/api/routes"
)

func main() {
	// Create a new ServeMux
	mux := http.NewServeMux()

	// Setup routes
	routes.SetupRoutes(mux)

	// Server configuration
	srv := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	// Server run context
	serverCtx, serverStopCtx := context.WithCancel(context.Background())

	// Listen for syscall signals for process to interrupt/quit
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	go func() {
		<-sig

		// Shutdown signal with grace period of 30 seconds
		shutdownCtx, _ := context.WithTimeout(serverCtx, 30*time.Second)

		go func() {
			<-shutdownCtx.Done()
			if shutdownCtx.Err() == context.DeadlineExceeded {
				log.Fatal("graceful shutdown timed out.. forcing exit.")
			}
		}()

		// Trigger graceful shutdown
		err := srv.Shutdown(shutdownCtx)
		if err != nil {
			log.Fatal(err)
		}
		serverStopCtx()
	}()

	// Run the server
	fmt.Println("Server is running on port 8080")
	err := srv.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}

	// Wait for server context to be stopped
	<-serverCtx.Done()
}`, g.config.ModulePath)
	}

	return g.writeFile(filepath.Join("cmd", "server", "main.go"), content)
}

func (g *Generator) generateSQLCConfig() error {
	content := `version: "2"
sql:
  - engine: "postgresql"
    queries: "internal/db/queries/"
    schema: "internal/db/migrations/"
    gen:
      go:
        package: "db"
        out: "internal/db/sqlc"
        sql_package: "database/sql"
        emit_json_tags: true
        emit_interface: true
        emit_empty_slices: true`

	return g.writeFile("sqlc.yaml", content)
}

func (g *Generator) generateEnvFile() error {
	content := `# Application
APP_NAME=app
APP_ENV=development
APP_PORT=8080

# Database
DB_HOST=localhost
DB_PORT=5432
DB_USER=postgres
DB_PASSWORD=postgres
DB_NAME=app_db
DB_SSL_MODE=disable

# JWT
JWT_SECRET=your_jwt_secret_here
JWT_EXPIRATION=24h`

	if g.config.IncludeRedis {
		content += `

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=
REDIS_DB=0`
	}

	if err := g.writeFile(".env.example", content); err != nil {
		return err
	}

	return g.writeFile(".env", content)
}

func (g *Generator) generateReadme() error {
	features := []string{
		"- Clean Architecture",
		"- Chi Router",
		"- PostgreSQL Database",
		"- SQLC for type-safe SQL",
		"- Air for live reloading",
		"- Docker support",
	}

	if g.config.IncludeJWT {
		features = append(features, "- JWT Authentication")
	}
	if g.config.IncludeRedis {
		features = append(features, "- Redis Cache")
	}
	if g.config.IncludeWebSocket {
		features = append(features, "- WebSocket Support")
	}
	if g.config.IncludeSwagger {
		features = append(features, "- Swagger Documentation")
	}
	if g.config.IncludeTests {
		features = append(features, "- Integration and Unit Tests")
	}

	content := fmt.Sprintf(`# %s

## Description

A modern Go web application with clean architecture.

## Features

%s

## Prerequisites

- Go 1.22 or higher
- Docker and Docker Compose
- Make

## Getting Started

1. Clone the repository
2. Run 'make install-tools' to install required tools
3. Copy '.env.example' to '.env' and update the values
4. Run 'make docker-up' to start the services
5. Run 'make migrate-up' to run database migrations
6. Run 'make dev' to start the development server

## Project Structure

.
├── cmd/
│   └── server/          # Application entry points
├── internal/
│   ├── api/            # API layer (handlers, middleware, routes)
│   ├── config/         # Configuration
│   ├── db/            # Database layer
│   ├── domain/        # Domain models
│   ├── repository/    # Data access layer
│   └── service/       # Business logic
├── pkg/
│   └── utils/         # Shared utilities
└── scripts/          # Scripts for development

## Available Commands

- make build: Build the application
- make run: Run the application
- make test: Run tests
- make docker-up: Start Docker containers
- make docker-down: Stop Docker containers
- make migrate-up: Run database migrations
- make migrate-down: Rollback database migrations
- make dev: Run with live reload
- make sqlc: Generate SQLC code

## License

MIT`,
		g.config.Name,
		strings.Join(features, "\n"))

	return g.writeFile("README.md", content)
}

func (g *Generator) generateSwaggerFiles() error {
	content := `{
  "swagger": "2.0",
  "info": {
    "title": "API Documentation",
    "description": "API documentation for the application",
    "version": "1.0.0"
  },
  "host": "localhost:8080",
  "basePath": "/api/v1",
  "schemes": ["http", "https"],
  "consumes": ["application/json"],
  "produces": ["application/json"]
}`

	return g.writeFile(filepath.Join("docs", "swagger.json"), content)
}

func (g *Generator) generateAuthFiles() error {
	var jwtMiddleware string

	switch g.config.Router {
	case RouterChi:
		jwtMiddleware = fmt.Sprintf(`package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"%s/pkg/utils"
)

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			utils.RespondWithError(w, http.StatusUnauthorized, "No authorization header")
			return
		}

		tokenString := strings.Replace(authHeader, "Bearer ", "", 1)
		claims, err := utils.ValidateToken(tokenString)
		if err != nil {
			utils.RespondWithError(w, http.StatusUnauthorized, "Invalid token")
			return
		}

		ctx := context.WithValue(r.Context(), "user", claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}`, g.config.ModulePath)

	case RouterGin:
		jwtMiddleware = fmt.Sprintf(`package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"%s/pkg/utils"
)

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "No authorization header"})
			return
		}

		tokenString := strings.Replace(authHeader, "Bearer ", "", 1)
		claims, err := utils.ValidateToken(tokenString)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			return
		}

		c.Set("user", claims)
		c.Next()
	}
}`, g.config.ModulePath)

	case RouterEcho:
		jwtMiddleware = fmt.Sprintf(`package middleware

import (
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
	"%s/pkg/utils"
)

func AuthMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		authHeader := c.Request().Header.Get("Authorization")
		if authHeader == "" {
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "No authorization header"})
		}

		tokenString := strings.Replace(authHeader, "Bearer ", "", 1)
		claims, err := utils.ValidateToken(tokenString)
		if err != nil {
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid token"})
		}

		c.Set("user", claims)
		return next(c)
	}
}`, g.config.ModulePath)

	default: // Standard library
		jwtMiddleware = fmt.Sprintf(`package middleware

import (
	"context"
	"net/http"
	"strings"

	"%s/pkg/utils"
)

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			utils.RespondWithError(w, http.StatusUnauthorized, "No authorization header")
			return
		}

		tokenString := strings.Replace(authHeader, "Bearer ", "", 1)
		claims, err := utils.ValidateToken(tokenString)
		if err != nil {
			utils.RespondWithError(w, http.StatusUnauthorized, "Invalid token")
			return
		}

		ctx := context.WithValue(r.Context(), "user", claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}`, g.config.ModulePath)
	}

	if err := g.writeFile(filepath.Join("internal", "api", "middleware", "auth.go"), jwtMiddleware); err != nil {
		return err
	}

	// Generate JWT utils
	jwtUtils := `package utils

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var jwtKey = []byte("your-secret-key") // TODO: Move to environment variable

type Claims struct {
	UserID string ` + "`json:\"user_id\"`" + `
	Role   string ` + "`json:\"role\"`" + `
	jwt.RegisteredClaims
}

func GenerateToken(userID, role string) (string, error) {
	claims := &Claims{
		UserID: userID,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtKey)
}

func ValidateToken(tokenString string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtKey, nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}`

	return g.writeFile(filepath.Join("pkg", "utils", "jwt.go"), jwtUtils)
}

func (g *Generator) generateWebSocketFiles() error {
	// Generate WebSocket manager
	wsManager := fmt.Sprintf(`package websocket

import (
	"sync"

	"github.com/gorilla/websocket"
)

type Client struct {
	ID   string
	Conn *websocket.Conn
	Send chan []byte
}

type Manager struct {
	clients    map[*Client]bool
	broadcast  chan []byte
	register   chan *Client
	unregister chan *Client
	mutex      sync.Mutex
}

func NewManager() *Manager {
	return &Manager{
		clients:    make(map[*Client]bool),
		broadcast:  make(chan []byte),
		register:   make(chan *Client),
		unregister: make(chan *Client),
	}
}

func (m *Manager) Start() {
	for {
		select {
		case client := <-m.register:
			m.mutex.Lock()
			m.clients[client] = true
			m.mutex.Unlock()
		case client := <-m.unregister:
			if _, ok := m.clients[client]; ok {
				m.mutex.Lock()
				delete(m.clients, client)
				close(client.Send)
				m.mutex.Unlock()
			}
		case message := <-m.broadcast:
			m.mutex.Lock()
			for client := range m.clients {
				select {
				case client.Send <- message:
				default:
					close(client.Send)
					delete(m.clients, client)
				}
			}
			m.mutex.Unlock()
		}
	}
}

func (m *Manager) Broadcast(message []byte) {
	m.broadcast <- message
}`)

	if err := g.writeFile(filepath.Join("internal", "websocket", "manager.go"), wsManager); err != nil {
		return err
	}

	// Generate WebSocket handler
	wsHandler := fmt.Sprintf(`package websocket

import (
	"log"
	"net/http"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all origins in development
	},
}

type Handler struct {
	manager *Manager
}

func NewHandler(manager *Manager) *Handler {
	return &Handler{
		manager: manager,
	}
}

func (h *Handler) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("WebSocket upgrade error:", err)
		return
	}

	client := &Client{
		Conn: conn,
		Send: make(chan []byte, 256),
	}

	h.manager.register <- client

	go h.writePump(client)
	go h.readPump(client)
}

func (h *Handler) readPump(client *Client) {
	defer func() {
		h.manager.unregister <- client
		client.Conn.Close()
	}()

	for {
		_, message, err := client.Conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("WebSocket read error: %v", err)
			}
			break
		}

		h.manager.Broadcast(message)
	}
}

func (h *Handler) writePump(client *Client) {
	defer client.Conn.Close()

	for {
		select {
		case message, ok := <-client.Send:
			if !ok {
				client.Conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			w, err := client.Conn.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}
			w.Write(message)

			if err := w.Close(); err != nil {
				return
			}
		}
	}
}`)

	return g.writeFile(filepath.Join("internal", "websocket", "handler.go"), wsHandler)
}

func (g *Generator) generateTodoAPI() error {
	if err := g.generateTodoModel(); err != nil {
		return err
	}
	if err := g.generateTodoRepository(); err != nil {
		return err
	}
	if err := g.generateTodoService(); err != nil {
		return err
	}
	if err := g.generateTodoHandler(); err != nil {
		return err
	}
	if err := g.generateTodoRoutes(); err != nil {
		return err
	}
	if err := g.generateTodoMigration(); err != nil {
		return err
	}
	if err := g.generateTodoQueries(); err != nil {
		return err
	}
	return nil
}

func (g *Generator) generateTodoModel() error {
	if g.config.Database == DatabaseGORM {
		return g.generateGormTodoModel()
	}
	return g.generateBasicTodoModel()
}

func (g *Generator) generateGormTodoModel() error {
	content := fmt.Sprintf(`package domain

import (
	"time"

	"gorm.io/gorm"
)

type Todo struct {
	ID          string    %sjson:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"%s
	Title       string    %sjson:"title" gorm:"not null"%s
	Description string    %sjson:"description"%s
	Completed   bool      %sjson:"completed" gorm:"default:false"%s
	CreatedAt   time.Time %sjson:"created_at" gorm:"autoCreateTime"%s
	UpdatedAt   time.Time %sjson:"updated_at" gorm:"autoUpdateTime"%s
}

type CreateTodoInput struct {
	Title       string %sjson:"title" validate:"required"%s
	Description string %sjson:"description"%s
}

type UpdateTodoInput struct {
	Title       *string %sjson:"title"%s
	Description *string %sjson:"description"%s
	Completed   *bool   %sjson:"completed"%s
}

func (Todo) TableName() string {
	return "todos"
}

func (t *Todo) BeforeCreate(tx *gorm.DB) error {
	if t.ID == "" {
		t.ID = uuid.New().String()
	}
	return nil
}`, "`", "`", "`", "`", "`", "`", "`", "`", "`", "`", "`", "`", "`", "`", "`", "`", "`", "`", "`", "`")

	return g.writeFile(filepath.Join("internal", "domain", "todo.go"), content)
}

func (g *Generator) generateBasicTodoModel() error {
	content := fmt.Sprintf(`package domain

import (
	"time"
)

type Todo struct {
	ID          string    %sjson:"id"%s
	Title       string    %sjson:"title"%s
	Description string    %sjson:"description"%s
	Completed   bool      %sjson:"completed"%s
	CreatedAt   time.Time %sjson:"created_at"%s
	UpdatedAt   time.Time %sjson:"updated_at"%s
}

type CreateTodoInput struct {
	Title       string %sjson:"title" validate:"required"%s
	Description string %sjson:"description"%s
}

type UpdateTodoInput struct {
	Title       *string %sjson:"title"%s
	Description *string %sjson:"description"%s
	Completed   *bool   %sjson:"completed"%s
}`, "`", "`", "`", "`", "`", "`", "`", "`", "`", "`", "`", "`", "`", "`", "`", "`", "`", "`", "`", "`", "`", "`")

	return g.writeFile(filepath.Join("internal", "domain", "todo.go"), content)
}

func (g *Generator) generateTodoRepository() error {
	if g.config.Database == DatabaseGORM {
		return g.generateGormTodoRepository()
	}
	return g.generateSQLCTodoRepository()
}

func (g *Generator) generateGormTodoRepository() error {
	content := fmt.Sprintf(`package repository

import (
	"context"
	"errors"

	"gorm.io/gorm"
	"%s/internal/domain"
)

type TodoRepository struct {
	db *gorm.DB
}

func NewTodoRepository(db *gorm.DB) *TodoRepository {
	return &TodoRepository{
		db: db,
	}
}

func (r *TodoRepository) Create(ctx context.Context, input domain.CreateTodoInput) (*domain.Todo, error) {
	todo := &domain.Todo{
		Title:       input.Title,
		Description: input.Description,
	}

	if err := r.db.WithContext(ctx).Create(todo).Error; err != nil {
		return nil, err
	}

	return todo, nil
}

func (r *TodoRepository) GetByID(ctx context.Context, id string) (*domain.Todo, error) {
	var todo domain.Todo
	if err := r.db.WithContext(ctx).First(&todo, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("todo not found")
		}
		return nil, err
	}

	return &todo, nil
}

func (r *TodoRepository) List(ctx context.Context) ([]domain.Todo, error) {
	var todos []domain.Todo
	if err := r.db.WithContext(ctx).Order("created_at desc").Find(&todos).Error; err != nil {
		return nil, err
	}

	return todos, nil
}

func (r *TodoRepository) Update(ctx context.Context, id string, input domain.UpdateTodoInput) (*domain.Todo, error) {
	todo, err := r.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	updates := make(map[string]interface{})
	if input.Title != nil {
		updates["title"] = *input.Title
	}
	if input.Description != nil {
		updates["description"] = *input.Description
	}
	if input.Completed != nil {
		updates["completed"] = *input.Completed
	}

	if err := r.db.WithContext(ctx).Model(todo).Updates(updates).Error; err != nil {
		return nil, err
	}

	return todo, nil
}

func (r *TodoRepository) Delete(ctx context.Context, id string) error {
	result := r.db.WithContext(ctx).Delete(&domain.Todo{}, "id = ?", id)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return errors.New("todo not found")
	}
	return nil
}`, g.config.ModulePath)

	return g.writeFile(filepath.Join("internal", "repository", "todo.go"), content)
}

func (g *Generator) generateSQLCTodoRepository() error {
	content := fmt.Sprintf(`package repository

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"%s/internal/db/sqlc"
	"%s/internal/domain"
)

type TodoRepository struct {
	q *db.Queries
}

func NewTodoRepository(db *sql.DB) *TodoRepository {
	return &TodoRepository{
		q: db.New(db),
	}
}

func (r *TodoRepository) Create(ctx context.Context, input domain.CreateTodoInput) (*domain.Todo, error) {
	todo, err := r.q.CreateTodo(ctx, db.CreateTodoParams{
		Title:       input.Title,
		Description: input.Description,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	})
	if err != nil {
		return nil, err
	}

	return &domain.Todo{
		ID:          todo.ID,
		Title:       todo.Title,
		Description: todo.Description,
		Completed:   todo.Completed,
		CreatedAt:   todo.CreatedAt,
		UpdatedAt:   todo.UpdatedAt,
	}, nil
}

func (r *TodoRepository) GetByID(ctx context.Context, id string) (*domain.Todo, error) {
	todo, err := r.q.GetTodoByID(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("todo not found")
		}
		return nil, err
	}

	return &domain.Todo{
		ID:          todo.ID,
		Title:       todo.Title,
		Description: todo.Description,
		Completed:   todo.Completed,
		CreatedAt:   todo.CreatedAt,
		UpdatedAt:   todo.UpdatedAt,
	}, nil
}

func (r *TodoRepository) List(ctx context.Context) ([]domain.Todo, error) {
	todos, err := r.q.ListTodos(ctx)
	if err != nil {
		return nil, err
	}

	var result []domain.Todo
	for _, todo := range todos {
		result = append(result, domain.Todo{
			ID:          todo.ID,
			Title:       todo.Title,
			Description: todo.Description,
			Completed:   todo.Completed,
			CreatedAt:   todo.CreatedAt,
			UpdatedAt:   todo.UpdatedAt,
		})
	}

	return result, nil
}

func (r *TodoRepository) Update(ctx context.Context, id string, input domain.UpdateTodoInput) (*domain.Todo, error) {
	todo, err := r.q.UpdateTodo(ctx, db.UpdateTodoParams{
		ID:          id,
		Title:       sql.NullString{String: *input.Title, Valid: input.Title != nil},
		Description: sql.NullString{String: *input.Description, Valid: input.Description != nil},
		Completed:   sql.NullBool{Bool: *input.Completed, Valid: input.Completed != nil},
		UpdatedAt:   time.Now(),
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("todo not found")
		}
		return nil, err
	}

	return &domain.Todo{
		ID:          todo.ID,
		Title:       todo.Title,
		Description: todo.Description,
		Completed:   todo.Completed,
		CreatedAt:   todo.CreatedAt,
		UpdatedAt:   todo.UpdatedAt,
	}, nil
}

func (r *TodoRepository) Delete(ctx context.Context, id string) error {
	err := r.q.DeleteTodo(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("todo not found")
		}
		return err
	}

	return nil
}`, g.config.ModulePath, g.config.ModulePath)

	return g.writeFile(filepath.Join("internal", "repository", "todo.go"), content)
}

func (g *Generator) generateTodoService() error {
	content := fmt.Sprintf(`package service

import (
	"context"

	"%s/internal/domain"
	"%s/internal/repository"
)

type TodoService struct {
	repo *repository.TodoRepository
}

func NewTodoService(repo *repository.TodoRepository) *TodoService {
	return &TodoService{
		repo: repo,
	}
}

func (s *TodoService) CreateTodo(ctx context.Context, input domain.CreateTodoInput) (*domain.Todo, error) {
	return s.repo.Create(ctx, input)
}

func (s *TodoService) GetTodoByID(ctx context.Context, id string) (*domain.Todo, error) {
	return s.repo.GetByID(ctx, id)
}

func (s *TodoService) ListTodos(ctx context.Context) ([]domain.Todo, error) {
	return s.repo.List(ctx)
}

func (s *TodoService) UpdateTodo(ctx context.Context, id string, input domain.UpdateTodoInput) (*domain.Todo, error) {
	return s.repo.Update(ctx, id, input)
}

func (s *TodoService) DeleteTodo(ctx context.Context, id string) error {
	return s.repo.Delete(ctx, id)
}`, g.config.ModulePath, g.config.ModulePath)

	return g.writeFile(filepath.Join("internal", "service", "todo.go"), content)
}

func (g *Generator) generateTodoHandler() error {
	var content string

	switch g.config.Router {
	case RouterChi:
		content = fmt.Sprintf(`package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"%s/internal/domain"
	"%s/internal/service"
	"%s/pkg/utils"
)

type TodoHandler struct {
	service *service.TodoService
}

func NewTodoHandler(service *service.TodoService) *TodoHandler {
	return &TodoHandler{
		service: service,
	}
}

func (h *TodoHandler) Create(w http.ResponseWriter, r *http.Request) {
	var input domain.CreateTodoInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	todo, err := h.service.CreateTodo(r.Context(), input)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	utils.RespondWithJSON(w, http.StatusCreated, todo)
}

func (h *TodoHandler) GetByID(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	todo, err := h.service.GetTodoByID(r.Context(), id)
	if err != nil {
		utils.RespondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	utils.RespondWithJSON(w, http.StatusOK, todo)
}

func (h *TodoHandler) List(w http.ResponseWriter, r *http.Request) {
	todos, err := h.service.ListTodos(r.Context())
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	utils.RespondWithJSON(w, http.StatusOK, todos)
}

func (h *TodoHandler) Update(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var input domain.UpdateTodoInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	todo, err := h.service.UpdateTodo(r.Context(), id, input)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	utils.RespondWithJSON(w, http.StatusOK, todo)
}

func (h *TodoHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := h.service.DeleteTodo(r.Context(), id); err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	utils.RespondWithJSON(w, http.StatusNoContent, nil)
}`, g.config.ModulePath, g.config.ModulePath, g.config.ModulePath)

	case RouterGin:
		content = fmt.Sprintf(`package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"%s/internal/domain"
	"%s/internal/service"
)

type TodoHandler struct {
	service *service.TodoService
}

func NewTodoHandler(service *service.TodoService) *TodoHandler {
	return &TodoHandler{
		service: service,
	}
}

func (h *TodoHandler) Create(c *gin.Context) {
	var input domain.CreateTodoInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload"})
		return
	}

	todo, err := h.service.CreateTodo(c.Request.Context(), input)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, todo)
}

func (h *TodoHandler) GetByID(c *gin.Context) {
	id := c.Param("id")
	todo, err := h.service.GetTodoByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, todo)
}

func (h *TodoHandler) List(c *gin.Context) {
	todos, err := h.service.ListTodos(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, todos)
}

func (h *TodoHandler) Update(c *gin.Context) {
	id := c.Param("id")
	var input domain.UpdateTodoInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload"})
		return
	}

	todo, err := h.service.UpdateTodo(c.Request.Context(), id, input)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, todo)
}

func (h *TodoHandler) Delete(c *gin.Context) {
	id := c.Param("id")
	if err := h.service.DeleteTodo(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.Status(http.StatusNoContent)
}`, g.config.ModulePath, g.config.ModulePath)

	case RouterEcho:
		content = fmt.Sprintf(`package handlers

import (
	"net/http"

	"github.com/labstack/echo/v4"
	"%s/internal/domain"
	"%s/internal/service"
)

type TodoHandler struct {
	service *service.TodoService
}

func NewTodoHandler(service *service.TodoService) *TodoHandler {
	return &TodoHandler{
		service: service,
	}
}

func (h *TodoHandler) Create(c echo.Context) error {
	var input domain.CreateTodoInput
	if err := c.Bind(&input); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request payload"})
	}

	todo, err := h.service.CreateTodo(c.Request().Context(), input)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusCreated, todo)
}

func (h *TodoHandler) GetByID(c echo.Context) error {
	id := c.Param("id")
	todo, err := h.service.GetTodoByID(c.Request().Context(), id)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, todo)
}

func (h *TodoHandler) List(c echo.Context) error {
	todos, err := h.service.ListTodos(c.Request().Context())
	if err != nil {
		return c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, todos)
}

func (h *TodoHandler) Update(c echo.Context) error {
	id := c.Param("id")
	var input domain.UpdateTodoInput
	if err := c.Bind(&input); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request payload"})
	}

	todo, err := h.service.UpdateTodo(c.Request().Context(), id, input)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, todo)
}

func (h *TodoHandler) Delete(c echo.Context) error {
	id := c.Param("id")
	if err := h.service.DeleteTodo(c.Request().Context(), id); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	return c.NoContent(http.StatusNoContent)
}`, g.config.ModulePath, g.config.ModulePath)

	default: // Standard library
		content = fmt.Sprintf(`package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"%s/internal/domain"
	"%s/internal/service"
	"%s/pkg/utils"
)

type TodoHandler struct {
	service *service.TodoService
}

func NewTodoHandler(service *service.TodoService) *TodoHandler {
	return &TodoHandler{
		service: service,
	}
}

func (h *TodoHandler) Create(w http.ResponseWriter, r *http.Request) {
	var input domain.CreateTodoInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	todo, err := h.service.CreateTodo(r.Context(), input)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	utils.RespondWithJSON(w, http.StatusCreated, todo)
}

func (h *TodoHandler) GetByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/todos/")
	todo, err := h.service.GetTodoByID(r.Context(), id)
	if err != nil {
		utils.RespondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	utils.RespondWithJSON(w, http.StatusOK, todo)
}

func (h *TodoHandler) List(w http.ResponseWriter, r *http.Request) {
	todos, err := h.service.ListTodos(r.Context())
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	utils.RespondWithJSON(w, http.StatusOK, todos)
}

func (h *TodoHandler) Update(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/todos/")
	var input domain.UpdateTodoInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	todo, err := h.service.UpdateTodo(r.Context(), id, input)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	utils.RespondWithJSON(w, http.StatusOK, todo)
}

func (h *TodoHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/todos/")
	if err := h.service.DeleteTodo(r.Context(), id); err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	utils.RespondWithJSON(w, http.StatusNoContent, nil)
}`, g.config.ModulePath, g.config.ModulePath, g.config.ModulePath)
	}

	return g.writeFile(filepath.Join("internal", "api", "handlers", "todo.go"), content)
}

func (g *Generator) generateTodoRoutes() error {
	var content string

	switch g.config.Router {
	case RouterChi:
		content = fmt.Sprintf(`package routes

import (
	"github.com/go-chi/chi/v5"
	"%s/internal/api/handlers"
	"%s/internal/api/middleware"
)

func SetupTodoRoutes(r chi.Router, h *handlers.TodoHandler) {
	r.Route("/api/v1/todos", func(r chi.Router) {
		r.Use(middleware.AuthMiddleware)

		r.Post("/", h.Create)
		r.Get("/{id}", h.GetByID)
		r.Get("/", h.List)
		r.Put("/{id}", h.Update)
		r.Delete("/{id}", h.Delete)
	})
}`, g.config.ModulePath, g.config.ModulePath)

	case RouterGin:
		content = fmt.Sprintf(`package routes

import (
	"github.com/gin-gonic/gin"
	"%s/internal/api/handlers"
	"%s/internal/api/middleware"
)

func SetupTodoRoutes(r *gin.Engine, h *handlers.TodoHandler) {
	v1 := r.Group("/api/v1")
	todos := v1.Group("/todos")
	todos.Use(middleware.AuthMiddleware())

	todos.POST("/", h.Create)
	todos.GET("/:id", h.GetByID)
	todos.GET("/", h.List)
	todos.PUT("/:id", h.Update)
	todos.DELETE("/:id", h.Delete)
}`, g.config.ModulePath, g.config.ModulePath)

	case RouterEcho:
		content = fmt.Sprintf(`package routes

import (
	"github.com/labstack/echo/v4"
	"%s/internal/api/handlers"
	"%s/internal/api/middleware"
)

func SetupTodoRoutes(e *echo.Echo, h *handlers.TodoHandler) {
	v1 := e.Group("/api/v1")
	todos := v1.Group("/todos", middleware.AuthMiddleware)

	todos.POST("", h.Create)
	todos.GET("/:id", h.GetByID)
	todos.GET("", h.List)
	todos.PUT("/:id", h.Update)
	todos.DELETE("/:id", h.Delete)
}`, g.config.ModulePath, g.config.ModulePath)

	default: // Standard library
		content = fmt.Sprintf(`package routes

import (
	"net/http"
	"%s/internal/api/handlers"
	"%s/internal/api/middleware"
)

func SetupTodoRoutes(mux *http.ServeMux, h *handlers.TodoHandler) {
	todoHandler := middleware.AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost:
			h.Create(w, r)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/todos":
			h.List(w, r)
		case r.Method == http.MethodGet:
			h.GetByID(w, r)
		case r.Method == http.MethodPut:
			h.Update(w, r)
		case r.Method == http.MethodDelete:
			h.Delete(w, r)
		default:
			http.NotFound(w, r)
		}
	}))

	mux.Handle("/api/v1/todos/", todoHandler)
	mux.Handle("/api/v1/todos", todoHandler)
}`, g.config.ModulePath, g.config.ModulePath)
	}

	return g.writeFile(filepath.Join("internal", "api", "routes", "todo.go"), content)
}

func (g *Generator) generateTodoMigration() error {
	content := `-- Create todos table
CREATE TABLE IF NOT EXISTS todos (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title VARCHAR(255) NOT NULL,
    description TEXT,
    completed BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create index on title
CREATE INDEX IF NOT EXISTS idx_todos_title ON todos(title);`

	return g.writeFile(filepath.Join("internal", "db", "migrations", "000001_create_todos_table.up.sql"), content)
}

func (g *Generator) generateTodoQueries() error {
	content := `-- name: CreateTodo :one
INSERT INTO todos (
    title,
    description,
    created_at,
    updated_at
) VALUES (
    $1, $2, $3, $4
)
RETURNING *;

-- name: GetTodoByID :one
SELECT * FROM todos
WHERE id = $1;

-- name: ListTodos :many
SELECT * FROM todos
ORDER BY created_at DESC;

-- name: UpdateTodo :one
UPDATE todos
SET
    title = COALESCE(NULLIF($2, ''), title),
    description = COALESCE(NULLIF($3, ''), description),
    completed = COALESCE($4, completed),
    updated_at = $5
WHERE id = $1
RETURNING *;

-- name: DeleteTodo :exec
DELETE FROM todos
WHERE id = $1;`

	return g.writeFile(filepath.Join("internal", "db", "queries", "todo.sql"), content)
}

func (g *Generator) generateDatabaseConfig() error {
	var content string

	if g.config.Database == DatabaseGORM {
		content = fmt.Sprintf(`package config

import (
	"fmt"
	"log"
	"os"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"%s/internal/domain"
)

func NewDatabase() *gorm.DB {
	dsn := fmt.Sprintf("host=%%s port=%%s user=%%s password=%%s dbname=%%s sslmode=%%s",
		os.Getenv("DB_HOST"),
		os.Getenv("DB_PORT"),
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASSWORD"),
		os.Getenv("DB_NAME"),
		os.Getenv("DB_SSL_MODE"),
	)

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("failed to connect to database:", err)
	}

	// Auto-migrate the schema
	err = db.AutoMigrate(&domain.Todo{})
	if err != nil {
		log.Fatal("failed to migrate database:", err)
	}

	return db
}`, g.config.ModulePath)
	} else {
		content = fmt.Sprintf(`package config

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func NewDatabase() *sql.DB {
	dsn := fmt.Sprintf("host=%%s port=%%s user=%%s password=%%s dbname=%%s sslmode=%%s",
		os.Getenv("DB_HOST"),
		os.Getenv("DB_PORT"),
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASSWORD"),
		os.Getenv("DB_NAME"),
		os.Getenv("DB_SSL_MODE"),
	)

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		log.Fatal("failed to connect to database:", err)
	}

	if err := db.Ping(); err != nil {
		log.Fatal("failed to ping database:", err)
	}

	return db
}`)
	}

	return g.writeFile(filepath.Join("internal", "config", "database.go"), content)
}

func (g *Generator) generateMongoDBConfig() error {
	content := fmt.Sprintf(`package config

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func NewMongoDatabase() *mongo.Database {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	uri := fmt.Sprintf("mongodb://%s:%s@%s:%s",
		os.Getenv("MONGO_USER"),
		os.Getenv("MONGO_PASSWORD"),
		os.Getenv("MONGO_HOST"),
		os.Getenv("MONGO_PORT"),
	)

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		log.Fatal("failed to connect to MongoDB:", err)
	}

	// Ping the database
	if err := client.Ping(ctx, nil); err != nil {
		log.Fatal("failed to ping MongoDB:", err)
	}

	return client.Database(os.Getenv("MONGO_DB_NAME"))
}`)

	return g.writeFile(filepath.Join("internal", "config", "mongodb.go"), content)
}

func (g *Generator) generateMongoTodoRepository() error {
	content := fmt.Sprintf(`package repository

import (
	"context"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"%s/internal/domain"
)

type TodoRepository struct {
	collection *mongo.Collection
}

func NewTodoRepository(db *mongo.Database) *TodoRepository {
	return &TodoRepository{
		collection: db.Collection("todos"),
	}
}

func (r *TodoRepository) Create(ctx context.Context, input domain.CreateTodoInput) (*domain.Todo, error) {
	todo := &domain.Todo{
		Title:       input.Title,
		Description: input.Description,
		Completed:   false,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	result, err := r.collection.InsertOne(ctx, todo)
	if err != nil {
		return nil, err
	}

	todo.ID = result.InsertedID.(primitive.ObjectID).Hex()
	return todo, nil
}

func (r *TodoRepository) GetByID(ctx context.Context, id string) (*domain.Todo, error) {
	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return nil, err
	}

	var todo domain.Todo
	err = r.collection.FindOne(ctx, bson.M{"_id": objectID}).Decode(&todo)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, domain.ErrTodoNotFound
		}
		return nil, err
	}

	return &todo, nil
}

func (r *TodoRepository) List(ctx context.Context) ([]domain.Todo, error) {
	cursor, err := r.collection.Find(ctx, bson.M{})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var todos []domain.Todo
	if err := cursor.All(ctx, &todos); err != nil {
		return nil, err
	}

	return todos, nil
}

func (r *TodoRepository) Update(ctx context.Context, id string, input domain.UpdateTodoInput) (*domain.Todo, error) {
	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return nil, err
	}

	update := bson.M{
		"$set": bson.M{
			"updated_at": time.Now(),
		},
	}

	if input.Title != nil {
		update["$set"].(bson.M)["title"] = *input.Title
	}
	if input.Description != nil {
		update["$set"].(bson.M)["description"] = *input.Description
	}
	if input.Completed != nil {
		update["$set"].(bson.M)["completed"] = *input.Completed
	}

	result := r.collection.FindOneAndUpdate(
		ctx,
		bson.M{"_id": objectID},
		update,
		options.FindOneAndUpdate().SetReturnDocument(options.After),
	)

	var todo domain.Todo
	if err := result.Decode(&todo); err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, domain.ErrTodoNotFound
		}
		return nil, err
	}

	return &todo, nil
}

func (r *TodoRepository) Delete(ctx context.Context, id string) error {
	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return err
	}

	result, err := r.collection.DeleteOne(ctx, bson.M{"_id": objectID})
	if err != nil {
		return err
	}

	if result.DeletedCount == 0 {
		return domain.ErrTodoNotFound
	}

	return nil
}`, g.config.ModulePath)

	return g.writeFile(filepath.Join("internal", "repository", "todo_mongodb.go"), content)
}

func (g *Generator) generateCommonMiddleware() error {
	// Generate logging middleware
	loggingMiddleware := fmt.Sprintf(`package middleware

import (
	"log"
	"net/http"
	"time"
)

func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Create a custom response writer to capture the status code
		rw := &responseWriter{
			ResponseWriter: w,
			statusCode:    http.StatusOK,
		}

		next.ServeHTTP(rw, r)

		duration := time.Since(start)

		log.Printf(
			"[%%s] %%s %%s - Status: %%d - Duration: %%v",
			r.Method,
			r.RequestURI,
			r.RemoteAddr,
			rw.statusCode,
			duration,
		)
	})
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}`)

	if err := g.writeFile(filepath.Join("internal", "api", "middleware", "logging.go"), loggingMiddleware); err != nil {
		return err
	}

	// Generate CORS middleware
	corsMiddleware := fmt.Sprintf(`package middleware

import (
	"net/http"
)

func CORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Authorization, Content-Type")
		w.Header().Set("Access-Control-Max-Age", "300")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}`)

	if err := g.writeFile(filepath.Join("internal", "api", "middleware", "cors.go"), corsMiddleware); err != nil {
		return err
	}

	// Generate rate limiting middleware
	rateLimitMiddleware := fmt.Sprintf(`package middleware

import (
	"net/http"
	"sync"
	"time"
)

type RateLimiter struct {
	requests map[string][]time.Time
	mu       sync.Mutex
	limit    int
	window   time.Duration
}

func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		requests: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
	}
}

func (rl *RateLimiter) RateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr

		rl.mu.Lock()
		now := time.Now()
		
		// Remove old requests
		var recent []time.Time
		for _, t := range rl.requests[ip] {
			if now.Sub(t) <= rl.window {
				recent = append(recent, t)
			}
		}
		rl.requests[ip] = recent

		// Check if limit is exceeded
		if len(recent) >= rl.limit {
			rl.mu.Unlock()
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		// Add current request
		rl.requests[ip] = append(rl.requests[ip], now)
		rl.mu.Unlock()

		next.ServeHTTP(w, r)
	})
}`)

	if err := g.writeFile(filepath.Join("internal", "api", "middleware", "rate_limit.go"), rateLimitMiddleware); err != nil {
		return err
	}

	// Generate recovery middleware
	recoveryMiddleware := fmt.Sprintf(`package middleware

import (
	"log"
	"net/http"
	"runtime/debug"
)

func RecoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Printf("panic: %%v\n\n%%s", err, debug.Stack())
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()

		next.ServeHTTP(w, r)
	})
}`)

	return g.writeFile(filepath.Join("internal", "api", "middleware", "recovery.go"), recoveryMiddleware)
}

func (g *Generator) generateRedisFiles() error {
	// Generate Redis config
	redisConfig := fmt.Sprintf(`package config

import (
	"context"
	"fmt"
	"os"

	"github.com/redis/go-redis/v9"
)

func NewRedisClient() *redis.Client {
	client := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%s", os.Getenv("REDIS_HOST"), os.Getenv("REDIS_PORT")),
		Password: os.Getenv("REDIS_PASSWORD"),
		DB:       0,
	})

	// Test the connection
	ctx := context.Background()
	if err := client.Ping(ctx).Err(); err != nil {
		panic(fmt.Sprintf("Failed to connect to Redis: %v", err))
	}

	return client
}`)

	if err := g.writeFile(filepath.Join("internal", "config", "redis.go"), redisConfig); err != nil {
		return err
	}

	// Generate Redis cache service
	redisCacheService := fmt.Sprintf(`package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"%s/internal/domain"
)

type CacheService struct {
	client *redis.Client
}

func NewCacheService(client *redis.Client) *CacheService {
	return &CacheService{
		client: client,
	}
}

func (s *CacheService) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("failed to marshal value: %w", err)
	}

	return s.client.Set(ctx, key, data, expiration).Err()
}

func (s *CacheService) Get(ctx context.Context, key string, dest interface{}) error {
	data, err := s.client.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil
		}
		return fmt.Errorf("failed to get value: %w", err)
	}

	return json.Unmarshal(data, dest)
}

func (s *CacheService) Delete(ctx context.Context, key string) error {
	return s.client.Del(ctx, key).Err()
}

// Example usage with Todo
func (s *CacheService) GetTodo(ctx context.Context, id string) (*domain.Todo, error) {
	var todo domain.Todo
	key := fmt.Sprintf("todo:%s", id)
	
	err := s.Get(ctx, key, &todo)
	if err != nil {
		return nil, err
	}

	if todo.ID == "" {
		return nil, nil
	}

	return &todo, nil
}

func (s *CacheService) SetTodo(ctx context.Context, todo *domain.Todo) error {
	key := fmt.Sprintf("todo:%s", todo.ID)
	return s.Set(ctx, key, todo, 24*time.Hour)
}

func (s *CacheService) DeleteTodo(ctx context.Context, id string) error {
	key := fmt.Sprintf("todo:%s", id)
	return s.Delete(ctx, key)
}

// Example of caching all todos
func (s *CacheService) GetAllTodos(ctx context.Context) ([]domain.Todo, error) {
	var todos []domain.Todo
	err := s.Get(ctx, "todos:all", &todos)
	if err != nil {
		return nil, err
	}
	return todos, nil
}

func (s *CacheService) SetAllTodos(ctx context.Context, todos []domain.Todo) error {
	return s.Set(ctx, "todos:all", todos, 1*time.Hour)
}

func (s *CacheService) InvalidateAllTodos(ctx context.Context) error {
	return s.Delete(ctx, "todos:all")
}`, g.config.ModulePath)

	return g.writeFile(filepath.Join("internal", "service", "cache.go"), redisCacheService)
}

// Helper function to write files
func (g *Generator) writeFile(path string, content string) error {
	fullPath := filepath.Join(g.config.Name, path)
	err := os.MkdirAll(filepath.Dir(fullPath), 0755)
	if err != nil {
		return fmt.Errorf("error creating directory for %s: %v", path, err)
	}

	err = os.WriteFile(fullPath, []byte(content), 0644)
	if err != nil {
		return fmt.Errorf("error writing file %s: %v", path, err)
	}

	return nil
} 