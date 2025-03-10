# Go Project Generator

A powerful and flexible Go project generator for creating production-ready web applications with clean architecture.

## Features

- Clean Architecture with proper separation of concerns
- Multiple Router Options:
  - Chi (lightweight and fast)
  - Standard library net/http
  - Gin (feature-rich web framework)
  - Echo (high performance)
- Database Options:
  - PostgreSQL with SQLC (type-safe SQL)
  - PostgreSQL with GORM (full-featured ORM)
  - MongoDB (using official Go driver)
- Optional Features:
  - JWT Authentication
  - Redis Caching
  - WebSocket Support
  - Swagger Documentation
  - Test Files
- Docker and Docker Compose setup
- Live Reloading with Air
- Makefile for common operations
- Environment configuration
- Structured logging
- Middleware examples
- Error handling
- Clean project layout

## Installation

```bash
go install github.com/Just-a-NoobieDev/go-generator@latest
```

## Usage

### Command-Line Interface

```bash
go-generator [flags]
go-generator [command]
```

### Available Commands

- `help` - Show help for go-generator
- `version` - Show go-generator version

### Flags

```
-n, --name string      Project name
-r, --router string    Router type (chi, std, gin, echo)
-d, --database string  Database type (sqlc, gorm, mongodb)
-i, --interactive     Interactive mode
    --ws              Include WebSocket support
    --jwt             Include JWT authentication
    --redis           Include Redis support
    --swagger         Include Swagger documentation
    --tests           Include test files
```

### Examples

```bash
# Create a new project with Chi router and SQLC
go-generator -n myapp -r chi -d sqlc

# Create a new project with Gin, GORM, and additional features
go-generator -n myapp -r gin -d gorm --jwt --redis --swagger

# Interactive mode
go-generator -i

# Show help
go-generator help

# Show version
go-generator version
```

## Project Structure

```
.
├── cmd/
│   └── server/          # Application entry points
├── internal/
│   ├── api/            # API layer
│   │   ├── handlers/   # Request handlers
│   │   ├── middleware/ # HTTP middleware
│   │   └── routes/     # Route definitions
│   ├── config/         # Configuration
│   ├── db/            # Database layer
│   │   ├── migrations/ # Database migrations
│   │   ├── queries/    # SQL queries (SQLC)
│   │   └── sqlc/      # Generated SQLC code
│   ├── domain/        # Domain models
│   ├── repository/    # Data access layer
│   └── service/       # Business logic
├── pkg/               # Public packages
│   └── utils/         # Shared utilities
└── scripts/          # Development scripts
```

## Prerequisites

- Go 1.22 or higher
- Docker and Docker Compose
- Make

## Getting Started

1. Generate a new project:

   ```bash
   # Using flags
   go-generator -n myapp -r chi -d sqlc --jwt --redis

   # Or using interactive mode
   go-generator -i
   ```

2. Navigate to your project:

   ```bash
   cd myapp
   ```

3. Install required tools:

   ```bash
   make install-tools
   ```

4. Start the development environment:

   ```bash
   make docker-up
   ```

5. Run database migrations:

   ```bash
   make migrate-up
   ```

6. Start the application with live reload:
   ```bash
   make dev
   ```

## Available Make Commands

- `make build` - Build the application
- `make run` - Run the application
- `make test` - Run tests
- `make docker-build` - Build Docker images
- `make docker-up` - Start Docker containers
- `make docker-down` - Stop Docker containers
- `make migrate-up` - Run database migrations
- `make migrate-down` - Rollback database migrations
- `make dev` - Run with live reload
- `make sqlc` - Generate SQLC code
- `make install-tools` - Install required development tools

## Generated API Example

The generator creates a complete Todo API with the following endpoints:

```
POST   /api/v1/todos     # Create a new todo
GET    /api/v1/todos     # List all todos
GET    /api/v1/todos/:id # Get a specific todo
PUT    /api/v1/todos/:id # Update a todo
DELETE /api/v1/todos/:id # Delete a todo
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
