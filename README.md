# Go Project Generator

A powerful and flexible Go project generator that creates production-ready web applications with clean architecture. Currently supports monolithic architecture only (microservices support planned for future releases).

## Installation

```bash
go install github.com/Just-a-NoobieDev/go-generator@latest
```

## Features

### Architecture

- Clean Monolithic Architecture
- Clear Separation of Concerns
- Production-Ready Structure

### Router Options

- Chi Router (lightweight and fast)
- Standard library net/http
- Gin (feature-rich web framework)
- Echo (high performance, minimalist)

### Database Options

- PostgreSQL with SQLC (type-safe SQL)
- PostgreSQL with GORM (full-featured ORM)
- MongoDB (using official Go driver)

### Optional Features

- JWT Authentication
- Redis Caching
- WebSocket Support
- Swagger Documentation
- Integration and Unit Tests
- Docker and Docker Compose
- Live Reloading with Air
- Graceful Shutdown
- Structured Logging
- CORS Middleware
- Rate Limiting
- Panic Recovery

## Project Structure

The generator creates a monolithic application structure that follows clean architecture principles:

```
.
├── cmd/
│   └── server/          # Application entry points
├── internal/
│   ├── api/            # API layer
│   │   ├── handlers/   # Request handlers
│   │   ├── middleware/ # HTTP middleware
│   │   ├── routes/     # Route definitions
│   │   └── types/      # Request/Response types
│   ├── config/         # Configuration
│   ├── db/            # Database layer
│   │   ├── migrations/ # Database migrations
│   │   ├── queries/    # SQL queries (SQLC)
│   │   └── sqlc/      # Generated SQLC code
│   ├── domain/        # Domain models and interfaces
│   ├── repository/    # Data access layer
│   └── service/       # Business logic
├── pkg/
│   └── utils/         # Shared utilities
└── tests/            # Test suites
    ├── integration/  # Integration tests
    └── unit/        # Unit tests
```

## Prerequisites

- Go 1.22 or higher
- Docker and Docker Compose
- Make

## Example Usage

```bash
# Install the generator
go install github.com/Just-a-NoobieDev/go-generator@latest

# Create a new project
go-generator new myapp \
  --router chi \
  --database sqlc \
  --include-jwt \
  --include-redis \
  --include-websocket \
  --include-swagger \
  --include-tests
```

## Generated API Example

The generator includes a complete Todo API example that demonstrates:

1. RESTful endpoints:

   - POST /api/v1/todos - Create a todo
   - GET /api/v1/todos - List all todos
   - GET /api/v1/todos/:id - Get a todo by ID
   - PUT /api/v1/todos/:id - Update a todo
   - DELETE /api/v1/todos/:id - Delete a todo

2. Database operations with your chosen database:

   - SQLC with type-safe queries
   - GORM with auto-migrations
   - MongoDB with proper indexing

3. Optional features:
   - JWT authentication middleware
   - Redis caching for improved performance
   - WebSocket for real-time updates
   - Swagger documentation
   - Integration tests

## Getting Started

1. Clone the repository
2. Run 'make install-tools' to install required tools
3. Copy '.env.example' to '.env' and update the values
4. Run 'make docker-up' to start the services
5. Run 'make migrate-up' to run database migrations
6. Run 'make dev' to start the development server

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
- make swagger: Generate Swagger documentation

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

MIT

## Roadmap

- [ ] Microservices architecture support
- [ ] gRPC support
- [ ] Event-driven architecture patterns
- [ ] Kubernetes deployment templates
- [ ] GraphQL API support
- [ ] More database options

## Notes

This generator currently focuses on monolithic architecture, which is suitable for most small to medium-sized applications. If you need microservices architecture, please check the roadmap for upcoming features.
