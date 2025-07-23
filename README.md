# UCAN KMS (UCAN Key Management Service)

A UCAN-powered Key Management Service for managing encryption keys with fine-grained access control.

## Features

- Secure key management with Google KMS integration
- UCAN-based authorization for fine-grained access control
- Comprehensive audit logging for all security-sensitive operations
- Rate limiting and abuse protection
- Built-in observability with Cloudflare Workers Logs

## Prerequisites

- Node.js 18+
- pnpm 8+
- Cloudflare Workers CLI (`wrangler`)
- Google Cloud KMS access (for production)

## Installation

```bash
# Clone the repository
git clone https://github.com/storacha/ucan-kms.git
cd ucan-kms

# Install dependencies
pnpm install

# Set up environment variables
cp .env.example .env
# Edit .env with your configuration
```

## Configuration

Copy `.env.example` to `.env` and configure the following environment variables:

```env
# Required for production
UCAN_KMS_PRINCIPAL_KEY=your-principal-key
UCAN_KMS_SERVICE_DID=did:web:your-service.example.com

# Google KMS Configuration
GOOGLE_KMS_BASE_URL=https://cloudkms.googleapis.com/v1
GOOGLE_KMS_PROJECT_ID=your-project-id
GOOGLE_KMS_LOCATION=global
GOOGLE_KMS_KEYRING_NAME=your-keyring-name
GOOGLE_KMS_TOKEN=your-service-account-token

# Feature Flags
FF_DECRYPTION_ENABLED=true
FF_KMS_RATE_LIMITER_ENABLED=true

# Deployment
ENVIRONMENT=development
```

## Development

```bash
# Start development server
pnpm dev

# Run tests
pnpm test

# Run tests with coverage
pnpm test:coverage

# Lint code
pnpm lint

# Format code
pnpm format
```

## Testing

This project uses Mocha for testing with Chai assertions and Sinon for mocks. Test files follow the naming pattern `*.spec.js`.

```bash
# Run all tests
pnpm test

# Run tests in watch mode
pnpm test:watch

# Generate coverage report
pnpm test:coverage
```

## Audit Logging

UCAN KMS uses Cloudflare Workers Logs for comprehensive audit logging. All security-sensitive operations are automatically logged with structured JSON output.

### Logged Events

- Key management operations (creation, rotation, deletion)
- Key encryption/decryption requests
- Authorization successes and failures
- Rate limit events
- Service initialization and errors

### Accessing Logs

1. **Cloudflare Dashboard**: View logs in the Cloudflare Workers & Pages dashboard under your worker's "Logs" tab
2. **Logpush**: Set up Logpush to export logs to your preferred SIEM or log management system
3. **REST API**: Programmatically access logs using the [Cloudflare Logs API](https://developers.cloudflare.com/logs/)

### Log Retention

- Logs are retained according to your Cloudflare plan:
  - Free: 24 hours
  - Paid: 7 days
  - Enterprise: Custom retention available

For long-term retention, configure Logpush to export logs to your preferred storage solution.

## Deployment

### Prerequisites

1. Set up a Cloudflare Worker
2. Configure required secrets in Cloudflare:
   ```bash
   wrangler secret put UCAN_KMS_PRINCIPAL_KEY
   wrangler secret put GOOGLE_KMS_TOKEN
   # ... other secrets
   ```
3. (Recommended) Set up Logpush for long-term log retention

### Deploying

```bash
# Build and deploy
pnpm deploy
```

## UCAN Invocations API

### Encryption Setup

Sets up encryption for a new space.
TODO

### Key Decryption

Decrypts a symmetric key for a space.
TODO

## Contributing

Contributions are welcome! Please read our [Contributing Guidelines](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## License

This project is dual-licensed under:
- Apache License 2.0
- MIT License

See [LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT) for more details.
