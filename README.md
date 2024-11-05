 # Return rasterized PNG from sanitized and checked SVG URL

A secure service that fetches, validates, sanitizes and rasterizes SVG files from URLs. Returns PNGs with configurable dimensions. Features caching, rate limiting and protection against common attack vectors.

## Features

- Fetches SVG from provided URL
- Validates URLs and prevents local network access
- Sanitizes SVG using [svg-hush](https://lib.rs/svg-hush)
- Rasterizes to PNG with configurable dimensions
- Redis-based caching (24h for valid SVGs, 60s for errors)
- Rate limiting with Cloudflare IP support
- Automatic redirect for non-SVG URLs
- Responds with direct PNG for browsers or base64 JSON for API clients

## Requirements

- Node.js 18+
- Redis server
- [svg-hush](https://lib.rs/svg-hush) binary in `bin/svg-hush/target/release/svg-hush` (clone, have cargo installed and `cargo build --release`)
- Port 80 access (or configure different port)

## Installation

```bash
# Clone repository
git clone https://github.com/WietseWind/RasterizeSVG-Service
cd RasterizeSVG-Service

# Install dependencies
npm install

# Install PM2 globally
npm install -g pm2

# Create logs directory
mkdir logs

# Start service (requires sudo for port 80)
sudo npm run start:prod
```

## Configuration

Environment variables in `ecosystem.config.json`:
- `PORT`: Server port (default: 80)
- `REDIS_URL`: Redis connection string (default: redis://localhost:6379)

## Usage

### API Endpoint

```
GET /rasterize-svg
```

### Query Parameters

- `image`: (Required) URL of the SVG to process
- `width`: (Optional) Output width in pixels (32-4096, default: 1024)
- `height`: (Optional) Output height in pixels (32-4096, default: 1024)

### Examples

```bash
# Basic usage
curl http://localhost/rasterize-svg?url=https://example.com/image.svg

# Custom dimensions
curl http://localhost/rasterize-svg?url=https://example.com/image.svg&width=800&height=600
```

### Response Types

The service automatically detects the client type and responds appropriately:

#### Browser/Image Client
- Content-Type: image/png
- Direct PNG image response

#### API Client (curl, etc)
```json
{
  "success": true,
  "format": "png",
  "size": 12345,
  "width": 1024,
  "height": 1024,
  "contentType": "image/png",
  "data": "data:image/png;base64,..."
}
```

### Error Handling

- Non-SVG URLs: 301 redirect to original URL
- Invalid URLs: 400 Bad Request with error message
- Rate limit exceeded: 429 Too Many Requests
- Server errors: 500 Internal Server Error

## Rate Limiting

- 60 requests per 60 seconds per IP
- Proper handling of Cloudflare IPs and headers
- Auto-updating Cloudflare IP ranges

## Caching

- Successful SVG conversions: 24 hours
- Errors/redirects: 60 seconds
- Based on URL and requested dimensions

## Service Management

```bash
npm run start:prod  # Start service
npm run stop       # Stop service
npm run restart    # Restart service
npm run logs       # View logs
npm run status     # Check status
npm run monit      # Monitor resources
```

## Security

- URL validation prevents local network access
- SVG sanitization removes potentially harmful content
- Rate limiting prevents abuse
- Cloudflare IP validation ensures proper client IP detection
- Maximum file size limits (1MB)
- Timeouts on all external requests (10s)

## License

MIT

## Contributing

PRs welcome! Please ensure you follow the existing code style and add tests for any new features.
