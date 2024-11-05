import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { URL } from 'url';
import net from 'net';
import dns from 'dns';
import { promisify } from 'util';
import fetch from 'node-fetch';
import { spawn } from 'child_process';
import path from 'path';
import { fileURLToPath } from 'url';
import sharp from 'sharp';
import { existsSync } from 'fs';
import Redis from 'ioredis';
import { Address4, Address6 } from 'ip-address';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const dnsLookup = promisify(dns.lookup);
const app = express();
const port = process.env.PORT || 3000;

// After other constants:
const REDIS_URL = process.env.REDIS_URL || 'redis://localhost:6379';
const CACHE_TTL = 60 * 60 * 24; // 24 hours in seconds
const CACHE_TTL_ERROR = 60; // 1 min

// Add with other constants
const RATE_LIMIT = 60; // requests per window
const RATE_WINDOW = 60; // seconds
const CF_IPV4_URL = 'https://www.cloudflare.com/ips-v4';
const CF_IPV6_URL = 'https://www.cloudflare.com/ips-v6';

// Add this configuration setup
let cfRanges = [];

// Basic security headers with helmet
app.use(helmet());

// Remove X-Powered-By header
app.disable('x-powered-by');

// Enable CORS for all routes
app.use(cors());

// Constants
const MAX_BODY_SIZE = 1024 * 1024; // 1MB
const TIMEOUT_MS = 10000; // 10 seconds
const SVG_HUSH_PATH = path.join(__dirname, 'bin', 'svg-hush', 'target', 'release', 'svg-hush');
// Constants for image dimensions
const DEFAULT_SIZE = 1024;
const MIN_SIZE = 32;
const MAX_SIZE = 4096;

// Initialize Redis client
const redis = new Redis(REDIS_URL, {
  maxRetriesPerRequest: 3,
  enableOfflineQueue: false
});

redis.on('error', (err) => console.error('Redis error:', err));
redis.on('connect', () => console.log('Redis connected'));

// Replace the Cloudflare IP handling code
class IPRange {
  constructor(cidr) {
    if (cidr.includes(':')) {
      // IPv6
      this.address = new Address6(cidr);
      this.isV6 = true;
    } else {
      // IPv4
      this.address = new Address4(cidr);
      this.isV6 = false;
    }
  }

  contains(ip) {
    try {
      const testAddress = ip.includes(':') ? new Address6(ip) : new Address4(ip);
      return testAddress.isInSubnet(this.address);
    } catch (error) {
      console.error(`Invalid IP address: ${ip}`);
      return false;
    }
  }
}

async function loadCloudflareRanges() {
  try {
    const [ipv4Response, ipv6Response] = await Promise.all([
      fetch(CF_IPV4_URL),
      fetch(CF_IPV6_URL)
    ]);

    const [ipv4Text, ipv6Text] = await Promise.all([
      ipv4Response.text(),
      ipv6Response.text()
    ]);

    // Combine and parse all ranges
    const ranges = [...ipv4Text.split('\n'), ...ipv6Text.split('\n')]
      .filter(ip => ip.trim())
      .map(ip => new IPRange(ip.trim()));

    cfRanges = ranges;
    console.log(`Loaded ${cfRanges.length} Cloudflare IP ranges`);
  } catch (error) {
    console.error('Failed to load Cloudflare IP ranges:', error);
    process.exit(1);
  }
}

// The rest of the code remains the same
function isCloudflareIP(ip) {
  return cfRanges.some(range => range.contains(ip));
}

function getClientIP(req) {
  const socketIP = req.socket.remoteAddress;
  
  // If the connection is direct (not through Cloudflare)
  if (!isCloudflareIP(socketIP)) {
    return socketIP;
  }

  // If it's through Cloudflare, use CF-Connecting-IP
  const cfIP = req.headers['cf-connecting-ip'];
  if (cfIP) {
    return cfIP;
  }

  // Fallback to X-Forwarded-For only from Cloudflare
  const forwardedFor = req.headers['x-forwarded-for'];
  if (forwardedFor) {
    // Get the original client IP (first in the chain)
    return forwardedFor.split(',')[0].trim();
  }

  return socketIP;
}

// Rate limiting function
async function checkRateLimit(ip) {
  const key = `ratelimit:${ip}`;
  const multi = redis.multi();
  
  // Increment the counter
  multi.incr(key);
  // Set expiry if not exists
  multi.expire(key, RATE_WINDOW);
  // Get current value
  multi.get(key);
  
  const [, , count] = await multi.exec();
  const currentCount = parseInt(count[1], 10);
  
  return currentCount <= RATE_LIMIT;
}

// Add to app initialization
await loadCloudflareRanges();

// Refresh Cloudflare IPs periodically (every 24h)
setInterval(loadCloudflareRanges, 24 * 60 * 60 * 1000);

// Add this helper function for cache key generation
function getCacheKey(url, width, height) {
  return `svg:${width}x${height}:${url}`;
}

// Validate and normalize dimension
function validateDimension(size, defaultSize = DEFAULT_SIZE) {
  if (size === undefined) return defaultSize;
  
  const num = parseInt(size, 10);
  if (isNaN(num)) return defaultSize;
  
  return Math.max(MIN_SIZE, Math.min(MAX_SIZE, num));
}

// Validate that the binary exists
if (!existsSync(SVG_HUSH_PATH)) {
  console.error(`svg-hush binary not found at: ${SVG_HUSH_PATH}`);
  console.error('Please ensure the binary is compiled and placed in the correct location');
  process.exit(1);
}

function clientPrefersImage(req) {
  const accept = req.get('accept') || '';
  
  // Check if it's a browser or image-accepting client
  if (accept.includes('image/*') || 
      accept.includes('image/png') ||
      /Mozilla|Chrome|Safari|Edge|Opera/i.test(req.get('user-agent') || '')) {
    return true;
  }
  
  // If explicitly asking for JSON/text, return false
  if (accept.includes('application/json') || 
      accept.includes('text/plain') ||
      accept.includes('text/*')) {
    return false;
  }
  
  // Check if it's curl or similar tools
  const userAgent = req.get('user-agent') || '';
  if (userAgent.includes('curl') || 
      userAgent.includes('wget') || 
      userAgent.includes('HTTPie')) {
    return false;
  }
  
  // Default to image for unknown clients
  return true;
}

// Function to process SVG through svg-hush binary with proper error handling
async function processSvgThroughHush(svgContent) {
  return new Promise((resolve, reject) => {
    console.log(`Spawning svg-hush from: ${SVG_HUSH_PATH}`);
    
    const hushProcess = spawn(SVG_HUSH_PATH, ["-"], {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: process.env
    });
    
    const chunks = [];
    let errorChunks = [];

    hushProcess.stdout.on('data', (data) => {
      chunks.push(data);
    });

    hushProcess.stderr.on('data', (data) => {
      errorChunks.push(data);
      console.error(`svg-hush stderr: ${data}`);
    });

    hushProcess.on('error', (error) => {
      console.error(`Failed to start svg-hush: ${error.message}`);
      reject(new Error(`Failed to start svg-hush: ${error.message}`));
    });

    hushProcess.on('close', (code) => {
      if (code !== 0) {
        const errorMessage = Buffer.concat(errorChunks).toString();
        console.error(`svg-hush failed with code ${code}: ${errorMessage}`);
        reject(new Error(`svg-hush failed with code ${code}: ${errorMessage}`));
        return;
      }
      resolve(Buffer.concat(chunks).toString('utf8'));
    });

    // Handle errors on stdin stream
    hushProcess.stdin.on('error', (error) => {
      if (error.code === 'EPIPE') {
        // EPIPE means the process exited before we finished writing
        return;
      }
      console.error(`stdin error: ${error.message}`);
      reject(new Error(`stdin error: ${error.message}`));
    });

    // Write SVG content to stdin in a try-catch block
    try {
      hushProcess.stdin.write(svgContent);
      hushProcess.stdin.end();
    } catch (error) {
      console.error(`Failed to write to svg-hush: ${error.message}`);
      reject(new Error(`Failed to write to svg-hush: ${error.message}`));
    }
  });
}

// Function to convert SVG to PNG using Sharp
async function convertSvgToPng(svgBuffer, width, height) {
  return await sharp(svgBuffer)
    .resize(width, height, {
      fit: 'contain',        // Maintain aspect ratio
      position: 'center',    // Center the image
      background: { r: 0, g: 0, b: 0, alpha: 0 }  // Transparent background
    })
    .png()
    .toBuffer();
}

// Private IP ranges to block
const PRIVATE_IP_RANGES = [
  ['10.0.0.0', '10.255.255.255'],
  ['172.16.0.0', '172.31.255.255'],
  ['192.168.0.0', '192.168.255.255'],
  ['127.0.0.0', '127.255.255.255'],
  ['169.254.0.0', '169.254.255.255'],
  ['0.0.0.0', '0.255.255.255'],
  ['fc00::', 'fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'],
  ['fe80::', 'febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff'],
  ['::1', '::1'],
];

// Convert IP to numeric value for range checking
function ipToLong(ip) {
  if (net.isIPv4(ip)) {
    return ip.split('.')
      .reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
  }
  // For IPv6, we'll use a simple string comparison
  return ip;
}

// Check if IP is in private range
function isPrivateIP(ip) {
  if (net.isIPv4(ip)) {
    const ipLong = ipToLong(ip);
    return PRIVATE_IP_RANGES.some(([start, end]) => {
      if (net.isIPv4(start)) {
        const startLong = ipToLong(start);
        const endLong = ipToLong(end);
        return ipLong >= startLong && ipLong <= endLong;
      }
      return false;
    });
  } else if (net.isIPv6(ip)) {
    return PRIVATE_IP_RANGES.some(([start, end]) => {
      if (!net.isIPv4(start)) {
        return ip >= start && ip <= end;
      }
      return false;
    });
  }
  return false;
}

// Validate URL and check for private networks
async function validateUrl(urlString) {
  try {
    const url = new URL(urlString);
    
    // Check protocol
    if (!['http:', 'https:'].includes(url.protocol)) {
      throw new Error('Invalid protocol. Only HTTP and HTTPS are allowed.');
    }

    // Resolve domain to IP
    const { address } = await dnsLookup(url.hostname);
    
    // Check if IP is private
    if (isPrivateIP(address)) {
      throw new Error('Access to local network resources is not allowed.');
    }

    return url;
  } catch (error) {
    throw new Error(`URL validation failed: ${error.message}`);
  }
}

// Check if content is SVG
function isSVG(content) {
  // Convert buffer to string if needed
  const str = Buffer.isBuffer(content) ? content.toString('utf8', 0, 1000) : content;
  
  // Look for SVG signature in the first part of the content
  const svgRegex = /<svg[^>]*>/i;
  return svgRegex.test(str.slice(0, 1000));
}

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok' });
});

// Add middleware before your main route
app.use(async (req, res, next) => {
  const clientIP = getClientIP(req);
  
  try {
    const allowed = await checkRateLimit(clientIP);
    if (!allowed) {
      return res.status(429).json({
        error: 'Too Many Requests',
        message: `Rate limit exceeded. Maximum ${RATE_LIMIT} requests per ${RATE_WINDOW} seconds.`
      });
    }
    next();
  } catch (error) {
    console.error('Rate limiting error:', error);
    // On Redis error, allow the request but log it
    next();
  }
});

// Main endpoint that handles the image query parameter
app.get('/rasterize-svg', async (req, res) => {
  const imageQuery = req.query.url;

  // Get and validate dimensions
  const width = validateDimension(req.query.width);
  const height = validateDimension(req.query.height);

  const cacheKey = getCacheKey(imageQuery, width, height);
  
  if (!imageQuery) {
    return res.status(400).json({
      error: 'Missing required query parameter: url'
    });
  }

  // Add dimension validation error messages
  if (req.query.width && (width === DEFAULT_SIZE)) {
    return res.status(400).json({
      error: 'Invalid width parameter',
      message: `Width must be between ${MIN_SIZE} and ${MAX_SIZE} pixels`
    });
  }

  if (req.query.height && (height === DEFAULT_SIZE)) {
    return res.status(400).json({
      error: 'Invalid height parameter',
      message: `Height must be between ${MIN_SIZE} and ${MAX_SIZE} pixels`
    });
  }

  // Try to get from cache first
  try {
    const cached = await redis.getBuffer(cacheKey);
    if (cached) {
      console.log('Cache hit:', cacheKey);
      const cacheStr = cached.toString().trim()
      if (cacheStr.slice(0, 1) === '{' && cacheStr.slice(-1) === '}') {
        return res.json({ ...JSON.parse(cacheStr), cached: true, })
      }
      if (clientPrefersImage(req)) {
        res.set('Content-Type', 'image/png');
        res.set('Content-Disposition', 'inline; filename="image.png"');
        return res.send(cached);
      } else {
        return res.json({
          success: true,
          format: 'png',
          size: cached.length,
          width: width,
          height: height,
          contentType: 'image/png',
          data: `data:image/png;base64,${cached.toString('base64')}`,
          cached: true
        });
      }
    }
  } catch (err) {
    console.error('Redis get error:', err);
    // Continue without cache
  }

  try {
    // Validate URL and check for private network access
    const validatedUrl = await validateUrl(imageQuery);

    // Fetch the URL with timeout
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);

    try {
      const response = await fetch(validatedUrl.toString(), {
        signal: controller.signal,
      });

      clearTimeout(timeout);

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      // Check content length header if available
      const contentLength = response.headers.get('content-length');
      if (contentLength && parseInt(contentLength) > MAX_BODY_SIZE) {
        throw new Error('Content too large');
      }

      // Read the response while checking size
      let size = 0;
      const chunks = [];

      // Set up stream handling
      response.body.on('data', (chunk) => {
        size += chunk.length;
        if (size > MAX_BODY_SIZE) {
          response.body.destroy();
          throw new Error('Content too large');
        }
        chunks.push(chunk);
      });

      // Wait for the stream to complete
      await new Promise((resolve, reject) => {
        response.body.on('end', resolve);
        response.body.on('error', reject);
      });

      // Combine chunks and check content
      const content = Buffer.concat(chunks);

      // Check if content is SVG
      if (!isSVG(content)) {
        // throw new Error('Content is not a valid SVG');
        console.log(`Not a valid SVG, redirecting to: ${validatedUrl.toString()}`);
        return res.redirect(301, validatedUrl.toString());
      }

      // Process SVG through svg-hush
      const processedSvg = await processSvgThroughHush(content.toString('utf8'));
      
      // Convert processed SVG to PNG
      const pngBuffer = await convertSvgToPng(Buffer.from(processedSvg), width, height);

      // After successful PNG generation (right after convertSvgToPng), add:
      try {
        await redis.set(cacheKey, pngBuffer, 'EX', CACHE_TTL);
      } catch (err) {
        console.error('Redis set error:', err);
        // Continue without caching
      }

      // // Set appropriate headers and send PNG
      // res.set('Content-Type', 'image/png');
      // res.send(pngBuffer);

      // Determine response format based on client
      if (clientPrefersImage(req)) {
        // Send direct image response
        res.set('Content-Type', 'image/png');
        res.set('Content-Disposition', 'inline; filename="image.png"');
        res.send(pngBuffer);
      } else {
        // Send JSON response with base64 image
        res.json({
          success: true,
          format: 'png',
          size: pngBuffer.length,
          width: 1024,
          height: 1024,
          contentType: 'image/png',
          data: `data:image/png;base64,${pngBuffer.toString('base64')}`
        });
      }
    } catch (error) {
      if (error.name === 'AbortError') {
        throw new Error('Request timed out');
      }
      throw error;
    } finally {
      clearTimeout(timeout);
    }

  } catch (error) {
    const err = {
      error: 'Validation failed',
      message: error.message
    }

    try {
      await redis.set(cacheKey, JSON.stringify(err), 'EX', CACHE_TTL_ERROR);
    } catch (err) {
      console.error('Redis set error:', err);
      // Continue without caching
    }

    res.status(400).json(err);
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    error: 'Something broke!',
    message: err.message
  });
});

// 404 handler for undefined routes
app.use((req, res) => {
  res.status(404).json({
    error: 'Not Found',
    message: 'The requested resource does not exist'
  });
});

// Start the server
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});

// For graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received. Shutting down gracefully...');
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
});
