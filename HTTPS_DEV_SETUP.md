# Local HTTPS Development Setup

This project uses **mkcert** to generate local SSL certificates for secure development testing, especially for testing the URL verification module with proper CORS and SSL handling.

## Why HTTPS in Development?

- Test CORS headers correctly
- Simulate production SSL/TLS behavior
- Verify module reachability checks with real SSL certificates
- Test secure endpoint configurations

## Setup Instructions

### 1. Install mkcert

**macOS (Homebrew):**
```bash
brew install mkcert
```

**Windows (Chocolatey):**
```bash
choco install mkcert
```

**Linux (Ubuntu/Debian):**
```bash
sudo apt install libnss3-tools
sudo curl -L https://github.com/FiloSottile/mkcert/releases/download/v1.4.4/mkcert-v1.4.4-linux-amd64 -o /usr/local/bin/mkcert
sudo chmod +x /usr/local/bin/mkcert
```

### 2. Generate Certificates

From the project root:

```bash
# Install mkcert's CA certificate in your system trust store (one-time)
mkcert -install

# Generate certificates for localhost (with SAN: localhost+2)
mkcert localhost+2 127.0.0.1 ::1
```

This creates:
- `localhost+2.pem` (certificate)
- `localhost+2-key.pem` (private key)

### 3. Start Development Server

```bash
npm run dev
```

The dev server will:
- ✅ Use HTTPS if certificates exist
- ⚠️ Fall back to HTTP if certificates are missing
- Listen on `https://localhost:5173`

## Certificate Management

- Certificates are **excluded from Git** (see `.gitignore`)
- Each developer generates their own certificates locally
- No secrets committed to the repository

## Troubleshooting

**Certificates not loading?**
```bash
# Verify certificate files exist in project root
ls -la localhost+2*

# Regenerate if needed
mkcert -install && mkcert localhost+2 127.0.0.1 ::1
```

**CORS errors in browser?**
Check that the module's `verifyUrl` function includes `mode: 'no-cors'` for local testing.

**Untrusted certificate warnings?**
Make sure you ran `mkcert -install` to add the CA to your system trust store.

## References

- [mkcert GitHub](https://github.com/FiloSottile/mkcert)
- [Vite HTTPS Configuration](https://vitejs.dev/config/server-options.html#server-https)
