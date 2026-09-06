# IOC Radar backend

This server keeps VirusTotal, AbuseIPDB, and urlscan.io API keys outside the Chrome extension.

## Local setup

Use Node.js 18 or newer. Set the environment variables before starting the server:

```powershell
$env:VIRUSTOTAL_API_KEY = 'server-only-key'
$env:ABUSEIPDB_API_KEY = 'server-only-key'
$env:URLSCAN_API_KEY = 'server-only-key'
$env:PORT = '8787'
node .\server\index.js
```

The extension calls `http://localhost:8787/scan` during local development.

Health check:

```powershell
Invoke-RestMethod http://localhost:8787/health
```

Scan test:

```powershell
Invoke-RestMethod -Uri http://localhost:8787/scan -Method Post -ContentType 'application/json' -Body '{"type":"domain","value":"example.com"}'
```

For production, deploy this server behind HTTPS, set `ALLOWED_ORIGIN` to the extension origin or deployment policy, and change `BACKEND_URL` in `js/popup.js` plus the matching `host_permissions` entry in `manifest.json`.

Never commit real API keys or a `.env` file.
