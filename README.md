# InvestigateR 🔍

**A powerful threat intelligence and analysis tool for SOC analysts**

<img width="1262" height="538" alt="image" src="https://github.com/user-attachments/assets/8892ac4e-020f-4b22-866c-6b6b7aea97ee" />

InvestigateR is an automated analysis tool that enables SOC analysts to quickly gather comprehensive information about IP addresses, domains, URLs, and file hashes. By querying multiple threat intelligence sources in parallel, the tool saves time and increases the effectiveness of security investigations.

## 🎯 Target Audience

This tool is specifically designed for:
- **SOC Analysts** - Quick triage and threat intelligence gathering
- **Security Researchers** - Comprehensive analysis of suspicious observables
- **Incident Responders** - Gathering context during incident response
- **Threat Hunters** - Proactive investigation of potential threats

## ✨ Key Features

- **Parallel Queries** - All selected tools are queried simultaneously for maximum speed
- **Real-time Streaming** - Results appear instantly during investigation (Server-Sent Events)
- **20+ Enrichment Utils** - Integration with leading TI platforms and databases
- **Auto-resolution** - Automatic DNS resolution of domains to IP addresses
- **Flexible Input** - Supports IP addresses, domains, URLs, and file hashes
- **Save/Load Results** - Export and load investigations in JSON format with timestamps
- **Modular Architecture** - Easily add new tools via the module system
- **Dark Mode UI** - Modern, user-friendly interface
- **Hide Safe Results** - Automatically filter "safe" results for faster triage

## ⚠️ Disclaimer

InvestigateR is intended solely for legitimate security research, SOC operations, threat hunting, and incident response. You must only use this tool on systems, networks, and data for which you have explicit permission. Unauthorized use of this tool is strictly prohibited. The authors assume no liability for misuse or damage resulting from improper use.

## 🛠️ Available Tools

### Free Tools (No API Key Required)
- **SANS Internet Storm Center** - Threat intelligence feeds for IP addresses
- **PhishTank** - Phishing URL database
- **OpenPhish** - Phishing feed
- **IP Blocklists** - 33+ IP blocklist checks
- **Domain Blocklists** - 31+ domain blocklist checks
- **DNS Records** - Complete DNS lookup (A, AAAA, MX, TXT, NS, SOA, SPF)
- **WHOIS** - Domain registration information
- **Reverse DNS** - PTR record lookup
- **crt.sh** - SSL/TLS certificate history
- **Wayback Machine** - Historical website snapshots
- **Shodan InternetDB** - Open ports and vulnerabilities
- **URLScan Search** - Search URLScan.io database

### Tools with API Key Required
- **AbuseIPDB** - IP reputation and abuse reports
- **VirusTotal** - Multi-engine malware scanning
- **IPInfo** - Geographic and ASN information
- **URLScan.io** - URL scanning and screenshot analysis
- **OpenCTI** - Threat intelligence platform integration
- **AlienVault OTX** - Open Threat Exchange with pulse information
- **Google Safe Browsing** - Malware and phishing detection
- **URLQuery** - URL threat intelligence database
- **MalwareBazaar** - Malware hash database
- **ThreatFox** - IOC database from Abuse.ch
- **URLHaus** - Malware URL database
- **Hybrid Analysis** - Sandbox analysis check if listed

### Tools with Optional API Key
- **GreyNoise** - Internet scanning and botnet detection (works without API key, enhanced with key)

## 📦 Installation

### Option 1: Docker Compose (Recommended)

The easiest way to run InvestigateR is using Docker Compose:

```bash
# Clone the repository
git clone <repository-url>
cd InvestigateR

# Start the application
docker-compose up -d

# View logs
docker-compose logs -f

# Stop the application
docker-compose down
```

The application will be available at `http://localhost:5000`

**Note:** API keys are stored in a Docker named volume (persists across container updates). Configure them through the web interface after starting.

**Performance Note:** Named volumes can be slower on Windows. If you experience performance issues, you can use a bind mount instead by uncommenting the volume line in `docker-compose.yml` and creating `api_keys.json` on your host first.

### Option 2: Docker (Manual)

#### From GitHub Container Registry (GHCR)

```bash
# Pull the latest version
docker pull ghcr.io/robinzor/investigater:latest

# Run the container (accessible from all interfaces)
docker run -d \
  -p 5000:5000 \
  --name InvestigateR \
  ghcr.io/robinzor/investigater:latest

# Run with localhost-only binding (more secure)
docker run -d \
  -p 127.0.0.1:5000:5000 \
  -e BIND_HOST=127.0.0.1 \
  --name InvestigateR \
  ghcr.io/robinzor/investigater:latest
```

#### Local Build

```bash
# Clone the repository
git clone <repository-url>
cd InvestigateR

# Build the Docker image
docker build -t InvestigateR:latest .

# Run the container
docker run -d \
  -p 5000:5000 \
  --name InvestigateR \
  InvestigateR:latest
```

### Option 3: Local Installation

#### Requirements
- Python 3.11 or higher
- pip

#### Steps

```bash
# Clone the repository
git clone <repository-url>
cd InvestigateR

# Install dependencies
pip install -r requirements.txt

# Start the application
python app.py
```

The application is now available at `http://localhost:5000`

## ⚙️ Configuration

### Setting Up API Keys

1. Open the application in your browser
2. Click **Settings** in the top right corner
3. Enter API keys for the tools you want to use
4. Click **Save Settings**

**Note:** Some tools work without an API key, but with limited functionality or rate limits.

### API Keys Storage

API keys are stored automatically by the application:

- **Docker**: Keys are stored in a named volume at `/app/data/api_keys.json` (persists across container updates)
- **Local Installation**: Keys are stored in `api_keys.json` in the project root directory

The application automatically creates the file with default structure when you first save API keys through the web interface.

**Alternative (Local Installation Only):** You can also manually create the `api_keys.json` file in the project root:

```json
{
  "abuseipdb": "your-api-key-here",
  "virustotal": "your-api-key-here",
  "ipinfo": "your-api-key-here",
  "urlscan": "your-api-key-here",
  "greynoise": "your-api-key-here",
  "opencti": "your-api-key-here",
  "opencti_url": "https://your-opencti-instance.com"
}
```

## 🚀 Usage

### Basic Workflow

1. **Open the Application** - Navigate to `http://localhost:5000`

2. **Enter Observables** - Paste IP addresses, domains, URLs, or file hashes (one per line) in the text field

3. **Select Tools** - Choose the threat intelligence tools you want to use:
   - **Free Tools** - Work without API key
   - **API Key Required** - Require a valid API key
   - **Optional API Key** - Work without, but with more features with key

4. **Start Investigation** - Click **Submit** to start the investigation

5. **View Results** - Results appear in real-time in cards:
   - Each observable gets its own card
   - Tool results are grouped per observable
   - Risk scores are visually displayed

6. **Export Results** - Click **Save Results** to save the investigation as JSON

7. **Load Previous Investigations** - Use **Load Results** to load a previously saved investigation

### Advanced Features

#### Auto-Resolution
- **Auto-resolve Domain to IP** - Automatically fetch IP addresses from domains
- **Auto-resolve URL to Domain** - Extract domains from URLs
- **Auto-resolve URL IP** - Extract IP addresses from URLs

These options are enabled by default and can be adjusted in the processing options.

#### Hide Safe Results
Enable this option to automatically hide "safe" results:
- No detections in VirusTotal
- Not found in threat databases
- No risk indicators

This significantly speeds up triage.

#### Save/Load Results
- **Save Results** - Save the current investigation as JSON with timestamp
- **Load Results** - Load a previously saved investigation
- Results are saved with timestamps for clarity

## 🏗️ Architecture

InvestigateR uses a modular architecture where each threat intelligence tool is a standalone module:

```
utils/modules/
├── base.py              # Base class for all modules
├── interfaces.py        # Interfaces for decoupling
├── abuseipdb/          # AbuseIPDB module
│   ├── __init__.py     # Module configuration
│   ├── query.py        # API query logic
│   └── normalizer.py   # Output normalization
└── [other tools]/      # Other modules follow the same pattern
```

### Module System

Each module consists of 3 files:
1. **`__init__.py`** - Module class with configuration (name, input types, API key requirements)
2. **`query.py`** - Async API query logic
3. **`normalizer.py`** - Output normalization to standard format

New tools can be easily added by creating a new module directory.

## 🔄 CI/CD

The application has automatic CI/CD via GitHub Actions:

- **Automatic Builds** - On every push to `main`/`master`
- **Docker Images** - Automatically built and pushed to GitHub Container Registry (GHCR)
- **Tags** - Version tags are automatically built and pushed
- **Multi-arch** - Supports different platforms

### Workflow

1. Push to `main`/`master` → Build and push `:latest` tag
2. Push a tag (e.g., `v1.0.0`) → Build and push version tag
3. Images are available at `ghcr.io/robinzor/investigater`

## 📊 Results Display

Results are displayed in card format:

### Cards View
- Visual cards per observable
- Tool results grouped per observable
- Color-coded risk scores
- Direct links to external reports

## 🔒 Security Considerations

- **API Keys** - API keys are stored securely:
  - **Docker**: Stored in named volume (not accessible from host filesystem)
  - **Local**: Keep `api_keys.json` secure and ensure it's in `.gitignore`
- **Network** - The application makes outbound connections to external APIs
- **Data** - Results may contain sensitive information - store securely
- **Rate Limits** - Respect rate limits of external APIs

## 🤝 Contributing

Contributions are welcome! For adding new tools, see `utils/modules/README.md` for the module structure.

## 📝 License

MIT License

Copyright (c) 2025 Robinzor

See [LICENSE](LICENSE) file for details.

## 🙏 Credits

InvestigateR integrates with the following threat intelligence platforms and services:
- AbuseIPDB, VirusTotal, IPInfo, GreyNoise, URLScan.io
- AlienVault OTX, Abuse.ch, PhishTank, OpenPhish
- SANS Internet Storm Center, Shodan, MalwareBazaar
- And many others...

Thanks to all providers for their open APIs and threat intelligence feeds!

---

**Developed for SOC analysts🛡️**
