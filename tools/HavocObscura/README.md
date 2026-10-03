# HavocObscura

Havoc C2 Profile Generator - creates customized `.yaotl` profiles that mimic legitimate website traffic.

Based on [PyObscura](https://github.com/dmcxblue/PyObscura) for Cobalt Strike, adapted for Havoc C2.

## Features

- **Auto URI Discovery** - Scrapes target website for realistic URIs
- **Smart Header Selection** - Prioritizes meaningful headers, excludes problematic ones
- **Bot Protection Bypass** - Stealth mode with realistic browser headers
- **OPSEC Spawn Processes** - Randomly selects from known-good injection targets
- **Multiple Listener Support** - HTTP/HTTPS + optional SMB pivot
- **Discord Webhooks** - Optional notifications for agent check-ins
- **External C2 Service** - Configure custom transport endpoints

## Installation

```bash
cd /path/to/Havoc/tools/HavocObscura
pip install -r requirements.txt
```

## Usage

### Auto-discover URIs from target
```bash
python HavocObscura.py \
    --url https://www.microsoft.com \
    --autodiscover \
    --slow \
    --request-speed stealth \
    --outprofile microsoft.yaotl \
    --sleep 30 \
    --jitter 40
```

### Manual URIs (Outlook profile)
```bash
python HavocObscura.py \
    --url https://outlook.office.com \
    --uris "/owa/service.svc /EWS/Exchange.asmx /autodiscover/autodiscover.json" \
    --outprofile outlook.yaotl \
    --sleep 15 \
    --jitter 35
```

### With SMB pivot listener
```bash
python HavocObscura.py \
    --url https://teams.microsoft.com \
    --autodiscover \
    --smb-pipe "msagent_0e" \
    --outprofile teams_pivot.yaotl
```

### Behind a redirector
```bash
python HavocObscura.py \
    --url https://your-legit-site.com \
    --autodiscover \
    --trust-xff \
    --hosts "redirector1.com,redirector2.com" \
    --outprofile redirector.yaotl
```

### HTTP mode (lab/testing only)
```bash
python HavocObscura.py \
    --url https://sharepoint.example.com \
    --autodiscover \
    --http \
    --port 8080 \
    --outprofile lab.yaotl
```

## Options

| Option | Description |
|--------|-------------|
| `--url` | Target URL to mimic (required) |
| `--outprofile` | Output profile filename (required) |
| `--uris` | Space-separated URIs to use |
| `--autodiscover` | Auto-discover URIs from target |
| `--slow` | Use slow request mode (bot bypass) |
| `--request-speed` | Request speed: fast/medium/slow/stealth or custom (e.g., 5 or 3-7) |
| `--sleep` | Sleep time in seconds (default: 10) |
| `--jitter` | Jitter percentage (default: 30) |
| `--http` | Use HTTP instead of HTTPS |
| `--port` | Listener port (default: 443 for HTTPS, 80 for HTTP) |
| `--hosts` | Comma-separated C2 hosts |
| `--operator` | Operator username (default: operator) |
| `--password` | Operator password (default: changeme123) |
| `--trust-xff` | Trust X-Forwarded-For header (for redirectors) |
| `--kill-date` | Kill date (YYYY-MM-DD HH:MM:SS) |
| `--listener-name` | Custom listener name |
| `--smb-pipe` | Add SMB listener with this pipe name |
| `--service-endpoint` | External C2 service endpoint |
| `--service-password` | External C2 service password |
| `--webhook` | Discord webhook URL for notifications |
| `-v, --verbose` | Verbose output |

## Request Speed Presets

| Preset | Delay Range | Use Case |
|--------|-------------|----------|
| `fast` | 0.5-1.5s | Quick testing |
| `medium` | 2-4s | Normal crawling (default) |
| `slow` | 4-8s | Careful crawling |
| `stealth` | 8-15s | Akamai/Cloudflare bypass |

## Testing Generated Profiles

```bash
# Validate syntax
./havoc server --profile output.yaotl -v --debug

# Start teamserver
./havoc server --profile output.yaotl -v
```

## OPSEC Spawn Processes

The generator randomly selects from these known-good spawn targets:
- `RuntimeBroker.exe`
- `SearchProtocolHost.exe`
- `smartscreen.exe` / `WerFault.exe`
- `dllhost.exe`
- `svchost.exe`
- `wmiprvse.exe`

## Version History

### v1.0
- Initial release
- Auto URI discovery from target websites
- Smart header selection
- Bot protection bypass (slow mode)
- SMB pivot listener support
- Discord webhook integration
- External C2 service configuration
