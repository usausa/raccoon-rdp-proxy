# Raccoon.RdpProxy

A relay proxy that **rewrites the `clientAddress` inside the RDP protocol itself** (`TS_EXTENDED_INFO_PACKET`, in the Client Info PDU) and re-establishes the session against a different host. For targets that require NLA (Network Level Authentication), it authenticates through a **hand-rolled CredSSP credential bridge**. **Verified against a real Windows NLA server.**

- .NET 10 / Worker service (Windows service / systemd daemon)
- Rewrites `clientAddress` / `clientName` / identity fields inside the RDP protocol
- CredSSP credential bridge for NLA-required targets (hand-rolled NTLMv2 + pubKeyAuth + TSCredentials)
- Source-IP restriction (CIDR ACL) and concurrent relaying of multiple targets
- Single binary with no external runtime dependency

## Topology

```
[client]           [relay Linux (this proxy)]                        [target]
192.168.1.10  ──▶  192.168.1.20 : 3389   ┐ terminates self-signed    192.168.2.10:3389
 mstsc (wants NLA) (dual-homed)          │ TLS (client leg=TLS only) (still requires NLA)
                   192.168.2.20 ─────────┘ auth + rewrite via CredSSP ─▶
                   (TCP source & CredSSP)
```

Goal: **make `WTSClientAddress` on `192.168.2.10` become `192.168.2.20`.** → Achieved.

## How it works

The proxy **terminates two TLS sessions** and bridges SSL (client side) ↔ NLA (backend side), while **rewriting three PDUs** along the way.

| Leg | Security | Detail |
|---|---|---|
| **Client leg** (mstsc→relay) | TLS only | mstsc requests NLA, but it is downgraded to SSL and terminated (avoids acting as an NTLM server) |
| **Backend leg** (relay→target) | **NLA (CredSSP)** | Authenticates with **CredSSP** using the configured credentials (hand-rolled NTLMv2 + pubKeyAuth + TSCredentials) |

**The three rewrites during relaying** (to absorb the SSL↔NLA mismatch):

1. **`serverSelectedProtocol`** (client→backend, MCS Connect Initial / CS_CORE): SSL → the backend-selected value (HYBRID).
   Without this the backend detects a downgrade and sends RST.
2. **`clientRequestedProtocols`** (backend→client, MCS Connect Response / SC_CORE): the request the proxy sent → the value mstsc requested.
   Without this mstsc raises an authentication error (0x609).
3. **`clientAddress`** (client→backend, Client Info PDU / TS_EXTENDED_INFO_PACKET): the primary rewrite.

The TCP source is also bound via `Source`, so **both the in-packet clientAddress and the real TCP source** become the specified value.

## Requirements

- The relay host must be able to reach the target, and the IP given in `Source` must actually exist on it (dual-homing recommended)
- The published binary is self-contained, so **no .NET runtime is needed on the relay host**. The .NET 10 SDK is only needed to run from source (`dotnet run`)
- Open the listen port on the relay: `sudo firewall-cmd --add-port=3389/tcp` (depending on the environment, check separate nftables etc. settings too)

## Configuration (appsettings.json)

Settings live under the **`Proxy` section**. **Values directly under the section are the defaults**, and **each element of `Maps[]`** represents one listen-port→target mapping. `Source` / `ClientAddress` / `ClientName` / `MaskClientInfo` / `Credentials` / `Allow` can be **overridden per map** (anything not specified inherits the global default).

| Key | Default | Description |
|---|---|---|
| `Proxy:Listen` | `0.0.0.0` | Listen address |
| `Proxy:Cert` | `proxy.pfx` | Server certificate (PFX). If absent, a 10-year cert is generated on first run |
| `Proxy:CertPassword` | `null` | PFX password |
| `Proxy:Source` | `null` | TCP source bind toward the target (`null` = default route) |
| `Proxy:ClientAddress` | `""` | The clientAddress to write into the RDP packet |
| `Proxy:ClientName` | `null` | Rewrite clientName (`""` for an empty name, `null` to pass through) |
| `Proxy:MaskClientInfo` | `false` | Additionally erase `clientDigProductId` / `clientDir` |
| `Proxy:CredsspImpl` | `handroll` | CredSSP implementation (`handroll` / `negotiate`) |
| `Proxy:Credentials` | — | CredSSP credentials (`Domain` / `User` / `Password` / `NtHash`) |
| `Proxy:Allow` | `[]` | Source-IP allowlist (CIDR; empty means allow all) |
| `Proxy:Maps` | `[]` | Array of listen-port→target (at least one required) |

`Maps[]` element: `ListenPort` (listen port) / `Host` (target) / `Port` (default 3389), plus the overridable `Source` / `ClientAddress` / `ClientName` / `MaskClientInfo` / `Credentials` / `Allow`.

```jsonc
{
  "Proxy": {
    "Listen": "0.0.0.0",
    "Cert": "proxy.pfx",
    "Source": "192.168.2.20",
    "ClientAddress": "192.168.2.20",
    "Credentials": { "Domain": "", "User": "Administrator", "Password": "ChangeMe" },
    "Maps": [
      { "ListenPort": 3389, "Host": "192.168.2.10", "Port": 3389 },
      { "ListenPort": 13389, "Host": "192.168.2.11", "Port": 3389,
        "Credentials": { "Domain": "", "User": "Administrator", "Password": "other-pass" } },
      { "ListenPort": 23389, "Host": "192.168.2.12", "Port": 3389 }
    ]
  }
}
```
- The listen address is shared, so **each map needs its own `ListenPort`**. The example gives the first target the standard 3389 (connect with just the host name) and the rest 13389 / 23389.
- The startup log prints each map's effective values (`Map 0.0.0.0:3389 -> 192.168.2.10:3389 src=… clientAddr=… domain=… user=… allow=…`).
- If `Password` / `NtHash` are unset, CredSSP is disabled (TLS termination only = for targets without NLA).
- `Domain`: empty or `.` for a local account, the NetBIOS name for a domain. Instead of a plaintext `Password` you may specify `NtHash` (the 16-byte hex of MD4(password)).

Settings can also be overridden with environment variables or command-line arguments (e.g. `--Proxy:ClientAddress=…`, `Proxy__Maps__0__Host=…`, `--Serilog:MinimumLevel:Default=Debug`).

### Source-IP restriction (Allow)
Connections from anything other than the allowed CIDRs are **rejected immediately before TLS** (logged as `connection rejected (not in allow list).`). Empty/unspecified means allow all. **Overridable per map** (unspecified inherits the global).
```jsonc
{
  "Proxy": {
    "Allow": ["192.168.1.0/24"],
    "Maps": [
      { "ListenPort": 3389, "Host": "192.168.2.10", "Port": 3389 },
      { "ListenPort": 13389, "Host": "192.168.2.13", "Port": 3389,
        "Allow": ["192.168.1.10/32", "192.168.1.11/32"] }
    ]
  }
}
```

### Masking identity info (ClientName / MaskClientInfo)
Identity fields other than `ClientAddress` (IP) can also be rewritten. **Two independent switches** let you choose the granularity (overridable per map).

| Setting | Effect | Target field | Where it surfaces |
|---|---|---|---|
| `ClientAddress` (always) | Always rewritten | `clientAddress` | `WTSClientAddress` |
| **`ClientName`** = value | Rewrite clientName | `clientName` (`""` for empty) | `WTSClientName`, some logs |
| **`MaskClientInfo`** = true | Additionally erase | `clientDigProductId` + `clientDir` | product ID, path |

```jsonc
// (A) Rewrite "only" clientName and clientAddress
{ "Proxy": { "ClientAddress": "192.168.2.20", "ClientName": "RELAY01",
  "Maps": [ { "ListenPort": 3389, "Host": "192.168.2.10", "Port": 3389 } ] } }

// (B) In addition to the above, also erase product ID and path (maximum masking)
{ "Proxy": { "ClientAddress": "192.168.2.20", "ClientName": "RELAY01", "MaskClientInfo": true,
  "Maps": [ { "ListenPort": 3389, "Host": "192.168.2.10", "Port": 3389 } ] } }
```
**Fields not masked** (kept by default because they affect session behavior/UX): `clientBuild` (version), keyboard layout/IME (locale), `clientTimeZone` (time zone), screen resolution.

### Certificates
- If `Cert` is unspecified, a self-signed (10-year) certificate is generated dynamically at startup. If you specify `Cert = proxy.pfx` and the file does not exist, a **10-year PFX + .CER is generated on first run** and the same file is read thereafter (so the certificate stays constant).
- `--make-cert proxy.pfx` generates one standalone. Import the `.CER` into the client's "Trusted Root" to silence the mstsc certificate warning.

## Running as a resident service

**A single instance can handle multiple targets** (list multiple maps with per-target credentials in `Proxy:Maps`). Run it as a Windows service, systemd unit, or Docker container.

(The Linux binary is produced by `build-linux-aot.sh` / `build-linux-aot.bat` / `build-linux-singlefile.bat` — see the header comment in each script.)

### Windows service
```pwsh
# Install (elevated; the space after binPath= is required)
sc.exe create Raccoon.RdpProxy binPath= "C:\path\to\Raccoon.RdpProxy.exe" start= auto
sc.exe start Raccoon.RdpProxy

# Uninstall
sc.exe stop Raccoon.RdpProxy
sc.exe delete Raccoon.RdpProxy
```
When started as a service, the current directory is pinned to the executable's location, so `appsettings.json` / `proxy.pfx` / `Log/` are resolved from there.

### systemd (Linux)
```bash
sudo mkdir -p /opt/rdp-proxy
sudo cp Raccoon.RdpProxy /opt/rdp-proxy/
sudo cp appsettings.json /opt/rdp-proxy/       # put the multiple maps here
sudo chmod 600 /opt/rdp-proxy/appsettings.json # tighten perms (contains credentials)
sudo cp rdp-proxy.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now rdp-proxy
journalctl -u rdp-proxy -f                     # view logs
```
(The included [rdp-proxy.service](rdp-proxy.service) uses `Type=notify` to wait until the listeners are up. `proxy.pfx` is auto-generated on first run and saved in `/opt/rdp-proxy`. To use a different directory, change `WorkingDirectory` / `ExecStart` / `ReadWritePaths` in the unit together.)

### Docker / docker-compose
Because of dual-homing and source binding, **host networking is required** (the listen ports open directly on the host). Credentials are not baked into the image; mount them at `/cfg`.
```bash
sudo mkdir -p /opt/raccoon-rdpproxy
sudo cp Raccoon.RdpProxy/appsettings.json /opt/raccoon-rdpproxy/
sudo chmod 600 /opt/raccoon-rdpproxy/appsettings.json
docker compose up -d --build      # included docker-compose.yml (network_mode: host, /opt/raccoon-rdpproxy:/cfg)
docker compose logs -f
```
Without compose:
```bash
docker build -t raccoon-rdpproxy .
docker run -d --name raccoon-rdpproxy --restart unless-stopped \
  --network host -v /opt/raccoon-rdpproxy:/cfg raccoon-rdpproxy
```
(The included [Dockerfile](Dockerfile) / [docker-compose.yml](docker-compose.yml) build the binary from source, so no prior local build is needed. The `appsettings.json` / `proxy.pfx` / `Log/` under `/cfg` are used.)

## Verifying the rewrite (run on the target)

**Show `WTSClientAddress` (= the in-packet clientAddress):**
```powershell
Add-Type @'
using System; using System.Runtime.InteropServices;
public static class Wts {
  [DllImport("wtsapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern bool WTSQuerySessionInformationW(IntPtr h,int sid,int cls,out IntPtr p,out int n);
  [DllImport("wtsapi32.dll")] static extern void WTSFreeMemory(IntPtr p);
  public static string Addr(int sid){ IntPtr p; int n;
    if(!WTSQuerySessionInformationW(IntPtr.Zero,sid,14,out p,out n)) return null; // 14=WTSClientAddress
    try{ if(Marshal.ReadInt32(p)!=2) return null;   // AF_INET / IPv4 is at offset 6..9
      return Marshal.ReadByte(p,6)+"."+Marshal.ReadByte(p,7)+"."+Marshal.ReadByte(p,8)+"."+Marshal.ReadByte(p,9);
    } finally { WTSFreeMemory(p);} }
  public static string User(int sid){ IntPtr p; int n;
    if(!WTSQuerySessionInformationW(IntPtr.Zero,sid,5,out p,out n)) return "";
    try{ return Marshal.PtrToStringUni(p);} finally { WTSFreeMemory(p);} }
}
'@
0..15 | % { $a=[Wts]::Addr($_); if($a){ "session {0,-3} user={1,-18} WTSClientAddress={2}" -f $_,[Wts]::User($_),$a } }
```
After connecting through the relay, if this shows the configured `ClientAddress` the rewrite succeeded.

**Note**: The "Source Network Address" in Event Viewer (Security 4624 / TerminalServices 1149) comes from the **TCP source**, and follows the `Source` bind alone (a separate mechanism from the in-packet rewrite).

## Diagnostic tools (CLI modes)

Diagnostic/utility modes that run without starting the host and then exit:

- **`--credssp-probe HOST:PORT`**: verify **only CredSSP authentication** without mstsc (TCP→X.224→TLS→CredSSP). Useful for isolating credential validity vs. connectivity.
  ```bash
  ./Raccoon.RdpProxy --credssp-probe 192.168.2.10:3389 --user Administrator --password 'pw' --domain ''
  ```
  Judge by `★ CredSSP authenticated` vs. `× … errorCode=0xC000006D` (= password mismatch), etc.
- **`--credssp-impl handroll|negotiate`**: the default is the dependency-free `handroll`. `negotiate` uses the standard .NET SSPI (Linux needs `gss-ntlmssp`). The hand-rolled path has been verified equivalent to SSPI, so the default is normally fine.
- **`--make-cert PATH`**: generate a 10-year PFX/.CER and exit.
- **`--selftest`**: self-tests (protocol rewrites, NTLM crypto vectors, CredSSP DER).
- **`--e2etest`**: integration test (fake client ↔ real service ↔ fake backend, verifying the clientAddress rewrite over the full path).

## Limitations & security
- This is effectively a MITM that decrypts and relays RDP. It assumes **use on your own infrastructure**.
- You can narrow acceptance with the **source-IP restriction (`Allow`)** (anything not allowed is rejected before TLS). Recommended alongside a firewall.
- Credentials are stored in `appsettings.json`. Tighten permissions with `chmod 600`, or prefer using `NtHash`.
- Kerberos is out of scope (it assumes falling back to NTLM over an IP connection). Standard RDP Security (RC4) is also out of scope.
- The client leg downgrades NLA to SSL. If the mstsc "server authentication" policy is strict, connection may fail (the default allows it).
