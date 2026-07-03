"""
╔══════════════════════════════════════════════════════════╗
║         🔐 CyberSec Toolkit - Beginner Edition           ║
║    Network Scanner + Web App Security Checker            ║
╚══════════════════════════════════════════════════════════╝

PURPOSE:
  A hands-on toolkit to learn cybersecurity fundamentals.
  IMPORTANT: Only scan systems/websites you OWN or have
  WRITTEN PERMISSION to test. Unauthorized scanning is illegal.

MODULES:
  1. Network Scanner  - Discover open ports on a host
  2. Web App Scanner  - Check for common web vulnerabilities
"""

import socket
import sys
import time
import urllib.request
import urllib.error
import urllib.parse
import ssl
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed


# ──────────────────────────────────────────────
# COLORS (makes terminal output easier to read)
# ──────────────────────────────────────────────
class Color:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

def red(text):    return f"{Color.RED}{text}{Color.RESET}"
def green(text):  return f"{Color.GREEN}{text}{Color.RESET}"
def yellow(text): return f"{Color.YELLOW}{text}{Color.RESET}"
def blue(text):   return f"{Color.BLUE}{text}{Color.RESET}"
def cyan(text):   return f"{Color.CYAN}{text}{Color.RESET}"
def bold(text):   return f"{Color.BOLD}{text}{Color.RESET}"


# ──────────────────────────────────────────────
# MODULE 1: NETWORK PORT SCANNER
# ──────────────────────────────────────────────

# Well-known ports and their services
COMMON_PORTS = {
    21:   "FTP (File Transfer)",
    22:   "SSH (Secure Shell)",
    23:   "Telnet (Insecure!)",
    25:   "SMTP (Email)",
    53:   "DNS (Domain Name)",
    80:   "HTTP (Web)",
    110:  "POP3 (Email)",
    143:  "IMAP (Email)",
    443:  "HTTPS (Secure Web)",
    445:  "SMB (File Sharing)",
    3306: "MySQL (Database)",
    3389: "RDP (Remote Desktop)",
    5432: "PostgreSQL (Database)",
    6379: "Redis (Cache)",
    8080: "HTTP Alt (Web Dev)",
    8443: "HTTPS Alt",
    27017:"MongoDB (Database)",
}

# Ports that are risky when exposed to the internet
RISKY_PORTS = {23, 21, 445, 3389, 3306, 5432, 6379, 27017}


def resolve_hostname(host: str) -> str:
    """Convert hostname to IP address."""
    try:
        ip = socket.gethostbyname(host)
        return ip
    except socket.gaierror:
        return None


def scan_single_port(host: str, port: int, timeout: float = 1.0) -> bool:
    """
    Try to connect to a single port.
    Returns True if the port is OPEN, False if closed/filtered.
    
    HOW IT WORKS:
      We create a TCP socket (like opening a phone line),
      then try to "call" the target on a specific port number.
      If the connection succeeds → port is open.
      If refused or timed out → port is closed.
    """
    try:
        # AF_INET = IPv4, SOCK_STREAM = TCP connection
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))  # 0 = success
        sock.close()
        return result == 0
    except Exception:
        return False


def grab_banner(host: str, port: int) -> str:
    """
    Try to read a service banner (the greeting message a service sends).
    This tells us WHAT SOFTWARE is running on an open port.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((host, port))
        # Some services send a banner automatically; others need a prompt
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        sock.close()
        # Return just the first line
        return banner.split("\n")[0][:80] if banner else ""
    except Exception:
        return ""


def network_scanner(host: str, port_range: tuple = (1, 1024), threads: int = 100):
    """
    Main network scanning function.
    
    PARAMETERS:
      host       - Target hostname or IP (e.g., "192.168.1.1")
      port_range - (start_port, end_port) tuple
      threads    - How many ports to scan simultaneously (faster!)
    """
    print(f"\n{bold('═' * 55)}")
    print(f"  🔍 {bold('NETWORK PORT SCANNER')}")
    print(f"{'═' * 55}")
    
    # Step 1: Resolve hostname to IP
    print(f"\n[*] Target:  {cyan(host)}")
    ip = resolve_hostname(host)
    if not ip:
        print(red(f"[!] ERROR: Cannot resolve hostname '{host}'"))
        print(yellow("    → Check if the hostname is correct"))
        return
    
    print(f"[*] IP:      {cyan(ip)}")
    print(f"[*] Ports:   {port_range[0]} → {port_range[1]}")
    print(f"[*] Threads: {threads} (parallel scanning)")
    print(f"[*] Started: {datetime.now().strftime('%H:%M:%S')}")
    print(f"\n{yellow('[*] Scanning... (this may take a moment)')}\n")
    
    open_ports = []
    start_time = time.time()
    ports_to_scan = range(port_range[0], port_range[1] + 1)
    total = len(ports_to_scan)
    scanned = 0
    
    # Step 2: Scan ports in parallel using threads (much faster!)
    with ThreadPoolExecutor(max_workers=threads) as executor:
        # Submit all port scans at once
        future_to_port = {
            executor.submit(scan_single_port, ip, port): port
            for port in ports_to_scan
        }
        
        # Collect results as they complete
        for future in as_completed(future_to_port):
            port = future_to_port[future]
            scanned += 1
            
            # Show progress every 100 ports
            if scanned % 100 == 0 or scanned == total:
                pct = int((scanned / total) * 30)
                bar = "█" * pct + "░" * (30 - pct)
                print(f"\r  [{bar}] {scanned}/{total}", end="", flush=True)
            
            if future.result():  # Port is open!
                open_ports.append(port)
    
    elapsed = time.time() - start_time
    print(f"\n\n{bold('── RESULTS ──────────────────────────────────────────')}")
    print(f"  Scanned {total} ports in {elapsed:.1f} seconds\n")
    
    if not open_ports:
        print(green("  ✓ No open ports found in this range"))
        print(yellow("    (Host may have a firewall, or be offline)"))
        return
    
    print(f"  Found {bold(str(len(open_ports)))} open port(s):\n")
    
    risks_found = []
    
    for port in sorted(open_ports):
        service = COMMON_PORTS.get(port, "Unknown Service")
        is_risky = port in RISKY_PORTS
        
        # Try to grab a service banner for more info
        banner = grab_banner(ip, port)
        
        status_icon = "⚠️ " if is_risky else "✓ "
        color_fn = red if is_risky else green
        
        print(f"  {color_fn(f'{status_icon} PORT {port:5d}')}  │  {service}")
        if banner:
            print(f"             │  {cyan('Banner:')} {banner[:60]}")
        if is_risky:
            risks_found.append((port, service))
    
    # Step 3: Security recommendations
    if risks_found:
        print(f"\n{bold(red('── ⚠️  SECURITY WARNINGS ──────────────────────────────'))}")
        tips = {
            23:    "Telnet sends data in PLAINTEXT. Replace with SSH (port 22).",
            21:    "FTP sends passwords unencrypted. Use SFTP or FTPS instead.",
            445:   "SMB exposed to internet is dangerous (e.g., WannaCry attack).",
            3389:  "RDP should NEVER be open to the internet. Use VPN first.",
            3306:  "MySQL should not be publicly accessible. Use firewall rules.",
            5432:  "PostgreSQL should not be publicly accessible.",
            6379:  "Redis has NO authentication by default! Restrict access.",
            27017: "MongoDB has been hacked via open port. Add authentication!",
        }
        for port, service in risks_found:
            tip = tips.get(port, "Restrict access to trusted IPs only.")
            print(f"\n  {red(f'● Port {port} ({service})')}")
            print(f"    → {tip}")
    
    print(f"\n{bold('═' * 55)}\n")


# ──────────────────────────────────────────────
# MODULE 2: WEB APPLICATION SECURITY SCANNER
# ──────────────────────────────────────────────

def make_request(url: str, timeout: int = 5) -> tuple:
    """
    Make an HTTP request and return (response_object, error_string).
    Handles both HTTP and HTTPS.
    """
    try:
        # Don't verify SSL cert (we want to detect bad certs separately)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "CyberSecToolkit/1.0 (Educational Scanner)"}
        )
        response = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        return response, None
    except urllib.error.HTTPError as e:
        return e, None  # HTTPError is also a valid response
    except Exception as e:
        return None, str(e)


def check_ssl_certificate(host: str) -> dict:
    """
    Check the SSL/TLS certificate of a website.
    
    WHY THIS MATTERS:
      SSL certificates encrypt traffic between browser and server.
      An expired or invalid cert warns users their connection isn't secure.
    """
    result = {"status": "unknown", "details": ""}
    try:
        ctx = ssl.create_default_context()
        conn = ctx.wrap_socket(
            socket.socket(socket.AF_INET),
            server_hostname=host
        )
        conn.settimeout(5)
        conn.connect((host, 443))
        cert = conn.getpeercert()
        conn.close()
        
        # Check expiry date
        expire_str = cert.get("notAfter", "")
        if expire_str:
            expire_date = datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
            days_left = (expire_date - datetime.now()).days
            if days_left < 0:
                result = {"status": "expired", "details": f"Expired {abs(days_left)} days ago!"}
            elif days_left < 30:
                result = {"status": "expiring_soon", "details": f"Expires in {days_left} days"}
            else:
                result = {"status": "valid", "details": f"Valid for {days_left} more days"}
        
        # Get certificate issuer
        issuer = dict(x[0] for x in cert.get("issuer", []))
        result["issuer"] = issuer.get("organizationName", "Unknown")
        result["subject"] = dict(x[0] for x in cert.get("subject", []))
        
    except ssl.SSLCertVerificationError:
        result = {"status": "invalid", "details": "Certificate verification failed!"}
    except Exception as e:
        result = {"status": "error", "details": str(e)}
    
    return result


def check_security_headers(headers: dict) -> list:
    """
    Check for important HTTP security headers.
    
    WHY THIS MATTERS:
      Security headers tell the browser how to handle your site safely.
      Missing headers = easy attack vectors for hackers.
    """
    checks = []
    
    # Each entry: (header_name, why_it_matters, severity)
    important_headers = [
        (
            "Strict-Transport-Security",
            "Forces HTTPS — prevents downgrade attacks",
            "HIGH"
        ),
        (
            "Content-Security-Policy",
            "Prevents XSS attacks by controlling what scripts can run",
            "HIGH"
        ),
        (
            "X-Frame-Options",
            "Prevents clickjacking attacks (your site loaded in an iframe)",
            "MEDIUM"
        ),
        (
            "X-Content-Type-Options",
            "Prevents MIME-type sniffing attacks",
            "MEDIUM"
        ),
        (
            "Referrer-Policy",
            "Controls what URL info is shared with other sites",
            "LOW"
        ),
        (
            "Permissions-Policy",
            "Controls browser feature access (camera, microphone, etc.)",
            "LOW"
        ),
    ]
    
    # Normalize headers to lowercase for comparison
    lower_headers = {k.lower(): v for k, v in headers.items()}
    
    for header_name, description, severity in important_headers:
        present = header_name.lower() in lower_headers
        value = lower_headers.get(header_name.lower(), "")
        checks.append({
            "header": header_name,
            "present": present,
            "value": value,
            "description": description,
            "severity": severity,
        })
    
    return checks


def check_sensitive_paths(base_url: str) -> list:
    """
    Check if sensitive files/directories are publicly accessible.
    
    WHY THIS MATTERS:
      Developers sometimes accidentally expose config files, admin panels,
      or backup files that contain passwords and secrets.
    """
    sensitive_paths = [
        ("/.env",              "Environment file — may contain DB passwords, API keys!"),
        ("/.git/config",       "Git config — exposes repository info"),
        ("/admin",             "Admin panel — should require strong authentication"),
        ("/wp-admin",          "WordPress admin — common brute-force target"),
        ("/phpinfo.php",       "PHP info page — reveals server configuration"),
        ("/robots.txt",        "Robots file — may reveal hidden paths"),
        ("/sitemap.xml",       "Sitemap — reveals all pages"),
        ("/.htaccess",         "Apache config — may reveal security rules"),
        ("/backup.zip",        "Backup file — may contain source code!"),
        ("/config.php",        "Config file — may contain credentials"),
        ("/.DS_Store",         "Mac OS file — reveals directory structure"),
        ("/server-status",     "Apache status — reveals server internals"),
    ]
    
    results = []
    for path, description in sensitive_paths:
        url = base_url.rstrip("/") + path
        response, error = make_request(url, timeout=3)
        
        if response and hasattr(response, "status"):
            status = response.status
        elif response and hasattr(response, "code"):
            status = response.code
        else:
            status = 0
        
        found = status in (200, 301, 302, 403)  # 403 = exists but forbidden
        accessible = status == 200
        
        results.append({
            "path": path,
            "url": url,
            "status": status,
            "found": found,
            "accessible": accessible,
            "description": description,
        })
    
    return results


def check_server_info(headers: dict) -> dict:
    """
    Check if the server reveals too much information.
    
    WHY THIS MATTERS:
      When servers advertise their software version (e.g., "Apache 2.4.1"),
      hackers know exactly which vulnerabilities to exploit.
    """
    info = {}
    lower = {k.lower(): v for k, v in headers.items()}
    
    if "server" in lower:
        info["server"] = lower["server"]
    if "x-powered-by" in lower:
        info["x_powered_by"] = lower["x-powered-by"]
    if "x-aspnet-version" in lower:
        info["aspnet_version"] = lower["x-aspnet-version"]
    
    return info


def web_scanner(target_url: str):
    """
    Main web application security scanning function.
    
    PARAMETERS:
      target_url - The website URL to scan (e.g., "https://example.com")
    """
    # Normalize URL
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url
    
    parsed = urllib.parse.urlparse(target_url)
    host = parsed.hostname
    is_https = parsed.scheme == "https"
    
    print(f"\n{bold('═' * 55)}")
    print(f"  🌐 {bold('WEB APP SECURITY SCANNER')}")
    print(f"{'═' * 55}")
    print(f"\n[*] Target: {cyan(target_url)}")
    print(f"[*] Host:   {cyan(host)}")
    print(f"[*] Time:   {datetime.now().strftime('%H:%M:%S')}\n")
    
    # ── CHECK 1: Can we reach the site? ──────────────────
    print(f"{yellow('[*] Connecting to website...')}")
    response, error = make_request(target_url)
    
    if not response:
        print(red(f"\n[!] Cannot reach {target_url}"))
        print(yellow(f"    Error: {error}"))
        return
    
    status = response.status if hasattr(response, "status") else response.code
    headers = dict(response.headers) if hasattr(response, "headers") else {}
    print(green(f"[✓] Site is reachable — HTTP Status: {status}"))
    
    # ── CHECK 2: HTTPS ────────────────────────────────────
    print(f"\n{bold('── 1. HTTPS / SSL CHECK ─────────────────────────────')}")
    if not is_https:
        print(red("  ✗ Site is NOT using HTTPS!"))
        print(yellow("    → All data is transmitted in plaintext"))
        print(yellow("    → Get a free SSL certificate at letsencrypt.org"))
    else:
        print(green("  ✓ Site uses HTTPS"))
        ssl_result = check_ssl_certificate(host)
        status_map = {
            "valid":         (green,  f"  ✓ Certificate is VALID — {ssl_result.get('details','')}"),
            "expiring_soon": (yellow, f"  ⚠ Certificate expiring soon — {ssl_result.get('details','')}"),
            "expired":       (red,    f"  ✗ Certificate EXPIRED — {ssl_result.get('details','')}"),
            "invalid":       (red,    f"  ✗ Certificate INVALID — {ssl_result.get('details','')}"),
        }
        s = ssl_result.get("status", "error")
        fn, msg = status_map.get(s, (yellow, f"  ? SSL check inconclusive: {ssl_result.get('details','')}"))
        print(fn(msg))
        if ssl_result.get("issuer"):
            print(f"    Issued by: {ssl_result['issuer']}")
    
    # ── CHECK 3: Security Headers ─────────────────────────
    print(f"\n{bold('── 2. SECURITY HEADERS ──────────────────────────────')}")
    header_checks = check_security_headers(headers)
    
    missing_high = 0
    for check in header_checks:
        if check["present"]:
            val_preview = f" → {check['value'][:40]}" if check["value"] else ""
            print(green(f"  ✓ {check['header']}{val_preview}"))
        else:
            severity_color = red if check["severity"] == "HIGH" else yellow
            print(severity_color(f"  ✗ MISSING: {check['header']}"))
            print(f"      Why it matters: {check['description']}")
            if check["severity"] == "HIGH":
                missing_high += 1
    
    if missing_high == 0:
        print(green("\n  ✓ All high-priority headers are present!"))
    else:
        print(red(f"\n  ✗ {missing_high} high-priority header(s) missing!"))
    
    # ── CHECK 4: Server Information Disclosure ────────────
    print(f"\n{bold('── 3. SERVER INFO DISCLOSURE ────────────────────────')}")
    server_info = check_server_info(headers)
    
    if not server_info:
        print(green("  ✓ Server does not reveal version information"))
    else:
        print(yellow("  ⚠ Server is revealing software information:"))
        for key, value in server_info.items():
            print(red(f"    • {key}: {value}"))
        print(yellow("    → Attackers use this to find known exploits"))
        print(yellow("    → Remove or obscure version numbers in server config"))
    
    # ── CHECK 5: Sensitive Paths ──────────────────────────
    print(f"\n{bold('── 4. SENSITIVE FILE EXPOSURE ───────────────────────')}")
    print(yellow("  [*] Checking for exposed sensitive files..."))
    path_results = check_sensitive_paths(target_url)
    
    critical_found = []
    for r in path_results:
        if r["accessible"]:
            critical_found.append(r)
            print(red(f"  ✗ ACCESSIBLE: {r['path']} (HTTP {r['status']})"))
            print(red(f"      ⚠ {r['description']}"))
        elif r["found"] and r["status"] == 403:
            print(yellow(f"  ⚠ EXISTS (forbidden): {r['path']} — {r['description']}"))
    
    if not critical_found:
        accessible_count = sum(1 for r in path_results if r["found"])
        if accessible_count == 0:
            print(green("  ✓ No sensitive files found publicly accessible"))
        else:
            print(green("  ✓ No critically accessible sensitive files found"))
    
    # ── SUMMARY ───────────────────────────────────────────
    print(f"\n{bold('── SUMMARY ──────────────────────────────────────────')}")
    
    issues = []
    if not is_https:
        issues.append(("CRITICAL", "No HTTPS — data sent in plaintext"))
    if missing_high > 0:
        issues.append(("HIGH", f"{missing_high} critical security header(s) missing"))
    if server_info:
        issues.append(("MEDIUM", "Server software version disclosed"))
    if critical_found:
        issues.append(("HIGH", f"{len(critical_found)} sensitive file(s) publicly accessible"))
    
    if not issues:
        print(green("  ✓ No major issues found! Site has good basic security."))
    else:
        print(f"  Found {len(issues)} issue(s) to address:\n")
        for severity, msg in issues:
            color_fn = red if severity in ("CRITICAL", "HIGH") else yellow
            print(color_fn(f"  [{severity}] {msg}"))
    
    print(f"\n{bold('═' * 55)}\n")
    print(yellow("  REMINDER: Only scan websites you own or have permission to test!"))
    print(f"{bold('═' * 55)}\n")


# ──────────────────────────────────────────────
# MAIN MENU
# ──────────────────────────────────────────────

def print_banner():
    print(cyan("""
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║   🔐  CyberSec Toolkit  — Beginner Edition               ║
║       Network Scanner + Web App Security Checker         ║
║                                                          ║
║   ⚠️   LEGAL NOTICE: Only scan systems you OWN or have   ║
║        written permission to test!                       ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝
"""))


def main():
    print_banner()
    
    print(bold("Choose a module:"))
    print("  1) Network Port Scanner")
    print("  2) Web App Security Scanner")
    print("  3) Run both on a target")
    print("  0) Exit\n")
    
    choice = input("Enter choice (0-3): ").strip()
    
    if choice == "0":
        print("\nGoodbye!\n")
        sys.exit(0)
    
    elif choice == "1":
        host = input("\nEnter target IP or hostname: ").strip()
        print("\nPort range options:")
        print("  1) Common ports only (fast: ~100 ports)")
        print("  2) Standard range (1–1024)")
        print("  3) Extended range (1–5000)")
        
        range_choice = input("Choose range (1-3): ").strip()
        ranges = {"1": (1, 100), "2": (1, 1024), "3": (1, 5000)}
        port_range = ranges.get(range_choice, (1, 1024))
        
        network_scanner(host, port_range)
    
    elif choice == "2":
        url = input("\nEnter target URL (e.g. https://example.com): ").strip()
        web_scanner(url)
    
    elif choice == "3":
        target = input("\nEnter target domain (e.g. example.com): ").strip()
        
        print("\nRunning both modules...\n")
        
        # Run network scan
        network_scanner(target, (1, 1024))
        
        # Run web scan
        web_scanner("https://" + target)
    
    else:
        print(red("\n[!] Invalid choice. Please run again."))
    
    # Ask to run again
    again = input("\nRun another scan? (y/n): ").strip().lower()
    if again == "y":
        main()


if __name__ == "__main__":
    main()
