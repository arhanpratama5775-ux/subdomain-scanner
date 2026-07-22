#!/usr/bin/env python3
"""
Subdomain Scanner - Find subdomains for a domain
Uses wordlist-based brute force with DNS resolution.

Usage:
    python scanner.py example.com                    # Quick scan
    python scanner.py example.com -w wordlist.txt    # Custom wordlist
    python scanner.py example.com --threads 50       # Adjust speed
"""

import sys
import os
import socket
import argparse
import concurrent.futures
from datetime import datetime


# ══════════════════════════════════════════════════
#  COLORS
# ══════════════════════════════════════════════════
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'


# ══════════════════════════════════════════════════
#  DEFAULT WORDLIST
# ══════════════════════════════════════════════════
DEFAULT_SUBDOMAINS = [
    # Common
    'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
    'ns3', 'dns', 'dns1', 'dns2', 'proxy', 'vpn', 'gateway', 'router',

    # Web
    'admin', 'administrator', 'webdisk', 'cpanel', 'whm', 'webhost',
    'api', 'dev', 'development', 'staging', 'stage', 'test', 'testing',
    'beta', 'alpha', 'demo', 'sandbox', 'preview', 'pre',

    # Server types
    'blog', 'forum', 'shop', 'store', 'portal', 'dashboard', 'panel',
    'login', 'auth', 'sso', 'accounts', 'my', 'portal',

    # Apps
    'app', 'apps', 'mobile', 'm', 'wap', 'ios', 'android',

    # Database
    'db', 'database', 'sql', 'mysql', 'postgres', 'redis', 'mongo', 'elastic',

    # Monitoring
    'monitor', 'status', 'stats', 'metrics', 'grafana', 'kibana', 'prometheus',

    # DevOps
    'ci', 'cd', 'jenkins', 'gitlab', 'github', 'git', 'svn',
    'docker', 'k8s', 'kubernetes', 'registry',

    # Cloud
    'aws', 'azure', 'gcp', 'cloud', 'cdn', 'static', 'assets', 'media',

    # Mail
    'imap', 'pop3', 'smtp', 'mx', 'email', 'mail2', 'mail3',

    # Security
    'vpn', 'firewall', 'waf', 'ids', 'ips',

    # Misc
    'backup', 'bak', 'old', 'new', 'temp', 'tmp', 'archive',
    'files', 'upload', 'uploads', 'download', 'downloads',
    'docs', 'documentation', 'wiki', 'help', 'support',
    'images', 'img', 'pics', 'photos', 'video', 'videos',
    'cdn1', 'cdn2', 'cdn3', 'edge', 'node1', 'node2',
]


# ══════════════════════════════════════════════════
#  SCANNER
# ══════════════════════════════════════════════════
class SubdomainScanner:
    def __init__(self, domain, timeout=3):
        self.domain = domain
        self.timeout = timeout
        self.found = []

    def check_subdomain(self, subdomain):
        """Check if subdomain exists"""
        hostname = f"{subdomain}.{self.domain}"
        try:
            ip = socket.gethostbyname(hostname)
            return {'subdomain': hostname, 'ip': ip, 'status': 'found'}
        except socket.gaierror:
            return None
        except Exception:
            return None

    def scan(self, wordlist, max_threads=50):
        """Scan subdomains with threading"""
        total = len(wordlist)
        print(f"\n{Colors.CYAN}Scanning {total} subdomains for {self.domain}...{Colors.ENDC}\n")

        start_time = datetime.now()
        found = []
        checked = 0

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
            future_to_sub = {executor.submit(self.check_subdomain, sub): sub for sub in wordlist}

            for future in concurrent.futures.as_completed(future_to_sub):
                checked += 1
                result = future.result()

                if result:
                    found.append(result)
                    print(f"  {Colors.GREEN}[FOUND]{Colors.ENDC} {result['subdomain']} → {result['ip']}")

                # Progress indicator
                if checked % 50 == 0 or checked == total:
                    print(f"{Colors.DIM}  Progress: {checked}/{total} ({len(found)} found){Colors.ENDC}", end='\r')

        elapsed = (datetime.now() - start_time).total_seconds()
        print(f"\n\n{Colors.GREEN}Scan complete: {len(found)} subdomains found in {elapsed:.1f}s{Colors.ENDC}\n")

        return sorted(found, key=lambda x: x['subdomain'])


# ══════════════════════════════════════════════════
#  DISPLAY
# ══════════════════════════════════════════════════
def display_results(domain, results):
    """Display scan results"""
    print(f"{Colors.BOLD}Results for {domain}:{Colors.ENDC}\n")

    if results:
        print(f"  {'Subdomain':<35} {'IP Address'}")
        print(f"  {'-'*55}")

        for r in results:
            print(f"  {r['subdomain']:<35} {r['ip']}")

        print(f"\n{Colors.GREEN}Total: {len(results)} subdomain(s) found{Colors.ENDC}")
    else:
        print(f"{Colors.YELLOW}No subdomains found{Colors.ENDC}")

    print()


def display_banner():
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*55}{Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.CYAN}  Subdomain Scanner{Colors.ENDC}")
    print(f"{Colors.DIM}  Find subdomains via DNS brute force{Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'='*55}{Colors.ENDC}")


# ══════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(
        description='Subdomain Scanner - Find subdomains for a domain',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s example.com                    # Quick scan with defaults
  %(prog)s example.com -w wordlist.txt    # Custom wordlist
  %(prog)s example.com --threads 100      # Faster scan
  %(prog)s example.com --timeout 1        # Faster timeout
        """
    )

    parser.add_argument('domain', help='Target domain')
    parser.add_argument('-w', '--wordlist', help='Custom wordlist file (one subdomain per line)')
    parser.add_argument('-t', '--threads', type=int, default=50, help='Number of threads (default: 50)')
    parser.add_argument('--timeout', type=float, default=3, help='DNS timeout in seconds (default: 3)')

    args = parser.parse_args()

    display_banner()

    # Load wordlist
    wordlist = DEFAULT_SUBDOMAINS
    if args.wordlist:
        try:
            with open(args.wordlist, 'r') as f:
                wordlist = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            print(f"{Colors.CYAN}Loaded {len(wordlist)} words from {args.wordlist}{Colors.ENDC}")
        except FileNotFoundError:
            print(f"{Colors.RED}Error: Wordlist not found: {args.wordlist}{Colors.ENDC}")
            sys.exit(1)
    else:
        print(f"{Colors.DIM}Using default wordlist ({len(DEFAULT_SUBDOMAINS)} words){Colors.ENDC}")

    # Create scanner
    scanner = SubdomainScanner(args.domain, args.timeout)

    # Scan
    results = scanner.scan(wordlist, args.threads)

    # Display
    display_results(args.domain, results)


if __name__ == '__main__':
    main()
