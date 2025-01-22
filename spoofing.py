#!/usr/bin/env python3
"""
GOLDENHELO - Anti-Phishing and Anti-Spoofing Protection Tool
Author: Jasraj
Description: A tool to detect and block potential phishing URLs and email spoofing attempts
"""

import re
import socket
import ssl
import urllib.parse
import dns.resolver
import requests
from typing import Dict, List, Tuple
import sys
import time

def print_banner():
    banner = """
    ███████╗███████╗ ██████╗ ██╗     ██████╗ ███████╗███╗   ██╗██╗  ██╗███████╗██╗      ██████╗ 
    ██╔════╝██╔════╝██╔═══██╗██║     ██╔══██╗██╔════╝████╗  ██║██║  ██║██╔════╝██║     ██╔═══██╗
    █████╗  ███████╗██║   ██║██║     ██║  ██║█████╗  ██╔██╗ ██║███████║█████╗  ██║     ██║   ██║
    ██╔══╝  ╚════██║██║   ██║██║     ██║  ██║██╔══╝  ██║╚██╗██║██╔══██║██╔══╝  ██║     ██║   ██║
    ███████╗███████║╚██████╔╝███████╗██████╔╝███████╗██║ ╚████║██║  ██║███████╗███████╗╚██████╔╝
    ╚══════╝╚══════╝ ╚═════╝ ╚══════╝╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝ 
    """
    print(banner)
    print("\033[1;34m" + "=" * 80 + "\033[0m")
    print("\033[1;32m[+] Anti-Phishing and Anti-Spoofing Protection Tool")
    print("[+] Author: Jasraj")
    print("[+] Version: 1.0\033[0m")
    print("\033[1;34m" + "=" * 80 + "\033[0m\n")

class GOLDENHELO:
    def __init__(self):
        # Initialize all necessary attributes
        self.suspicious_terms = [
            'login', 'verify', 'account', 'banking', 'secure', 'update',
            'password', 'confirm', 'suspicious', 'unusual', 'activity'
        ]
        self.whitelist_domains = [
            'google.com',
            'microsoft.com',
            'amazon.com',
            'paypal.com'
        ]
        self.blocked_urls = set()

    def block_url(self, url: str) -> None:
        """Add URL to blocked list"""
        self.blocked_urls.add(url)
        print(f"\033[1;31m[!] URL has been blocked: {url}\033[0m")

    def is_blocked(self, url: str) -> bool:
        """Check if URL is in blocked list"""
        return url in self.blocked_urls

    def _similar_domain(self, domain1: str, domain2: str) -> bool:
        """Check if domains are suspiciously similar"""
        # Remove common prefixes/suffixes
        d1 = domain1.replace('www.', '').replace('.com', '')
        d2 = domain2.replace('www.', '').replace('.com', '')
        
        # Calculate similarity score
        if len(d1) != len(d2):
            return False
            
        differences = sum(1 for a, b in zip(d1, d2) if a != b)
        return differences <= 2

    def analyze_url(self, url: str) -> Tuple[bool, List[str]]:
        """Analyze a URL for potential phishing indicators"""
        print(f"\n\033[1;33m[*] Analyzing URL: {url}\033[0m")
        print("[*] Running security checks...")
        time.sleep(1)

        reasons = []
        try:
            # Check if URL is already blocked
            if self.is_blocked(url):
                return True, ["URL is already in blocked list"]

            parsed = urllib.parse.urlparse(url)
            domain = parsed.netloc.lower()
            
            # Basic URL validation
            if not domain:
                return True, ["Invalid URL format"]

            # Check for suspicious characters in domain
            if re.search(r'[^a-zA-Z0-9\-\.]', domain):
                reasons.append("Domain contains suspicious characters")
            
            # Check for similar-looking domains
            for legitimate in self.whitelist_domains:
                if domain != legitimate and self._similar_domain(domain, legitimate):
                    reasons.append(f"Domain appears similar to {legitimate}")
            
            # Check for suspicious terms
            for term in self.suspicious_terms:
                if term in url.lower():
                    reasons.append(f"Contains suspicious term: {term}")
            
            # Check SSL certificate
            if parsed.scheme == 'https':
                try:
                    print("[*] Checking SSL certificate...")
                    context = ssl.create_default_context()
                    with socket.create_connection((domain, 443), timeout=5) as sock:
                        with context.wrap_socket(sock, server_hostname=domain) as ssock:
                            cert = ssock.getpeercert()
                            if not cert or 'subject' not in cert:
                                reasons.append("Invalid SSL certificate")
                except Exception as e:
                    reasons.append(f"SSL certificate verification failed: {str(e)}")
            
            return len(reasons) > 0, reasons
            
        except Exception as e:
            return True, [f"Error analyzing URL: {str(e)}"]

    def check_email_spoofing(self, headers: Dict[str, str]) -> Tuple[bool, List[str]]:
        """Analyze email headers for signs of spoofing"""
        print("\n\033[1;33m[*] Analyzing email headers...\033[0m")
        reasons = []
        
        if not headers:
            return True, ["No headers provided"]

        # Check SPF record
        if 'Received-SPF' in headers:
            if 'fail' in headers['Received-SPF'].lower():
                reasons.append("SPF check failed")
        
        # Check DKIM
        if 'DKIM-Signature' not in headers:
            reasons.append("No DKIM signature found")
        
        # Check DMARC
        if 'From' in headers:
            try:
                domain = headers['From'].split('@')[1].strip('>')
                dmarc_record = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
                if not dmarc_record:
                    reasons.append("No DMARC record found")
            except Exception as e:
                reasons.append(f"DMARC verification failed: {str(e)}")
        
        return len(reasons) > 0, reasons

def interactive_mode():
    """Run the tool in interactive mode"""
    defender = GOLDENHELO()
    
    while True:
        print("\n\033[1;36m[+] Choose an option:")
        print("1. Scan a single URL")
        print("2. Scan multiple URLs")
        print("3. Check email headers")
        print("4. View blocked URLs")
        print("5. Exit\033[0m")
        
        try:
            choice = input("\nEnter your choice (1-5): ").strip()
            
            if choice == '1':
                url = input("\nEnter the URL to scan: ").strip()
                if not url:
                    print("\033[1;31m[-] URL cannot be empty\033[0m")
                    continue
                    
                is_suspicious, reasons = defender.analyze_url(url)
                
                if is_suspicious:
                    print("\n\033[1;31m[!] WARNING: Suspicious URL detected!\033[0m")
                    print("\nReasons:")
                    for reason in reasons:
                        print(f"\033[1;31m[-] {reason}\033[0m")
                    defender.block_url(url)
                else:
                    print("\n\033[1;32m[+] URL appears to be safe\033[0m")
                    
            elif choice == '2':
                print("\nEnter URLs (one per line, empty line to finish):")
                urls = []
                while True:
                    url = input().strip()
                    if not url:
                        break
                    urls.append(url)
                
                if not urls:
                    print("\033[1;31m[-] No URLs provided\033[0m")
                    continue

                print("\n[*] Scanning multiple URLs...")
                for url in urls:
                    is_suspicious, reasons = defender.analyze_url(url)
                    if is_suspicious:
                        print(f"\n\033[1;31m[!] WARNING: {url} is suspicious!\033[0m")
                        for reason in reasons:
                            print(f"\033[1;31m[-] {reason}\033[0m")
                        defender.block_url(url)
                    else:
                        print(f"\n\033[1;32m[+] {url} appears to be safe\033[0m")
                        
            elif choice == '3':
                print("\nEnter email headers (format: HeaderName: Value, empty line to finish):")
                headers = {}
                while True:
                    header = input().strip()
                    if not header:
                        break
                    if ':' in header:
                        name, value = header.split(':', 1)
                        headers[name.strip()] = value.strip()
                
                if not headers:
                    print("\033[1;31m[-] No headers provided\033[0m")
                    continue

                is_spoofed, reasons = defender.check_email_spoofing(headers)
                if is_spoofed:
                    print("\n\033[1;31m[!] WARNING: Potential email spoofing detected!\033[0m")
                    for reason in reasons:
                        print(f"\033[1;31m[-] {reason}\033[0m")
                else:
                    print("\n\033[1;32m[+] Email headers appear legitimate\033[0m")
                    
            elif choice == '4':
                if defender.blocked_urls:
                    print("\n\033[1;33m[*] Blocked URLs:\033[0m")
                    for url in defender.blocked_urls:
                        print(f"\033[1;31m[-] {url}\033[0m")
                else:
                    print("\n\033[1;32m[+] No URLs have been blocked yet\033[0m")
                    
            elif choice == '5':
                print("\n\033[1;32m[+] Thank you for using GOLDENHELO! Goodbye!\033[0m")
                sys.exit(0)
                
            else:
                print("\n\033[1;31m[-] Invalid choice. Please try again.\033[0m")

        except KeyboardInterrupt:
            print("\n\n\033[1;32m[+] Program interrupted. Goodbye!\033[0m")
            sys.exit(0)
        except Exception as e:
            print(f"\n\033[1;31m[-] An error occurred: {str(e)}\033[0m")

def main():
    """Main function"""
    print_banner()
    interactive_mode()

if __name__ == "__main__":
    main()