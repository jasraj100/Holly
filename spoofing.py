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

class GOLDENHELO:
    def __init__(self):
        # Common phishing keywords
        self.suspicious_terms = [
            'login', 'verify', 'account', 'banking', 'secure', 'update',
            'password', 'confirm', 'suspicious', 'unusual', 'activity'
        ]
        
        # Known legitimate domain whitelist (example)
        self.whitelist_domains = [
            'google.com',
            'microsoft.com',
            'amazon.com',
            'paypal.com'
        ]
        
        # Initialize blocked URLs list
        self.blocked_urls = set()

    def analyze_url(self, url: str) -> Tuple[bool, List[str]]:
        """
        Analyze a URL for potential phishing indicators
        Returns: (is_suspicious, list of reasons)
        """
        reasons = []
        try:
            parsed = urllib.parse.urlparse(url)
            domain = parsed.netloc.lower()
            
            # Check for suspicious characters in domain
            if re.search(r'[^a-zA-Z0-9\-\.]', domain):
                reasons.append("Domain contains suspicious characters")
            
            # Check for similar-looking domains (homograph attack)
            for legitimate in self.whitelist_domains:
                if domain != legitimate and self._similar_domain(domain, legitimate):
                    reasons.append(f"Domain appears similar to {legitimate}")
            
            # Check for suspicious terms in URL
            for term in self.suspicious_terms:
                if term in url.lower():
                    reasons.append(f"Contains suspicious term: {term}")
            
            # Check SSL certificate
            if parsed.scheme == 'https':
                try:
                    context = ssl.create_default_context()
                    with socket.create_connection((domain, 443)) as sock:
                        with context.wrap_socket(sock, server_hostname=domain) as ssock:
                            cert = ssock.getpeercert()
                            if not cert or 'subject' not in cert:
                                reasons.append("Invalid SSL certificate")
                except:
                    reasons.append("SSL certificate verification failed")
            
            # Check if domain is newly registered (requires additional API)
            # This is a placeholder for domain age checking
            
            return len(reasons) > 0, reasons
            
        except Exception as e:
            return True, [f"Error analyzing URL: {str(e)}"]

    def check_email_spoofing(self, headers: Dict[str, str]) -> Tuple[bool, List[str]]:
        """
        Analyze email headers for signs of spoofing
        Returns: (is_spoofed, list of reasons)
        """
        reasons = []
        
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
            except:
                reasons.append("DMARC verification failed")
        
        return len(reasons) > 0, reasons

    def block_url(self, url: str) -> None:
        """Add URL to blocked list"""
        self.blocked_urls.add(url)

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
        return differences <= 2  # Allow up to 2 character differences

    def scan_text_for_urls(self, text: str) -> List[Tuple[str, bool, List[str]]]:
        """
        Scan text content for URLs and analyze them
        Returns: List of (url, is_suspicious, reasons)
        """
        results = []
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        urls = re.findall(url_pattern, text)
        
        for url in urls:
            is_suspicious, reasons = self.analyze_url(url)
            results.append((url, is_suspicious, reasons))
            if is_suspicious:
                self.block_url(url)
                
        return results

def main():
    """Example usage of GOLDENHELO"""
    defender = GOLDENHELO()
    
    # Example URL scanning
    test_urls = [
        'https://google.com',
        'http://g00gle.com',
        'https://bank-account-verify.com',
    ]
    
    print("Testing URL scanning:")
    for url in test_urls:
        is_suspicious, reasons = defender.analyze_url(url)
        print(f"\nAnalyzing: {url}")
        print(f"Suspicious: {is_suspicious}")
        if reasons:
            print("Reasons:")
            for reason in reasons:
                print(f"- {reason}")
        
        if is_suspicious:
            defender.block_url(url)
    
    # Example email header checking
    test_headers = {
        'From': 'user@example.com',
        'Received-SPF': 'fail',
    }
    
    print("\nTesting email spoofing detection:")
    is_spoofed, reasons = defender.check_email_spoofing(test_headers)
    print(f"Spoofing detected: {is_spoofed}")
    if reasons:
        print("Reasons:")
        for reason in reasons:
            print(f"- {reason}")

if __name__ == "__main__":
    main()