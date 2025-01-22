#!/usr/bin/env python3
"""
GOLDENHELO - Information Disclosure Vulnerability Protection System
Author: Jasraj
Description: Advanced system to detect and prevent information disclosure vulnerabilities
"""

import re
import os
import sys
import json
import time
import logging
import socket
import platform
import subprocess
from typing import Dict, List, Tuple, Set
from datetime import datetime
import hashlib
import urllib.parse
import psutil

class InfoDisclosureDefender:
    def __init__(self):
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            filename='info_disclosure.log'
        )
        self.logger = logging.getLogger('InfoDisclosureDefender')
        
        # Initialize detection patterns
        self.sensitive_patterns = {
            'error_messages': [
                r'(?i)Warning:.*?\bon line\b.*?\d+',
                r'(?i)Fatal error:.*?',
                r'(?i)Exception.*?:.*?',
                r'(?i)SQL syntax.*?',
                r'(?i)SQLSTATE.*?',
                r'(?i)\.php on line \d+',
                r'(?i)stack trace:',
                r'(?i)Debug trace:'
            ],
            'system_info': [
                r'(?i)Windows NT \d+\.\d+',
                r'(?i)Linux kernel \d+\.\d+',
                r'(?i)Apache/\d+\.\d+',
                r'(?i)PHP/\d+\.\d+',
                r'(?i)MySQL/\d+\.\d+',
                r'(?i)/home/\w+/',
                r'(?i)C:\\.*?\\',
                r'(?i)/var/www/',
                r'(?i)/usr/local/'
            ],
            'sensitive_data': [
                r'(?i)password[s]?.*?[=:].*?[\w\d]+',
                r'(?i)username[s]?.*?[=:].*?[\w\d]+',
                r'(?i)secret.*?[=:].*?[\w\d]+',
                r'(?i)api[_-]key.*?[=:].*?[\w\d]+',
                r'(?i)access[_-]token.*?[=:].*?[\w\d]+',
                r'(?i)admin.*?[=:].*?[\w\d]+',
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'  # Email addresses
            ],
            'version_info': [
                r'(?i)version[:\s][\"\']*[\d\.]+[\"\']*',
                r'(?i)v[\d\.]+\b',
                r'(?i)build[\s:][\"\']*[\d\.]+[\"\']*'
            ]
        }
        
        # Initialize blocked patterns and sources
        self.blocked_patterns = set()
        self.blocked_sources = set()
        
        # System information to protect
        self.system_info = self._gather_system_info()
        
        # Initialize counters
        self.detection_count = 0
        self.blocked_count = 0

    def _gather_system_info(self) -> Dict:
        """Gather system information to protect"""
        return {
            'os': platform.system(),
            'os_version': platform.version(),
            'architecture': platform.machine(),
            'hostname': socket.gethostname(),
            'cpu_info': platform.processor(),
            'python_version': sys.version,
            'user_paths': os.environ.get('PATH', ''),
            'system_paths': [os.path.abspath(p) for p in sys.path]
        }

    def scan_content(self, content: str, source: str = "unknown") -> Tuple[bool, List[str]]:
        """
        Scan content for information disclosure vulnerabilities
        Returns: (is_vulnerable, list of findings)
        """
        findings = []
        is_vulnerable = False
        
        # Check if source is already blocked
        if source in self.blocked_sources:
            return True, ["Source is blocked due to previous violations"]
        
        # Scan for each type of sensitive pattern
        for category, patterns in self.sensitive_patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, content)
                for match in matches:
                    found_text = match.group()
                    
                    # Check if this reveals system information
                    if self._is_system_info_leak(found_text):
                        finding = f"System information leak detected in {category}"
                        findings.append(finding)
                        is_vulnerable = True
                        self._handle_violation(pattern, source)
                        
                    # Check for sensitive data patterns
                    elif category == 'sensitive_data':
                        finding = f"Sensitive data pattern detected: {found_text[:20]}..."
                        findings.append(finding)
                        is_vulnerable = True
                        self._handle_violation(pattern, source)
                    
                    # Check for error messages
                    elif category == 'error_messages':
                        finding = f"Error message disclosure detected"
                        findings.append(finding)
                        is_vulnerable = True
                        self._handle_violation(pattern, source)
                        
                    # Check for version information
                    elif category == 'version_info':
                        finding = f"Version information disclosed"
                        findings.append(finding)
                        is_vulnerable = True
                        self._handle_violation(pattern, source)
        
        return is_vulnerable, findings

    def _is_system_info_leak(self, text: str) -> bool:
        """Check if text contains actual system information"""
        system_info_str = json.dumps(self.system_info).lower()
        return any(
            info.lower() in text.lower()
            for info in system_info_str.split()
            if len(info) > 4  # Avoid short common words
        )

    def _handle_violation(self, pattern: str, source: str) -> None:
        """Handle detected violation"""
        self.detection_count += 1
        self.blocked_patterns.add(pattern)
        self.blocked_sources.add(source)
        self.blocked_count += 1
        
        # Log the violation
        self.logger.warning(f"Information disclosure detected from {source}")

    def scan_file(self, filepath: str) -> Tuple[bool, List[str]]:
        """Scan a file for information disclosure"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            return self.scan_content(content, filepath)
        except Exception as e:
            return True, [f"Error scanning file: {str(e)}"]

    def scan_directory(self, directory: str) -> Dict[str, Tuple[bool, List[str]]]:
        """Scan a directory recursively"""
        results = {}
        for root, _, files in os.walk(directory):
            for file in files:
                filepath = os.path.join(root, file)
                try:
                    is_vulnerable, findings = self.scan_file(filepath)
                    if is_vulnerable:
                        results[filepath] = (is_vulnerable, findings)
                except Exception as e:
                    results[filepath] = (True, [f"Error: {str(e)}"])
        return results

    def get_statistics(self) -> Dict:
        """Get detection statistics"""
        return {
            'total_detections': self.detection_count,
            'blocked_patterns': len(self.blocked_patterns),
            'blocked_sources': len(self.blocked_sources),
            'total_blocks': self.blocked_count
        }

def print_banner():
    """Print the tool banner"""
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
    print("\033[1;32m[+] Information Disclosure Vulnerability Protection System")
    print("[+] Author: Jasraj")
    print("[+] Version: 1.0\033[0m")
    print("\033[1;34m" + "=" * 80 + "\033[0m\n")

def interactive_mode():
    """Run the tool in interactive mode"""
    defender = InfoDisclosureDefender()
    
    while True:
        print("\n\033[1;36m[+] Choose an option:")
        print("1. Scan text/content")
        print("2. Scan file")
        print("3. Scan directory")
        print("4. View statistics")
        print("5. View blocked sources")
        print("6. Exit\033[0m")
        
        try:
            choice = input("\nEnter your choice (1-6): ").strip()
            
            if choice == '1':
                content = input("\nEnter the content to scan: ").strip()
                if not content:
                    print("\033[1;31m[-] Content cannot be empty\033[0m")
                    continue
                
                is_vulnerable, findings = defender.scan_content(content)
                if is_vulnerable:
                    print("\n\033[1;31m[!] WARNING: Information disclosure detected!\033[0m")
                    print("\nFindings:")
                    for finding in findings:
                        print(f"\033[1;31m[-] {finding}\033[0m")
                else:
                    print("\n\033[1;32m[+] No information disclosure detected\033[0m")
                    
            elif choice == '2':
                filepath = input("\nEnter the file path to scan: ").strip()
                if not os.path.isfile(filepath):
                    print("\033[1;31m[-] File does not exist\033[0m")
                    continue
                
                is_vulnerable, findings = defender.scan_file(filepath)
                if is_vulnerable:
                    print(f"\n\033[1;31m[!] WARNING: Information disclosure detected in {filepath}!\033[0m")
                    print("\nFindings:")
                    for finding in findings:
                        print(f"\033[1;31m[-] {finding}\033[0m")
                else:
                    print("\n\033[1;32m[+] No information disclosure detected\033[0m")
                    
            elif choice == '3':
                directory = input("\nEnter the directory path to scan: ").strip()
                if not os.path.isdir(directory):
                    print("\033[1;31m[-] Directory does not exist\033[0m")
                    continue
                
                print("\n[*] Scanning directory...")
                results = defender.scan_directory(directory)
                if results:
                    print("\n\033[1;31m[!] WARNING: Information disclosure detected!\033[0m")
                    for filepath, (_, findings) in results.items():
                        print(f"\n\033[1;31m[!] File: {filepath}\033[0m")
                        for finding in findings:
                            print(f"\033[1;31m[-] {finding}\033[0m")
                else:
                    print("\n\033[1;32m[+] No information disclosure detected\033[0m")
                    
            elif choice == '4':
                stats = defender.get_statistics()
                print("\n\033[1;33m[*] Detection Statistics:\033[0m")
                for key, value in stats.items():
                    print(f"\033[1;33m[-] {key}: {value}\033[0m")
                    
            elif choice == '5':
                if defender.blocked_sources:
                    print("\n\033[1;33m[*] Blocked Sources:\033[0m")
                    for source in defender.blocked_sources:
                        print(f"\033[1;31m[-] {source}\033[0m")
                else:
                    print("\n\033[1;32m[+] No sources have been blocked yet\033[0m")
                    
            elif choice == '6':
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