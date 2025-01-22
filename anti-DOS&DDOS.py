"""
GOLDENHELO - Advanced Anti-DDoS Protection System
Author: Jasraj
Description: Enterprise-grade DDoS protection system with adaptive rate limiting,
            traffic analysis, and automated IP blocking
"""

import time
import threading
import logging
from collections import defaultdict, deque
from datetime import datetime, timedelta
import socket
import struct
import psutil
import numpy as np
from typing import Dict, List, Set, Tuple
import ipaddress

class DDOSDefender:
    def __init__(self):
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('DDOSDefender')
        
        # Traffic tracking
        self.ip_requests = defaultdict(lambda: deque(maxlen=1000))
        self.blocked_ips = set()
        self.suspicious_ips = set()
        self.whitelist = set()
        
        # Configuration
        self.RATE_LIMIT = 100  # requests per second
        self.BURST_LIMIT = 500  # max burst requests
        self.MEMORY_THRESHOLD = 90  # percentage
        self.CPU_THRESHOLD = 90  # percentage
        self.NETWORK_THRESHOLD = 80  # percentage of max bandwidth
        
        # Track system resources
        self.baseline_metrics = self._establish_baseline()
        
        # Initialize monitoring threads
        self._start_monitoring()

    def _establish_baseline(self) -> Dict:
        """Establish baseline system metrics"""
        metrics = {
            'cpu_usage': [],
            'memory_usage': [],
            'network_usage': []
        }
        
        # Collect baseline metrics for 60 seconds
        for _ in range(6):  # 6 samples, 10 seconds each
            cpu = psutil.cpu_percent(interval=10)
            memory = psutil.virtual_memory().percent
            network = self._get_network_usage()
            
            metrics['cpu_usage'].append(cpu)
            metrics['memory_usage'].append(memory)
            metrics['network_usage'].append(network)
        
        return {
            'cpu_baseline': np.mean(metrics['cpu_usage']),
            'memory_baseline': np.mean(metrics['memory_usage']),
            'network_baseline': np.mean(metrics['network_usage'])
        }

    def _start_monitoring(self) -> None:
        """Start monitoring threads"""
        threading.Thread(target=self._monitor_system_resources, daemon=True).start()
        threading.Thread(target=self._clean_old_data, daemon=True).start()
        threading.Thread(target=self._analyze_traffic_patterns, daemon=True).start()

    def _monitor_system_resources(self) -> None:
        """Monitor system resources and adjust thresholds"""
        while True:
            cpu_usage = psutil.cpu_percent()
            memory_usage = psutil.virtual_memory().percent
            network_usage = self._get_network_usage()
            
            # Adjust rate limits based on system load
            self._adjust_rate_limits(cpu_usage, memory_usage, network_usage)
            
            # Log suspicious activity
            if cpu_usage > self.CPU_THRESHOLD or \
               memory_usage > self.MEMORY_THRESHOLD or \
               network_usage > self.NETWORK_THRESHOLD:
                self.logger.warning(f"High resource usage detected - CPU: {cpu_usage}%, "
                                  f"Memory: {memory_usage}%, Network: {network_usage}%")
                
            time.sleep(1)

    def _get_network_usage(self) -> float:
        """Get current network usage percentage"""
        net_io = psutil.net_io_counters()
        return (net_io.bytes_sent + net_io.bytes_recv) / 1024 / 1024  # MB

    def _adjust_rate_limits(self, cpu_usage: float, memory_usage: float, 
                          network_usage: float) -> None:
        """Dynamically adjust rate limits based on system load"""
        # Calculate load factor
        load_factor = max(cpu_usage / self.CPU_THRESHOLD,
                         memory_usage / self.MEMORY_THRESHOLD,
                         network_usage / self.NETWORK_THRESHOLD)
        
        if load_factor > 1:
            # Reduce rate limits under high load
            self.RATE_LIMIT = max(10, int(self.RATE_LIMIT / load_factor))
            self.BURST_LIMIT = max(50, int(self.BURST_LIMIT / load_factor))
        else:
            # Gradually restore original limits
            self.RATE_LIMIT = min(100, int(self.RATE_LIMIT * 1.1))
            self.BURST_LIMIT = min(500, int(self.BURST_LIMIT * 1.1))

    def _analyze_traffic_patterns(self) -> None:
        """Analyze traffic patterns for attack signatures"""
        while True:
            current_time = time.time()
            
            for ip, requests in self.ip_requests.items():
                if ip in self.whitelist:
                    continue
                    
                # Calculate request statistics
                if len(requests) > 0:
                    time_window = current_time - requests[0]
                    request_rate = len(requests) / time_window if time_window > 0 else float('inf')
                    
                    # Check for attack patterns
                    if self._detect_attack_pattern(requests, request_rate):
                        self.block_ip(ip)
                        self.logger.warning(f"Attack pattern detected from {ip}")
            
            time.sleep(5)

    def _detect_attack_pattern(self, requests: deque, rate: float) -> bool:
        """
        Detect various attack patterns
        Returns: True if attack pattern detected
        """
        if rate > self.RATE_LIMIT:
            return True
            
        # Check for suspicious patterns
        request_times = list(requests)
        if len(request_times) > 10:
            # Check for perfectly timed requests (bot behavior)
            intervals = np.diff(request_times)
            if np.std(intervals) < 0.1:
                return True
            
            # Check for exponential growth in request rate
            if self._detect_exponential_growth(request_times):
                return True
        
        return False

    def _detect_exponential_growth(self, times: List[float]) -> bool:
        """Detect exponential growth in request rate"""
        if len(times) < 10:
            return False
            
        # Calculate request rates over time
        windows = np.array_split(times, 5)
        rates = [len(w) / (w[-1] - w[0]) for w in windows if len(w) > 1]
        
        # Check if rates are increasing exponentially
        if len(rates) > 2:
            growth_factors = [rates[i+1]/rates[i] for i in range(len(rates)-1)]
            return all(f > 1.5 for f in growth_factors)
            
        return False

    def _clean_old_data(self) -> None:
        """Clean old request data periodically"""
        while True:
            current_time = time.time()
            
            # Remove old requests
            for ip in list(self.ip_requests.keys()):
                self.ip_requests[ip] = deque(
                    [t for t in self.ip_requests[ip] if current_time - t < 3600],
                    maxlen=1000
                )
                
                # Remove IP from tracking if no recent requests
                if len(self.ip_requests[ip]) == 0:
                    del self.ip_requests[ip]
            
            # Periodically unblock IPs that have been blocked for a while
            for ip in list(self.blocked_ips):
                if self._can_unblock_ip(ip):
                    self.blocked_ips.remove(ip)
                    self.logger.info(f"Unblocked IP: {ip}")
            
            time.sleep(300)  # Clean every 5 minutes

    def _can_unblock_ip(self, ip: str) -> bool:
        """Check if an IP can be unblocked based on its history"""
        # Implementation would depend on your specific criteria
        return True

    def handle_request(self, ip: str, request_data: Dict) -> bool:
        """
        Handle incoming request and determine if it should be blocked
        Returns: True if request is allowed, False if it should be blocked
        """
        if ip in self.whitelist:
            return True
            
        if ip in self.blocked_ips:
            return False
            
        # Record request time
        current_time = time.time()
        self.ip_requests[ip].append(current_time)
        
        # Check rate limiting
        recent_requests = len([t for t in self.ip_requests[ip] 
                             if current_time - t < 1])
        
        if recent_requests > self.RATE_LIMIT:
            self.block_ip(ip)
            return False
            
        # Check for burst attacks
        if len(self.ip_requests[ip]) > self.BURST_LIMIT:
            self.block_ip(ip)
            return False
        
        return True

    def block_ip(self, ip: str) -> None:
        """Block an IP address"""
        if ip not in self.blocked_ips:
            self.blocked_ips.add(ip)
            self.logger.warning(f"Blocked IP: {ip}")
            
            # Implement actual IP blocking (e.g., using iptables)
            self._implement_ip_block(ip)

    def _implement_ip_block(self, ip: str) -> None:
        """Implement actual IP blocking using system firewall"""
        try:
            # Example using iptables (requires root privileges)
            import subprocess
            cmd = f"iptables -A INPUT -s {ip} -j DROP"
            subprocess.run(cmd.split(), check=True)
        except Exception as e:
            self.logger.error(f"Failed to implement IP block: {e}")

def main():
    """Example usage of DDOSDefender"""
    defender = DDOSDefender()
    
    # Example simulation of requests
    test_ips = ['192.168.1.100', '10.0.0.50', '172.16.0.1']
    
    print("Testing DDoS protection:")
    for ip in test_ips:
        # Simulate normal traffic
        print(f"\nTesting traffic from {ip}")
        for _ in range(10):
            allowed = defender.handle_request(ip, {})
            print(f"Request allowed: {allowed}")
            time.sleep(0.1)
        
        # Simulate attack traffic
        print(f"\nSimulating attack from {ip}")
        for _ in range(200):
            allowed = defender.handle_request(ip, {})
            if not allowed:
                print(f"Attack detected and blocked from {ip}")
                break

if __name__ == "__main__":
    main()