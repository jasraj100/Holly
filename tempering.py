import os
import hashlib
import json
import time
from datetime import datetime
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class SystemIntegrityMonitor:
    """
    A system integrity monitoring tool that tracks file changes and maintains audit logs.
    """
    def __init__(self, monitored_paths, baseline_file="baseline.json", log_file="integrity_monitor.log"):
        self.monitored_paths = monitored_paths
        self.baseline_file = baseline_file
        self.baseline = {}
        
        # Set up logging
        logging.basicConfig(
            filename=log_file,
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        
        self.observer = Observer()
        
    def calculate_file_hash(self, filepath):
        """Calculate SHA-256 hash of a file."""
        sha256_hash = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            logging.error(f"Error calculating hash for {filepath}: {str(e)}")
            return None

    def create_baseline(self):
        """Create a baseline of file hashes for monitored paths."""
        for path in self.monitored_paths:
            if os.path.exists(path):
                if os.path.isfile(path):
                    self.baseline[path] = {
                        'hash': self.calculate_file_hash(path),
                        'last_modified': os.path.getmtime(path)
                    }
                elif os.path.isdir(path):
                    for root, _, files in os.walk(path):
                        for file in files:
                            filepath = os.path.join(root, file)
                            self.baseline[filepath] = {
                                'hash': self.calculate_file_hash(filepath),
                                'last_modified': os.path.getmtime(filepath)
                            }
        
        # Save baseline to file
        with open(self.baseline_file, 'w') as f:
            json.dump(self.baseline, f, indent=4)
        logging.info("Baseline created successfully")

    def verify_integrity(self):
        """Verify system integrity against the baseline."""
        if not os.path.exists(self.baseline_file):
            logging.error("Baseline file not found")
            return False

        with open(self.baseline_file, 'r') as f:
            stored_baseline = json.load(f)

        violations = []
        for filepath, stored_data in stored_baseline.items():
            if not os.path.exists(filepath):
                violations.append(f"Missing file: {filepath}")
                continue

            current_hash = self.calculate_file_hash(filepath)
            if current_hash != stored_data['hash']:
                violations.append(f"Modified file: {filepath}")
                logging.warning(f"File integrity violation detected: {filepath}")

        return violations

class FileChangeHandler(FileSystemEventHandler):
    """Handle file system events for real-time monitoring."""
    def on_modified(self, event):
        if not event.is_directory:
            logging.warning(f"File modification detected: {event.src_path}")

    def on_created(self, event):
        if not event.is_directory:
            logging.warning(f"New file created: {event.src_path}")

    def on_deleted(self, event):
        if not event.is_directory:
            logging.warning(f"File deleted: {event.src_path}")

def main():
    # Example usage
    paths_to_monitor = [
        "/path/to/important/files",
        "/path/to/critical/configs"
    ]
    
    monitor = SystemIntegrityMonitor(paths_to_monitor)
    
    # Create initial baseline
    monitor.create_baseline()
    
    # Set up real-time monitoring
    event_handler = FileChangeHandler()
    for path in paths_to_monitor:
        if os.path.exists(path):
            monitor.observer.schedule(event_handler, path, recursive=True)
    
    monitor.observer.start()
    
    try:
        while True:
            # Periodically verify integrity
            violations = monitor.verify_integrity()
            if violations:
                logging.critical("Integrity violations detected:")
                for violation in violations:
                    logging.critical(violation)
            time.sleep(300)  # Check every 5 minutes
            
    except KeyboardInterrupt:
        monitor.observer.stop()
        monitor.observer.join()

if __name__ == "__main__":
    main()