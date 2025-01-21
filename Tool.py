import os
import subprocess
import requests

def print_banner():
    """Print the program banner."""
    banner = r"""
     _    _       _      
    | |  | |     | |   
    | |__| | ___ | |  
    |  __  |/ _ \| |
    | |  | | (_) | |
    |_|  |_|\___/|_|

     HOLLY - Jasraj Choudhary
    """
    print(banner)

def download_wordlist():
    """Download a large password list from a GitHub repository."""
    url = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt"
    wordlist_path = "wordlist.txt"

    if not os.path.exists(wordlist_path):
        print("Downloading wordlist...")
        try:
            response = requests.get(url, stream=True)
            response.raise_for_status()
            with open(wordlist_path, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            print("Wordlist downloaded successfully.")
        except Exception as e:
            print(f"Failed to download wordlist: {e}")
    else:
        print("Wordlist already exists.")

    return wordlist_path

def run_john(hash_file, wordlist):
    """Run John the Ripper on a hash file."""
    try:
        print("Running John the Ripper...")
        command = ["john", hash_file, "--wordlist", wordlist]
        subprocess.run(command, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error running John the Ripper: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")

def run_hashcat(hash_file, hash_type, wordlist):
    """Run Hashcat on a hash file."""
    try:
        print("Running Hashcat...")
        command = ["hashcat", "-m", hash_type, hash_file, wordlist]
        subprocess.run(command, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error running Hashcat: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")

def validate_file(file_path, expected_type):
    """Validate the file path and type."""
    if not os.path.exists(file_path):
        print(f"Error: The specified {expected_type} file does not exist.")
        return False

    if os.path.getsize(file_path) == 0:
        print(f"Error: The specified {expected_type} file is empty.")
        return False

    return True

def main():
    # Print the program banner
    print_banner()

    # Automatically download the wordlist
    wordlist_path = download_wordlist()

    print("Choose an option:")
    print("1. Use John the Ripper")
    print("2. Use Hashcat")

    choice = input("Enter your choice (1 or 2): ").strip()

    if choice == "1":
        hash_file = input("Enter the path to the hash file for John the Ripper: ").strip()
        if not validate_file(hash_file, "hash"):
            return
        if hash_file == wordlist_path:
            print("Error: The hash file cannot be the same as the wordlist.")
            return
        run_john(hash_file, wordlist_path)
    elif choice == "2":
        hash_file = input("Enter the path to the hash file for Hashcat: ").strip()
        if not validate_file(hash_file, "hash"):
            return
        if hash_file == wordlist_path:
            print("Error: The hash file cannot be the same as the wordlist.")
            return
        hash_type = input("Enter the hash type for Hashcat: ").strip()
        run_hashcat(hash_file, hash_type, wordlist_path)
    else:
        print("Invalid choice. Please restart the program and select either 1 or 2.")

if __name__ == "__main__":
    main()
