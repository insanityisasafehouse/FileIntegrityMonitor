import os
import hashlib
import json
from datetime import datetime

# --- Configuration ---
# File to store the baseline hashes.
# This file will be created/updated in the same directory as the script.
HASH_DATABASE_FILE = "file_hashes.json"

# --- Helper Functions ---

def calculate_file_hash(filepath: str, hash_algorithm='sha256') -> str:
    """
    Calculates the cryptographic hash of a file.

    Args:
        filepath (str): The path to the file.
        hash_algorithm (str): The hashing algorithm to use (e.g., 'md5', 'sha1', 'sha256').

    Returns:
        str: The hexadecimal digest of the file's hash, or None if the file cannot be read.
    """
    try:
        # Create a hash object based on the specified algorithm.
        hasher = hashlib.new(hash_algorithm)
        # Open the file in binary read mode.
        with open(filepath, 'rb') as f:
            # Read the file in chunks to handle large files efficiently.
            for chunk in iter(lambda: f.read(4096), b''):
                hasher.update(chunk)
        return hasher.hexdigest()
    except FileNotFoundError:
        print(f"Warning: File not found - {filepath}")
        return None
    except Exception as e:
        print(f"Error calculating hash for {filepath}: {e}")
        return None

def load_baseline_hashes(db_file: str) -> dict:
    """
    Loads the previously stored baseline hashes from a JSON file.

    Args:
        db_file (str): The path to the JSON database file.

    Returns:
        dict: A dictionary containing the baseline hashes, or an empty dictionary if the file doesn't exist or is invalid.
    """
    if os.path.exists(db_file):
        try:
            with open(db_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError:
            print(f"Warning: Corrupted hash database '{db_file}'. Starting with an empty baseline.")
            return {}
        except Exception as e:
            print(f"Error loading baseline hashes from '{db_file}': {e}")
            return {}
    return {}

def save_baseline_hashes(db_file: str, hashes: dict):
    """
    Saves the current file hashes as the new baseline to a JSON file.

    Args:
        db_file (str): The path to the JSON database file.
        hashes (dict): The dictionary of hashes to save.
    """
    try:
        with open(db_file, 'w', encoding='utf-8') as f:
            json.dump(hashes, f, indent=4)
        print(f"Baseline hashes saved to '{db_file}'.")
    except Exception as e:
        print(f"Error saving baseline hashes to '{db_file}': {e}")

def monitor_directory(directory_path: str, db_file: str):
    """
    Monitors a directory for file changes by comparing current hashes
    with a stored baseline.

    Args:
        directory_path (str): The path to the directory to monitor.
        db_file (str): The path to the hash database file.
    """
    if not os.path.isdir(directory_path):
        print(f"Error: Directory not found - '{directory_path}'")
        return

    print(f"\nMonitoring directory: {directory_path}")
    print("-" * 50)

    baseline_hashes = load_baseline_hashes(db_file)
    current_hashes = {}
    
    # Flags to track changes
    files_added = 0
    files_modified = 0
    files_deleted = 0

    # Walk through the directory and calculate hashes for all files
    for root, _, files in os.walk(directory_path):
        for filename in files:
            filepath = os.path.join(root, filename)
            # Normalize path to use as key, making it relative to the monitored directory
            relative_filepath = os.path.relpath(filepath, directory_path)
            
            current_hash = calculate_file_hash(filepath)
            if current_hash:
                current_hashes[relative_filepath] = current_hash

    # Compare current hashes with baseline
    for filepath, current_hash in current_hashes.items():
        if filepath not in baseline_hashes:
            print(f"[+] NEW FILE: {filepath}")
            files_added += 1
        elif baseline_hashes[filepath] != current_hash:
            print(f"[*] MODIFIED FILE: {filepath}")
            files_modified += 1
        # else: File exists and hash matches, no change

    # Check for deleted files
    for filepath in baseline_hashes:
        if filepath not in current_hashes:
            print(f"[-] DELETED FILE: {filepath}")
            files_deleted += 1

    print("\n--- Monitoring Summary ---")
    print(f"Files Added: {files_added}")
    print(f"Files Modified: {files_modified}")
    print(f"Files Deleted: {files_deleted}")

    if files_added == 0 and files_modified == 0 and files_deleted == 0:
        print("No changes detected in monitored files.")
    else:
        print("Changes detected. Consider updating baseline if changes are legitimate.")

    print("-" * 50)
    print("Monitoring complete.")

def main():
    """
    Main function to run the File Integrity Monitor.
    Allows user to set a baseline or check for changes.
    """
    print("-" * 50)
    print("File Integrity Monitor")
    print("-" * 50)

    while True:
        directory_to_monitor = input("Enter the directory path to monitor (e.g., './data', 'q' to quit): ")
        if directory_to_monitor.lower() == 'q':
            break

        if not os.path.isdir(directory_to_monitor):
            print("Invalid directory path. Please enter a valid directory.")
            continue

        print("\nChoose an action:")
        print("1. Set Baseline (first run or after legitimate changes)")
        print("2. Check for Changes")
        choice = input("Enter choice (1 or 2): ")

        if choice == '1':
            print("\nCalculating initial hashes to set baseline...")
            current_hashes = {}
            for root, _, files in os.walk(directory_to_monitor):
                for filename in files:
                    filepath = os.path.join(root, filename)
                    relative_filepath = os.path.relpath(filepath, directory_to_monitor)
                    current_hash = calculate_file_hash(filepath)
                    if current_hash:
                        current_hashes[relative_filepath] = current_hash
            save_baseline_hashes(HASH_DATABASE_FILE, current_hashes)
            print("Baseline successfully set.")
        elif choice == '2':
            monitor_directory(directory_to_monitor, HASH_DATABASE_FILE)
        else:
            print("Invalid choice. Please enter 1 or 2.")
        print("\n" + "=" * 50)

if __name__ == "__main__":
    # Create a dummy directory and file for testing
    if not os.path.exists("test_monitor_dir"):
        os.makedirs("test_monitor_dir")
        with open("test_monitor_dir/test_file.txt", "w") as f:
            f.write("This is a test file.")
        with open("test_monitor_dir/another_file.log", "w") as f:
            f.write("Log entry 1.\nLog entry 2.")
        print("\nCreated 'test_monitor_dir' with sample files for testing.")
        print("You can try modifying 'test_monitor_dir/test_file.txt' or deleting 'test_monitor_dir/another_file.log' after setting a baseline to see changes.")

    main()
