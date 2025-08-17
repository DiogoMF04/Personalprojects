import hashlib
import os
import json
import datetime

# Define the file to store the hashes
HASH_DB_FILE = "file_hashes.json"

def calculate_file_hash(filepath, hash_algorithm="sha256"):
    """
    Calculates the cryptographic hash of a given file.

    Args:
        filepath (str): The path to the file.
        hash_algorithm (str): The hashing algorithm to use (e.g., "md5", "sha1", "sha256").

    Returns:
        str: The hexadecimal digest of the file's hash, or None if an error occurs.
    """
    try:
        # Create a hash object based on the chosen algorithm
        hasher = hashlib.new(hash_algorithm)
        # Read the file in chunks to handle large files efficiently
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hasher.update(chunk)
        return hasher.hexdigest()
    except FileNotFoundError:
        print(f"Error: File not found at '{filepath}'.")
        return None
    except Exception as e:
        print(f"Error calculating hash for '{filepath}': {e}")
        return None

def load_hash_database():
    """
    Loads the stored file hashes from the JSON database file.
    """
    if os.path.exists(HASH_DB_FILE):
        try:
            with open(HASH_DB_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError:
            print(f"Warning: '{HASH_DB_FILE}' is corrupted or empty. Starting with an empty database.")
            return {}
        except Exception as e:
            print(f"Error loading hash database: {e}. Starting with an empty database.")
            return {}
    return {}

def save_hash_database(db):
    """
    Saves the current hash database to the JSON file.
    """
    try:
        with open(HASH_DB_FILE, 'w', encoding='utf-8') as f:
            json.dump(db, f, indent=4)
    except Exception as e:
        print(f"Error saving hash database: {e}")

def add_file_to_monitor(filepath):
    """
    Calculates the hash of a file and adds/updates it in the database.
    """
    db = load_hash_database()
    file_hash = calculate_file_hash(filepath)
    if file_hash:
        db[filepath] = {
            "hash": file_hash,
            "timestamp": datetime.datetime.now().isoformat(),
            "algorithm": "sha256"
        }
        save_hash_database(db)
        print(f"'{filepath}' added/updated in monitoring with hash: {file_hash}")
    else:
        print(f"Failed to add '{filepath}' to monitoring.")

def check_file_integrity(filepath):
    """
    Checks the current hash of a file against its stored hash in the database.
    """
    db = load_hash_database()
    if filepath not in db:
        print(f"'{filepath}' is not currently being monitored. Please add it first.")
        return

    stored_info = db[filepath]
    stored_hash = stored_info["hash"]
    stored_timestamp = stored_info["timestamp"]
    stored_algo = stored_info.get("algorithm", "sha256") # Default to sha256 if not specified

    current_hash = calculate_file_hash(filepath, stored_algo)

    if current_hash is None:
        print(f"Could not calculate current hash for '{filepath}'. Cannot verify integrity.")
        return

    print(f"\n--- Integrity Check for '{filepath}' ---")
    print(f"  Monitored since: {stored_timestamp}")
    print(f"  Stored Hash ({stored_algo}): {stored_hash}")
    print(f"  Current Hash ({stored_algo}): {current_hash}")

    if stored_hash == current_hash:
        print("✅ Integrity OK: File has not been modified.")
    else:
        print("🚨 INTEGRITY COMPROMISED: File has been modified!")
    print("------------------------------------------")

def list_monitored_files():
    """
    Lists all files currently being monitored.
    """
    db = load_hash_database()
    if not db:
        print("No files are currently being monitored.")
        return

    print("\n--- Currently Monitored Files ---")
    for filepath, info in db.items():
        print(f"- {filepath} (Hash: {info['hash']}, Last Monitored: {info['timestamp']})")
    print("-----------------------------------")

def remove_file_from_monitor(filepath):
    """
    Removes a file from the monitoring database.
    """
    db = load_hash_database()
    if filepath in db:
        del db[filepath]
        save_hash_database(db)
        print(f"'{filepath}' removed from monitoring.")
    else:
        print(f"'{filepath}' is not in the monitoring list.")

def run_integrity_checker():
    """
    Main function for the File Integrity Checker CLI.
    """
    print("\n--- File Integrity Checker ---")
    print("This tool helps you monitor files for unauthorized changes.")
    print("Hashes are stored in 'file_hashes.json'.")
    print("------------------------------")

    while True:
        print("\nOptions:")
        print("1. Add/Update file to monitor")
        print("2. Check file integrity")
        print("3. List monitored files")
        print("4. Remove file from monitor")
        print("5. Exit")

        choice = input("Enter your choice (1-5): ")

        if choice == '1':
            filepath = input("Enter the path to the file to add/update: ")
            add_file_to_monitor(filepath)
        elif choice == '2':
            filepath = input("Enter the path to the file to check: ")
            check_file_integrity(filepath)
        elif choice == '3':
            list_monitored_files()
        elif choice == '4':
            filepath = input("Enter the path to the file to remove: ")
            remove_file_from_monitor(filepath)
        elif choice == '5':
            print("Exiting File Integrity Checker. Goodbye!")
            break
        else:
            print("Invalid choice. Please enter a number between 1 and 5.")

if __name__ == "__main__":
    run_integrity_checker()
