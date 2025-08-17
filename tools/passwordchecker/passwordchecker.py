import re
import string
import math
import getpass # For securely getting password input without showing it

def calculate_entropy(password):
    """
    Calculates the Shannon entropy of a password.
    Entropy measures the unpredictability of a password. Higher is better.
    Formula: Entropy = log2(R^L) = L * log2(R)
    Where:
        L = Length of the password
        R = Size of the character set (charset) used in the password
    """
    charset_size = 0
    
    # Estimate the size of the character set based on types of characters present
    if re.search(r"[a-z]", password):
        charset_size += 26  # Lowercase letters
    if re.search(r"[A-Z]", password):
        charset_size += 26  # Uppercase letters
    if re.search(r"\d", password):
        charset_size += 10  # Digits (0-9)
    # Common special characters (excluding space for simplicity in this calculation)
    if re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?`~]", password):
        charset_size += len("!@#$%^&*()_+-=[]{};':\"\\|,.<>/?`~") # Approx 32-33 common ones
    
    if charset_size == 0: # Handle empty or completely unrecognized character sets
        return 0.0

    password_length = len(password)
    if password_length == 0:
        return 0.0

    entropy = password_length * math.log2(charset_size)
    return entropy

def check_password_strength(password, common_passwords=None):
    """
    Checks the strength of a password based on several criteria and provides feedback.
    Includes entropy calculation and optional common password check.
    Returns a tuple: (strength_label, score, entropy, feedback_messages)
    """
    score = 0
    feedback = []

    # Criteria weights and minimums
    min_length = 12 # Increased minimum length for better security
    has_uppercase_weight = 1
    has_lowercase_weight = 1
    has_digit_weight = 1
    has_special_weight = 1
    
    # Entropy calculation
    entropy = calculate_entropy(password)

    # 1. Length
    if len(password) >= min_length:
        score += 2
    else:
        feedback.append(f"Password should be at least {min_length} characters long. (Currently {len(password)})")

    # 2. Character types
    has_uppercase = bool(re.search(r"[A-Z]", password))
    has_lowercase = bool(re.search(r"[a-z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_special = bool(re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?`~]", password))

    if has_uppercase:
        score += has_uppercase_weight
    else:
        feedback.append("Include uppercase letters (A-Z).")

    if has_lowercase:
        score += has_lowercase_weight
    else:
        feedback.append("Include lowercase letters (a-z).")

    if has_digit:
        score += has_digit_weight
    else:
        feedback.append("Include numbers (0-9).")

    if has_special:
        score += has_special_weight
    else:
        feedback.append("Include special characters (e.g., !@#$%^&*).")

    # 3. Variety of character types (bonus points for combining types)
    character_types_count = sum([has_uppercase, has_lowercase, has_digit, has_special])
    if character_types_count >= 3:
        score += 1
    if character_types_count == 4:
        score += 1

    # 4. Check for common patterns (e.g., sequences, repeated characters)
    if re.search(r"(.)\1\1\1", password): # Four or more repeated characters
        score -= 2 # Deduct more for longer repetitions
        feedback.append("Avoid repeating characters four or more times (e.g., 'aaaa').")
    
    # Simple check for common sequences (e.g., "abc", "123")
    common_sequences = ["abc", "123", "qwe", "asd", "zxc", "poi", "lkj", "pkm", "098", "654"]
    for seq in common_sequences:
        if seq in password.lower() or seq[::-1] in password.lower():
            score -= 1
            feedback.append(f"Avoid common keyboard sequences like '{seq}'.")
            break

    # 5. Dictionary Attack Prevention (check against common_passwords list)
    if common_passwords and password.lower() in common_passwords:
        score = 0 # Mark as very weak regardless of other factors
        feedback = ["This password is a very common and easily guessed password. Choose a unique one!"]
        strength_label = "🚨 EXTREMELY WEAK (Common Password)"
        return strength_label, score, entropy, feedback

    # Categorize strength based on score and entropy
    # Entropy thresholds are generally:
    # < 28 bits: Very Weak (brute-forced in seconds/minutes)
    # 28-35 bits: Weak
    # 36-59 bits: Reasonable
    # 60-127 bits: Strong
    # >= 128 bits: Very Strong
    
    if entropy >= 60 and score >= 7:
        strength_label = "💪 Excellent"
    elif entropy >= 40 and score >= 5:
        strength_label = "👍 Strong"
    elif entropy >= 28 and score >= 3:
        strength_label = "👌 Medium"
    else:
        strength_label = "🚩 Weak"

    # Further adjust if length is still an issue despite score
    if len(password) < 8: # A hard lower bound for length
        strength_label = "🚩 Very Weak (Too Short)"
        if "Password should be at least" not in " ".join(feedback):
             feedback.append("Password is too short. Aim for at least 8 characters.")

    return strength_label, score, entropy, feedback

def load_common_passwords(filepath="common_passwords.txt"):
    """Loads a list of common passwords from a text file."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            # Read and convert to lowercase for case-insensitive comparison
            return {line.strip().lower() for line in f if line.strip()}
    except FileNotFoundError:
        print(f"Warning: '{filepath}' not found. Dictionary attack prevention disabled.")
        print("Download a common password list (e.g., rockyou.txt) and place it in the same directory.")
        return None
    except Exception as e:
        print(f"Error loading common passwords: {e}")
        return None

def main():
    """
    Main function for a user-friendly password strength checker.
    """
    print("\n✨ Password Strength Analyzer ✨")
    print("----------------------------------")
    print("This tool helps you create stronger passwords.")
    print("Press Ctrl+C or type 'exit' to quit.")
    print("----------------------------------\n")

    # Load common passwords once at the start
    print("Loading common passwords for dictionary attack check...")
    # For a real scenario, use a smaller, curated list for performance,
    # or implement a more advanced data structure (e.g., a Bloom filter)
    # for very large lists like rockyou.txt (which is very large).
    # For a beginner project, a smaller list (e.g., top 100k) is fine.
    common_passwords_set = load_common_passwords()
    if common_passwords_set:
        print(f"Loaded {len(common_passwords_set)} common passwords.")
    print("-" * 30)

    try:
        while True:
            # Use getpass to hide input for better security and user experience
            password = getpass.getpass("Enter your password: ")
            
            if password.lower() == 'exit':
                break

            if not password:
                print("\n🚫 Password cannot be empty. Please try again.\n")
                continue

            strength_label, score, entropy, feedback = check_password_strength(password, common_passwords_set)

            print("\n" + "=" * 40)
            print(f"🔑 Password Analysis for: {'*' * len(password)}")
            print(f"   Strength: {strength_label}")
            print(f"   Score: {score}/~9 (Higher is better)")
            print(f"   Entropy: {entropy:.2f} bits (Aim for 60+ for strong)")
            
            if feedback:
                print("\n💡 Suggestions for Improvement:")
                for item in feedback:
                    print(f"   - {item}")
            else:
                print("\n🎉 Excellent! This password meets all recommended criteria and is strong.")
            print("=" * 40 + "\n")
            
    except KeyboardInterrupt:
        print("\nExiting Password Strength Analyzer. Goodbye! 👋")
    except Exception as e:
        print(f"\nAn unexpected error occurred: {e}")

if __name__ == "__main__":
    main()