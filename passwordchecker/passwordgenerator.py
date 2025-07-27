import random
import string

def generate_password(size):
    """
    Generates a strong, random password of a specified size.
    It guarantees at least one uppercase letter, one lowercase letter,
    one digit, and one special character if the size allows (>= 4).
    The remaining characters are chosen randomly from all possible types,
    and the final password is shuffled for maximum unpredictability.

    Args:
        size (int): The desired length of the password.

    Returns:
        str: The generated password.
    """
    if not isinstance(size, int) or size <= 0:
        raise ValueError("Password size must be a positive integer.")

    # Define character sets
    lowercase_chars = string.ascii_lowercase
    uppercase_chars = string.ascii_uppercase
    digit_chars = string.digits
    special_chars = string.punctuation # Includes common special characters

    # Combine all characters into one pool for general random selection
    all_chars = lowercase_chars + uppercase_chars + digit_chars + special_chars

    password_characters = []

    # Ensure at least one of each character type if size permits
    if size >= 4:
        password_characters.append(random.choice(lowercase_chars))
        password_characters.append(random.choice(uppercase_chars))
        password_characters.append(random.choice(digit_chars))
        password_characters.append(random.choice(special_chars))

        # Fill the remaining length with random characters from the combined pool
        for _ in range(size - 4):
            password_characters.append(random.choice(all_chars))
    else:
        # If size is less than 4, just pick random characters from the combined pool
        # It won't guarantee all types, but will use the full range available.
        for _ in range(size):
            password_characters.append(random.choice(all_chars))

    # Shuffle the list of characters to ensure randomness in position
    random.shuffle(password_characters)

    # Join the characters to form the final password string
    generated_pwd = "".join(password_characters)
    return generated_pwd

def main():
    """
    Main function to get user input for password size and display the generated password.
    """
    print("\n✨ Random Password Generator ✨")
    print("----------------------------------")
    print("Generate a strong password of your desired length.")
    print("Press Ctrl+C or type 'exit' to quit.")
    print("----------------------------------\n")

    try:
        while True:
            try:
                user_input = input("Enter desired password length (e.g., 12, 16, 20) or 'exit': ")
                if user_input.lower() == 'exit':
                    break

                size = int(user_input)
                if size <= 0:
                    print("\n🚫 Please enter a positive integer for password length.\n")
                    continue
                elif size < 4:
                    print("\n⚠️ Warning: For passwords less than 4 characters, it's hard to guarantee all character types.\n")

                password = generate_password(size)

                print("\n" + "=" * 40)
                print(f"Generated Password ({size} chars): {password}")
                print("=" * 40 + "\n")

            except ValueError:
                print("\n🚫 Invalid input. Please enter a number or 'exit'.\n")
            except Exception as e:
                print(f"\nAn unexpected error occurred: {e}\n")

    except KeyboardInterrupt:
        print("\nExiting Password Generator. Goodbye! 👋")

if __name__ == "__main__":
    main()
