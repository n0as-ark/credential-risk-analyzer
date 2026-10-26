import secrets
import string

LOWER = string.ascii_lowercase
UPPER = string.ascii_uppercase
DIGITS = string.digits
SPECIAL = "!@#$%^&*-_+=?"
POOL = LOWER + UPPER + DIGITS + SPECIAL

# Password lengths (in characters) to cycle through, so the random group
# covers a wide range of entropy; every length must be at least 4
LENGTHS = [8, 10, 12, 14, 16, 18, 20, 24]

def random_password(length: int) -> str:
    """return a random password of the given length (at least 4)."""
    # Start with one character from each type so the password
    # always uses the full 75-character pool
    chars = [secrets.choice(group) for group in (LOWER, UPPER, DIGITS, SPECIAL)]

    # Fill the remaining positions from the whole pool
    chars += [secrets.choice(POOL) for _ in range(length - 4)]

    # Shuffle so the guaranteed characters aren't always at the start
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)

def generate_passwords(count: int) -> list[str]:
    """return 'count' number of unique passwords"""
    passwords = []
    while len(passwords) < count:
        length = LENGTHS[len(passwords) % len(LENGTHS)]     # cycle through LENGTH in order
        password = random_password(length)

        # skip the duplicate
        if password not in passwords:
            passwords.append(password)
    return passwords

def main():
    passwords = generate_passwords(110)
    with open("random_passwords.txt","w") as f:
        f.write("\n".join(passwords) + "\n")
    print(f"Wrote {len(passwords)} passwords to random_passwords.txt")

if __name__ == "__main__":
    main()