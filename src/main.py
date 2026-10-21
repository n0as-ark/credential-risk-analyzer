import argparse
import getpass
import requests
import sys

from entropy import calculate_entropy, calculate_shannon_entropy
from breach_check import check_breach
from risk_score import analyze

def analyze_password(password: str, offline: bool = False) -> dict:
    """run the full pipeline for the given password: entropy + breach check + score.

    
    """
    entropy_bits = calculate_entropy(password)
    shannon_bits = calculate_shannon_entropy(password)

    breach_count = None     # None = not checked / unknown

    if not offline:
        try:
            breach_count = check_breach(password)
        except requests.RequestException as exc:
            # Network or API failure: warn the user instead of crashing.
            # Goes to stderr so it doesn't mix with results if output is redirected.
            print(
                f"  [!] Warning: breach check failed ({exc}). "
                f"Treating breach status as unknown for this password.",
                file=sys.stderr,
            )
            breach_count = None

    known = breach_count is not None
    result = analyze(entropy_bits, breach_count if known else 0)
    result['Shannon Entropy'] = shannon_bits
    result['Breach Status Known'] = known

    return result

def main():
    parser = argparse.ArgumentParser(
        description="Credential Risk Analyzer -- combines entropy and "
                    "breach data into a single password risk score."
    )

    parser.add_argument(
        "--password",
        help="Password to analyze directly (visible in shell history -- "
             "prefer leaving this out to get a hidden prompt instead)",
    )

    parser.add_argument(
        "--offline", action="store_true",
        help="Skip the online HIBP breach check entirely (entropy-only)",
    )

    args = parser.parse_args()

    password = args.password or getpass.getpass("Enter password to check: ")
    result = analyze_password(password, offline=args.offline)

if __name__ == "__main__":
    main()