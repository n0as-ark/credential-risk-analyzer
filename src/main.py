import argparse
import getpass
import requests
import sys
import csv

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
    result['Shannon Entropy'] = round(shannon_bits,2)
    result['Breach Status Known'] = known
    result['Masked Password'] = mask_password(password)

    return result

def mask_password(password:str) -> str:
    """return a masked version of the password (only first + last char visible)
    """
    if len(password) <=2:
        return "*" * len(password)
    return password[0] + "*" * (len(password) - 2) + password[-1]

def print_result(masked_password: str, result: dict) -> None:
    print(f"\n  Password:               {masked_password}")
    print(f"  Entropy (Pool-based):   {round(result['Entropy'],2)} bits")
    print(f"  Entropy (Shannon):      {round(result['Shannon Entropy'],2)} bits")

    if result['Breach Status Known']:
        if result['Breach Count'] >0:
            print(f"  Breach Status:          FOUND in {result['Breach Count']:,} breaches")
        else:
            print(f"  Breach Status:          Not found in known breaches")
    else:
        print(f"  Breach Status:          UNKNOWN (offline mode or API error)")

    print(f"  Risk Score:             {round(result['Risk Score'],2)} / 100")
    print(f"  Risk Label:             {result['Risk Label']}")

def write_csv(results: list, output_path: str) -> None:
    fieldnames = [
        "Masked Password", "Entropy", "Shannon Entropy",
        "Breach Count", "Breach Status", "Risk Score", "Risk Label"
    ]
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for result in results:
            writer.writerow({k: result[k] for k in fieldnames})
    print(f"\nResults written to {output_path}")

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

    parser.add_argument(
        "--file", help="Path to a text file with one password per line (batch mode)"
    )

    parser.add_argument(
        "--output", help="Path to write a CSV report (batch mode only)"
    )

    args = parser.parse_args()
    if args.file:
        with open(args.file, "r") as f:
            passwords = [line.strip() for line in f if line.strip()]

        results = []
        for pw in passwords:
            result = analyze_password(pw, offline=args.offline)
            print_result(result['Masked Password'], result)
            results.append(result)

        if args.output:
            write_csv(results, args.output)
    else:
        password = args.password or getpass.getpass("Enter password to check: ")
        result = analyze_password(password, offline=args.offline)
        print_result(result['Masked Password'], result)

if __name__ == "__main__":
    main()