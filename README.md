# Credential Risk Analyzer

A small command-line Python tool that looks at whether passwords that seem strong are actually safe. It evaluates a password using two measures: its **entropy**, which indicates how big the search space would be if someone had to guess it from scratch, and **whether that exact password has appeared in a known data breach**, using the *[Have I Been Pwned](https://haveibeenpwned.com/Passwords) Pwned Passwords API*. Only the first 5 characters of the password's SHA-1 hash are sent to the API, so the password itself never leaves the machine. The two measures are combined into a single risk score from 10 to 100, where a breach match always outweighs entropy.

I started this project after my [XOR encryption tool](https://n0as-ark.github.io/logbook/blog/xor-cipher-excel-password-intro), because encryption is only as strong as its key, and that key is usually password. I wrote about the project as I built it on my blog, starting with [Is a "Strong" Password Actually Safe?](https://n0as-ark.github.io/logbook/blog/is-a-strong-password-actually-safe)

## Status

Complete.

- [x] Entropy calculation (pool-based and Shannon)
- [x] Breach check (k-anonymity)
- [x] Risk score
- [x] Command-line interface (single password or a file of passwords, CSV output)
- [x] Analysis of 354 sample passwords

## Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```
## Usage

Check a single password. If you leave out `--password`, the tool asks for it with a hidden prompt, which keeps it out of your shell history:

```
python -m src.main
```

Check a file of passwords (one per line) and save the results as a CSV:

```
python -m src.main --file passwords.txt --output results.csv
```

Run `python -m src.main --help` for all options.

## How the score works
- If the password has appeared in a breach, the score starts at 80 and rises by 4 for every factor of ten in the breach count, up to 100.
- If it hasn't, the score depends only on entropy, from 70 at 0 bits down to 10 at 80 bits or more.
- Scores below 30 are labelled LOW, 30 to 59 MEDIUM, and 60 and above HIGH.

LOW means no known breach an high entropy. **It does not mean the password is safe**, because *a password that follows a predictable pattern can score LOW*.

## Results

I ran 354 sample passwords (common, pattern-based, and random) through the tool. Entropy separated the common passwords from the rest, but it could not distinguish pattern-based passwords from random ones. The full write-up is in [Same Entropy, Different Exposure](https://n0as-ark.github.io/logbook/blog/same-entropy-different-exposure). The results only show how the tool behaves on these examples and not how passwords behave in general.

## Project layout

```
src/
  entropy.py        entropy calculation
  breach_check.py   Pwned Passwords check (k-anonymity)
  risk_score.py     scoring and labels
  main.py           command-line interface
  passwords/
    random_passwords.py            generates the random passwords
    common_passwords.txt           common passwords
    pattern_based_passwords.txt    pattern-based passwords
    random_passwords.txt           random passwords
    sample_passwords.txt           sample input file
```

## Blog series

1. [Is a "Strong" Password Actually Safe?](https://n0as-ark.github.io/logbook/blog/is-a-strong-password-actually-safe)
2. [How Password Entropy Works (and Where It Misleads)](https://n0as-ark.github.io/logbook/blog/how-password-entropy-works)
3. [How "Have I Been Pwned" Checks Passwords Without Seeing Them](https://n0as-ark.github.io/logbook/blog/checking-passwords-without-revealing-them)
4. [Same Entropy, Different Exposure: Testing My Credential Risk Analyzer](https://n0as-ark.github.io/logbook/blog/same-entropy-different-exposure)

## License

MIT
