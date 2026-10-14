# Credential Risk Analyzer

A small command-line Python tool that looks at whether passwords that seem strong are actually safe. It evaluates a password using two measures: its **entropy**, which indicates how big the search space would be if someone had to guess it from scratch, and **whether that exact password has appeared in a known data breach**, using the *[Have I Been Pwned](https://haveibeenpwned.com/Passwords) Pwned Passwords API*. Only the first 5 characters of the password's SHA-1 hash are sent to the API, so the password itself never leaves the machine. The two measures will be combined into a single risk score out of 100.

I started this project after my [XOR encryption tool](https://n0as-ark.github.io/logbook/blog/xor-cipher-excel-password-intro), because encryption is only as strong as its key, and that key is usually password. I'm writing about it as I go on my blog, starting with [Is a "Strong" Password Actually Safe?](https://n0as-ark.github.io/logbook/blog/is-a-strong-password-actually-safe)

## Status

Work in progress.

- [x] Entropy calculation (pool-based and Shannon)
- [ ] Breach check
- [ ] Risk score

## Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```