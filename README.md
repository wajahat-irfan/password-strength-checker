# Password Strength Checker

A command-line tool that scores a password out of 100 and explains how to make it stronger.

**Author:** Wajahat Irfan — BS Computer Science student (7th semester), GPGC No. 1 Abbottabad

## What it does

- Scores a password from 0–100 based on **length** and **character variety** (lowercase, uppercase, numbers, symbols)
- Warns if the password is on a small built-in list of common passwords (`123456`, `password`, `qwerty`, `admin`, `letmein`, …)
- Prints a verdict — Very weak / Weak / Good / Strong — plus practical tips for improvement
- Accepts the password as a command-line argument or via a hidden prompt (so it is not echoed on screen)
- **NEW — crack-time estimate:** shows the estimated entropy (bits) and how long a brute-force attack would take on average, assuming ~10 billion guesses/second (a fast offline GPU attack). Common passwords are flagged as crackable instantly
- **NEW — passphrase generator:** `--generate` creates a random multi-word passphrase (diceware-style, words joined with `-`) from a built-in word list, using cryptographically secure randomness, and scores it right away

## How to run

```bash
python main.py "MyP@ssw0rd!"
python main.py --generate       # 4-word passphrase
python main.py --generate 6     # 6-word passphrase
```

Or enter the password interactively:

```bash
python main.py
```

No extra packages needed — Python 3 standard library only.

## Example output

```
$ python main.py "hello123"
Password length: 8 characters
Score: 50/100 — Weak
Estimated entropy: 41.4 bits
Estimated crack time: 2.4 minutes (at ~10,000,000,000 guesses/second)
Tips to improve it:
  - Add uppercase letters (A-Z).
  - Add symbols (!, @, #, $, ...).
  - Avoid common sequences like '123', 'abc' or words like 'password'.
```

```
$ python main.py --generate
Generated passphrase (4 words): bronze-dagger-basket-fern

Password length: 25 characters
Score: 80/100 — Strong
Estimated entropy: 146.4 bits
Estimated crack time: 193,003,807,343,755,074,862,055,424 years (effectively uncrackable by brute force)
Tips to improve it:
  - Add uppercase letters (A-Z).
  - Add numbers (0-9).
```

```
$ python main.py "password"
WARNING: This password is on the list of most commonly used passwords.
         It can be guessed in seconds. Never use it.
Password length: 8 characters
Score: 10/100 — Very weak
Tips to improve it:
  - Add uppercase letters (A-Z).
  - Add numbers (0-9).
  - Add symbols (!, @, #, $, ...).
  - Avoid common sequences like '123', 'abc' or words like 'password'.
```

## Skills shown

- Python CLI argument handling (`sys.argv`) and secure hidden input (`getpass`)
- Regular expressions for character-class checks
- Scoring / heuristic design and clear user-facing output
- Awareness of common-password attacks and password hygiene
- Entropy estimation and human-readable time formatting
- Secure random passphrase generation with `secrets.choice`
