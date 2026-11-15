#!/usr/bin/env python3
"""
Password Strength Checker
--------------------------
A simple CLI tool that scores a password out of 100 based on length and
character variety, warns if the password appears in a small list of
commonly used (and therefore easily guessed) passwords, and estimates
how long the password would take to crack. It can also generate a
random multi-word passphrase (diceware-style) from a built-in word list.

Usage:
    python main.py "MyP@ssw0rd!"
    python main.py                     # prompts for a password (hidden input)
    python main.py --generate          # generate a 4-word passphrase
    python main.py --generate 6        # generate a 6-word passphrase
"""

import getpass
import math
import re
import secrets
import sys

# Small built-in list of very common passwords. These are publicly known
# examples from leaked-password lists — never use any of them.
COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345",
    "1234567", "qwerty", "abc123", "password1", "111111",
    "123123", "admin", "letmein", "welcome", "monkey",
    "dragon", "football", "iloveyou", "master", "sunshine",
}

# Built-in word list for passphrase generation. Short, common English
# words — a passphrase is strong because it is long, not because the
# words are obscure. Words are picked with `secrets` (cryptographically
# secure randomness).
WORDLIST = [
    "apple", "anchor", "arrow", "autumn", "banana", "banner", "basket",
    "beach", "beacon", "berry", "bicycle", "blanket", "blossom", "blue",
    "board", "bottle", "branch", "brave", "bread", "bridge", "bright",
    "breeze", "bronze", "brook", "bubble", "bucket", "butter", "cabin",
    "camel", "candle", "canyon", "castle", "cedar", "chair", "cheese",
    "cherry", "chess", "chicken", "circle", "citrus", "cliff", "clock",
    "cloud", "coffee", "comet", "copper", "coral", "cotton", "couch",
    "crane", "crystal", "curtain", "dagger", "daisy", "dance", "dawn",
    "delta", "desert", "diamond", "dinner", "diver", "doctor", "dog",
    "dollar", "dolphin", "donkey", "door", "dragon", "dream", "drift",
    "drum", "duck", "eagle", "earth", "echo", "eclipse", "edge",
    "elder", "elephant", "ember", "engine", "falcon", "feather", "fern",
    "field", "figure", "fire", "fisher", "flame", "flute", "forest",
    "fossil", "fox", "frost", "galaxy", "garden", "garlic", "gem",
    "giant", "ginger", "glacier", "globe", "gold", "goose", "grain",
    "grape", "grass", "green", "guitar", "hammer", "harbor", "hawk",
    "hazel", "heart", "heaven", "helmet", "heron", "honey", "horse",
    "house", "hunter", "ice", "ink", "iron", "island", "ivory", "jade",
    "jacket", "jazz", "jelly", "jewel", "journey", "jungle", "keeper",
    "kettle", "king", "kite", "kitten", "knight", "ladder", "lake",
    "lamp", "lantern", "leaf", "lemon", "leopard", "letter", "light",
    "lily", "lion", "lizard", "llama", "locket", "lotus", "lumber",
    "lunar", "magic", "maple", "marble", "market", "marsh", "meadow",
    "melon", "mercury", "metal", "meteor", "midnight", "mango", "mist",
    "monkey", "moon", "moss", "mountain", "mouse", "music", "napkin",
    "needle", "nest", "nickel", "night", "noble", "north", "novel",
    "oak", "oasis", "ocean", "olive", "onion", "opal", "orange",
    "orchard", "otter", "owl", "oyster", "palm", "panda", "paper",
    "parrot", "peach", "pearl", "pebble", "pelican", "pencil", "penguin",
    "pepper", "petal", "phoenix", "piano", "picnic", "pilot", "pine",
    "pirate", "planet", "plaza", "plum", "pocket", "poem", "polar",
    "pond", "pony", "poplar", "porch", "prairie", "prism", "pumpkin",
    "puzzle", "quartz", "queen", "quest", "rabbit", "radar", "rainbow",
    "raven", "reef", "ribbon", "rice", "rider", "ridge", "river",
    "robin", "robot", "rocket", "rock", "rose", "ruby", "saddle",
    "sailor", "salmon", "salt", "sand", "sapphire", "saturn", "scale",
    "scarlet", "school", "scout", "sea", "seal", "seed", "shadow",
    "shark", "sheep", "shell", "shield", "ship", "silver", "singer",
    "sister", "skate", "sky", "slate", "sleep", "snow", "soap",
    "soccer", "soda", "solar", "song", "sorrel", "sparrow", "spice",
    "spider", "spoon", "spring", "squirrel", "stable", "star", "steel",
    "stone", "storm", "straw", "stream", "street", "sugar", "summer",
    "sun", "sunset", "surf", "swan", "sweet", "swift", "sword",
    "table", "tango", "taste", "tea", "temple", "tent", "tiger",
    "timber", "toast", "tobacco", "tomato", "topaz", "torch", "tower",
    "train", "travel", "tree", "treasure", "trumpet", "tulip", "tunnel",
    "turkey", "turtle", "umbrella", "valley", "velvet", "venus", "violet",
    "violin", "volcano", "voyage", "walnut", "wander", "warrior", "water",
    "wave", "weather", "weaver", "whale", "wheat", "wheel", "whisper",
    "willow", "wind", "window", "wing", "winter", "wisdom", "wolf",
    "wood", "wool", "world", "yellow", "yoga", "youth", "zebra", "zenith",
]

# Assumed attacker speed for the crack-time estimate: 10 billion guesses
# per second (a fast offline attack with modern GPUs). This is a rough
# estimate, not a guarantee — a password in a leaked list or a common
# pattern can be guessed far faster.
GUESSES_PER_SECOND = 10_000_000_000


def score_password(password: str) -> tuple[int, list[str]]:
    """Return (score out of 100, list of tips)."""
    score = 0
    tips = []

    length = len(password)

    # Length: up to 40 points
    if length >= 16:
        score += 40
    elif length >= 12:
        score += 30
    elif length >= 8:
        score += 20
    elif length >= 6:
        score += 10
    else:
        tips.append("Use at least 12 characters (16+ is better).")

    # Character variety: up to 40 points (10 each)
    if re.search(r"[a-z]", password):
        score += 10
    else:
        tips.append("Add lowercase letters (a-z).")

    if re.search(r"[A-Z]", password):
        score += 10
    else:
        tips.append("Add uppercase letters (A-Z).")

    if re.search(r"[0-9]", password):
        score += 10
    else:
        tips.append("Add numbers (0-9).")

    if re.search(r"[^a-zA-Z0-9]", password):
        score += 10
    else:
        tips.append("Add symbols (!, @, #, $, ...).")

    # Bonus: no repeated character runs / no simple sequences (up to 20)
    if not re.search(r"(.)\1\1", password):
        score += 10
    else:
        tips.append("Avoid repeating the same character 3+ times in a row.")

    if not re.search(r"(123|abc|qwe|password|admin)", password.lower()):
        score += 10
    else:
        tips.append("Avoid common sequences like '123', 'abc' or words like 'password'.")

    return min(score, 100), tips


def verdict(score: int) -> str:
    if score >= 80:
        return "Strong"
    if score >= 60:
        return "Good"
    if score >= 40:
        return "Weak"
    return "Very weak"


def estimate_entropy(password: str) -> float:
    """Estimate entropy in bits from the character sets used."""
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"[0-9]", password):
        pool += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        pool += 32  # common printable symbols
    if pool == 0:
        return 0.0
    return len(password) * math.log2(pool)


def format_duration(seconds: float) -> str:
    """Turn a number of seconds into a human-readable duration."""
    if seconds < 1:
        return "less than a second"
    if seconds < 60:
        return f"{seconds:.1f} seconds"
    minutes = seconds / 60
    if minutes < 60:
        return f"{minutes:.1f} minutes"
    hours = minutes / 60
    if hours < 24:
        return f"{hours:.1f} hours"
    days = hours / 24
    if days < 365:
        return f"{days:.1f} days"
    years = days / 365.25
    if years < 100:
        return f"{years:.1f} years"
    if years < 1_000_000:
        return f"{years:,.0f} years"
    return f"{years:,.0f} years (effectively uncrackable by brute force)"


def estimate_crack_time(password: str) -> str:
    """Estimate how long a brute-force attack would take, on average.

    Assumes the attacker must try half of all possible combinations at
    GUESSES_PER_SECOND guesses per second. Common passwords are guessed
    instantly, whatever the estimate says.
    """
    entropy = estimate_entropy(password)
    combinations = 2 ** entropy
    seconds = (combinations / 2) / GUESSES_PER_SECOND
    return format_duration(seconds)


def generate_passphrase(word_count: int = 4) -> str:
    """Generate a random passphrase of `word_count` words joined by '-'."""
    words = [secrets.choice(WORDLIST) for _ in range(word_count)]
    return "-".join(words)


def check_and_print(password: str) -> None:
    is_common = password.lower() in COMMON_PASSWORDS
    score, tips = score_password(password)
    if is_common:
        score = min(score, 10)
        print("WARNING: This password is on the list of most commonly used passwords.")
        print("         It can be guessed in seconds. Never use it.")

    print(f"Password length: {len(password)} characters")
    print(f"Score: {score}/100 — {verdict(score)}")
    entropy = estimate_entropy(password)
    print(f"Estimated entropy: {entropy:.1f} bits")
    if is_common:
        print("Estimated crack time: instantly (common password)")
    else:
        print(
            "Estimated crack time: "
            f"{estimate_crack_time(password)} "
            f"(at ~{GUESSES_PER_SECOND:,} guesses/second)"
        )
    if tips:
        print("Tips to improve it:")
        for tip in tips:
            print(f"  - {tip}")
    else:
        print("No improvement tips — good password habits!")


def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] in ("--generate", "-g", "--passphrase"):
        word_count = 4
        if len(sys.argv) > 2:
            try:
                word_count = int(sys.argv[2])
            except ValueError:
                print("Error: word count must be a number, e.g. --generate 6")
                sys.exit(1)
        if not 3 <= word_count <= 10:
            print("Error: word count must be between 3 and 10.")
            sys.exit(1)
        passphrase = generate_passphrase(word_count)
        print(f"Generated passphrase ({word_count} words): {passphrase}")
        print()
        check_and_print(passphrase)
        return

    if len(sys.argv) > 1:
        password = sys.argv[1]
    else:
        password = getpass.getpass("Enter password to check: ")

    if not password:
        print("No password entered.")
        sys.exit(1)

    check_and_print(password)


if __name__ == "__main__":
    main()
