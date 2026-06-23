"""
Secure Random Password Generator
Backend: Python + Flask
Frontend: HTML + CSS (+ small vanilla JS for copy/theme/slider)
"""

import os
import csv
import math
import string
import secrets
from datetime import datetime

from flask import Flask, render_template, request, redirect, url_for, session, send_file, flash

app = Flask(__name__)

HISTORY_FILE = os.path.join(os.path.dirname(__file__), "history.txt")
EXPORT_FILE = os.path.join(os.path.dirname(__file__), "passwords.csv")
SECRET_KEY_FILE = os.path.join(os.path.dirname(__file__), ".secret_key")


def load_secret_key():
    """
    Secret key resolution order:
    1. SECRET_KEY environment variable (recommended for production/deployment)
    2. A locally generated key cached in .secret_key (so sessions survive restarts
       during local development, without ever hardcoding a key in source control)
    3. As a last resort, generate a fresh one for this run only
    """
    env_key = os.environ.get("SECRET_KEY")
    if env_key:
        return env_key

    if os.path.exists(SECRET_KEY_FILE):
        with open(SECRET_KEY_FILE, "r", encoding="utf-8") as f:
            cached = f.read().strip()
            if cached:
                return cached

    new_key = secrets.token_hex(32)
    try:
        with open(SECRET_KEY_FILE, "w", encoding="utf-8") as f:
            f.write(new_key)
    except OSError:
        pass  # fall back to in-memory-only key if the file can't be written
    return new_key


app.secret_key = load_secret_key()

MIN_LENGTH = 8
MAX_LENGTH = 64


# -------------------------------------------------------------------
# Core password logic
# -------------------------------------------------------------------
def build_pool(use_upper, use_lower, use_numbers, use_symbols):
    pool = ""
    if use_lower:
        pool += string.ascii_lowercase
    if use_upper:
        pool += string.ascii_uppercase
    if use_numbers:
        pool += string.digits
    if use_symbols:
        pool += string.punctuation
    return pool


def generate_password(length, pool, required_chars=None):
    """
    Generate a password that is GUARANTEED to contain at least one character
    from every selected category (required_chars), not just a random draw
    from the combined pool. This avoids the (rare but real) case where, e.g.,
    symbols were requested but none happened to be picked.
    """
    required_chars = required_chars or []

    # Start with one guaranteed character from each required category.
    password_chars = [secrets.choice(chars) for chars in required_chars]

    # Fill the rest randomly from the full combined pool.
    remaining = length - len(password_chars)
    password_chars += [secrets.choice(pool) for _ in range(max(remaining, 0))]

    # Securely shuffle so the guaranteed characters aren't always at the front.
    for i in range(len(password_chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        password_chars[i], password_chars[j] = password_chars[j], password_chars[i]

    return "".join(password_chars[:length])


def calculate_entropy(length, pool_size):
    if pool_size <= 0:
        return 0.0
    return round(length * math.log2(pool_size), 2)


def estimate_pool_size(password):
    """
    Estimate the character pool size for a password the user TYPED themselves
    (as opposed to one we generated, where we already know the exact pool).
    We look at which character classes actually appear in the password.
    """
    pool_size = 0
    if any(c in string.ascii_lowercase for c in password):
        pool_size += 26
    if any(c in string.ascii_uppercase for c in password):
        pool_size += 26
    if any(c in string.digits for c in password):
        pool_size += 10
    if any(c in string.punctuation for c in password):
        pool_size += len(string.punctuation)

    # Anything else (spaces, accented/unicode letters, emoji, etc.) - rough
    # catch-all bump so entropy isn't underestimated for those characters.
    known = string.ascii_letters + string.digits + string.punctuation
    if any(c not in known for c in password):
        pool_size += 50

    return pool_size


def calculate_strength(password):
    """Score based on length + character variety. Returns (label, score 0-100)."""
    score = 0

    length = len(password)
    if length >= 16:
        score += 40
    elif length >= 12:
        score += 30
    elif length >= 8:
        score += 20
    else:
        score += 5

    has_lower = any(c in string.ascii_lowercase for c in password)
    has_upper = any(c in string.ascii_uppercase for c in password)
    has_digit = any(c in string.digits for c in password)
    has_symbol = any(c in string.punctuation for c in password)

    variety = sum([has_lower, has_upper, has_digit, has_symbol])
    score += variety * 15  # up to 60

    score = min(score, 100)

    if score >= 80:
        label = "Strong"
    elif score >= 55:
        label = "Medium"
    else:
        label = "Weak"

    return label, score


# -------------------------------------------------------------------
# History helpers (persisted to a text file)
# -------------------------------------------------------------------
def append_history(entries):
    with open(HISTORY_FILE, "a", encoding="utf-8") as f:
        for entry in entries:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"{timestamp} | {entry['password']} | {entry['strength']} | "
                     f"{entry['entropy']} bits\n")


def read_history():
    if not os.path.exists(HISTORY_FILE):
        return []
    with open(HISTORY_FILE, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f.readlines() if line.strip()]
    return list(reversed(lines))  # newest first


def compute_stats():
    history = read_history()
    if not history:
        return {
            "count": 0, "avg_length": 0, "strong_count": 0,
            "medium_count": 0, "weak_count": 0, "avg_entropy": 0,
            "strong_pct": 0,
        }

    lengths = []
    entropies = []
    strong_count = medium_count = weak_count = 0

    for line in history:
        parts = line.split(" | ")
        if len(parts) >= 4:
            pwd, strength, entropy_str = parts[1], parts[2], parts[3]
            lengths.append(len(pwd))
            try:
                entropies.append(float(entropy_str.replace(" bits", "")))
            except ValueError:
                pass

            if strength == "Strong":
                strong_count += 1
            elif strength == "Medium":
                medium_count += 1
            else:
                weak_count += 1

    total = len(history)
    avg_length = round(sum(lengths) / len(lengths), 1) if lengths else 0
    avg_entropy = round(sum(entropies) / len(entropies), 1) if entropies else 0
    strong_pct = round((strong_count / total) * 100) if total else 0

    return {
        "count": total,
        "avg_length": avg_length,
        "strong_count": strong_count,
        "medium_count": medium_count,
        "weak_count": weak_count,
        "avg_entropy": avg_entropy,
        "strong_pct": strong_pct,
    }


# -------------------------------------------------------------------
# Routes
# -------------------------------------------------------------------
@app.route("/", methods=["GET"])
def index():
    return render_template(
        "index.html",
        passwords=session.pop("passwords", None),
        history=read_history()[:10],
        stats=compute_stats(),
        min_length=MIN_LENGTH,
        max_length=MAX_LENGTH,
    )


@app.route("/generate", methods=["POST"])
def generate():
    try:
        length = int(request.form.get("length", 0))
    except ValueError:
        flash("Password length must be a number.")
        return redirect(url_for("index"))

    try:
        count = int(request.form.get("count", 1))
    except ValueError:
        count = 1

    use_upper = request.form.get("uppercase") == "on"
    use_lower = request.form.get("lowercase") == "on"
    use_numbers = request.form.get("numbers") == "on"
    use_symbols = request.form.get("symbols") == "on"

    # --- Validation ---
    if length < MIN_LENGTH:
        flash(f"Password length must be at least {MIN_LENGTH}.")
        return redirect(url_for("index"))
    if length > MAX_LENGTH:
        flash(f"Password length cannot exceed {MAX_LENGTH}.")
        return redirect(url_for("index"))
    if count < 1 or count > 20:
        flash("Number of passwords must be between 1 and 20.")
        return redirect(url_for("index"))
    if not any([use_upper, use_lower, use_numbers, use_symbols]):
        flash("Select at least one character type.")
        return redirect(url_for("index"))

    pool = build_pool(use_upper, use_lower, use_numbers, use_symbols)

    required_chars = []
    if use_lower:
        required_chars.append(string.ascii_lowercase)
    if use_upper:
        required_chars.append(string.ascii_uppercase)
    if use_numbers:
        required_chars.append(string.digits)
    if use_symbols:
        required_chars.append(string.punctuation)

    if length < len(required_chars):
        flash(f"Length must be at least {len(required_chars)} to include one of every selected type.")
        return redirect(url_for("index"))

    results = []
    for _ in range(count):
        pwd = generate_password(length, pool, required_chars)
        label, score = calculate_strength(pwd)
        entropy = calculate_entropy(length, len(pool))
        results.append({"password": pwd, "strength": label, "score": score, "entropy": entropy})

    append_history(results)
    session["passwords"] = results
    return redirect(url_for("index"))


@app.route("/check", methods=["POST"])
def check_password():
    pwd = request.form.get("custom_password", "")

    if not pwd:
        flash("Please type a password to check.")
        return redirect(url_for("index"))
    if len(pwd) > 128:
        flash("That password is too long to check (max 128 characters).")
        return redirect(url_for("index"))

    pool_size = estimate_pool_size(pwd)
    entropy = calculate_entropy(len(pwd), pool_size)
    label, score = calculate_strength(pwd)

    result = {"password": pwd, "strength": label, "score": score, "entropy": entropy}

    append_history([result])
    session["passwords"] = [result]
    return redirect(url_for("index"))


@app.route("/export", methods=["GET"])
def export():
    history = read_history()
    with open(EXPORT_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Timestamp", "Password", "Strength", "Entropy (bits)"])
        for line in history:
            parts = line.split(" | ")
            if len(parts) >= 4:
                timestamp, pwd, strength, entropy = parts
                writer.writerow([timestamp, pwd, strength, entropy.replace(" bits", "")])
    return send_file(EXPORT_FILE, as_attachment=True, download_name="passwords.csv")


@app.route("/clear-history", methods=["POST"])
def clear_history():
    if os.path.exists(HISTORY_FILE):
        os.remove(HISTORY_FILE)
    flash("History cleared.")
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(debug=True)
