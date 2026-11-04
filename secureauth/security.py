import re


USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{4,30}$")
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s.]+(?:\.[^@\s.]+)+$")
SPECIAL_RE = re.compile(r"[^A-Za-z0-9]")
PASSWORD_MIN_LENGTH = 12
PASSWORD_MAX_LENGTH = 128


def validate_email(email):
    return len(email) <= 254 and EMAIL_RE.fullmatch(email) is not None


def validate_username(username):
    return USERNAME_RE.fullmatch(username) is not None


def password_feedback(password):
    checks = {
        "length": len(password) >= PASSWORD_MIN_LENGTH,
        "uppercase": any(char.isupper() for char in password),
        "lowercase": any(char.islower() for char in password),
        "number": any(char.isdigit() for char in password),
        "special": SPECIAL_RE.search(password) is not None,
    }
    suggestions = []
    if not checks["length"]:
        suggestions.append(f"Use at least {PASSWORD_MIN_LENGTH} characters.")
    if not checks["uppercase"]:
        suggestions.append("Add an uppercase letter.")
    if not checks["lowercase"]:
        suggestions.append("Add a lowercase letter.")
    if not checks["number"]:
        suggestions.append("Add a number.")
    if not checks["special"]:
        suggestions.append("Add a special character.")
    score = sum(checks.values())
    strength = "strong" if score == 5 else "medium" if score >= 3 else "weak"
    return {"checks": checks, "suggestions": suggestions, "strength": strength}


def validate_password(password):
    if not PASSWORD_MIN_LENGTH <= len(password) <= PASSWORD_MAX_LENGTH:
        return False, "Password must be between 12 and 128 characters."
    feedback = password_feedback(password)
    if feedback["strength"] != "strong":
        return False, "Password must include uppercase and lowercase letters, a number, and a special character."
    return True, ""
