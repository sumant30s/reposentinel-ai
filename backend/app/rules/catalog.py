RULES = {
    "RS001": (
        "Dynamic SQL query",
        "high",
        "CWE-89",
        "A03:2021 Injection",
        "Use driver placeholders and pass values separately; allowlist SQL identifiers.",
    ),
    "RS002": (
        "Hard-coded credential",
        "high",
        "CWE-798",
        "A07:2021 Identification and Authentication Failures",
        "Remove the credential, rotate it if real, and load it from a secret manager or environment.",
    ),
    "RS003": (
        "Dynamic code execution",
        "high",
        "CWE-95",
        "A03:2021 Injection",
        "Use a strict parser such as json.loads and a fixed set of allowed operations.",
    ),
    "RS004": (
        "Potential unsafe deserialization",
        "high",
        "CWE-502",
        "A08:2021 Software and Data Integrity Failures",
        "Avoid pickle for untrusted data. Use JSON with schema validation.",
    ),
    "RS005": (
        "Shell command execution",
        "high",
        "CWE-78",
        "A03:2021 Injection",
        "Pass an argument list with shell=False, validate inputs, and use a fixed executable.",
    ),
    "RS006": (
        "Weak cryptographic hash",
        "medium",
        "CWE-327",
        "A02:2021 Cryptographic Failures",
        "Use modern purpose-appropriate cryptography; use Argon2/bcrypt for passwords, not a fast hash.",
    ),
    "RS007": (
        "TLS certificate verification disabled",
        "high",
        "CWE-295",
        "A02:2021 Cryptographic Failures",
        "Enable certificate validation and configure the correct CA trust store.",
    ),
    "RS008": (
        "Debug configuration enabled",
        "medium",
        "CWE-489",
        "A05:2021 Security Misconfiguration",
        "Disable debug mode in production and keep detailed errors out of public responses.",
    ),
    "RS009": (
        "Dependency security advisory",
        "medium",
        "CWE-1395",
        "A06:2021 Vulnerable and Outdated Components",
        "Review the advisory, upgrade to a fixed compatible version, and run regression tests.",
    ),
}

ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
