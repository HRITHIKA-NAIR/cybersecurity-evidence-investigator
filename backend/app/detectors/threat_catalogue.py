from __future__ import annotations

CoverageMode = str

DIRECT = "direct_or_indicator"
INDICATOR = "indicator_only"
DYNAMIC = "dynamic_analysis_dependent"
CONTEXTUAL = "contextual_limited"
ARCHITECTURE = "architecture_taxonomy"

THREAT_CATALOGUE: dict[int, tuple[str, CoverageMode]] = {
    1: ("Email-based attacks", DIRECT),
    2: ("Attachment attacks", DIRECT),
    3: ("Malicious Office documents", DIRECT),
    4: ("PDF attacks", DIRECT),
    5: ("HTML attachment attacks", DIRECT),
    6: ("HTML smuggling", DIRECT),
    7: ("SVG attacks", DIRECT),
    8: ("Image attacks", DIRECT),
    9: ("Archive attacks", DIRECT),
    10: ("ZIP bombs / decompression bombs", DIRECT),
    11: ("Double-extension attacks", DIRECT),
    12: ("Right-to-left Unicode filename attacks", DIRECT),
    13: ("File-type spoofing", DIRECT),
    14: ("Polyglot files", DIRECT),
    15: ("Shortcut attacks", DIRECT),
    16: ("Disk-image attacks", DIRECT),
    17: ("OneNote attacks", DIRECT),
    18: ("Website phishing", DIRECT),
    19: ("Clone phishing sites", DIRECT),
    20: ("Homograph websites", DIRECT),
    21: ("Typosquatting", DIRECT),
    22: ("Combosquatting", DIRECT),
    23: ("Subdomain deception", DIRECT),
    24: ("Browser-in-the-Browser attacks", DIRECT),
    25: ("Reverse-proxy phishing / AiTM", DIRECT),
    26: ("Drive-by download", DIRECT),
    27: ("Watering-hole attack", CONTEXTUAL),
    28: ("Malvertising", CONTEXTUAL),
    29: ("SEO poisoning", CONTEXTUAL),
    30: ("Fake software updates", DIRECT),
    31: ("ClickFix", DIRECT),
    32: ("CrashFix", DIRECT),
    33: ("Fake CAPTCHA attacks", DIRECT),
    34: ("Download attacks", DIRECT),
    35: ("Trojan", DIRECT),
    36: ("Virus", DIRECT),
    37: ("Worm", INDICATOR),
    38: ("Ransomware", INDICATOR),
    39: ("Infostealers", DIRECT),
    40: ("Remote Access Trojans — RATs", INDICATOR),
    41: ("Backdoors", INDICATOR),
    42: ("Rootkits", DYNAMIC),
    43: ("Bootkits", DYNAMIC),
    44: ("Keyloggers", INDICATOR),
    45: ("Spyware", INDICATOR),
    46: ("Adware / Potentially Unwanted Programs", DIRECT),
    47: ("Cryptojacking", DIRECT),
    48: ("Botnets", INDICATOR),
    49: ("Web shells", DIRECT),
    50: ("JavaScript attacks", DIRECT),
    51: ("Obfuscation", DIRECT),
    52: ("Packers", DIRECT),
    53: ("Fileless malware", INDICATOR),
    54: ("Living-off-the-Land techniques", DIRECT),
    55: ("DLL side-loading", DIRECT),
    56: ("DLL search-order hijacking", INDICATOR),
    57: ("Process injection", DYNAMIC),
    58: ("Supply-chain attacks", CONTEXTUAL),
    59: ("Dependency confusion", DIRECT),
    60: ("Typosquatted packages", DIRECT),
    61: ("Malicious browser extensions", DIRECT),
    62: ("Session hijacking", INDICATOR),
    63: ("Cookie theft", INDICATOR),
    64: ("Browser credential theft", INDICATOR),
    65: ("Watermarked / tracked documents", DIRECT),
    66: ("Web vulnerability attacks", CONTEXTUAL),
    67: ("Credential attacks", CONTEXTUAL),
    68: ("Social engineering variants", DIRECT),
    69: ("Smishing", DIRECT),
    70: ("Vishing", DIRECT),
    71: ("Quishing", DIRECT),
    72: ("Deepfake social engineering", CONTEXTUAL),
    73: ("AI-assisted phishing", CONTEXTUAL),
    74: ("Cloaking", CONTEXTUAL),
    75: ("Redirect chains", DIRECT),
    76: ("Open-redirect abuse", DIRECT),
    77: ("URL shortener abuse", DIRECT),
    78: ("Cloud-hosting abuse", DIRECT),
    79: ("DNS-based attacks", CONTEXTUAL),
    80: ("Domain generation algorithms", CONTEXTUAL),
    81: ("Fast-flux infrastructure", CONTEXTUAL),
    82: ("Command-and-Control", INDICATOR),
    83: ("Exfiltration", DYNAMIC),
    84: ("Old → modern evolution", ARCHITECTURE),
    85: (
        "Think in attack chains, not isolated files",
        ARCHITECTURE,
    ),
    86: (
        "Investigator classification model",
        ARCHITECTURE,
    ),
}


def coverage_for(
    topic_number: int,
) -> dict:
    name, mode = THREAT_CATALOGUE[
        topic_number
    ]

    return {
        "topic_number": topic_number,
        "threat_family": name,
        "coverage_mode": mode,
    }
