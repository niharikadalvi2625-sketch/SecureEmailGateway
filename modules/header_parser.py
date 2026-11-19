
import re


def analyze_headers(raw_header):
    results = {
        "SPF": "Not Found",
        "DKIM": "Not Found",
        "DMARC": "Not Found"
    }

    # Find Authentication-Results header
    auth_headers = re.findall(
        r"Authentication-Results:\s*(.*(?:\n[ \t]+.*)*)",
        raw_header,
        re.IGNORECASE
    )

    if not auth_headers:
        return results

    auth_text = " ".join(auth_headers)

    # Extract SPF, DKIM and DMARC results
    for protocol in ["SPF", "DKIM", "DMARC"]:
        pattern = rf"\b{protocol.lower()}=(pass|fail|softfail|neutral|none|temperror|permerror)"
        match = re.search(pattern, auth_text, re.IGNORECASE)

        if match:
            results[protocol] = match.group(1).upper()

    return results
