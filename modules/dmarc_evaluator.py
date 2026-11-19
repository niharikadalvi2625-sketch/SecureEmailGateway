
import re
from email import message_from_string
from email.policy import default


def is_aligned(auth_domain, from_domain):
    if not auth_domain:
        return False

    auth_domain = auth_domain.lower().strip(".")
    from_domain = from_domain.lower().strip(".")

    return (
        auth_domain == from_domain
        or auth_domain.endswith("." + from_domain)
        or from_domain.endswith("." + auth_domain)
    )


def evaluate_dmarc(raw_header):
    message = message_from_string(raw_header, policy=default)

    from_address = message.get("From", "")
    match = re.search(r"@([A-Za-z0-9.-]+)", from_address)

    if not match:
        return {
            "status": "ERROR",
            "message": "Invalid or missing From address.",
            "domain": None
        }

    from_domain = match.group(1).lower()

    auth_results = message.get_all("Authentication-Results", [])
    auth_text = " ".join(str(value) for value in auth_results).lower()

    spf_match = re.search(
        r"\bspf=pass\b[^;]*?\bsmtp\.mailfrom=(?:[^@\s;]+@)?([a-z0-9.-]+)",
        auth_text
    )

    dkim_matches = re.findall(
        r"\bdkim=pass\b[^;]*?\bheader\.d=([a-z0-9.-]+)",
        auth_text
    )

    spf_aligned = (
        bool(spf_match)
        and is_aligned(spf_match.group(1), from_domain)
    )

    dkim_aligned = any(
        is_aligned(domain, from_domain)
        for domain in dkim_matches
    )

    if spf_aligned or dkim_aligned:
        status = "PASS"
        result_message = (
            "DMARC passed: at least one aligned SPF or DKIM result passed."
        )
    else:
        status = "FAIL"
        result_message = (
            "DMARC failed: no aligned SPF or DKIM pass was found."
        )

    return {
        "status": status,
        "message": result_message,
        "domain": from_domain,
        "spf_aligned": spf_aligned,
        "dkim_aligned": dkim_aligned
    }
