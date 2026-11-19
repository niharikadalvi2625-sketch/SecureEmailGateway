
import os
import dkim

from email.message import EmailMessage
from email.policy import SMTP


def sign_test_email():

    domain = b"example.test"
    selector = b"test"

    # Load private key
    with open("keys/dkim_private.pem", "rb") as file:
        private_key = file.read()

    # Load public DNS record
    with open("keys/dkim_public.txt", "r") as file:
        dns_record = file.read().strip()

    # Create test email
    message = EmailMessage(policy=SMTP)

    message["From"] = "sender@example.test"
    message["To"] = "receiver@example.test"
    message["Subject"] = "DKIM Authentication Test"

    message.set_content(
        "This is a test email signed using DKIM."
    )

    raw_message = message.as_bytes()

    # Sign email
    signature = dkim.sign(
        raw_message,
        selector,
        domain,
        private_key,
        include_headers=[
            b"from",
            b"to",
            b"subject"
        ],
        canonicalize=(b"relaxed", b"relaxed")
    )

    signed_message = signature + raw_message

    # Save signed email
    os.makedirs("outputs", exist_ok=True)

    output_path = "outputs/signed_test_email.eml"

    with open(output_path, "wb") as file:
        file.write(signed_message)

    # Local DNS lookup using generated public key
    expected_name = selector + b"._domainkey." + domain

    def local_dns_lookup(name, timeout=5):
        if name.rstrip(b".") == expected_name:
            return dns_record.encode("utf-8")
        return b""

    # Verify signature
    verification = dkim.verify(
        signed_message,
        dnsfunc=local_dns_lookup
    )

    return {
        "status": "PASS" if verification else "FAIL",
        "message": (
            "DKIM signature verified successfully."
            if verification
            else "DKIM signature verification failed."
        ),
        "file": output_path
    }
