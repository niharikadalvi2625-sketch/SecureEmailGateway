
from pathlib import Path


def generate_dns_records(domain, sending_ip, selector="test"):
    domain = domain.strip().lower()
    sending_ip = sending_ip.strip()
    selector = selector.strip()

    public_key_path = (
        Path(__file__).resolve().parent.parent
        / "keys"
        / "dkim_public.txt"
    )

    if not public_key_path.exists():
        raise FileNotFoundError(
            "DKIM public key not found. Generate DKIM keys first."
        )

    public_key = public_key_path.read_text(
        encoding="utf-8"
    ).strip()

    if not public_key.startswith("v=DKIM1"):
        public_key = f"v=DKIM1; k=rsa; p={public_key}"

    return {
        "SPF": {
            "host": "@",
            "type": "TXT",
            "value": f"v=spf1 ip4:{sending_ip} -all"
        },
        "DKIM": {
            "host": f"{selector}._domainkey",
            "type": "TXT",
            "value": public_key
        },
        "DMARC": {
            "host": "_dmarc",
            "type": "TXT",
            "value": (
                "v=DMARC1; p=none; "
                f"rua=mailto:dmarc@{domain}"
            )
        }
    }
