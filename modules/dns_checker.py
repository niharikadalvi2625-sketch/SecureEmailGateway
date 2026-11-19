
import dns.resolver


def check_txt_record(record_name, prefix):
    try:
        answers = dns.resolver.resolve(record_name, "TXT")

        records = []

        for record in answers:
            value = b"".join(record.strings).decode(
                "utf-8", errors="replace"
            )

            if value.startswith(prefix):
                records.append(value)

        return {
            "status": "FOUND" if records else "NOT FOUND",
            "records": records
        }

    except dns.resolver.NXDOMAIN:
        return {"status": "NOT FOUND", "records": []}

    except dns.exception.DNSException as error:
        return {
            "status": "DNS ERROR",
            "records": [],
            "error": str(error)
        }


def get_dns_records(domain, selector="default"):

    results = {}

    # Check SPF record
    results["SPF"] = check_txt_record(
        domain, "v=spf1"
    )

    # Check DMARC record
    results["DMARC"] = check_txt_record(
        f"_dmarc.{domain}", "v=DMARC1"
    )

    # Check DKIM public key record
    dkim_domain = f"{selector}._domainkey.{domain}"

    results["DKIM"] = check_txt_record(
        dkim_domain, "v=DKIM1"
    )

    return results
