
import spf


def verify_spf(sender_ip, mail_from, helo="localhost"):
    try:
        if not sender_ip or not mail_from:
            return {
                "status": "ERROR",
                "message": "Sender IP and email address are required."
            }

        result, explanation = spf.check2(
            i=sender_ip.strip(),
            s=mail_from.strip(),
            h=helo.strip()
        )

        return {
            "status": result.upper(),
            "message": explanation
        }

    except Exception as error:
        return {
            "status": "ERROR",
            "message": str(error)
        }


if __name__ == "__main__":
    test_result = verify_spf(
        sender_ip="8.8.8.8",
        mail_from="user@gmail.com",
        helo="mail.google.com"
    )

    print("SPF Verification Result:")
    print("Status:", test_result["status"])
    print("Message:", test_result["message"])
