
from flask import Flask, render_template, request, send_file

from modules.header_parser import analyze_headers
from modules.dns_checker import get_dns_records
from modules.dkim_signer import sign_test_email
from modules.dmarc_evaluator import evaluate_dmarc
from modules.spf_checker import verify_spf
from modules.dns_record_generator import generate_dns_records

app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def home():

    results = None
    raw_header = ""
    dns_results = None
    domain = ""
    selector = "default"
    dkim_result = None
    dmarc_evaluation = None
    spf_result = None
    generated_records = None
    generation_error = None

    sender_ip = ""
    mail_from = ""
    helo = "localhost"

    if request.method == "POST":

        action = request.form.get("action")

        if action == "analyze":

            raw_header = request.form.get("email_header", "")

            if raw_header.strip():
                results = analyze_headers(raw_header)
                dmarc_evaluation = evaluate_dmarc(raw_header)

        elif action == "dns_check":

            domain = request.form.get("domain", "").strip()
            selector = request.form.get("selector", "default").strip()

            if domain and selector:
                dns_results = get_dns_records(domain, selector)

        elif action == "dkim_test":

            try:
                dkim_result = sign_test_email()

            except Exception as error:
                dkim_result = {
                    "status": "ERROR",
                    "message": str(error),
                    "file": None
                }

        elif action == "spf_check":

            sender_ip = request.form.get("sender_ip", "").strip()
            mail_from = request.form.get("mail_from", "").strip()
            helo = request.form.get("helo", "localhost").strip()

            spf_result = verify_spf(sender_ip, mail_from, helo)

        elif action == "generate_dns":

            domain = request.form.get("domain", "").strip()
            sender_ip = request.form.get("sender_ip", "").strip()
            selector = request.form.get("selector", "test").strip()

            try:
                generated_records = generate_dns_records(
                    domain, sender_ip, selector
                )
            except Exception as error:
                generation_error = str(error)

    return render_template(
        "index.html",
        results=results,
        raw_header=raw_header,
        dns_results=dns_results,
        domain=domain,
        selector=selector,
        dkim_result=dkim_result,
        dmarc_evaluation=dmarc_evaluation,
        spf_result=spf_result,
        sender_ip=sender_ip,
        mail_from=mail_from,
        helo=helo,
        generated_records=generated_records,
        generation_error=generation_error
    )


@app.route("/download-signed-email")
def download_signed_email():

    return send_file(
        "outputs/signed_test_email.eml",
        as_attachment=True,
        download_name="signed_test_email.eml",
        mimetype="message/rfc822"
    )


if __name__ == "__main__":
    app.run(debug=True)
