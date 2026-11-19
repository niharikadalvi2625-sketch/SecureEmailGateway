# Secure Email Authentication Gateway

## 1. Project Overview

The Secure Email Authentication Gateway is a Python-based web application designed to demonstrate email authentication mechanisms and improve email security.

It provides tools to analyze email headers, verify SPF records, check DNS records, generate DKIM signatures, evaluate DMARC alignment, and generate DNS configuration records.

## 2. Objectives

- Understand email authentication protocols.
- Verify sender authorization using SPF.
- Generate and verify DKIM digital signatures.
- Evaluate DMARC alignment.
- Analyze email authentication headers.
- Generate SPF, DKIM and DMARC DNS records.

## 3. Technologies Used

- Python
- Flask
- HTML
- dnspython
- dkimpy
- pyspf
- cryptography

## 4. Features

1. **Email Header Analysis:** Parses email authentication headers and displays reported SPF, DKIM and DMARC results.

2. **SPF Verification:** Checks whether a sender IP address is authorized according to the sender domain's SPF policy.

3. **DNS Record Checker:** Checks SPF, DKIM and DMARC TXT records using DNS lookups.

4. **DKIM Key Generation:** Generates an RSA key pair and stores the public and private keys.

5. **DKIM Signing and Verification:** Signs a test email and verifies its digital signature using the generated public key.

6. **DMARC Evaluation:** Evaluates SPF and DKIM alignment with the sender domain using authentication results.

7. **DNS Configuration Generator:** Generates sample SPF, DKIM and DMARC DNS records.

## 5. Project Structure

```text
SecureEmailGateway/
│
├── modules/
│   ├── header_parser.py
│   ├── dns_checker.py
│   ├── dkim_keys.py
│   ├── dkim_signer.py
│   ├── dmarc_evaluator.py
│   ├── spf_checker.py
│   └── dns_record_generator.py
│
├── templates/
│   └── index.html
│
├── static/
├── keys/
├── outputs/
├── app.py
├── config.py
├── requirements.txt
└── README.md
```

## 6. Installation and Execution

1. Create and activate a Python virtual environment.
2. Install the required dependencies:

```bash
pip install -r requirements.txt
```

3. Run the Flask application:

```bash
python app.py
```

4. Open the following address in a web browser:

```text
http://127.0.0.1:5000/
```

## 7. Testing Results

- Email header analysis: Implemented.
- SPF verification: Successfully tested.
- DNS record checking: Successfully tested.
- DKIM key generation: Successful.
- DKIM signing and local verification: PASS.
- DMARC alignment evaluation: Successfully tested with aligned and unaligned sample headers.
- DNS configuration generation: Successfully tested.
- Signed email download: Successful.

## 8. Limitations

- Actual DNS record publication requires ownership or administrative access to a domain.
- DKIM signing and verification currently use a locally generated key pair.
- DMARC evaluation uses a simplified alignment implementation based on reported authentication results.
- DNS configuration records are generated as templates and are not automatically published.

## 9. Conclusion

The Secure Email Authentication Gateway demonstrates important email authentication mechanisms through a web-based application. It provides practical experience with SPF, DKIM, DMARC, DNS lookups, digital signatures and email header analysis.