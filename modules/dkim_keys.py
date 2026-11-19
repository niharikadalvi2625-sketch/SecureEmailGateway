
import os
import base64

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


def generate_dkim_keys():

    # Generate RSA 2048-bit private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Get public key
    public_key = private_key.public_key()

    # Convert private key to PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Convert public key to DER format
    public_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Encode public key in Base64
    public_base64 = base64.b64encode(public_der).decode("utf-8")

    # Create keys directory if it doesn't exist
    os.makedirs("keys", exist_ok=True)

    # Save private key
    with open("keys/dkim_private.pem", "wb") as file:
        file.write(private_pem)

    # Create DKIM DNS TXT record
    dns_record = f"v=DKIM1; k=rsa; p={public_base64}"

    with open("keys/dkim_public.txt", "w") as file:
        file.write(dns_record)

    print("DKIM keys generated successfully!")
    print("\nPrivate key saved: keys/dkim_private.pem")
    print("Public key saved: keys/dkim_public.txt")
    print("\nDKIM DNS TXT Record:\n")
    print(dns_record)


if __name__ == "__main__":
    generate_dkim_keys()
