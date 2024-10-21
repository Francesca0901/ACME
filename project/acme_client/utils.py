# ============== UTILS ================

import base64
import hashlib
import json
import requests
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


jose_header = {"Content-Type": "application/jose+json"}

def int_to_bytes(val):
    return val.to_bytes((val.bit_length() + 7) // 8, 'big') or b'\0'

def b64encode(value):
    if isinstance(value, str):
        value = value.encode("utf-8") # encode string to bytes
    return base64.urlsafe_b64encode(value).decode().rstrip("=") # ACME protocol specifies base64url encoding without padding

def get_protected_header(alg, nonce, url, kid=None, jwk=None):
    header = {
        "alg": alg,
        "nonce": nonce,
        "url": url,
    }
    if kid is not None:
        header["kid"] = kid
    elif jwk is not None:
        header["jwk"] = jwk
    else:
        raise ValueError("Either 'kid' or 'jwk' must be provided in the protected header.")
    return header


def get_jws_object(encoded_header, encoded_payload, private_key):
    signing_input = f"{encoded_header}.{encoded_payload}".encode("utf-8")
    signature = private_key.sign(
        signing_input,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return {
        "protected": encoded_header,
        "payload": encoded_payload,
        "signature": b64encode(signature)
    }

def post_as_get(self, url):
    # Prepare the JWS with an empty payload (POST-as-GET)
    protected_header = get_protected_header(
        "RS256", self.nonce, url, kid=self.account_kid
    )
    encoded_header = b64encode(json.dumps(protected_header))

    empty_payload = ''
    # encoded_payload = b64encode(json.dumps(empty_payload))

    jws_object = get_jws_object(encoded_header, empty_payload, self.private_key)
    response = requests.post(url, json=jws_object, headers=jose_header, verify=self.verify)

    # Update nonce from response
    self.nonce = response.headers.get('Replay-Nonce', self.get_nonce())

    if response.status_code == 200:
        return response
    else:
        print(f"POST-as-GET failed with status code {response.status_code}")
        return None
    
def get_key_authorization(token, jwk):
    # Serialize the JWK to JSON with lexicographically sorted keys and without whitespace
    jwk_json = json.dumps(jwk, sort_keys=True, separators=(',', ':'))
    jwk_bytes = jwk_json.encode('utf-8')

    thumbprint = hashlib.sha256(jwk_bytes).digest()
    key_authorization = f"{token}.{b64encode(thumbprint)}"
    return key_authorization

def generate_csr_key(domains):
    cert_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    csr_builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, domains[0])])
    )
    alt_names = [x509.DNSName(domain) for domain in domains]
    csr_builder = csr_builder.add_extension(
        x509.SubjectAlternativeName(alt_names), critical=False
    )

    csr = csr_builder.sign(cert_private_key, hashes.SHA256()) 
    csr_der = csr.public_bytes(encoding=Encoding.DER)
    csr_b64 = b64encode(csr_der)

    with open("key.pem", "wb") as f:
        f.write(cert_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    return csr_b64