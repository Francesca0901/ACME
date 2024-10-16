# ============== UTILS ================

import base64
import json
import requests
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

jose_header = {"Content-Type": "application/jose+json"}

def b64encode(value):
    if isinstance(value, str):
        value = value.encode("utf-8")
    return base64.urlsafe_b64encode(value).decode().rstrip("=")

# def get_jwk(self, public_key):
#     jwk = {
#         "kty": "RSA",
#         "e": b64encode(public_key.public_numbers().e),
#         "n": b64encode(public_key.public_numbers().n)
#     }
#     self.jwk = jwk
#     return jwk

def get_protected_header(alg, jwk, nonce, url, kid=None):
    if kid:
        return {
            "alg": alg,
            "nonce": nonce,
            "url": url,
            "kid": kid
        }
    else:
        return {
            "alg": alg,
            "nonce": nonce,
            "url": url,
            "jwk": jwk
        }

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
        "RS256", get_jwk(self.public_key), self.nonce, url
    )
    encoded_header = b64encode(json.dumps(protected_header))

    empty_payload = {}
    encoded_payload = b64encode(json.dumps(empty_payload))

    jws_object = get_jws_object(encoded_header, encoded_payload, self.private_key)
    response = requests.post(url, json=jws_object, headers=jose_header)

    if response.status_code == 200:
        return response.json()
    else:
        print(f"POST-as-GET failed with status code {response.status_code}")
        return None
    
def get_key_authorization(self, token):
    thumbprint = self.public_key.thumbprint(hashes.SHA256())
    key_authorization = f"{token}.{b64encode(thumbprint)}"
    return key_authorization