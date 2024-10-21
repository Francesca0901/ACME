import hashlib
import time
import requests
import json
import base64
from cryptography.hazmat.primitives.asymmetric import rsa
import utils
import dns01_handler
from cryptography import x509
from cryptography.hazmat.backends import default_backend as default_backend


jose_header = {"Content-Type": "application/jose+json"}

class ACME_client():
    def __init__(self, server_url, domain):
        self.server_url = server_url
        self.domain = domain
        self.get_directory()
        self.get_nonce()

        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.public_key = self.private_key.public_key()

        self.get_jwk()

    # Directory fetching (GET /dir)
    def get_directory(self):
        response = requests.get(self.server_url, verify='pebble.minica.pem')
        res = response.json() 
        if response.status_code != 200:
            print("Failed to get directory")
            quit()

        self.newNonce_url = res['newNonce']
        self.newAccount_url = res['newAccount']
        self.newOrder_url = res['newOrder']
        self.revokeCert_url = res['revokeCert']
        self.keyChange_url = res['keyChange']  

    def get_nonce(self):
        if self.newNonce_url is None:
            return False

        response = requests.head(self.newNonce_url)
        if response.status_code != 200 or response.status_code != 204:
            print("Failed to get nonce")
            quit()

        self.nonce = response.headers['Replay-Nonce']
        return self.nonce

    def get_jwk(self, public_key):
        jwk = {
            "kty": "RSA",
            "e": utils.b64encode(public_key.public_numbers().e),
            "n": utils.b64encode(public_key.public_numbers().n)
        }
        self.jwk = jwk
        return jwk


    # Account creation (POST /newAccount)
    def create_account(self):
        payload = {
            "termsOfServiceAgreed": True,
            "contact": ["mailto:admin@example.com"]
        }
        
        protected_header = utils.get_protected_header("RS256", self.jwk, self.nonce, self.newAccount_url) 
        encoded_header = utils.b64encode(json.dumps(protected_header))
        encoded_payload = utils.b64encode(json.dumps(payload))

        jws_object = utils.get_jws_object(encoded_header, encoded_payload, self.private_key)
        
        response = requests.post(self.newAccount_url, json=jws_object, headers=jose_header)
        if response.status_code == 201:
            print("Account created successfully")
            self.account_kid = response.headers['Location']


    # Certificate request (POST /newOrder)
    def submit_order(self, domains):
        payload = {
            "identifiers" : [{"type": "dns", "value": domain} for domain in domains]
        }
        encoded_payload = utils.b64encode(json.dumps(payload))

        protected_header = utils.get_protected_header("RS256", self.account_kid, self.nonce, self.newOrder_url)
        encoded_header = utils.b64encode(json.dumps(protected_header))

        jws_object = utils.get_jws_object(encoded_header, encoded_payload, self.private_key)

        response = requests.post(self.newOrder_url, json=jws_object, headers=jose_header)
        # response = server_post(self.newAccount_url, jws_object, jose_header)
        if response.status_code == 201:
            self.order_url = response.headers['Location']
            self.authorizations = response.json()['authorizations']
            self.finalize = response.json()['finalize']
            print("Order submitted successfully")
            return response.json()
        else:
            print("Failed to submit order")
            print(response.text)
            return None

    # Challenge solving (DNS-01 or HTTP-01)
    def solve_challenges(self):
        auth_urls = self.authorizations
        for auth_url in auth_urls:
            auth_requirement = utils.post_as_get(auth_url)

            for challenge in auth_requirement["challenges"]:
                if challenge["type"] == "dns-01":
                    print("Solving DNS challenge")
                    challenge_token = challenge["token"]
                    challenge_url = challenge["url"]
                    key_authorization = utils.get_key_authorization(challenge_token)
                    hashed_key_authorization = hashlib.sha256(key_authorization.encode('utf-8')).digest() # A sequence of bytes
                    hashed_key_authorization = utils.b64encode(hashed_key_authorization) 

                    provisioned_RR = f'_acme-challenge.{self.domain}. 300 IN TXT "{hashed_key_authorization}"'

                    dns01_handler.start_dns_server(provisioned_RR)

                    # Notify the server that the challenge is ready
                    self.poll_status(challenge_url, success_status="valid", failure_status="invalid")

                    dns01_handler.stop_dns_server()

        # Believe all requirements have been fulfilled, finalize the order
        self.finalize_order()


    # Polling challenge status and fetching certificates
    def poll_status(self, url, success_status="valid", failure_status="invalid"):
        while True:
            response = utils.post_as_get(url)

            if response.status_code != 200:
                print(f"Failed to poll authorization status for {url}")
                return False
            
            if response.json()["status"] in failure_status:
                return False
            elif response.json()["status"] in success_status:
                return response.json()
            else:
                retry_after = response.headers.get("Retry-After", 3)
                time.sleep(retry_after)

    
    # Certificate finalization while all challenges are valid (POST /finalize)
    def finalize_order(self):
        # Make sure all auth are Valid
        if not self.poll_status(self.order_url, success_status=["valid", "processing", "ready"], failure_status="invalid"):
            print("Not all authorizations are valid, won't start finalization")
            return False
        
        # Send finalization request (CSR)
        finalize_url = self.finalize

        protected_header = utils.get_protected_header("RS256", kid=self.account_kid, nonce=self.nonce, url=finalize_url)
        encoded_header = utils.b64encode(json.dumps(protected_header))

        csr = utils.generate_csr()
        payload = {
            "csr": csr
        }
        encoded_payload = utils.b64encode(json.dumps(payload))

        jws_object = utils.get_jws_object(encoded_header, encoded_payload, self.private_key)
        response = requests.post(finalize_url, json=jws_object, headers=jose_header)

        if response.status_code == 200:
            response_obj = self.poll_status(self.order_url, success_status="valid", failure_status=["invalid", "pending", "ready"])
            if response_obj:
                print("Certificate issued successfully")
                return response_obj["certificate"] # return the certificate url
            else:
                print("Failed to issue certificate")
                return False
            
        else:
            print("Failed to finalize order")

    # Certificate download (GET /cert)
    def download_cert(self, cert_url):
        while True:
            response = utils.post_as_get(cert_url)
            if response.status_code == 200:
                cert = response.content
                with open("cert.pem", "wb") as f:
                    f.write(cert)
                    f.close()
                cert = x509.load_pem_x509_certificate(cert, default_backend())
                self.cert = cert
            else:
                retry_after = response.headers.get("Retry-After", 3)
                print(f"Failed to download certificate, retrying in {retry_after} seconds")
                time.sleep(retry_after)
    
    # Certificate revocation (POST /revokeCert)
    def revoke_cert(self):
        pass




