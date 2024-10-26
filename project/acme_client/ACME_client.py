import hashlib
import time
import requests
import json
import base64
from cryptography.hazmat.primitives.asymmetric import rsa
import acme_client.utils as utils
import acme_client.dns01_handler as dns01_handler
from cryptography import x509
from cryptography.hazmat.backends import default_backend as default_backend


jose_header = {"Content-Type": "application/jose+json"}

class ACME_client():
    def __init__(self, server_url, record, domains):
        self.server_url = server_url
        self.record = record
        self.domains = domains
        self.verify = 'pebble.minica.pem'  
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
        response = requests.get(self.server_url, verify=self.verify)
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

        response = requests.head(self.newNonce_url, verify=self.verify)
        if response.status_code not in [200, 204]:
            print("Failed to get nonce")
            quit()

        self.nonce = response.headers['Replay-Nonce']
        return self.nonce

    def get_jwk(self):
        jwk = {
            "kty": "RSA",
            "e": utils.b64encode(utils.int_to_bytes(self.public_key.public_numbers().e)),
            "n": utils.b64encode(utils.int_to_bytes(self.public_key.public_numbers().n))
        }
        self.jwk = jwk
        return jwk


    # Account creation (POST /newAccount)
    def create_account(self):
        payload = {
            "termsOfServiceAgreed": True,
            "contact": ["mailto:admin@example.com"]
        }
        
        protected_header = utils.get_protected_header("RS256", jwk=self.jwk, nonce=self.nonce, url=self.newAccount_url) 
        encoded_header = utils.b64encode(json.dumps(protected_header))
        encoded_payload = utils.b64encode(json.dumps(payload))

        jws_object = utils.get_jws_object(encoded_header, encoded_payload, self.private_key)
        
        response = requests.post(self.newAccount_url, json=jws_object, headers=jose_header, verify=self.verify)

        # Update nonce from response
        self.nonce = response.headers.get('Replay-Nonce', self.get_nonce())

        if response.status_code == 201:
            print("Account created successfully")
            self.account_kid = response.headers['Location']


    # Certificate request (POST /newOrder)
    def submit_order(self, domains):
        payload = {
            "identifiers" : [{"type": "dns", "value": domain} for domain in domains]
        }
        encoded_payload = utils.b64encode(json.dumps(payload))

        protected_header = utils.get_protected_header("RS256", jwk=None, kid=self.account_kid, nonce=self.nonce, url=self.newOrder_url)
        encoded_header = utils.b64encode(json.dumps(protected_header))

        jws_object = utils.get_jws_object(encoded_header, encoded_payload, self.private_key)

        response = requests.post(self.newOrder_url, json=jws_object, headers=jose_header, verify=self.verify)
        
        # Update nonce from response
        self.nonce = response.headers.get('Replay-Nonce', self.get_nonce())

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
        print(f"Auth urls: {auth_urls}")
        for auth_url in auth_urls:
            response = utils.post_as_get(self,auth_url)
            if response is None:
                print(f"Failed to get authorization at {auth_url}")
                continue

            auth_requirement = response.json()

            domain = auth_requirement["identifier"]["value"]
            print(f"Processing authorization for domain: {domain}")

            for challenge in auth_requirement["challenges"]:
                if challenge["type"] == "dns-01":
                    print("Solving DNS challenge for domain: ", domain)
                    challenge_token = challenge["token"]
                    challenge_url = challenge["url"]
                    if not challenge_token or not challenge_url:
                        print("Invalid challenge data")
                        continue

                    key_authorization = utils.get_key_authorization(challenge_token, self.jwk)
                    hashed_key_authorization = hashlib.sha256(key_authorization.encode('utf-8')).digest() # A sequence of bytes
                    hashed_key_authorization = utils.b64encode(hashed_key_authorization)

                    # Convert bytes to string if necessary
                    if isinstance(hashed_key_authorization, bytes):
                        hashed_key_authorization = hashed_key_authorization.decode('utf-8')

                    # dns01_server = dns01_handler.start_dns_server(provisioned_RR, address=self.record)
                    dns_server = dns01_handler.start_dns_server(
                        domain=f"_acme-challenge.{domain}.",
                        txt_value=hashed_key_authorization,
                        record=self.record,
                        address="0.0.0.0"
                        # address="127.0.0.1"
                    )

                    # Notify the server that the challenge is ready
                    print("Notifying server that challenge is ready")

                    protected_header = utils.get_protected_header("RS256", jwk=None, kid=self.account_kid, nonce=self.nonce, url=challenge_url)
                    encoded_header = utils.b64encode(json.dumps(protected_header))
                    payload = {}
                    encoded_payload = utils.b64encode(json.dumps(payload))
                    jws_object = utils.get_jws_object(encoded_header, encoded_payload, self.private_key)
                    response = requests.post(challenge_url, json=jws_object, headers=jose_header, verify=self.verify)

                    # Update nonce from response
                    self.nonce = response.headers.get('Replay-Nonce', self.get_nonce())

                    # print(f"Response from server: {response.text}")

                    # Poll the challenge status
                    print("Polling authorization status")
                    challenge_status = self.poll_status(challenge_url, success_status=["valid"], failure_status=["invalid"])

                    dns01_handler.stop_dns_server(dns_server)

                    if not challenge_status:
                        print("Challenge failed")
                        return False
                    else:
                        print("Challenge succeeded")

        # Believe all requirements have been fulfilled, finalize the order
        cert_url = self.finalize_order()
        return cert_url


    # Polling challenge status and fetching certificates
    def poll_status(self, url, success_status="valid", failure_status="invalid"):
        while True:
            response = utils.post_as_get(self,url)

            if response.status_code != 200:
                print(f"Failed to poll authorization status for {url}")
                return False

            response_json = response.json()
            status = response_json["status"]

            print(f"Polling status for {url}: {status}")
            # print(response_json)
            
            if status in failure_status:
                print(f"Authorization status for {url}: {status}")
                print(response_json)
                return False
            elif status in success_status:
                return response_json
            else:
                retry_after = response.headers.get("Retry-After", 3)
                time.sleep(retry_after)

    
    # Certificate finalization while all challenges are valid (POST /finalize)
    def finalize_order(self):
        # # Make sure all auth are Valid
        # print("Polling authorization status")
        # if not self.poll_status(self.order_url, success_status=["valid", "processing", "ready"], failure_status="invalid"):
        #     print("Failed to validate all authorizations")
        #     return False
        
        # Send finalization request (CSR)
        print ("======Finalizing order======")
        finalize_url = self.finalize

        protected_header = utils.get_protected_header("RS256", kid=self.account_kid, nonce=self.nonce, url=finalize_url)
        encoded_header = utils.b64encode(json.dumps(protected_header))

        csr = utils.generate_csr_key(self.domains)
        payload = {
            "csr": csr
        }
        encoded_payload = utils.b64encode(json.dumps(payload))

        jws_object = utils.get_jws_object(encoded_header, encoded_payload, self.private_key)
        response = requests.post(finalize_url, json=jws_object, headers=jose_header, verify=self.verify)

        # Update nonce from response
        self.nonce = response.headers.get('Replay-Nonce', self.get_nonce())

        if response.status_code == 200:
            print("Finalized order successfully, now poll for certificate")
            response_obj = self.poll_status(self.order_url, success_status="valid", failure_status=["invalid", "pending", "ready"])
            if response_obj:
                print("Certificate issued successfully")
                return response_obj["certificate"] # return the certificate url
            else:
                print("Failed to issue certificate")
                return False
            
        else:
            print(response.text)
            print("Failed to finalize order")

    # Certificate download (GET /cert)
    def download_cert(self, cert_url):
        print("=====Downloading certificate======")
        while True:
            print(f"Downloading certificate from {cert_url}")
            response = utils.post_as_get(self,cert_url)
            if response.status_code == 200:
                cert = response.content
                with open("cert.pem", "wb") as f:
                    f.write(cert)
                    f.close()
                cert = x509.load_pem_x509_certificate(cert, default_backend())
                self.cert = cert
                print(":) Certificate downloaded successfully")
                return cert
            else:
                retry_after = response.headers.get("Retry-After", 3)
                print(f"Failed to download certificate, retrying in {retry_after} seconds")
                time.sleep(retry_after)
    
    # Certificate revocation (POST /revokeCert)
    def revoke_cert(self):
        pass




