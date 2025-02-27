# ACME Project: Frequently Asked Questions

## Preamble: How is my code tested? 

Your code is automatically executed on the GitLab CI every time you push a
commit. You can also trigger a manual execution through the Pipelines page.

Each run, the CI schedules several jobs. In each one, your code is executed in a
particular mode (by changing the command line flags) and a specific
functionality of your project is tested. What is being tested can be derived
from the name of the Job.

Following is a list of all jobs and what behavior the expected behavior:

- `{http,dns}-{single,multi}-domain`: Runs your ACME client and expects it to
obtain a certificate for either a single or multiple domains. The challenge used
to verify the domain ownership is either HTTP or DNS. The obtained certificate
should be served via the HTTPS server.
- `dns-wildcard-domain`: Runs you ACME client and expects it to obtain a
wildcard certificate, which can only be accomplished via the DNS challenge. The
obtained certificate should be served via the HTTPS server.
- `{http,dns}-revocation`: The ACME client is executed only once. It is supposed
to perform the same steps as in `{http,dns}-{single,multi}-domain`, except that,
as soon as the certificate is obtained, it should be immediately revoked. The
HTTPS server should still serve the revoked certificate.
- `invalid-certificate`: This test case is peculiar. Your ACME client is not
actually supposed to execute at all; Instead, it should detect that the ACME
server is using an invalid certificate and refuse to proceed.

Regardless of the test at hand, the execution always follows the following
high-level steps:

1. Your ACME client is executed and the execution mode is provided via command
   line parameters and flags (see the Project Description for more details).
2. The client is expected to do its job and is closely monitored by looking at
   the output from Pebble, the ACME server.
3. When the end is reached, either because a test case failed or the grader
   verified the behavior successfully, the appropriate endpoint of the Shutdown
server is called, allowing the client to shut down gracefully.

## How can I get more detailed feedback from the grader in the GitLab CI?

Each job in the GitLab CI generates an artifact. A download link for the
artifact associated with a completed job can be found in the right-hand side of
the GitLab UI. Each artifact consists of a zip file containing a
`.test-out/<test name>` folder, with the following files inside:

- `tester_out.txt`: Contains the verbose output of the grader program. It will
point out which test case failed and will contain debugging prints which can be
useful to trace the cause of the failure.
- `testing_log.txt`: Contains a slimmed down version of `tester_out.txt`. It is
easier to spot at a glance which particular test case failed, but you should
always refer to `tester_out.txt` which contains a more detailed report.
- `pebble_out.txt`: Contains the log of the Pebble ACME server that resulted
from the execution of your ACME client. This may be useful in some rare
occurrences.
- `<test name>.json`: This is used internally to grade the CI run. It contains a
summary of all test pass/failures. You can ignore this file.

The grader behaves as a state machine. It moves between states when specific
steps of the protocol are performed. This is achieved by looking at the log
output of Pebble. When a state transition occurs, additional tests are performed
to ensure that your ACME client is behaving as expected. You can trace the
behavior of the grader's state machine via the debug output found in
`tester_out.txt`.

Also, you can edit the files in `scripts/` to print out some debug information
inside the GitLab CI (In particular, you may add commands to
`scripts/docker-run.sh`). Please, refrain from modifying the `.gitlab-ci.yaml`
file as our tools might flag your project as potentially cheating if they detect
any changes.

## I get incomplete points for the `invalid-certificate` test although my implementation seems to behave correctly.

As mentioned in the [preamble](#preamble-how-is-my-code-tested), this test expects
your ACME to refuse starting when the ACME server is using an invalid
certificate. This test also requires that both your DNS and HTTPS servers are
not reachable when an invalid certificate is detected.

## My servers do not seem to receive anything.

This problem can occur in two circumstances: if you use Dockerized Pebble or if
you upload your code to the GitLab CI.

The problem is the same in both cases: You probably bound your servers to the
`localhost` interface (IP address `127.0.0.1`) instead of the IP provided via
the `record` argument (or IP address `0.0.0.0`). While this configuration works
fine for completely local testing, it will not work in the GitLab environment,
where requests will be received from different machines, or with Pebble in a
Docker container (which counts as 'outside of the machine').

If you are using dockerized Pebble, it's also important to set the `-dnsserver`
argument to `10.30.50.1` (your local machine) in the
[`docker-compose.yml`](https://github.com/letsencrypt/pebble/blob/main/docker-compose.yml#L5)
file (assuming your DNS server in fact runs on your local machine).

Keep in mind that you can use the `curl` command to perform HTTP(S) requests to
your servers and the `dig` command to request DNS records from your DNS Server.
If your servers aren't working as intended, try to manually perform the same
requests that Pebble would and check if and what your servers reply. 

## My HTTPS server is not reached after the ACME protocol run

The testing script sends a HEAD request to your HTTPS server (the one that
should show the downloaded certificate) in order to check whether the HTTPS
server is live and reachable. Make sure that your server also responds to HEAD
requests.

## When should my servers be started and shutdown?

You can start the HTTP and the DNS Server immediately after the first messages
exchanged with Pebble, as long as the certificate provided by Pebble is valid.
The HTTPS server can be started as soon as the certificate is retrieved. All
servers should be reachable until the `/shutdown` request is received. 

## I just cannot get my JWS to work correctly.

Some pitfalls to avoid when creating the JWS:

- Don't use the default base64 encoding, but the url-safe base64 encoding with
trailing '=' removed (as per [Section 2 of RFC
7515](https://www.rfc-editor.org/rfc/rfc7515#section-2)).
- Remove white-space and line-breaks in the json dump that should be encoded
(ibid).
- Use a proper byte encoding of the integer key parameters (e and n in RSA): The
resulting byte string of an integer i should be `ceil( i.bit_length() / 8 )`
bytes long. In particular, there must be no leading zero octet in the byte-string
([Section 8 of RFC
8555](https://datatracker.ietf.org/doc/html/rfc8555#section-8.1)).
- When using RSA, create the signature with PKCSv1.5 padding and the SHA256 hash
function (as in [Appendix A.2 of
RFC7515](https://www.rfc-editor.org/rfc/rfc7515#appendix-A.2)) 
- In case of a POST-as-GET, make sure the `payload` field is an empty string.
Otherwise, when performing a POST request, the payload is going to be either
`base64url({})`, for an empty payload, or `base64url({ ..some fields.. })` otherwise.
- When using elliptic-curve signatures, use the concatenated byte representation
of the `r` and `s` values as the signature (the signature output by the
cryptographic library is not necessarily in the right format), as stated in
[Appendix A.3 of RFC7515](https://www.rfc-editor.org/rfc/rfc7515#appendix-A.3).

Here are some tools that can be helpful when debugging JOSE-related issues:
- http://kjur.github.io/jsjws/tool_verifyanalyze.html
- https://8gwifi.org/jwsverify.jsp

## I am using ECDSA and my JWS is almost always accepted, but occasionally Pebble will return a malformed error with error code 400

Signatures generated using ECDSA are composed of two coordinates, r and s, which
are elements of the group that is used to define the elliptic curve.
Occasionally one (or both) of these coordinates will have a length that doesn't
correspond to the maximum length of a group element. In those cases the
signature won't be correctly parsed and therefore the JWS will be rejected. As
ECDSA is a randomized algorithm, retrying to send the same request (with a new
signature) will most likely solve the problem. 

## My implementation passes the DNS challenges by the ACME server, but not the DNS tests after the protocol run.

When the ACME protocol run finishes, the testing setup tests your DNS server
once again. In this test, the `dns.resolver` from `dnspython` is used, which we
have learned to be a lot less forgiving than other DNS client implementations
(e.g., the one used by Pebble, which accepts your DNS response). The hint to the
used library should help you in debugging.

## The scores of my implementation vary from run to run.

We recommend sticking to `dnslib.DNSServer` for the DNS Server in Python, as in
the past it has proven to be more reliable than
`socketserver`+`BaseRequestHandler`.

 ## The test setup seems to not find my `run` script.

Confusingly, the problem is not that `/project/run` does not exist (it does),
but that the first line of `project/run` reads to a Unix system as
`#!/bin/bash^M` instead of `#!/bin/bash` (if the file was edited under Windows).
It is the interpreter `/bin/bash^M` that does not exist. The `^M` is a carriage
return added by DOS. You can fix the format of your `project/run` file as
described [here](https://stackoverflow.com/a/29747593).
Alternatively, if you want to avoid this issue in the first place, make sure to
configure your editor to use UNIX line endings (LF) instead of Windows's (CRLF).
For example, if you want to achieve this in VSCode, have a look
[here](https://stackoverflow.com/a/48694365).

## I correctly serve the certificate but I get no points

This can happen if you obtained the certificate through the wrong challenge.
For example, if you used the `http01` challenge in place of the `dns01` or vice versa.

Your client has to use the appropriate challenge based on the command line
parameters it receives at the start of its execution.

## I have trouble installing Pebble.

Possibly the easiest way to install Pebble is to download the precompiled binary
from the [GitHub
Releases](https://github.com/letsencrypt/pebble/releases/tag/v2.6.0) page. Just
make sure to get the one for your specific OS/architecture. Extracting it and
making the Pebble file executable (only required on UNIX systems) should be
enough. Pebble will also need a configuration file in order to run (it has to be
supplied to Pebble via the `-config` flag). You can find an example
configuration file in Pebble's repository at [this
link](https://github.com/letsencrypt/pebble/blob/7c154bcd476a6e7e6c36221cec89b7027e019c04/test/config/pebble-config.json).

Thus, following these steps you should be able to get Pebble running:
1. Download the compiled binary for your platform, extract it and make it
   executable (if necessary).
2. Clone the [Pebble](https://github.com/letsencrypt/pebble) repository with Git
   and `cd` into it. This way you have the default configuration in
   `tests/config` and the certificates in `tests/certs` relative to your working
   directory.
3. Now, you can run:
   - If you're on a UNIX-like system (i.e., Linux, MacOS, BSD):
       ```sh
       $ PEBBLE_WFE_NONCEREJECT=0 /path/to/downlaoded/pebble -dnsserver 0.0.0.0:10053
       ````
   -  If you're on Windows:
       ```sh
       $ PEBBLE_WFE_NONCEREJECT=0 C:\path\to\downlaoded\pebble.exe -dnsserver 127.0.0.1:10053
       ````
   Replace `/path/to/downlaoded/pebble` with the path to your Pebble executable.

If you want to compile Pebble yourself (possibly, because you'd like to add some
debugging prints), then you can try following the instructions from the [Pebble
readme](https://github.com/letsencrypt/pebble/tree/7c154bcd476a6e7e6c36221cec89b7027e019c04?tab=readme-ov-file#install).
Once compiled, make sure to execute the Pebble binary you just built, by
changing the path in the command above.
