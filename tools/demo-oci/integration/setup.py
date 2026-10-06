#!/usr/bin/env python3
"""Create fresh disposable TLS/htpasswd files, without displaying secret values.

Integration setup only: requires OpenSSL and either Unix crypt with Blowfish
(Python 3.9 on CI Linux), or htpasswd. The installed-binary demo needs neither.
"""
import argparse
import os
from pathlib import Path
import secrets
import shlex
import shutil
import subprocess


def private(path, raw):
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("--port", type=int, default=15000)
    args = parser.parse_args()
    root = args.root.resolve()
    root.mkdir(mode=0o700, parents=False, exist_ok=False)
    (root / "tls").mkdir(mode=0o700)
    (root / "auth").mkdir(mode=0o700)
    # This fixed public synthetic username is not a production identity.
    user = "rio-synthetic-writer"
    password = secrets.token_urlsafe(32)
    hashed = None
    try:
        import crypt
        if crypt.METHOD_BLOWFISH in crypt.methods:
            hashed = crypt.crypt(password, crypt.mksalt(crypt.METHOD_BLOWFISH))
    except (ImportError, AttributeError):
        pass
    if not hashed:
        helper = shutil.which("htpasswd")
        if not helper:
            raise SystemExit("Integration setup needs bcrypt-capable Unix crypt or htpasswd")
        # Password goes through stdin, never arguments, logs or the shell.
        result = subprocess.run([helper, "-niBC", "12", user], input=(password + "\n").encode(),
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode:
            raise SystemExit("Disposable bcrypt generation failed")
        hashed = result.stdout.decode().strip().split(":", 1)[1]
    if not hashed.startswith(("$2a$", "$2b$", "$2y$")):
        raise SystemExit("bcrypt is required; weaker hashes are not accepted")
    private(root / "auth/htpasswd", (user + ":" + hashed + "\n").encode())
    result = subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                             "-keyout", str(root / "tls/key.pem"), "-out", str(root / "tls/cert.pem"),
                             "-days", "2", "-subj", "/CN=localhost",
                             "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        raise SystemExit("Disposable certificate generation failed")
    os.chmod(root / "tls/key.pem", 0o600)
    values = {"RIO_OCI_INTEGRATION": "1", "RIO_OCI_TEST_REGISTRY": "127.0.0.1:%d" % args.port,
              "RIO_OCI_TEST_REPOSITORY": "rio-integration/synthetic", "RIO_OCI_TEST_USERNAME": user,
              "RIO_OCI_TEST_PASSWORD": password, "RIO_OCI_TEST_CA_FILE": str(root / "tls/cert.pem"),
              "RIO_OCI_TEST_ALLOW_HTTP": "0", "RIO_OCI_TEST_REFERRERS": "unsupported", "RIO_OCI_TEST_DENIED_USERNAME": "rio-synthetic-denied",
              "RIO_OCI_TEST_DENIED_PASSWORD": secrets.token_urlsafe(32),
              "RIO_OCI_TEST_PRODUCT": "Distribution", "RIO_OCI_TEST_VERSION": "3.1.2",
              "RIO_OCI_TEST_IMAGE_DIGEST": "sha256:d106962e6fe3fa69c178cec77eeeee5edb626b8df6535b7bd6b95e658a0a5ca9"}
    private(root / "test.env", ("\n".join(key + "=" + shlex.quote(value) for key, value in values.items()) + "\n").encode())
    print("Created disposable OCI TLS/auth fixtures. Private values were not displayed.")


if __name__ == "__main__":
    main()
