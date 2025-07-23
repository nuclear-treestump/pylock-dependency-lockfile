from pydepguardnext.api.seal.seal import get_manifest_data, make_manifest_data
from pydepguardnext.api.log.logit import logit
import argparse

logslug = "cli.sign"

def add_run_command(subparsers):
    run_parser = subparsers.add_parser("sign", help="Sign a file, directory, or manifest")
    run_parser.add_argument("--method", help="Method to use", choices=["openssl", "pdgnative"], required=True)
    run_parser.add_argument("--target-type", help="Target type", choices=["manifest", "file", "directory"], required=True)
    run_parser.add_argument("--target", help="Target file or directory. If target-type is manifest, manifest's file tree will be used.")
    run_parser.
    run_parser.add_argument("--output", help="Output file")
    run_parser.set_defaults(handler=handle_run_command)

def handle_run_command(args):
    if args.method == "openssl":
        # Call OpenSSL signing function
        pass
    elif args.method == "pdgnative":
        # Call PDG native signing function
        logit("PDG Signing selected", "i", source=f"{logslug}.{handle_run_command.__name__}")
        """
        WARNING: PDG Native signing is an experimental feature primarily used for IPC communication between PDG components.

        It is not proven as production-ready for general use cases. Use at your own risk.

        Encrypting with PDG Native may not provide the same level of security and trust as established methods like OpenSSL.
        This method is provided as a native method of securing IPC communications between PDG components. 

        THIS IS HANDROLLED CRYPTOGRAPHY. DO NOT USE FOR HIGHER SECURITY NEEDS WITHOUT A FULL SECURITY AUDIT.

        PDG Native signing uses a combination of the following steps:
        1. The parent process generates a 4096 byte cryptographically random object during certificate generation. This is known as the "entropy blob".
        2. This object is stored in the parent process environment and is not written to disk unless explicitly done so by the user.
        3. The parent process generates a derived certificate for the child process, which includes a hash of the entropy blob + environmental pinning variables (e.g., process ID, user ID, platform hash, and child folder contents).
        4. The child process DOES NOT receive the entropy blob. It is provided a byte representation of the environmental pinning variables and the timestamp of certificate generation.
        5. The child process also receives a SHA512 hash of the entropy blob + environmental pinning variables + timestamp of certification generation.
        6. The child process receives this hash as part of its signing key. During transmission a nonce is added to the hash to prevent replay attacks.
        7. The parent process can recreate the hash at any time by using the entropy blob + environmental pinning variables + timestamp of certification generation, and can then add the nonce to verify the child process signature.

        This creates a trust relationship between the parent and child process. The child process can encrypt messages using the hash + timestamp + nonce as its encryption key, but cannot create the entropy itself to make valid parent keys.
        
        This is essentially asymmetric signing, but without the complexity of public/private key pairs.
        1. The parent process has the entropy blob and can create valid signatures for the child process.
        2. The child process cannot create valid signatures without the entropy blob, which is only available to the parent process.
        3. The parent process can verify signatures from the child process by recreating the hash using the entropy blob.
        4. The child process can verify signatures from the parent process by using the hash it received during certificate generation.
        5. The parent process can revoke the child process certificate by changing the entropy blob and regenerating the certificate.

        Usage:
        1. The child process uses the hash + timestamp + nonce as its encryption key to sign messages.
        2. The parent process uses the entropy blob + environmental pinning variables + timestamp + nonce to recreate the hash and verify the child process encrypted message.
        3. The parent process can also use the entropy blob + environmental pinning variables + timestamp + nonce to encrypt messages with scrypt using this derived key to the child process.
        4. The child process uses the hash + timestamp + nonce to verify the parent process signature.

        This is zero-trust asymmetric ENCRYPTION without the complexity of public/private key pairs.

        In theory, this could be as secure as RSA signing, but it has not been vetted or tested to the same degree.
        1. Limited Testing: PDG Native signing has not undergone extensive testing and validation like OpenSSL.
        2. Security Risks: Without thorough vetting, there may be undiscovered vulnerabilities in the PDG Native signing implementation.
        3. Lack of Community Review: OpenSSL benefits from a large community of security experts reviewing its codebase, whereas PDG Native signing lacks this level of scrutiny.
        """
        pass

