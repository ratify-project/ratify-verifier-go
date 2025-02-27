# Cosign Verifier

## Introduction

In order to provide signatures over arbitrary artifacts, Sigstore performs three major operations:

- OIDC Issuance, vouch that a client is in control of an identity
- Associate short-lived public key certificates with these identities (from a Certificate Authority), and publish these certificates to an Identity Log.
- Publish a long-lived signature over an artifact (or artifact meta-data) to an Artifact Log, allowing verifiers to check its validity.

The first and second operations are performed by a system called Fulcio, which functions as a Certificate Authority and transparency log for a namespace of OIDC identities (Identity Log). The third operation is performed by a system called Rekor, a transparency log for artifact signatures (Artifact Log). And cosign is the reference Sigstore client implementation to sign arbitrary artifacts. With these components, Sigstore completed trust setup, signing and verification.

The Sigstore team plans to refactor parts of cosign into a new, minimal, and user-friendly API named `sigstore-go`. Currently in beta, `sigstore-go` has passed the `sigstore-conformance` signing and verification test suite.
`sigstore-go` is built as a modular Go codebase including cryptographic signature creation and validation, integration with external services (Fulcio for certificates and Rekor for record-keeping) and API layers.
The `ratify-verifier-go` implementation shares the same underlying library, `sigstore-go`, as the cosign verifier.

## Concepts

Artifact signing: To sign an artifact, a signer generates a private/public key pair and uses the secret key to sign an arbitrary piece of data.

Artifact Log: Record of artifact metadata created by signers.

Identity Log: Record of mappings from identities to signing keys.

OpenID Connect (OIDC): A widely-supported protocol allowing relying parties (applications) to verify the identity of resource owners (end users) as confirmed by identity providers.

Identity Provider: Mechanism vouching that an entity (individual) controls an identity (e.g., email account)

Signers: Individuals vouching for the authenticity of content.

Verifiers: Individuals checking that content is authentic.

Certificate Authority(CA): Entity verifying identity and issues cryptographic certificates to signers.

Webpublickeyinfrastructure (PKI): A mature and widely deployed trust ecosystem. At its core, web PKI uses X.509 certificates to pin the trust of web servers to a “certificate authority” (or CA).

## Scenarios

`sigstore-go` supports multiple verification scenarios based on different signing methods, artifact types, and trust sources. These scenarios can be categorized into the following main types.

| **Verification Scenario**         | **Purpose**                                                            | **Use Case**                                                                 |
|-----------------------------------|------------------------------------------------------------------------|-----------------------------------------------------------------------------|
| **Keyless Verification**          | Fulcio issues short-lived certificates binding an ephemeral key to an OpenID Connect identity. Signing events are logged in Rekor, a signature transparency log. | CI/CD pipelines or automated workflows where no private key management is needed. |
| **Key-Based Verification**        | Verifies signature using a known **public key**.                        | Environments where signatures are verified with a known public key. |
| **Timestamp Verification**        | Verifies the **timestamp** of the signature to prevent time-based attacks. Not standalone verification. | Long-term signature validity checks, ensuring signatures are valid at a specific point in time. |
| **Rekor Transparency Log (TLog)** | Verifies inclusion of the signature in the **Rekor Transparency Log** for audibility. Not standalone verification. | Auditing and compliance to ensure signatures are publicly recorded in an immutable log. |

### Verification Input

1. The Artifact to Verify
The actual file, container image, or other digital asset being verified.

2. Verification materials
    - The Signature(s) of the Artifact. The cryptographic signature(s) created when the artifact was signed.
    - Verification options i.e. whether to expect SCTs, Tlog entries, or signed timestamps and expected identity and digest to verify.

3. Verification Key or Certificate
    - Key-Based Verification: User provides a public key (e.g., PEM-encoded RSA, ECDSA, or Ed25519).
    - Keyless Verification (Fulcio-based Certificate Verification): User provides the signing certificate (issued by Fulcio).

### Verification Output

Upon successful verification—meaning the signature is valid and all criteria are met—the output includes key information such as:

verification_success: Indicates if the verification was successful.
artifact_digest: The cryptographic hash of the artifact.
signer_identity: The identity associated with the signing certificate (if keyless signing was used).
signing_cert: Metadata about the Fulcio-issued certificate (if applicable).
rekor_entry: Confirms whether the signature exists in the transparency log (for keyless verification).
timestamp_verified: Ensures that the signature has a valid timestamp (if timestamping was used).

If any component of the verification fails (e.g., invalid signature, missing key, revoked certificate), the verifier returns an error.

## References

- [Sigstore Security Model](https://docs.sigstore.dev/about/security/)
- [Cosign Signature Spec](https://github.com/sigstore/cosign/blob/main/specs/SIGNATURE_SPEC.md)
- [Sigstore Client Spec](https://github.com/sigstore/architecture-docs/blob/main/client-spec.md#4-verification)
- [Cosign Verifying Signatures Description](https://docs.sigstore.dev/cosign/verifying/verify)
- [sigstore-go Verification Abstractions](https://github.com/sigstore/sigstore-go-archived/issues/35)
- [Sigstore: Software Signing for Everybody](https://dl.acm.org/doi/pdf/10.1145/3548606.3560596)