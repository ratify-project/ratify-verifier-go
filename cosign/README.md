# Cosign Verifier

## Introduction

This package contains the source code for the ratify-verifier-go cosign client library.

This package is built on the `sigstore-go` library, a low-level Go library that provides a suite of tools and standards designed for signing, verifying, and securing software supply chains.
`sigstore-go` focuses on the core functionalities of signing and verification, offering a minimal and user-friendly API without integration of registry operations or additional features like container image management.
In contrast, Cosign contains higher-level APIs within the Sigstore ecosystem that integrates these functionalities with container registries and other tools for end-to-end supply chain security.
Cosign builds on `sigstore-go` and extends its capabilities to include container image signing, verification, and storage in registries.

Using `sigstore-go` library makes it a more streamlined choice for developers seeking to implement lightweight and flexible signature verification.
Additionally, the Sigstore team plans to refactor parts of Cosign to rely more heavily on `sigstore-go`, making the interaction between the two libraries even closer.

## Concepts

Artifact Signatures  

- Artifacts may be signed using different cryptographic schemes. The verifier must support a variety of signature formats, including RSA, ECDSA, and Ed25519.
- The use of DSSE helps bundle signatures with metadata, providing additional context and validation capabilities.

Transparency Logs  

- Transparency logs, such as those maintained by the Sigstore project, provide an immutable record of signature entries.
- Verifying against these logs adds an extra layer of assurance that a signature has been publicly disclosed and has not been secretly revoked or altered.
- As a primary and recommanded solution, Cosign will then store the signature and certificate in the Rekor transparency log.

Verification Workflows  

- The verifier must account for different workflows, such as verifying container images, software binaries, or other artifacts.
- Each workflow may involve different states of metadata, such as embedded signatures versus detached signatures, and requires customization accordingly.
- `sigstore-go` library includes a few abstractions to support different use cases, testing, and extensibility:

  - `SignedEntity` - an interface type respresenting a signed message or attestation, with a signature and metadata, implemented by `Bundle`, a type which wraps the `Bundle` type from `protobuf-specs`.
  - `TrustedMaterial` - an interface type representing a trusted set of keys or certificates for verifying certificates, timestamps, and artifact transparency logs, implemented by `TrustedRoot`

## Scenarios

`sigstore-go` supports multiple verification scenarios based on different signing methods, artifact types, and trust sources.
These scenarios can be categorized into following main types and for this library we are going to implement the first four verification for basic user scenarios.

| **Verification Scenario**         | **Purpose**                                                            | **Use Case**                                                                 |
|-----------------------------------|------------------------------------------------------------------------|-----------------------------------------------------------------------------|
| **Keyless Verification**          | Verifies signature using **OIDC/Fulcio**-based trust (no private key needed). | CI/CD pipelines or automated workflows where no private key management is needed. |
| **Rekor Transparency Log (TLog)** | Verifies inclusion of the signature in the **Rekor Transparency Log** for audibility. | Auditing and compliance to ensure signatures are publicly recorded in an immutable log. |
| **Timestamp Verification**        | Verifies the **timestamp** of the signature to prevent time-based attacks. | Long-term signature validity checks, ensuring signatures are valid at a specific point in time. |
| **Key-Based Verification**        | Verifies signature using a known **public key**.                        | Environments where signatures are verified with a known public key. |
| **Blob Verification**             | Verifies detached file signatures (e.g., `.sig` file).                 | Verifying detached signatures for documents, binaries, or standalone files. |
| **Bundle Verification**           | Verifies a set of files signed together as a **bundle**.               | Ensuring integrity of a collection of files or documents signed as a bundle. |
| **SCT Verification**              | Verifies **timestamp** of a certificate to ensure it was issued at a specific time. | Verifying certificates with timestamps for **long-term validity** or **audit trails**. |

Different scenarios related to keys and certificates management within the package

| **Component**                      | **Key Management Role**                                                                                 |
|------------------------------------|---------------------------------------------------------------------------------------------------------|
| **Keyless Signing (OIDC/Fulcio)**  | No private key management. Signing is authenticated via OIDC and Fulcio generates the certificate. |
| **Fulcio (Certificate Authority)** | Key management handled by Fulcio, private keys never exposed to the user.                               |
| **Rekor Transparency Log**         | No key storage, but logs signatures for public verification. Ensures transparency and trust.           |
| **Traditional Key-Based Signing**  | User manages private keys, and public keys are registered for signature verification.                 |

| **Component**                      | **Certificate Management Role**                                                                                     |
|------------------------------------|-----------------------------------------------------------------------------------------------------------------------|
| **Fulcio (Certificate Authority)** | Issues certificates attesting to the user's identity, ensuring the authenticity of the signer.                     |
| **Rekor (Transparency Log)**       | Provides certificate transparency by logging metadata and signatures used for signing.                              |
| **Traditional Certificate Management** | Public key registration and private key management are user responsibilities.                                           |

## References

[Cosign Signature Spec](https://github.com/sigstore/cosign/blob/main/specs/SIGNATURE_SPEC.md)

[Support the protobuf bundle format in Cosign](https://github.com/sigstore/cosign/issues/3139)

[sigstore-go](https://github.com/sigstore/sigstore-go/tree/main)

[Sigstore Client Spec](https://github.com/sigstore/architecture-docs/blob/main/client-spec.md#4-verification)

[Cosign Verifying Signatures Description](https://docs.sigstore.dev/cosign/verifying/verify)

[Sigstore Threat Model](https://docs.sigstore.dev/threat-model/)
