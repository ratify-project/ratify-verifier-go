# Cosign Verifier

## Introduction

Sigstore has a canonical Go client implementation, cosign, Cosign end users can leverage Fulcio’s short-lived code signing certificates and Rekor’s transparency log to confirm that an artifact was signed while the certificate was valid.

Sigstore’s Trust Root is made up of a rotation of five keyholders from varying companies and academic institutions who contribute to Sigstore. It leverages the principles of The Update Framework (TUF).

Sigstore team is planning to refactor part of cosign on `sigstore-go`, a more minimal and friendly API for integrating Go code with Sigstore.`sigstore-go` is currently beta, pass the `sigstore-conformance` signing and verification test suite. This verifier implementation uses the same library as for building cosign verifier.

## Concepts

Artifact Signatures  

- Artifacts may be signed using different cryptographic schemes. The verifier must support a variety of signature formats, including RSA, ECDSA, and Ed25519.
- The use of DSSE helps bundle signatures with metadata, providing additional context and validation capabilities.

Transparency Logs  

- Transparency logs, such as those maintained by the Sigstore project, provide an immutable record of signature entries.
- Verifying against these logs adds an extra layer of assurance that a signature has been publicly disclosed and has not been secretly revoked or altered.
- As a primary and recommended solution, Cosign will then store the signature and certificate in the Rekor transparency log.

Verification Workflows  

- The verifier must account for different workflows, such as verifying container images, software binaries, or other artifacts.
- Each workflow may involve different states of metadata, such as embedded signatures versus detached signatures, and requires customization accordingly.

## Scenarios

`sigstore-go` supports multiple verification scenarios based on different signing methods, artifact types, and trust sources.
These scenarios can be categorized into the following main types.

| **Verification Scenario**         | **Purpose**                                                            | **Use Case**                                                                 |
|-----------------------------------|------------------------------------------------------------------------|-----------------------------------------------------------------------------|
| **Keyless Verification**          | Fulcio issues short-lived certificates binding an ephemeral key to an OpenID Connect identity. Signing events are logged in Rekor, a signature transparency log. | CI/CD pipelines or automated workflows where no private key management is needed. |
| **Key-Based Verification**        | Verifies signature using a known **public key**.                        | Environments where signatures are verified with a known public key. |
| **Timestamp Verification**        | Verifies the **timestamp** of the signature to prevent time-based attacks. Not standalone verification. | Long-term signature validity checks, ensuring signatures are valid at a specific point in time. |
| **Rekor Transparency Log (TLog)** | Verifies inclusion of the signature in the **Rekor Transparency Log** for audibility. Not standalone verification. | Auditing and compliance to ensure signatures are publicly recorded in an immutable log. |
| **Blob Verification**             | Verifies detached file signatures (e.g., `.sig` file).                 | Verifying detached signatures for documents, binaries, or standalone files. |
| **Bundle Verification**           | Verifies a set of files signed together as a **bundle**.               | Ensuring integrity of a collection of files or documents signed as a bundle. |

### Verifier Input and Potential Output

A Verifier accepts a `SignedEntity` and a `Policy` and returns a `VerificationResult` including verification result as a boolean.

## References

- [Cosign Signature Spec](https://github.com/sigstore/cosign/blob/main/specs/SIGNATURE_SPEC.md)
- [Artifacts Guidance](https://github.com/opencontainers/image-spec/blob/main/artifacts-guidance.md)
- [Support the protobuf bundle format in Cosign](https://github.com/sigstore/cosign/issues/3139)
- [sigstore-go Verification Abstractions](https://github.com/sigstore/sigstore-go-archived/issues/35)
- [sigstore-go](https://github.com/sigstore/sigstore-go/tree/main)
- [Sigstore Client Spec](https://github.com/sigstore/architecture-docs/blob/main/client-spec.md#4-verification)
- [Cosign Verifying Signatures Description](https://docs.sigstore.dev/cosign/verifying/verify)
- [Sigstore Threat Model](https://docs.sigstore.dev/threat-model/)
