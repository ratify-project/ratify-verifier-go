# Cosign Verifier

## Introduction

This package contains the source code for the convenient Golang library implementation of the Ratify project Cosign Verifier workflow.

Cosign relies on code-signing certificate authority for digital identities (CA; Spec: Fulcio) and a timestamping service (RFC 3161) enables payload signatures using short-lived, single-use certificates issued to those identities. A signer requests a certificate from the CA, sign a payload, and get the signature timestamped. A verifier checks the signature timestamp falls during the certificate’s validity period.

## Concepts

**Payload**. The payload is the data to be signed (represented as a sequence of bytes). This might be a digital artifact, or an attestation/claim/metadata about a digital artifact.

**Certificate Transparency Log**. A service compliant with RFC 6962.

**Timestamping Service**. A service compliant with RFC 3161.

**Transparency Service (Timestamp)**. If the verification policy uses timestamps from the Transparency Service, the Verifier MUST verify the signature on the Transparency Service LogEntry against the pre-distributed root key material from the transparency service.

**Store**. Signature object are placed in specific location in an OCI registry to enable consistent, interoperable discovery. In tag-based discovery, signatures are stored in an OCI registry in a predictable location, addressable by tag. The location of signatures corresponding to a specific object can be computed using the digest of the object.

**Verifier**. A verifier validates a signature on a payload along with other verification material according to a *policy*.

**Policy**. The policy specifies:

* What must be true about the identity in a certificate (whom to trust).
* Which Fulcio, Timestamping Authority, and Transparency Service instances to trust (including root  key material for each).
* Whether to require signed timestamp(s) from a Timestamping Authority, and, if so, how many.
* Whether to require the signature metadata to be logged in one or more Transparency Services and, if so, how many.
* Whether to perform online or offline verification for the CT Log and the Transparency Service.
* Which [Transparency Service](https://docs.google.com/document/d/1NQUBSL9R64_vPxUEgVKGb0p81_7BVZ7PQuI078WFn-g/edit#heading=h.6w69n885z90t) formats the Verifier knows how to parse and validate.
* What to do with a payload, once verified.
* How to determine whether a signature has been revoked.

**Signature Verification**. The Verifier constructs the payload to be signed from the artifact and the additional payload metadata according to the verification policy and Transparency. Methods for doing so include:

* Using the raw bytes of the artifact as the payload.
* Hashing the artifact, then using the resultant digest as the payload.
* Using [DSSE](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md) as an envelope for the payload.
  * The DSSE `payloadType` must be `application/vnd.in-toto+json` per the [in-toto Envelope layer specification](https://github.com/in-toto/attestation/blob/main/spec/v1/envelope.md).
  * The payload MUST be an [in-toto statement](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md).
  * Verifier MUST ensure that the artifact's digest/algorithm tuple is present in the list of subjects in the in-toto statement.
  * Verifier SHOULD accept the raw artifact and compute the message digest to minimize any risk for confusion attacks.

The Verifier MUST verify the provided signature for the constructed payload against the key in the leaf of the certificate chain.

**Ratify Verifier**. Ratify Verifier is an implementation of the cosign verifier client.

## Scenarios

### Verify with Cosign Generated Encrypted Private/Public Keypair

1. Retrieve Image Digest from `ratify.Store`
2. Find Signature Object (image-digest.sig)
3. Extract Signature and Signed Payload
4. Get Verify Context from `verifycontextoptions`
5. Verify Signature with Public Key from `verifier.truststore`
6. Compare Signed Digest with Image Digest

### "Keyless signing" with the Sigstore Public Good Fulcio Certificate Authority and Rekor Transparency Log

1. Retrieve Image Digest from `ratify.Store`
2. Find Signature Object (image-digest.sig)
3. Extract Signature & Signing Certificate
4. Get Verify Context from `verifycontextoptions`
5. Verify Certificate (Fulcio CA) from `verifier.truststore`
6. Lookup Signature in Rekor Transparency Log
7. Compare Signed Digest with Image Digest
8. Validate OIDC Identity & Policy Check

### Muliplex Verify (TBD)

## References

[Cosign Signature Spec](https://github.com/sigstore/cosign/blob/main/specs/SIGNATURE_SPEC.md)

[Sigstore Client Spec](https://github.com/sigstore/architecture-docs/blob/main/client-spec.md#4-verification)

[Cosign Verifying Signatures Description](https://docs.sigstore.dev/cosign/verifying/verify)

[`ArtifactVerificationOptions` Policy](https://github.com/sigstore/protobuf-specs/blob/4dbf10bc287d76f1bfa68c05a78f3f5add5f56fe/protos/sigstore_verification.proto#L46-L108)

[`TrustedRoot` Policy](https://github.com/sigstore/protobuf-specs/blob/4dbf10bc287d76f1bfa68c05a78f3f5add5f56fe/protos/sigstore_trustroot.proto#L59-L88)

[Sigstore Threat Model](https://docs.sigstore.dev/threat-model/)
