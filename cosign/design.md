# **Cosign Verifier Library Implementation Using `sigstore-go`**

## Introduction

This document outlines the design of a Cosign verifier library using the newly developed `sigstore-go` API. The goal is to implement the `sigstore/cosign` library for `ratify` verifier API, and not relying on the legacy `sigstore/sigstore` library while ensuring compatibility with the `cosign` CLI experience.

## **2. Goals**

Implement a lightweight and efficient signature verification library.

- Align closely with `cosign` verification workflows.
- Provide a Go API that simplifies integration with policy engines like Ratify.
- Utilize `sigstore-go` to ensure maintainability and support future updates.

## **3. Architecture**

### **3.1. High-Level Flow**

1. **Fetch Signature & Public Key**: Retrieve the signature and associated key from a registry or local source.
2. **Verify Signature**: Use `sigstore-go` to validate the signature.
3. **Check Fulcio & Rekor** (if applicable): Verify against transparency logs and certificate chains.
4. **Policy Evaluation** (Optional): Provide hooks for `cosign` policy-based verification.

### **3.2. Component Breakdown**

| Component | Description |
|-----------|------------|
| `Verifier` | Core verification engine using `sigstore-go`. |
| `RegistryFetcher` | Retrieves signatures and attestations from OCI registries.Complete the executor behavor about getting signature descriptor. |
| `KeySource` | Loads keys from TUF, keyless (OIDC-based Fulcio), or user-provided sources. |
| `TransparencyLogVerifier` | Interacts with Rekor for transparency log validation. |
| `PolicyEvaluator` | (Optional) policy evaluation component. |

## **4. API Design**

### **4.1. Verifier Interface**

```go
type Verifier interface {
    // Name returns the name of the verifier.
    Name() string

    // Type returns the type name of the verifier.
    Type() string

    // Verifiable returns if the verifier can verify against the given artifact.
    Verifiable(artifact ocispec.Descriptor) bool

    // Verify verifies the subject in the store against the artifact and
    // returns the verification result.
    Verify(ctx context.Context, opts *VerifyOptions) (*VerificationResult, error)
}
```

### **4.2. Cosign Verify Options**

`CosignVerifyOptions` is needed for verification. Those values are preloaded when initialize the verifier and store in a trust material map, using `SubjectDescriptor` as key.

```go
type CosignVerifyOptions struct {
    Key              string   // Public key or keyless verification
    RekorURL         string   // Optional transparency log URL
    CertificateChain []byte   // Optional certificate chain for Fulcio
}
```

### **4.3. Cosign Verification Result**

`CosignVerificationResult` is provided in `VerificationResult.Detail` as additional information that can be used to provide more context.

```go
type CosignVerificationResult struct {
    VerifyOptions VerifyOptions // Showing ratify verifier input
    Signatures     []SignatureInfo
    TransparencyLog *RekorLogInfo
}
```

### **4.3.1 SignatureInfo**

```go
type SignatureInfo struct {
    Digest    string
    Signer    string
    Timestamp time.Time
}
```

## **5. Implementation Details**

### **5.1. Using sigstore-go**

- Use `sigstore-go/pkg/verify` for signature verification.
- Fetch signatures using `sigstore-go/pkg/fetch`.
- Integrate with `sigstore-go/pkg/rekor` for transparency log checks.

### **5.2. Compatibility with cosign CLI**

- Ensure CLI parity by supporting verification options (`--key`, `--rekor-url`, `--certificate-chain`).
- Handle public key and keyless verification workflows.

### **5.3. Integration with Ratify**

- Implement an adapter for Ratify to use the verifier.
- Provide a structured output compatible with Ratify policies.

## **6. Future Enhancements**

- Enhanced error handling and logging.
- Policy-based verification hooks.
