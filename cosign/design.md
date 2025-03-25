# **Cosign Verifier Library Implementation Using `sigstore-go`**

## 1. Introduction

This document outlines the design of a Cosign verifier library using the newly developed `sigstore-go` API.
The goal is to implement the `sigstore/cosign` library for `ratify` verifier API, and not relying on the legacy `sigstore/sigstore` library while ensuring compatibility with the `cosign` CLI experience.

## 2. Goals

Implement a lightweight and efficient signature verification library.

- Utilize `sigstore-go` to ensure maintainability and support future updates.
- Provide a Go API that simplifies integration with policy engines like Ratify.
- Align closely with `cosign` verification workflows.

## 3. Architecture

### 3.1. High-Level Flow

1. **Initialize Verifier, Trust Materials, Policies**: Initialize Cosign verifier with verifier options
2. **Resolve Verify Option, Composite Verify Input**: Retrieve trust material and Cosign policy option.
3. **Perform Verify with Trust Materials and Policies**: Use API from `sigstore-go` library to validate the signature.

### 3.2. Component Breakdown

| Component | Description |
|-----------|------------|
| `Verifier`| Core verification engine using `sigstore-go`. |
| `PolicyProvider`| Interface that provide identity policies. |
| `TrustedMaterialProvider` | Interface that provides public keys, keyless identifies, and other resources needed for the trust chain. |

## 4. Design

### 4.1. Verifier Initialize

```go
type Verifier struct {
    name     string
    config   verify.VerifierConfig
    trustMaterialProvider TrustedMaterialProvider
    policyProvider PolicyProvider
}

type VerifierConfig struct { // nolint: revive
    // requireObserverTimestamps requires RFC3161 timestamps and/or log
    // integrated timestamps to verify short-lived certificates
    requireObserverTimestamps bool
    // observerTimestampThreshold is the minimum number of verified
    // RFC3161 timestamps and/or log integrated timestamps in a bundle
    observerTimestampThreshold int
    // requireTlogEntries requires log inclusion proofs in a bundle
    requireTlogEntries bool
    // tlogEntriesThreshold is the minimum number of verified inclusion
    // proofs in a bundle
    tlogEntriesThreshold int
    // requireSCTs requires SCTs in Fulcio certificates
    requireSCTs bool
    // ctlogEntriesTreshold is the minimum number of verified SCTs in
    // a Fulcio certificate
    ctlogEntriesThreshold int
}

type PolicyProvider interface {
    PolicyConfig(ocispec.Descriptor) PolicyConfig
}

type Policy{
    ignoreIdentities      bool
    // CertificateIdentities is defined by the sigstore-go library
    certificateIdentities CertificateIdentities
}

type TrustMaterialProvider interface {
    // user ocispec.Descriptor to retrive the root.TrustedMaterial
    // root.TrustedMaterial is a interface for trust material defined by
    // the sigstore-go library
    TrustMaterial(ocispec.Descriptor) root.TrustedMaterial
}
```

### 4.2. Verify Options

When ratify-go executor verify API, it takes following fields as input.

```go
type VerifyOptions struct {
    // Store is the store to access the artifacts. Required.
    Store Store

    // Repository represents the fully qualified repository name of the subject,
    // including the registry name.
    // Required.
    Repository string

    // SubjectDescriptor is the descriptor of the subject being verified.
    // Required.
    SubjectDescriptor ocispec.Descriptor

    // ArtifactDescriptor is the descriptor of the artifact being verified
    // against. Required.
    ArtifactDescriptor ocispec.Descriptor
}
```

With those descriptors and store to access the artifacts, the next step is to composite the cosign verify entity.
The entity also contains public key, policies that showing the expected identity and issuer in the signing certificate. These values are preloaded when initializing the verifier.

```go
type VerifyEntity struct {
    // verify.SignedEntity is a interface defined by sigstore-go as the verify input
    signedEntity        verify.SignedEntity
    // identityPolices is a list of policy options as verify input
    identityPolicies    []verify.PolicyOption
}
```

**NOTE:**

- Key-based verification requires providing the public key for cryptographically verification

- Keyless verification finds an x509 certificate with a public key on the signature and verifies it against the Fulcio root trust (or user-supplied root trust).

### 4.3. Verification Result

`VerificationResult` defines the verification result that a verifier plugin
must return.

```go
type VerificationResult struct {
    // Err is the error that occurred when the verification failed.
    // If the verification is successful, this field should be nil. Optional.
    Err error

    // Description describes the verification result if needed. Optional.
    Description string

    // Verifier refers to the verifier that generated the result. Required.
    Verifier Verifier

    // Detail is additional information that can be used to provide more context
    // about the verification result. Optional.
    Detail any
}


// `CosignVerificationResult` is provided in `VerificationResult.Detail` as additional information that can be used to provide more context.

type CosignVerificationResult struct {
    MediaType          string                        `json:"mediaType"`
    Signature          *SignatureVerificationResult  `json:"signature,omitempty"`
    VerifiedTimestamps []TimestampVerificationResult `json:"verifiedTimestamps"`
    VerifiedIdentity   *CertificateIdentity          `json:"verifiedIdentity,omitempty"`
}
```

## 5. Implementation Details

### 5.1. Using sigstore-go

#### 5.1.1 Legacy vs. New Implementation

| Aspect               | Legacy (`sigstore/cosign`)                                                                 | New (`sigstore-go`)                              |
|----------------------|--------------------------------------------------------------------------------------------|--------------------------------------------------|
| **Structure**        | Tightly coupled to Cosign CLI                                             | Modular, reusable library for SDK/API integrations                |
| **Verification**     | Hardcoded workflows (e.g., fixed certificate checks in `pkg/cosign`)      | Extensible via `sigstore-go` primitives (e.g., `TrustedRoot`)     |
| **Policy Support**   | Limited to Cosign’s CLI flags                                             | Native integration with Ratify’s verify option                    |
| **Performance**      | Optimized for CLI use cases (single-threaded verification)                | Optimized for serverless/API (caching, parallelization)           |  

- Use `sigstore-go/pkg/verify` for signature verification.
- Integrate with `sigstore-go/pkg/rekor` for transparency log checks.

### 5.2. Feature Compatibility with Cosign CLI

#### 5.2.1 Current Features

- Verification of Cosign signatures by creating bundles for them (see [conformance tests](test/conformance/main.go) for example)
- Verification with a Timestamp Authority (TSA)
- Verification with Rekor (Artifact Transparency Log)
- Structured verification results.

#### 5.2.2 Limitations

- Offline signature verification is currently not supported.
- Verification of attestations and annotations are not supported.

**NOTE:**
The verifier allows you to use the Sigstore Public Good TUF root or your own custom trusted root containing the root/intermediate certificates of the Fulcio/TSA/Rekor instances used to sign the bundle, in order to verify common open source bundles or bundles signed by your own private Sigstore instance.

## 6. Future Enhancements

- Enable `Provider` multiplexer.
- Support user-provided trusted chains.
- Support more policy for specific timestamps e.g., signed certificate timestamp, integrated timestamp.
