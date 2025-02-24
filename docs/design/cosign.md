# Cosign Verifer Support 2025

Author: Juncheng Zhu (@junczhu)

`ratify-verifier-go` cosign verifier is designed to support keyed verification and keyless verification:

- using `store` API to get the artifacts
- using `truststore` to store keys, certs and certchains
- using `verifycontextoptions` to store verify context other than `truststore`

## Keyed Data Flow

1. Retrieve Image Digest from `ratify.Store`
2. Find Signature Object (image-digest.sig)
3. Extract Signature and Signed Payload
4. Get Verify Context from `verifycontextoptions`
5. Verify Signature with Public Key from `verifier.truststore`
6. Compare Signed Digest with Image Digest

## Keyless Data Flow

1. Retrieve Image Digest from `ratify.Store`
2. Find Signature Object (image-digest.sig)
3. Extract Signature & Signing Certificate
4. Get Verify Context from `verifycontextoptions`
5. Verify Certificate (Fulcio CA) from `verifier.truststore`
6. Lookup Signature in Rekor Transparency Log
7. Compare Signed Digest with Image Digest
8. Validate OIDC Identity & Policy Check

## Implement Details

### Initiate Verifier

(Ratify) Verifier is initialized with `verifierOptions`, including `Name`, `VerifierContextOptions` and `TrustStore`

### VerifyContext

`VerifyContext` includes prepared context for verify which not contained by `VerifyOptions`.

### TrustStore

`TrustStore` holds keys, certs and certchains for verify.

### TrustPolicy

Implemented `TrustPolicy` for backward compatability

## Future Considerations

## Reference

[cosign signature spec](https://github.com/sigstore/cosign/blob/main/specs/SIGNATURE_SPEC.md)
[cosign verification spec](https://github.com/sigstore/architecture-docs/blob/main/client-spec.md#4-verification)