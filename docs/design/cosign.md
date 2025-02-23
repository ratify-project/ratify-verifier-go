# Cosign Verifer Support 2025

Author: Juncheng Zhu (@junczhu)

`ratify-verifier-go` cosign verifier is designed to support keyed verification and keyless verification:

- using `store` API to get the artifacts
- using `truststore` to store keys, certs and certchains
- using `verifycontextoptions` to store verify context other than `truststore`

## Keyed Data Flow

1. Call "verify" with `ratify.VerifyOptions`
2. Retrieve Image Digest from Registry using `ratify.Store`
3. Find Signature Object (image-digest.sig)
4. Extract Signature and Signed Payload
5. Get Verify Context from `verifycontextoptions`
6. Verify Signature with Public Key from `verifier.truststore`
7. Compare Signed Digest with Image Digest
8. Output Verification Result

## Keyless Data Flow

1. Call "verify" with `ratify.VerifyOptions`
2. Retrieve Image Digest from Registry
3. Find Signature Object (image-digest.sig)
4. Extract Signature & Signing Certificate
5. Verify Certificate (Fulcio CA)
6. Lookup Signature in Rekor Transparency Log
7. Compare Signed Digest with Image Digest
8. Validate OIDC Identity & Policy Check
9. Output Verification Result

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
