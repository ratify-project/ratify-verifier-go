# Cosign Verifer Support 2025

`ratify-verifier-go` cosign verifier is designed to support keyed verification and keyless verification:
- using `store` API to get the artifacts
- using `truststore` to store keys, certs and certchains
- using `trustpolicy` to define desired verification scenarios
- using `verifycontextoptions` to store verify context other than `truststore` and `trustpolicy`


## Support Key Configuration
### Data Flow
User runs "cosign verify"
       │
       ▼
Retrieve Image Digest from Registry
       │
       ▼
Find Signature Object (<image-digest>.sig)
       │
       ▼
Extract Signature and Signed Payload
       │
       ▼
Verify Signature with Public Key
       │
       ▼
Compare Signed Digest with Image Digest
       │
       ▼
Output Verification Result


## Support Keyless Configuration
### Data Flow
User runs "cosign verify"
       │
       ▼
Retrieve Image Digest from Registry
       │
       ▼
Find Signature Object (<image-digest>.sig)
       │
       ▼
Extract Signature & Signing Certificate
       │
       ▼
Verify Certificate (Fulcio CA)
       │
       ▼
Lookup Signature in Rekor Transparency Log
       │
       ▼
Compare Signed Digest with Image Digest
       │
       ▼
Validate OIDC Identity & Policy Check
       │
       ▼
Output Verification Result


### Cert Extension

## Implement Details

### VerifyContext

### TrustStore

### TrustPolicy

## Future Considerations