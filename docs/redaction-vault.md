# Encrypted Local Redaction Vault

The AEGF Redaction Vault enables reversible, encrypted redaction of sensitive parameters before external transmission.

## Cryptographic Design

- **Cipher:** AES-256-GCM authenticated encryption (`crypto/cipher`).
- **Nonces:** 96-bit cryptographically secure random nonces per stored record via `crypto/rand`.
- **Associated Data (AAD):** The opaque token string is bound as authenticated additional data to prevent token substitution attacks.
- **Master Key:** 32-byte master encryption key configured via `AEGF_VAULT_KEY` or file with `0600` permissions.
- **Zero-Plaintext:** Original sensitive values are encrypted before persistence in SQLite.

## Reversible Restoration

When upstream responses contain vaulted tokens, authorized operators or background workers can restore original values locally:

```bash
# Restore tokens in a JSON or text file
aegf vault restore --input redacted_response.json --output restored.json

# Restore from pipe
curl -s http://127.0.0.1:8080/openai/v1/customer | aegf vault restore
```

## Vault Retention and Purging

Expired records can be automatically purged:

```bash
aegf vault purge --older-than 30d
```
