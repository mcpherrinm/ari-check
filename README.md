# ari-check

A command-line tool to check [ACME Renewal Information (ARI)](https://www.rfc-editor.org/rfc/rfc9773) for certificates. Defaults to Let's Encrypt's production ACME directory.

Given a certificate serial number, it fetches the certificate, constructs the RFC 9773 CertID, and queries the ACME server's renewalInfo endpoint to display the suggested renewal window.

## Usage

```
ari-check [flags] <certificate-serial-number>
```

The serial number should be in hex, either colon-separated or plain:

```
ari-check 04:ab:cd:ef:12:34
ari-check 04abcdef1234
```

To use a different ACME directory:

```
ari-check -directory https://acme-staging-v02.api.letsencrypt.org/directory 04abcdef1234
```

## Building

```
go build -o ari-check .
```

## How it works

1. Fetches the ACME directory to discover the `renewalInfo` endpoint
2. Fetches the certificate from the ACME server by serial number
3. Constructs the ARI CertID: `base64url(AKI) "." base64url(Serial)` per RFC 9773
4. Queries the renewalInfo endpoint and displays the suggested renewal window

## Notice

This code was generated with the assistance of Claude, an AI assistant by Anthropic.
