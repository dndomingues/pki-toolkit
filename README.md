# PKI Toolkit

A Python toolkit for working with X.509 certificates, TLS, PKI automation, and machine identity.

---

## Overview

PKI Toolkit is an open-source project created to study, automate and demonstrate Public Key Infrastructure (PKI) concepts using Python.

The project aims to evolve into a complete toolkit for certificate inspection, validation and lifecycle automation.

The project will evolve from a simple certificate reader into a complete toolkit capable of:

- Reading X.509 certificates
- Inspecting certificate metadata
- Validating certificate chains
- Parsing CRLs
- Performing OCSP validation
- Scanning remote TLS endpoints
- Exporting certificate inventories
- Supporting PKI automation

---

## Project Structure

```
pki-toolkit/
│
├── src/
│   ├── reader.py       -> Certificate Reader 
│   ├── models.py       -> Shared data models
│   ├── utils.py        -> Helper functions
│   └── __init__.py     -> Package initialization
│
├── samples/
│
├── tests/
│
├── requirements.txt
└── README.md
```

---

## Current Features

- Read X.509 certificates in PEM format
- Display Subject and Issuer
- Display certificate version and serial number
- Display validity period and remaining days
- Identify public-key algorithm and key size
- Display signature algorithm
- Inspect Basic Constraints
- Extract Subject Alternative Names
- Inspect Key Usage
- Inspect Extended Key Usage
- Generate SHA-256 fingerprint
- Fetch certificates directly from remote TLS servers
- Support local PEM files and remote hostnames
- Handle DNS, connection and TLS handshake errors

---

## Planned Features

- Certificate Reader
- Certificate Metadata
- Certificate Chain Validator
- Certificate Expiration Report
- TLS Scanner
- OCSP Checker
- CRL Parser
- Certificate Inventory
- JSON Export
- CSV Export 

---

## Requirements

- Python 3.12+
- cryptography

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## Roadmap

Current Sprint:

- [x] Read PEM certificate
- [x] Display Subject
- [x] Display Issuer
- [x] Display Validity
- [x] Display Serial Number
- [x] Display Fingerprint
- [x] Identify public-key algorithm
- [x] Extract Subject Alternative Names
- [x] Inspect Basic Constraints
- [x] Inspect Key Usage
- [x] Inspect Extended Key Usage
- [x] Fetch certificate from remote TLS endpoint
- [x] Support local files and remote hostnames
- [x] Handle remote connection errors

---

## License

MIT License.