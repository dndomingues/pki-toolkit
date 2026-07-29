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

- Project structure
- Certificate Reader (in development)

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

- [ ] Read PEM certificate
- [ ] Display Subject
- [ ] Display Issuer
- [ ] Display Validity
- [ ] Display Serial Number
- [ ] Display Fingerprint

---

## License

MIT License.