"""AXIVON — Universal Lossless Cyber Event Intelligence Fabric.

Local hackathon prototype: ingest heterogeneous security telemetry, preserve
raw evidence byte-for-byte, detect format, parse, normalize to a canonical
model, validate, and produce field-level provenance plus cryptographic
integrity (SHA-256 / Merkle).

This package implements the CURRENT PROTOTYPE. Everything else (Kafka,
Kubernetes, AI/ML parser generation, distributed vaults) is documented as
TARGET / FUTURE ARCHITECTURE in the project docs — none of it lives here.
"""

__version__ = "0.1.0"
