# soc2-evaluator

SOC 2 readiness assessment and evidence collection orchestrator for .NET solutions.

> **Important Framing:** SOC 2 is an attestation issued by a licensed CPA firm. This tool is a *readiness assessment and evidence-gathering aid*. It does not certify compliance or state that a target "is compliant"; output consists of findings against a control mapping.

## Overview

`soc2eval` orchestrates mature security scanners and analyzers (gitleaks, Semgrep, OSV-Scanner, CA analyzers, etc.), normalizes findings against Trust Services Criteria (TSC) and organization control mappings, and generates tamper-evident, timestamped evidence bundles with provenance.

## Documentation

- [Implementation Plan](docs/plan.md)