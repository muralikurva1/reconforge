# ReconForge

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-orange)

**ReconForge** is an intelligence-driven CLI reconnaissance framework designed for structured offensive security workflows.

It combines fast port discovery, service detection, HTTP intelligence extraction, and structured reporting into a single deterministic tool.

---

## Features

- Fast TCP discovery using RustScan (Nmap fallback supported)
- Structured Nmap XML parsing
- HTTP intelligence extraction (WhatWeb + Gobuster)
- Redirect-aware enumeration
- Risk scoring and severity classification
- JSON + Markdown reporting
- Optional safe `/etc/hosts` handling via `--auto-hosts`
- Clean CLI-first interface
- Threaded multi-target support

---

## Installation

Clone the repository:

```bash
git clone https://github.com/muralikurva1/reconforge.git
cd reconforge
