# ReconForge

**ReconForge** is an intelligence-driven CLI reconnaissance framework built for offensive security workflows.

It combines fast discovery, structured intelligence extraction, adaptive enumeration, and dynamic risk scoring into a professional command-line tool.

---

## Features

- Fast TCP discovery (RustScan fallback to Nmap)
- Structured Nmap XML parsing
- Adaptive HTTP pivoting (auto redirect detection)
- Gobuster parsing with severity classification
- Technology fingerprinting (WhatWeb integration)
- Dynamic risk scoring engine
- Intelligence-based findings model
- JSON + Markdown report generation
- Multi-target support
- Threaded orchestration
- Clean professional CLI dashboard

---

## Installation

### 1. Clone repository

```bash
git clone https://github.com/<your-username>/reconforge.git
cd reconforge

⚠ Note:
If a target redirects to a domain (e.g., HTB lab environments), ReconForge may append the entry to /etc/hosts automatically.
Ensure you review changes before running in production environments.
