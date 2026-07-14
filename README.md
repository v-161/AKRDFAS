# AKRDFAS v1.5

### Advanced Kernel Rootkit Detection and Forensic Analysis System

![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Linux-success.svg)
![Version](https://img.shields.io/badge/Version-v1.5-orange.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

AKRDFAS (Advanced Kernel Rootkit Detection and Forensic Analysis System) is a Linux kernel-focused digital forensic investigation framework designed to detect stealth kernel-level threats, collect forensic evidence, correlate security findings, perform MITRE ATT&CK mapping, identify Indicators of Compromise (IOCs), and generate professional forensic investigation reports.

Version **1.5** introduces an AI-powered investigation engine, an enhanced interactive dashboard, improved HTML/PDF reporting, and a more comprehensive forensic analysis workflow.

---

# Table of Contents

* Overview
* What's New in v1.5
* Features
* Detection Workflow
* Architecture
* Project Structure
* Detection Modules
* Dashboard
* AI Investigation Engine
* Reports
* Requirements
* Installation
* Running AKRDFAS
* Generated Evidence
* Current Capabilities
* Current Limitations
* Roadmap
* Intended Applications
* Disclaimer
* License
* Author

---

# Overview

AKRDFAS was developed to provide a kernel-centric forensic investigation platform capable of:

* Detecting Linux kernel rootkits
* Identifying hidden kernel modules
* Detecting hidden processes
* Verifying kernel integrity
* Monitoring kernel hooks
* Detecting persistence mechanisms
* Comparing systems against trusted baselines
* Correlating forensic evidence
* Mapping findings to MITRE ATT&CK
* Detecting Indicators of Compromise
* Producing investigator-ready forensic reports

Unlike traditional monitoring tools, AKRDFAS focuses on kernel-level visibility and forensic evidence preservation.

---

# What's New in Version 1.5

### AI Investigation Engine

* AI-generated forensic investigation analysis
* Executive summaries
* Threat explanation
* Security impact assessment
* Recommended investigation steps
* Remediation guidance

### Interactive Dashboard

* Investigation overview
* AI investigation panel
* Threat summary
* MITRE ATT&CK visualization
* Charts
* Evidence browser
* Report management

### Enhanced Reporting

* Professional HTML reports
* Professional PDF reports
* Timeline generation
* Evidence integrity verification
* Chain of custody
* Threat scoring
* MITRE ATT&CK mapping
* AI investigation analysis

---

# Features

### Kernel Investigation

* Kernel Information Collection
* Kernel Baseline Creation
* Kernel Baseline Comparison
* Kernel Module Enumeration
* Hidden Kernel Module Detection
* Hidden Process Detection
* Kernel Integrity Verification
* Kernel Hook Detection
* Kernel Log Analysis
* Persistence Detection
* Network Connection Analysis

### Threat Intelligence

* Threat Correlation Engine
* Risk Scoring Engine
* IOC Detection
* MITRE ATT&CK Mapping
* Threat Assessment Engine

### Digital Forensics

* Evidence Collection
* Chain of Custody
* Timeline Generation
* Evidence Integrity Verification
* SHA256 Evidence Verification

### Reporting

* HTML Investigation Report
* PDF Investigation Report
* AI Investigation Report
* Executive Summary
* Threat Summary
* Evidence Statistics

### Dashboard

* Interactive Dashboard
* Investigation Viewer
* Report Browser
* MITRE Visualization
* AI Investigation Panel
* Threat Charts

---

# Detection Workflow

```text
System Investigation
        │
        ▼
Kernel Information Collection
        │
        ▼
Trusted Baseline Collection
        │
        ▼
Kernel Module Enumeration
        │
        ▼
Hidden Module Detection
        │
        ▼
Hidden Process Detection
        │
        ▼
Kernel Integrity Verification
        │
        ▼
Network Analysis
        │
        ▼
Persistence Analysis
        │
        ▼
Kernel Hook Detection
        │
        ▼
Kernel Log Analysis
        │
        ▼
Baseline Comparison
        │
        ▼
Threat Correlation
        │
        ▼
MITRE ATT&CK Mapping
        │
        ▼
IOC Detection
        │
        ▼
Threat Assessment
        │
        ▼
Evidence Verification
        │
        ▼
Timeline Generation
        │
        ▼
AI Investigation
        │
        ▼
HTML Report
        │
        ▼
PDF Report
```

---

# Architecture

```text
                    AKRDFAS

                   main.py
                      │
              Detection Engine
                      │
    ┌─────────────────┼──────────────────┐
    │                 │                  │
 Kernel Modules   Threat Engine     Evidence Manager
    │                 │                  │
    │                 │                  │
Baseline        Correlation        Chain of Custody
Integrity       Risk Engine        Timeline
Network         MITRE Mapping      Verification
Hooks           IOC Engine
Logs            AI Analyzer
Persistence
```

---

# Project Structure

```text
AKRDFAS/
│
├── baseline/
├── config/
│
├── core/
│   ├── ai_analyzer.py
│   ├── engine.py
│   ├── threat_engine.py
│   ├── correlation_engine.py
│   ├── risk_engine.py
│   ├── mitre_mapper.py
│   ├── evidence_manager.py
│   ├── integrity_verifier.py
│   ├── timeline_logger.py
│   ├── chain_of_custody.py
│   └── ...
│
├── modules/
│   ├── kernel/
│   ├── network/
│   └── ioc/
│
├── dashboard/
│   ├── assets/
│   ├── components/
│   ├── pages/
│   ├── utils/
│   └── app.py
│
├── reports/
│   ├── templates/
│   ├── html_report.py
│   └── pdf_report.py
│
├── database/
├── logs/
├── evidence/
├── main.py
└── requirements.txt
```

---

# Detection Modules

## Kernel Analysis

* Kernel Information Detector
* Kernel Baseline Detector
* Kernel Module Detector
* Hidden Module Detector
* Hidden Process Detector
* Kernel Integrity Detector
* Kernel Hook Detector
* Kernel Log Detector
* Persistence Detector

## Network Analysis

* Network Connection Detector

## IOC Detection

* IOC Matching Engine

---

# AI Investigation Engine

AKRDFAS v1.5 includes an AI-powered investigation assistant capable of producing:

* Executive Summary
* Threat Justification
* Finding Analysis
* Potential Attacker Behaviour
* Business Impact
* Investigation Steps
* Remediation Steps
* Final Assessment

The AI investigation is embedded directly into both HTML and PDF reports.

---

# Dashboard

The interactive dashboard provides:

* Case Overview
* Threat Summary
* AI Investigation Panel
* MITRE ATT&CK Mapping
* Investigation Reports
* Evidence Browser
* Charts and Statistics

---

# Reports

AKRDFAS automatically generates:

* HTML Investigation Report
* PDF Investigation Report

Each report includes:

* Executive Summary
* Threat Assessment
* Kernel Investigation
* Network Analysis
* MITRE ATT&CK Mapping
* IOC Matches
* Evidence Statistics
* Timeline
* Chain of Custody
* Evidence Integrity
* AI Investigation Analysis

---

# Requirements

* Linux
* Python 3.10+
* Root Privileges

Install dependencies

```bash
pip install -r requirements.txt
```

---

# Running AKRDFAS

Run Investigation

```bash
python main.py
```

Run Dashboard

```bash
python dashboard/app.py
```

Dashboard

```text
http://127.0.0.1:8050
```

---

# Generated Evidence

AKRDFAS automatically generates:

* Kernel Information
* Baseline
* Module Analysis
* Hidden Module Analysis
* Hidden Process Analysis
* Network Analysis
* Persistence Analysis
* Kernel Hooks
* Kernel Logs
* Threat Assessment
* MITRE Mapping
* IOC Matches
* Timeline
* Chain of Custody
* Evidence Verification
* AI Investigation
* HTML Report
* PDF Report

---

# Current Capabilities

* Linux Kernel Rootkit Detection
* Hidden Kernel Module Detection
* Hidden Process Detection
* Kernel Integrity Verification
* Kernel Hook Detection
* Persistence Detection
* IOC Matching
* MITRE ATT&CK Mapping
* Threat Correlation
* Threat Scoring
* AI Investigation Analysis
* Interactive Dashboard
* HTML Reports
* PDF Reports
* Evidence Verification
* Timeline Generation
* Chain of Custody Tracking

---

# Current Limitations

AKRDFAS v1.5 currently focuses on Linux kernel forensic investigation.

The framework does not currently:

* Remove rootkits automatically
* Perform live memory acquisition
* Support Windows
* Support macOS
* Perform malware reverse engineering
* Include SIEM integration
* Include remote agents

---

# Roadmap

## Version 1.6

* Enhanced AI reasoning
* Improved kernel hook detection
* Threat intelligence feeds
* Dashboard enhancements

## Version 2.0

* Memory Forensics
* Volatility Integration
* eBPF Monitoring
* Advanced IOC Database
* Threat Intelligence Integration

## Future

* Windows Kernel Support
* Cross-platform Detection
* Remote Investigation Agent
* Distributed Investigation
* SIEM Integration
* Live Incident Response

---

# Intended Applications

AKRDFAS can be used for:

* Linux Kernel Rootkit Detection
* Digital Forensics
* Incident Response
* Malware Analysis
* Cybersecurity Research
* Academic Projects
* SOC Investigations
* Linux Security Auditing

---

# Disclaimer

AKRDFAS is intended for educational, research, and authorized forensic investigation purposes only.

Users are responsible for ensuring they have proper authorization before analyzing any system.

---

# License

This project is licensed under the MIT License.

---

# Author

**v-161**

GitHub

https://github.com/v-161
