# Linux Privilege Escalation Automation Toolkit

## Introduction
Linux Privilege Escalation Automation Toolkit is a detection-only security auditing tool
developed during a cybersecurity internship.  
The purpose of this project is to automate common Linux privilege escalation enumeration
techniques used by security professionals to identify misconfigurations that could allow
unauthorized privilege escalation.

This toolkit focuses on **identification and reporting only** and does not execute
any exploit or malicious action.

---

## Problem Statement
Linux systems often suffer from misconfigurations such as:
- Improper file permissions
- Unsafe SUID/SGID binaries
- Misconfigured cron jobs
- Insecure sudo rules
- Weak service configurations

Manual auditing of these issues is time-consuming and error-prone.
This project automates the auditing process while keeping it safe and ethical.

---

## Project Objectives
- Automate Linux privilege escalation enumeration
- Identify real-world misconfigurations safely
- Understand attacker enumeration techniques
- Assist defenders in auditing Linux systems
- Generate a structured security report
- Follow ethical and detection-only practices

---

## Scope of the Project
The toolkit performs the following checks:

### 1. System Information Collection
- Logged-in user
- Group memberships
- Kernel version
- OS information

### 2. SUID Binary Enumeration
- Detects files with SUID bit set
- Highlights risky binaries (e.g. find, vim, perl, bash)
- Marks potential privilege escalation paths

### 3. SGID Binary Enumeration
- Identifies SGID binaries
- Flags group-based privilege risks

### 4. Weak File & Directory Permissions
- World-writable files
- World-writable directories
- Potential abuse of writable system resources

### 5. Sudo Misconfiguration Analysis
- Detects sudo privileges using `sudo -l`
- Identifies dangerous `NOPASSWD` rules

### 6. Systemd Service Review
- Lists enabled services
- Identifies services that require security review
- Focus on user-controlled paths and permissions

### 7. Cron Job Enumeration
- Reviews system-level cron jobs
- Detects writable cron locations
- Highlights timing-based attack risks

### 8. Linux Capabilities Check
- Detects files with elevated Linux capabilities
- Identifies unnecessary privileged capabilities

### 9. Kernel Version Identification
- Captures kernel version
- Flags outdated or vulnerable kernels (no exploitation)

---

## Tools & Technologies Used
- **Programming Language:** Python 3
- **Operating System:** Linux (Kali Linux / Ubuntu)
- **Linux Utilities Used:**
  - find
  - sudo
  - systemctl
  - crontab
  - getcap
  - uname
- **Development Tools:**
  - VS Code
  - Git & GitHub

---

## Workflow / Execution Flow
1. Collect basic system information
2. Scan for SUID binaries
3. Scan for SGID binaries
4. Check weak file and directory permissions
5. Analyze sudo configurations
6. Review enabled system services
7. Enumerate cron jobs
8. Check Linux capabilities
9. Capture kernel version
10. Generate final audit report

---

## How to Run the Tool

### Requirements
- Python 3
- Linux-based system
- Basic user access (root not mandatory)

### Execution
```bash
python3 privesc_audit_tool.py
