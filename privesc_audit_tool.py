#!/usr/bin/env python3

import os
import subprocess
import platform
from datetime import datetime

results = []

def run(cmd):
    try:
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL)
        return out.decode().strip()
    except:
        return ""

def save(level, area, msg, fix):
    results.append({
        "level": level,
        "area": area,
        "msg": msg,
        "fix": fix
    })

# system info
def collect_basic_info():
    user = run("whoami")
    groups = run("groups")
    kernel = run("uname -a")
    osinfo = run("cat /etc/os-release | grep PRETTY_NAME")

    save(
        "INFO",
        "System Info",
        f"User: {user}\nGroups: {groups}\nKernel: {kernel}\nOS: {osinfo}",
        "No action required"
    )

# suid check
def check_suid_binaries():
    suid_bins = run("find / -type f -perm -4000 2>/dev/null")
    risky = ["find", "vim", "perl", "awk", "bash", "python"]

    for b in suid_bins.splitlines():
        for r in risky:
            if r in b:
                save(
                    "HIGH",
                    "SUID Binary",
                    f"SUID binary looks risky: {b}",
                    "Remove SUID bit if not strictly required"
                )

# sgid check
def check_sgid_binaries():
    sgid_bins = run("find / -type f -perm -2000 2>/dev/null | head -n 15")
    if sgid_bins:
        save(
            "MEDIUM",
            "SGID Binary",
            sgid_bins,
            "Review group permissions on SGID files"
        )

# permission check
def check_permissions():
    writable_files = run("find / -type f -perm -0002 2>/dev/null | head -n 10")
    writable_dirs = run("find / -type d -perm -0002 2>/dev/null | head -n 10")

    if writable_files:
        save(
            "MEDIUM",
            "File Permissions",
            writable_files,
            "Restrict world writable file permissions"
        )

    if writable_dirs:
        save(
            "LOW",
            "Directory Permissions",
            writable_dirs,
            "Limit write access on directories"
        )

# sudo check
def check_sudo_rules():
    sudo_out = run("sudo -l")
    if sudo_out:
        if "NOPASSWD" in sudo_out:
            save(
                "HIGH",
                "Sudo",
                sudo_out,
                "Remove NOPASSWD sudo rules"
            )
        else:
            save(
                "INFO",
                "Sudo",
                sudo_out,
                "Review sudo access regularly"
            )

# service check
def check_services():
    services = run("systemctl list-unit-files --type=service --state=enabled --no-pager | head -n 12")
    if services:
        save(
            "MEDIUM",
            "Systemd Services",
            services,
            "Verify service files do not use user writable paths"
        )

# cron check
def check_cron():
    cron_paths = [
        "/etc/crontab",
        "/etc/cron.d",
        "/etc/cron.daily",
        "/etc/cron.hourly",
        "/etc/cron.weekly"
    ]

    for c in cron_paths:
        if os.path.exists(c):
            info = run(f"ls -la {c}")
            save(
                "HIGH",
                "Cron Jobs",
                f"Cron location found: {c}\n{info}",
                "Ensure cron scripts are owned by root and not writable"
            )

# capability check
def check_capabilities():
    caps = run("getcap -r / 2>/dev/null | head -n 10")
    if caps:
        save(
            "MEDIUM",
            "Capabilities",
            caps,
            "Remove unnecessary Linux capabilities"
        )

# kernel check
def kernel_info_check():
    kernel = platform.release()
    save(
        "INFO",
        "Kernel",
        f"Kernel version found: {kernel}",
        "Check kernel against known CVEs and update if required"
    )

# report
def write_report():
    name = "Linux_PrivEsc_Report_" + datetime.now().strftime("%Y%m%d_%H%M") + ".txt"
    with open(name, "w") as f:
        f.write("Linux Privilege Escalation Audit Report\n")
        f.write("=" * 45 + "\n\n")

        for r in results:
            f.write(f"[{r['level']}]\n")
            f.write(f"Area: {r['area']}\n")
            f.write(f"Details:\n{r['msg']}\n")
            f.write(f"Mitigation:\n{r['fix']}\n")
            f.write("-" * 45 + "\n")

    print("[+] Report saved as:", name)

# main
def main():
    print("[*] Linux PrivEsc Audit Started (Detection Only)\n")

    collect_basic_info()
    check_suid_binaries()
    check_sgid_binaries()
    check_permissions()
    check_sudo_rules()
    check_services()
    check_cron()
    check_capabilities()
    kernel_info_check()
    write_report()

    print("\n[*] Scan completed")

if __name__ == "__main__":
    main()
