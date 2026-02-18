#!/usr/bin/env python3
"""
ReconForge
Intelligence-Driven Reconnaissance Framework

Author: Murali Kurva
License: MIT
"""

import argparse
import subprocess
import os
import shutil
import json
import requests
import re
import sys
from lxml import etree
from concurrent.futures import ThreadPoolExecutor
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

VERSION = "1.1.1"
AUTHOR = "Murali Kurva"

console = Console()

SEVERITY_WEIGHTS = {
    "Critical": 10,
    "High": 6,
    "Medium": 3,
    "Low": 1,
    "Info": 0
}

# ==========================================================
# Utility
# ==========================================================

def run_cmd(cmd, verbose=False):
    if verbose:
        console.print(f"[yellow][CMD][/yellow] {cmd}")
    subprocess.run(cmd, shell=True)

def tool_exists(tool):
    return shutil.which(tool) is not None

# ==========================================================
# Safe /etc/hosts Handling
# ==========================================================

def add_host_entry(ip, domain, auto_hosts):
    if not auto_hosts:
        console.print("[yellow]Redirect detected but --auto-hosts not enabled.[/yellow]")
        return

    try:
        with open("/etc/hosts", "r") as f:
            if domain in f.read():
                console.print(f"[green]Host entry already exists for {domain}[/green]")
                return
    except:
        console.print("[red]Unable to read /etc/hosts[/red]")
        return

    console.print(f"[cyan]Adding {domain} → {ip} to /etc/hosts[/cyan]")
    subprocess.run(
        f"echo '{ip} {domain}' | sudo tee -a /etc/hosts > /dev/null",
        shell=True
    )

# ==========================================================
# TCP Discovery
# ==========================================================

def tcp_discovery(target, base, verbose):
    gnmap = f"{base}/scans/full_tcp.gnmap"

    if tool_exists("rustscan"):
        cmd = f"rustscan -a {target} --ulimit 5000 --no-banner -- -Pn -n -oG {gnmap}"
    else:
        cmd = f"nmap -p- -T4 --min-rate 1200 -Pn -n {target} -oG {gnmap}"

    run_cmd(cmd, verbose)

    ports = []
    if os.path.exists(gnmap):
        with open(gnmap) as f:
            for line in f:
                if "open" in line:
                    for p in line.split():
                        if "/open" in p:
                            ports.append(p.split("/")[0])

    return sorted(set(ports), key=int)

# ==========================================================
# Service Scan
# ==========================================================

def service_scan(target, ports, base, verbose):
    xml_file = f"{base}/scans/service_scan.xml"
    port_str = ",".join(ports)
    run_cmd(f"nmap -sC -sV -Pn -n -p {port_str} {target} -oX {xml_file}", verbose)
    return xml_file

def parse_services(xml_file):
    services = []

    if not os.path.exists(xml_file):
        return services

    tree = etree.parse(xml_file)

    for port in tree.xpath("//port[state/@state='open']"):
        services.append({
            "port": port.get("portid"),
            "name": port.find("service").get("name", ""),
            "product": port.find("service").get("product", ""),
            "version": port.find("service").get("version", "")
        })

    return services

# ==========================================================
# HTTP Intelligence
# ==========================================================

def detect_redirect(target):
    try:
        r = requests.get(f"http://{target}", allow_redirects=False, timeout=5)
        if "Location" in r.headers:
            match = re.search(r"http://([^/]+)/?", r.headers["Location"])
            if match:
                return match.group(1)
    except:
        pass
    return None

def parse_gobuster(file):
    findings = []
    if not os.path.exists(file):
        return findings

    with open(file) as f:
        for line in f:
            if ".env" in line:
                findings.append({
                    "type": "Exposed File",
                    "value": ".env",
                    "severity": "Critical",
                    "description": "Sensitive environment file exposed"
                })
            elif "login" in line:
                findings.append({
                    "type": "Auth Endpoint",
                    "value": "login",
                    "severity": "Medium",
                    "description": "Login panel discovered"
                })
            elif "admin" in line:
                findings.append({
                    "type": "Admin Panel",
                    "value": "admin",
                    "severity": "High",
                    "description": "Administrative endpoint discovered"
                })
    return findings

def parse_whatweb(file):
    findings = []
    if not os.path.exists(file):
        return findings

    with open(file) as f:
        data = f.read()

        php_match = re.search(r"PHP/([\d\.]+)", data)
        if php_match:
            findings.append({
                "type": "Technology",
                "value": f"PHP {php_match.group(1)}",
                "severity": "Info",
                "description": "PHP detected"
            })

        if "Bootstrap" in data:
            findings.append({
                "type": "Technology",
                "value": "Bootstrap",
                "severity": "Info",
                "description": "Frontend framework detected"
            })

    return findings

# ==========================================================
# Risk Engine
# ==========================================================

def calculate_risk(findings, services):
    score = 0

    for s in services:
        if s["port"] == "445":
            score += 8
        elif s["port"] == "5985":
            score += 6
        elif s["port"] == "80":
            score += 4
        else:
            score += 2

    for f in findings:
        score += SEVERITY_WEIGHTS.get(f["severity"], 0)

    return score

# ==========================================================
# Reporting
# ==========================================================

def generate_reports(target, services, findings, score, base):
    intel_dir = f"{base}/intelligence"
    os.makedirs(intel_dir, exist_ok=True)

    summary = {
        "target": target,
        "services": services,
        "findings": findings,
        "risk_score": score
    }

    with open(f"{intel_dir}/summary.json", "w") as f:
        json.dump(summary, f, indent=4)

    with open(f"{intel_dir}/report.md", "w") as f:
        f.write(f"# Recon Report for {target}\n\n")
        f.write(f"## Risk Score: {score}\n\n")
        f.write("## Services\n")
        for s in services:
            f.write(f"- Port {s['port']} : {s['product']}\n")
        f.write("\n## Findings\n")
        for finding in findings:
            f.write(f"- [{finding['severity']}] {finding['type']} → {finding['value']}\n")

# ==========================================================
# Scanner
# ==========================================================

def scan_target(target, args):
    console.print(Panel(
        f"[bold cyan]ReconForge v{VERSION}[/bold cyan]\n"
        f"Author: {AUTHOR}\n"
        f"Target: {target}",
        style="bold blue"
    ))

    base = f"recon_{target}"
    os.makedirs(f"{base}/scans", exist_ok=True)
    os.makedirs(f"{base}/http", exist_ok=True)

    ports = tcp_discovery(target, base, args.verbose)
    if not ports:
        console.print("[red]No open ports discovered.[/red]")
        return

    xml = service_scan(target, ports, base, args.verbose)
    services = parse_services(xml)

    findings = []

    if any("http" in s["name"] for s in services):
        domain = detect_redirect(target)
        url = f"http://{domain}" if domain else f"http://{target}"

        if domain:
            add_host_entry(target, domain, args.auto_hosts)

        if tool_exists("whatweb"):
            run_cmd(f"whatweb {url} > {base}/http/whatweb.txt", args.verbose)
            findings += parse_whatweb(f"{base}/http/whatweb.txt")

        if tool_exists("gobuster"):
            run_cmd(
                f"gobuster dir -u {url} -w /usr/share/seclists/Discovery/Web-Content/common.txt -t 40 -b 404 -o {base}/http/gobuster.txt",
                args.verbose
            )
            findings += parse_gobuster(f"{base}/http/gobuster.txt")

    score = calculate_risk(findings, services)

    table = Table(title="Intelligence Findings")
    table.add_column("Severity")
    table.add_column("Type")
    table.add_column("Value")

    for f in findings:
        table.add_row(f["severity"], f["type"], f["value"])

    console.print(table)
    console.print(Panel(f"Overall Risk Score: {score}", style="bold red"))
    generate_reports(target, services, findings, score, base)
    console.print("[bold green]ReconForge Scan Complete[/bold green]")

# ==========================================================
# Entry
# ==========================================================

def main():
    parser = argparse.ArgumentParser(
        description="ReconForge - Intelligence-Driven Reconnaissance Framework"
    )
    parser.add_argument("-t", "--target", nargs="+", required=True)
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--auto-hosts", action="store_true",
                        help="Automatically add redirect domains to /etc/hosts")

    args = parser.parse_args()

    try:
        with ThreadPoolExecutor(max_workers=3) as executor:
            for target in args.target:
                executor.submit(scan_target, target, args)
    except KeyboardInterrupt:
        console.print("\n[red]Scan interrupted by user.[/red]")
        sys.exit(0)

if __name__ == "__main__":
    main()
