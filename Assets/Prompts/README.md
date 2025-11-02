# ChatGPT Autofill Prompt (use this to generate similar reports on future findings)

```text
You are a cybersecurity analyst preparing a report based on my findings using the Markdown template provided above.

Rules:
- Output valid Markdown only.
- Follow the exact structure in the template (headings, tables, code blocks, and screenshot placeholders).
- No emojis, icons, or decorative characters.
- Use fenced code blocks for PowerShell, Bash, configuration files, and command outputs.
- Maintain a concise, factual, and professional SOC reporting tone.
- Include every relevant section, including manual and automated remediation steps, evidence, and screenshots.
- Do not alter or remove any section headers from the template.

Prepare a complete Markdown report using the template above based on the following finding details:

Finding details:
[Paste your notes: system(s), OS/version, component, tool plugins, exact settings, commands used, remediation steps (manual + automation), verification commands, severity, IDs, references, dates, and repository paths.]


```

# EXAMPLE GENERATED REPORT FROM CHATGPT
# Windows Server 2022 – Weak SMB Signing Configuration (V-220875)
**Category:** Network / System  

**Date Analyzed:** 10/08/2025  

**Author:** FIRST NAME LAST NAME

**Reference:** DISA STIG V-220875 / CVE-2017-0144 / Internal Scan ID: NS-2025-115

---

## Overview
The SMB service on multiple Windows Server hosts permitted unsigned SMB sessions. This enables man-in-the-middle attacks by allowing unverified traffic between clients and servers and violates DISA STIG V-220875 and NIST SP 800-53 SC-8.

---

## Affected Systems
| System   | OS / Version        | Component | Environment               |
|----------|---------------------|-----------|---------------------------|
| DC01     | Windows Server 2022 | SMB v2/v3 | On-Prem Domain Controller |
| FS01     | Windows Server 2019 | SMB v2/v3 | On-Prem File Server       |
| LAB-VM03 | Windows Server 2022 | SMB v3    | Test Environment          |

---

## Technical Summary
Credentialed scanning and manual inspection indicated that SMB client and server signing were not enforced:
- Microsoft network client: Digitally sign communications (always) — Disabled
- Microsoft network server: Digitally sign communications (always) — Disabled

This permits session hijacking, spoofing, and data tampering over SMB.

---

## Detection and Validation
**Tools / Methods Used:** Nessus Professional v10.7 (Plugin 57619), PowerShell validation, Group Policy review.

**Evidence (PowerShell):**
```powershell
# Check current SMB signing status (server)
Get-SmbServerConfiguration | Select EnableSecuritySignature, RequireSecuritySignature

# Check current SMB signing status (client)
Get-SmbClientConfiguration | Select EnableSecuritySignature, RequireSecuritySignature
```

**Representative Output:**
```
EnableSecuritySignature : False
RequireSecuritySignature : False
```

**Screenshot placeholders (commit images to /evidence/):**  
!PUT SCREENSHOTS HERE

---

## Remediation Steps
**Manual Fix via Group Policy (recommended):**
1. Open Group Policy Management Console (gpmc.msc).
2. Edit the applicable GPO linked to the target OU.
3. Navigate:  
   Computer Configuration → Windows Settings → Security Settings → Local Policies → Security Options
4. Set:
   - Microsoft network client: Digitally sign communications (always) → Enabled
   - Microsoft network server: Digitally sign communications (always) → Enabled
5. Apply policy: run `gpupdate /force` on targets or wait for next policy refresh; reboot if required.

**PowerShell Automation (server- and client-side enforcement):**
```powershell
# Enforce SMB signing for the client
Set-SmbClientConfiguration -RequireSecuritySignature $true -Force
Set-SmbClientConfiguration -EnableSecuritySignature  $true -Force

# Enforce SMB signing for the server
Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
Set-SmbServerConfiguration -EnableSecuritySignature  $true -Force
```

**Bash Automation (Samba on Linux for parity):**
```bash
# /etc/samba/smb.conf hardening
sudo cp /etc/samba/smb.conf /etc/samba/smb.conf.bak.$(date +%F)
sudo sed -i '/^\[global\]/a client signing = mandatory\nserver signing = mandatory' /etc/samba/smb.conf
sudo systemctl restart smbd
```

**Change Control:** Implement under change request CHG-2025-142 during a maintenance window.

**Screenshot placeholders (commit images to /evidence/):**  
!PUT SCREENSHOTS HERE

---

## Verification After Fix
1. Validate configuration:
```powershell
Get-SmbServerConfiguration | Select EnableSecuritySignature, RequireSecuritySignature
Get-SmbClientConfiguration | Select EnableSecuritySignature, RequireSecuritySignature
```

**Expected Output:**
```
EnableSecuritySignature : True
RequireSecuritySignature : True
```

2. Re-run Nessus scan; confirm Plugin 57619 no longer reports a finding.  
3. Capture an SMB negotiation trace and verify signing in the session setup.

**Screenshot placeholders (commit images to /evidence/):**  
!PUT SCREENSHOTS HERE

---

## Security Impact and Notes
| Impact          | Description                                                                 |
|-----------------|-----------------------------------------------------------------------------|
| Confidentiality | High — Unsigned sessions risk data interception.                            |
| Integrity       | High — Data can be altered in transit without detection.                    |
| Availability    | Low — Negligible operational impact from enabling signing.                  |

Notes: SMB signing overhead measured <2% in local tests; aligns with DISA STIG and CIS Benchmarks.

---

## References
- [DISA STIG: Windows Server 2022 V-220875](https://public.cyber.mil/stigs/downloads/)
- [Microsoft SMB Security Best Practices](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security)
- [NIST SP 800-53 Rev.5 SC-8](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [CVE-2017-0144 – SMB RCE (context)](https://nvd.nist.gov/vuln/detail/CVE-2017-0144)

---

## Summary Card
| Field           | Value         |
|-----------------|---------------|
| Finding ID      | WIN-22-220875 |
| Severity        | CAT II        |
| Status          | Closed        |
| Validated By    | F. Last   |
| Next Review     | 04/2026       |
| CVSS Base Score | 7.4 (High)    |
| MITRE ATT&CK    | T1021.002     |

---

## Repository Notes
- Folder: `/Windows-STIGs/SMB-Signing/`
- File: `README.md`
- Evidence: `/Windows-STIGs/SMB-Signing/evidence/`
- Scripts: `/Windows-STIGs/SMB-Signing/scripts/`
- Last Updated: 10/08/2025

---

## Screenshots Index
- `./evidence/screenshot-nessus-v220875.png`
- `./evidence/screenshot-smbconfig-dc01.png`
- `./evidence/screenshot-gpo-smb-signing.png`
- `./evidence/screenshot-applied-gpo.png`
- `./evidence/screenshot-pwsh-after-set.png`
- `./evidence/screenshot-nessus-cleared.png`
- `./evidence/screenshot-expected-output.png`
