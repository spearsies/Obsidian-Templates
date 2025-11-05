# IOC Template - File Hash

> **Status:** 🔴 Malicious | 🟡 Suspicious | 🟢 Clean  
> **Last Analyzed:** YYYY-MM-DD  
> **Detection Rate:** XX/70

## File Identification

**Primary Hash (SHA256):**  
`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`

**Alternate Hashes:**
- **MD5:** `d41d8cd98f00b204e9800998ecf8427e`
- **SHA1:** `da39a3ee5e6b4b0d3255bfef95601890afd80709`
- **SHA512:** [If available]
- **SSDEEP:** [If available]
- **Imphash:** [If PE file]

**File Names:**
- `malicious-file.exe` (Primary)
- `invoice.pdf.exe` (Alternate)
- `update.dll` (Alternate)

---

## File Metadata

**File Type:** PE32 / PE64 / ELF / Mach-O / Office Document / PDF / Script / Archive / Other  
**File Size:** XXX KB / MB  
**Magic Bytes:** `4D 5A` (MZ header)  
**MIME Type:** application/x-dosexec

**First Seen:** YYYY-MM-DD  
**Last Seen:** YYYY-MM-DD  
**Submission Count:** [Number of times submitted to VT]

---

## Threat Context

**Associated Threats:**
- **Malware Family:** [[Malware-Name]]
- **Threat Actor:** [[APT-Group-Name]]
- **Campaign:** [[Campaign-Name]]

**Malware Classification:**
- [ ] Ransomware
- [ ] RAT (Remote Access Trojan)
- [ ] Stealer
- [ ] Loader/Dropper
- [ ] Backdoor
- [ ] Banking Trojan
- [ ] Downloader
- [ ] Keylogger
- [ ] Worm
- [ ] Rootkit
- [ ] Other: ___________

**Threat Level:** 🔴 Critical | 🟡 High | 🟢 Medium | ⚪ Low

---

## Static Analysis

### PE Information (if Windows executable)

**Compile Time:** YYYY-MM-DD HH:MM:SS  
**Entry Point:** 0xXXXXXXXX  
**Subsystem:** Windows GUI / Console  
**Architecture:** x86 / x64 / ARM

**Packer/Obfuscation:**
- Packer: UPX / Themida / VMProtect / ASPack / None
- Obfuscation Level: High / Medium / Low / None
- Anti-debugging: Yes / No
- Anti-VM: Yes / No

**Digital Signature:**
- Signed: Yes / No
- Signer: [Certificate CN]
- Valid: Yes / No / Expired / Revoked
- Serial Number: [Serial]

**Resources:**
- Icon: [Description]
- Version Info: [Company/Product name]
- Anomalies: [Unusual resources]

### Strings Analysis

**Interesting Strings:**
```
http://malicious-domain.com/c2
C:\Windows\System32\malicious.dll
MALWARE_MUTEX_12345
```

**Embedded URLs:**
- http://c2-server.com/api
- https://malware-update.net

**Embedded IPs:**
- 192.168.1.1
- 10.0.0.1

**Registry Keys:**
```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Malware
HKLM\Software\[Malware Key]
```

**File Paths:**
```
C:\Users\Public\malware.exe
%APPDATA%\Microsoft\update.exe
```

---

## Dynamic Analysis

### Behavior Summary
[Brief description of observed behavior during sandbox execution]

**Execution Results:**
- Successfully executed: Yes / No
- Crashed: Yes / No
- Requires user interaction: Yes / No
- Sandbox evasion detected: Yes / No

### Process Activity

**Created Processes:**
- cmd.exe /c [command]
- powershell.exe -enc [base64]
- schtasks.exe /create ...

**Injected Into:**
- explorer.exe (PID: XXXX)
- svchost.exe (PID: XXXX)

**Process Tree:**
```
malware.exe (XXXX)
  └─ cmd.exe (XXXX)
      └─ powershell.exe (XXXX)
```

### File System Activity

**Files Created:**
- `C:\Users\Public\dropped.dll`
- `%TEMP%\payload.exe`
- `%APPDATA%\config.dat`

**Files Modified:**
- `C:\Windows\System32\drivers\etc\hosts`
- [System files modified]

**Files Deleted:**
- Shadow copies
- Security logs

### Registry Activity

**Keys Created/Modified:**
```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Update = "C:\path\to\malware.exe"
HKLM\Software\Policies\Microsoft\Windows Defender\DisableAntiSpyware = 1
```

### Network Activity

**DNS Queries:**
- malicious-domain.com → 192.168.1.1
- c2-server.net → 10.0.0.1

**HTTP Requests:**
```
GET http://c2-server.com/api/checkin HTTP/1.1
Host: c2-server.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
```

**Connections:**
| Destination | Port | Protocol | Purpose |
|-------------|------|----------|---------|
| 192.168.1.1 | 443 | TCP | C2 communication |
| 10.0.0.1 | 80 | TCP | Payload download |

**Data Exfiltration:**
- Size: XX MB
- Destination: 192.168.1.1:443
- Protocol: HTTPS

---

## Sandbox Analysis Links

### VirusTotal
**Detection Rate:** XX/70 vendors  
**Link:** https://www.virustotal.com/gui/file/[SHA256]  
**First Submission:** YYYY-MM-DD  
**Last Analysis:** YYYY-MM-DD

**Top Detections:**
- Vendor1: Trojan.GenericKD
- Vendor2: Win32.Malware
- Vendor3: HEUR:Trojan.Win32

### Any.Run
**Link:** [URL to Any.Run analysis]  
**Date:** YYYY-MM-DD  
**OS:** Windows 10 x64  
**Key Behaviors:** [Summary]

### Hybrid Analysis
**Link:** [URL to Hybrid Analysis]  
**Date:** YYYY-MM-DD  
**Threat Score:** XX/100  
**Key Behaviors:** [Summary]

### Joe Sandbox
**Link:** [URL to Joe Sandbox]  
**Detection Score:** XX/10  
**Classification:** [Classification]

### Other Sandboxes
- [Sandbox Name]: [Link and summary]

---

## YARA Matches

**Matched Rules:**
```yara
rule Malware_Family_Detection {
    meta:
        description = "Detects [Malware Family]"
        author = "Researcher"
    strings:
        $str1 = "unique_string"
        $hex = {4D 5A 90 00}
    condition:
        all of them
}
```

**Rule Names:**
- MALWARE_Family_Variant_A
- GENERIC_Trojan_Behavior
- APT_Group_Toolset

---

## Related Indicators

### Dropped/Downloaded Files
- [[IOC-Hash-2]] - `dropped-payload.dll`
- [[IOC-Hash-3]] - `downloaded-stage2.exe`

### Network Indicators
- [[IOC-IP-1]] - C2 server: 192.168.1.1
- [[IOC-Domain-1]] - C2 domain: malicious-domain.com

### Parent/Child Samples
- Parent Sample: [[IOC-Hash-Parent]] (Previous version)
- Child Sample: [[IOC-Hash-Child]] (Dropped payload)
- Variant: [[IOC-Hash-Variant]] (Same family, different hash)

---

## Detection Rules

### YARA Rule
```yara
rule Detect_Malware_Family {
    meta:
        description = "Detects [Malware Name]"
        author = "Your Name"
        date = "YYYY-MM-DD"
        reference = "[URL]"
        hash = "SHA256"
    strings:
        $s1 = "unique_identifier" ascii
        $s2 = {4D 5A 90 00 03 00 00 00}
        $hex = {E8 ?? ?? ?? ?? 83 C4 04}
    condition:
        uint16(0) == 0x5A4D and 
        filesize < 500KB and
        all of ($s*)
}
```

### Sigma Rule
```yaml
title: [Malware Name] Execution Detection
id: [UUID]
status: experimental
description: Detects execution of [Malware Name]
references:
    - https://example.com/analysis
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Hashes|contains: 'SHA256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    condition: selection
falsepositives:
    - Unlikely
level: critical
tags:
    - attack.execution
    - attack.t1204
```

### EDR Detection

**CarbonBlack Query:**
```
filemod_hash:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

**CrowdStrike IOA:**
```
ImageHash:"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
```

---

## Distribution & Prevalence

**Distribution Methods:**
- [ ] Phishing emails
- [ ] Drive-by downloads
- [ ] Exploit kits
- [ ] Software bundling
- [ ] Removable media
- [ ] Network shares
- [ ] Supply chain
- [ ] Other: ___________

**Geographic Distribution:**
- Primary: [Countries with highest infection]
- Secondary: [Other affected regions]

**Target Industries:**
- [ ] Financial
- [ ] Healthcare
- [ ] Government
- [ ] Energy
- [ ] Technology
- [ ] Retail
- [ ] Other: ___________

**Prevalence:**
- Observed Infections: [Number or estimate]
- Trend: Increasing / Stable / Decreasing
- Campaign Association: [[Campaign-Name]]

---

## Remediation

### Detection Methods
1. Hash-based detection (IOC matching)
2. Behavioral detection (sandbox/EDR)
3. Network-based detection (C2 communication)
4. YARA scanning

### Removal Steps
1. **Identify affected systems:**
   - Search for file hash in EDR/AV
   - Check for persistence mechanisms
   
2. **Isolate systems:**
   - Network isolation
   - Disable user access

3. **Remove malware:**
   - Use EDR quarantine/remove
   - Manual removal steps:
     - Stop processes: [Process names]
     - Delete files: [File paths]
     - Remove registry keys: [Keys]
     - Remove scheduled tasks: [Task names]

4. **Verify removal:**
   - Re-scan with AV/EDR
   - Check for persistence
   - Monitor for callbacks

5. **Restore and secure:**
   - Restore from clean backup if necessary
   - Reset credentials
   - Patch vulnerabilities
   - Re-image if heavily compromised

---

## Timeline

| Date | Event | Source |
|------|-------|--------|
| YYYY-MM-DD | First submitted to VT | VirusTotal |
| YYYY-MM-DD | Used in [Campaign] | Threat intel report |
| YYYY-MM-DD | Detected in our environment | Internal SOC |
| YYYY-MM-DD | Analysis completed | Security team |

---

## Intelligence Sources

### Analysis Reports
1. [Title] - [Vendor/Researcher] - [Date] - [URL]
2. [Title] - [Vendor/Researcher] - [Date] - [URL]

### Sample Sources
- VirusTotal: [Link]
- MalwareBazaar: [Link]
- VirusBay: [Link]
- Internal submission: [Details]

### Community Intelligence
- Twitter discussion: [Link]
- Reddit thread: [Link]
- Blog post: [Link]

---

## Notes

### Analysis Notes
[Add detailed analysis notes, observations, or unique characteristics]

### Attribution Notes
[Notes on threat actor attribution and confidence]

### False Positive Risk
**Likelihood:** High / Medium / Low  
**Reason:** [Why this might be flagged incorrectly]

---

## Metadata

**Tags:**  
`#ioc` `#ioc/hash` `#malware/[family-name]` `#active` `#high-priority`

**IOC Type:** File Hash  
**File Category:** Executable / Document / Archive / Script  
**Confidence Level:** High / Medium / Low  
**Threat Level:** Critical / High / Medium / Low

**Analyzed By:** [Your name]  
**Analysis Date:** YYYY-MM-DD  
**Last Updated:** YYYY-MM-DD  
**Sharing:** TLP:WHITE / TLP:GREEN / TLP:AMBER / TLP:RED

---

## Quick Links
- [[IOC-Dashboard]] - Return to IOC Dashboard
- [[Malware-Index]] - Related malware analysis
- [[APT-Index]] - Related threat actors
- [[Campaign-Index]] - Related campaigns