# APT Group Profile Template

> **Status:** 🔴 Active | 🟡 Monitoring | 🟢 Historical  
> **Last Updated:** YYYY-MM-DD  
> **Confidence:** High / Medium / Low

## Basic Information

**APT Designation:** APT## / [Group Name]  
**Alternative Names:**  
- Alias 1
- Alias 2
- Alias 3

**Attribution:**  
- **Nation-State:** [Country] or **Cybercriminal Group**
- **Suspected Affiliation:** [Government agency/organization]
- **Confidence Level:** High / Medium / Low

**First Observed:** YYYY-MM-DD  
**Last Activity:** YYYY-MM-DD  
**Current Status:** Active / Dormant / Historical

---

## Overview

[Brief description of the threat actor, their motivations, and historical significance]

**Key Characteristics:**
- Characteristic 1
- Characteristic 2
- Characteristic 3

---

## Targeting

### Primary Sectors
- [ ] Government / Defense
- [ ] Financial Services
- [ ] Healthcare
- [ ] Energy / Utilities
- [ ] Critical Infrastructure
- [ ] Technology / Telecommunications
- [ ] Education / Research
- [ ] Manufacturing
- [ ] Retail / E-commerce
- [ ] Other: ___________

### Geographic Focus
**Primary Targets:**  
- Country 1
- Country 2

**Secondary Targets:**  
- Region 1
- Region 2

### Target Selection Criteria
[How this threat actor selects victims]

---

## Tactics, Techniques & Procedures (TTPs)

### MITRE ATT&CK Mapping

**Initial Access:**
- [TA0001] - [Technique Name] - [T####]
- [TA0001] - [Technique Name] - [T####]

**Execution:**
- [TA0002] - [Technique Name] - [T####]

**Persistence:**
- [TA0003] - [Technique Name] - [T####]

**Privilege Escalation:**
- [TA0004] - [Technique Name] - [T####]

**Defense Evasion:**
- [TA0005] - [Technique Name] - [T####]

**Credential Access:**
- [TA0006] - [Technique Name] - [T####]

**Discovery:**
- [TA0007] - [Technique Name] - [T####]

**Lateral Movement:**
- [TA0008] - [Technique Name] - [T####]

**Collection:**
- [TA0009] - [Technique Name] - [T####]

**Command and Control:**
- [TA0011] - [Technique Name] - [T####]

**Exfiltration:**
- [TA0010] - [Technique Name] - [T####]

**Impact:**
- [TA0040] - [Technique Name] - [T####]

### Attack Flow
```
1. Initial Access → 
2. Execution → 
3. Persistence → 
4. Defense Evasion → 
5. Discovery → 
6. Lateral Movement → 
7. Collection → 
8. Exfiltration
```

---

## Malware Arsenal

### Custom Tools
- [[Malware-1]] - Description
- [[Malware-2]] - Description

### Modified Public Tools
- Tool 1 - Modifications made
- Tool 2 - Modifications made

### Commodity Malware
- Common tool 1
- Common tool 2

---

## Infrastructure

### Command & Control (C2)
**C2 Methods:**
- HTTP/HTTPS
- DNS
- Custom protocol
- Cloud services

**Known C2 Infrastructure:**
- [[IOC-IP-1]] - IP address - Last seen: YYYY-MM-DD
- [[IOC-Domain-1]] - Domain - Last seen: YYYY-MM-DD

### Hosting Patterns
- Preferred hosting providers
- Geographic distribution
- Registration patterns

---

## Indicators of Compromise (IOCs)

### Network Indicators

**IP Addresses:**
- `192.168.1.1` - Description - Confidence: High
- `10.0.0.1` - Description - Confidence: Medium

**Domains:**
- `malicious-domain.com` - Description - Confidence: High
- `c2-server.net` - Description - Confidence: Medium

**URLs:**
- `http://example.com/path` - Description

### File Indicators

**File Hashes:**
- MD5: `d41d8cd98f00b204e9800998ecf8427e`
- SHA1: `da39a3ee5e6b4b0d3255bfef95601890afd80709`
- SHA256: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`

**File Names:**
- `suspicious-file.exe`
- `installer.dll`

**File Paths:**
- `C:\Windows\Temp\malware.exe`
- `/tmp/backdoor`

### Behavioral Indicators
- Registry modifications
- Service creations
- Scheduled tasks
- Network patterns

---

## Notable Campaigns

### Campaign 1: [Campaign Name] (YYYY-MM)
**Targets:** [Sector/Region]  
**Objective:** [Espionage/Disruption/Financial]  
**Outcome:** [Description]  
**Link:** [[Campaign-Name]]

### Campaign 2: [Campaign Name] (YYYY-MM)
**Targets:** [Sector/Region]  
**Objective:** [Espionage/Disruption/Financial]  
**Outcome:** [Description]  
**Link:** [[Campaign-Name]]

---

## Detection & Hunting

### SIEM Queries

**Splunk:**
```spl
index=security sourcetype=firewall dest_ip IN (192.168.1.1, 10.0.0.1)
| stats count by src_ip, dest_ip, dest_port
```

**Elastic/KQL:**
```kql
destination.ip: (192.168.1.1 OR 10.0.0.1) AND event.category: network
```

### Sigma Rules
```yaml
title: [APT Name] Activity Detection
id: [UUID]
status: experimental
description: Detects activity consistent with [APT Name]
references:
  - https://example.com/report
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4688
    CommandLine|contains:
      - 'suspicious_string'
  condition: selection
falsepositives:
  - Legitimate admin activity
level: high
tags:
  - attack.t1234
```

### YARA Rules
```yara
rule APT_GroupName_Malware {
    meta:
        description = "Detects [APT Name] malware"
        author = "Your Name"
        date = "YYYY-MM-DD"
        reference = "URL"
        hash = "SHA256"
    strings:
        $s1 = "unique_string_1" ascii
        $s2 = "unique_string_2" wide
        $hex = { 4D 5A 90 00 }
    condition:
        uint16(0) == 0x5A4D and all of ($s*)
}
```

### Snort/Suricata Rules
```
alert tcp any any -> any 443 (msg:"[APT Name] C2 Communication"; \
  flow:established,to_server; content:"|unique_pattern|"; \
  classtype:trojan-activity; sid:1000001; rev:1;)
```

---

## Defensive Recommendations

### Immediate Actions
1. Block IOCs at perimeter
2. Hunt for indicators in environment
3. Review access logs for targeted systems
4. Implement enhanced monitoring

### Short-term (1-4 weeks)
- [ ] Deploy detection rules
- [ ] Conduct threat hunting exercises
- [ ] Update security controls
- [ ] Train security team on TTPs

### Long-term (1-6 months)
- [ ] Architecture hardening
- [ ] Implement zero-trust principles
- [ ] Enhance logging/monitoring
- [ ] Regular penetration testing

### Mitigation Controls
**Technical:**
- Control 1
- Control 2

**Procedural:**
- Process 1
- Process 2

---

## Intelligence Sources

### Primary Reports
1. [Report Title] - [Vendor/Researcher] - [Date] - [URL]
2. [Report Title] - [Vendor/Researcher] - [Date] - [URL]

### Additional Reading
- [Resource 1]
- [Resource 2]

### External References
- MITRE ATT&CK: [Group ID] - [URL]
- Mandiant/FireEye: [URL]
- CrowdStrike: [URL]
- Other vendors: [URL]

---

## Related Entities

**Associated APT Groups:**
- [[APT-Group-1]] - Relationship description
- [[APT-Group-2]] - Relationship description

**Malware Families:**
- [[Malware-Family-1]]
- [[Malware-Family-2]]

**Campaigns:**
- [[Campaign-1]]
- [[Campaign-2]]

---

## Timeline of Activity

| Date | Event | Impact | Source |
|------|-------|--------|--------|
| YYYY-MM-DD | First observed activity | Description | Link |
| YYYY-MM-DD | Major campaign | Description | Link |
| YYYY-MM-DD | Tool update | Description | Link |

---

## Analysis Notes

### Capabilities Assessment
**Sophistication:** Advanced / Moderate / Basic  
**Resource Level:** High / Medium / Low  
**Operational Security:** Excellent / Good / Poor

### Evolution & Trends
[How the threat actor has evolved over time]

### Knowledge Gaps
- [ ] Gap 1
- [ ] Gap 2
- [ ] Gap 3

### Intelligence Requirements
- [ ] Requirement 1
- [ ] Requirement 2
- [ ] Requirement 3

---

## Metadata

**Tags:**  
`#apt` `#apt##` `#nation-state` or `#cybercriminal` `#attribution/country` `#active` `#high-priority`

**Contributors:** [Your name/team]  
**Review Date:** YYYY-MM-DD  
**Next Review:** YYYY-MM-DD  

**Classification:** TLP:WHITE / TLP:GREEN / TLP:AMBER / TLP:RED

---

## Quick Links
- [[APT-Index]] - Return to APT Index
- [[Malware-Index]] - Related malware
- [[IOC-Dashboard]] - Active IOCs
- [[Campaign-Index]] - Related campaigns