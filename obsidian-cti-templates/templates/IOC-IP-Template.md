# IOC Template - IP Address

> **Status:** 🔴 Active | 🟡 Monitoring | 🟢 Inactive  
> **Last Verified:** YYYY-MM-DD  
> **Confidence:** High / Medium / Low

## Basic Information

**IP Address:** `192.168.1.1`  
**IP Type:** IPv4 / IPv6  
**First Seen:** YYYY-MM-DD  
**Last Seen:** YYYY-MM-DD  

**IOC Status:**
- [ ] Active C2 server
- [ ] Malware distribution
- [ ] Phishing infrastructure
- [ ] Scanning source
- [ ] Exploitation attempts
- [ ] Data exfiltration endpoint
- [ ] Historical/Inactive

---

## Threat Context

**Associated Threats:**
- **Malware Family:** [[Malware-Name]]
- **Threat Actor:** [[APT-Group-Name]]
- **Campaign:** [[Campaign-Name]]

**Threat Type:**
- [ ] Command & Control (C2)
- [ ] Malware hosting
- [ ] Phishing server
- [ ] Exploit server
- [ ] Scanner/Bot
- [ ] Proxy/VPN exit node
- [ ] Compromised legitimate server

**Severity Level:** 🔴 Critical | 🟡 High | 🟢 Medium | ⚪ Low

---

## Geographic & Network Information

### Geolocation
**Country:** [Country name]  
**Country Code:** [CC]  
**Region/State:** [Region]  
**City:** [City]  
**Latitude/Longitude:** [XX.XXXX, YY.YYYY]  
**Timezone:** UTC+X

### Network Details
**ASN:** ASXXXXX  
**ISP/Hosting:** [Provider name]  
**Organization:** [Organization]  
**Network Range:** [CIDR]

**Hosting Type:**
- [ ] Cloud (AWS/Azure/GCP/etc.)
- [ ] VPS/Dedicated
- [ ] Residential
- [ ] Mobile
- [ ] Tor exit node
- [ ] VPN provider
- [ ] Bulletproof hosting

**Reverse DNS:** `ptr-record.example.com`

---

## Technical Details

### Open Ports & Services
| Port | Protocol | Service | Banner |
|------|----------|---------|--------|
| 80 | TCP | HTTP | Apache 2.4.x |
| 443 | TCP | HTTPS | nginx 1.x |
| 22 | TCP | SSH | OpenSSH 8.x |

### SSL/TLS Certificates (if applicable)
**Certificate CN:** [Common Name]  
**Issuer:** [Certificate Authority]  
**Valid From:** YYYY-MM-DD  
**Valid To:** YYYY-MM-DD  
**SHA-1 Fingerprint:** `fingerprint`

### HTTP Headers (if web server)
```
Server: Apache/2.4.41 (Unix)
X-Powered-By: PHP/7.4
```

---

## Reputation & Intelligence

### Threat Intelligence Scores

**VirusTotal:**
- Detection: XX/90 vendors flagged as malicious
- Last Analysis: YYYY-MM-DD
- VT Link: [URL]

**AbuseIPDB:**
- Confidence: XX%
- Reports: XX reports
- Last Reported: YYYY-MM-DD
- Categories: [List categories]
- Link: [URL]

**Other Sources:**
- AlienVault OTX: [Pulses/Score]
- Shodan: [Link]
- Censys: [Link]
- ThreatFox: [Status]

### Reputation Lists
- [ ] Listed on Spamhaus
- [ ] Listed on SORBS
- [ ] Listed on Barracuda
- [ ] Listed on other RBLs: [List]

---

## Observed Activity

### Network Behavior
**Traffic Patterns:**
- Beaconing interval: Every XX seconds/minutes
- Typical ports: 80, 443, 8080, etc.
- Protocol: HTTP/HTTPS/DNS/Custom

**Communication:**
- Direction: Inbound / Outbound / Both
- Data transfer: Small / Medium / Large volumes
- Pattern: Regular / Irregular / Burst

### Attack Activity
**Observed Attacks:**
- [ ] Scanning attempts (port scans)
- [ ] Brute force attacks
- [ ] Exploitation attempts
- [ ] Malware callbacks
- [ ] Data exfiltration
- [ ] DDoS participation
- [ ] Phishing hosting

**Targeted Sectors:**
- [ ] Financial
- [ ] Healthcare
- [ ] Government
- [ ] Energy
- [ ] Technology
- [ ] Other: ___________

---

## Related Indicators

### Associated IPs
- `10.0.0.1` - Same subnet/infrastructure
- `172.16.0.1` - Related C2 server

### Associated Domains
- [[IOC-Domain-1]] - `malicious-domain.com`
- [[IOC-Domain-2]] - `c2-server.net`

### Associated URLs
- `http://192.168.1.1/payload.exe`
- `https://192.168.1.1/api/checkin`

### Associated Hashes
- [[IOC-Hash-1]] - Malware downloaded from this IP
- [[IOC-Hash-2]] - Related sample

---

## Detection & Response

### Firewall Rules

**Block Rule:**
```
# Cisco ASA
access-list outside_in deny ip 192.168.1.1 255.255.255.255 any

# iptables
iptables -A INPUT -s 192.168.1.1 -j DROP
iptables -A OUTPUT -d 192.168.1.1 -j DROP

# Windows Firewall
netsh advfirewall firewall add rule name="Block Malicious IP" dir=out action=block remoteip=192.168.1.1
```

### IDS/IPS Signatures

**Snort:**
```
alert tcp any any -> 192.168.1.1 any (msg:"Connection to known C2 server"; \
  classtype:trojan-activity; sid:1000001; rev:1;)
```

**Suricata:**
```
alert ip $HOME_NET any -> 192.168.1.1 any (msg:"Outbound to malicious IP"; \
  classtype:bad-unknown; sid:1000001; rev:1;)
```

### SIEM Queries

**Splunk:**
```spl
index=firewall OR index=proxy (dest_ip="192.168.1.1" OR src_ip="192.168.1.1")
| stats count by src_ip, dest_ip, dest_port, action
| where count > 0
```

**Elastic/KQL:**
```kql
(destination.ip: "192.168.1.1" OR source.ip: "192.168.1.1") AND 
event.category: (network OR firewall)
```

---

## Response Actions

### Immediate Actions
- [ ] Block IP at perimeter firewall
- [ ] Block IP at proxy/web gateway
- [ ] Add to threat intelligence feeds
- [ ] Alert SOC team

### Investigation Steps
1. Search logs for communication with this IP
2. Identify affected systems
3. Check for lateral movement
4. Review for data exfiltration
5. Scan affected systems for malware

### Affected Systems
| Hostname | IP Address | Last Connection | Status |
|----------|------------|-----------------|--------|
| WORKSTATION-01 | 10.0.1.100 | YYYY-MM-DD HH:MM | Quarantined |
| SERVER-02 | 10.0.2.50 | YYYY-MM-DD HH:MM | Investigating |

---

## Timeline

| Date | Event | Source |
|------|-------|--------|
| YYYY-MM-DD | First observed in the wild | Threat intel feed |
| YYYY-MM-DD | Used in [Campaign Name] | Vendor report |
| YYYY-MM-DD | Detected in our environment | Internal SOC |
| YYYY-MM-DD | Blocked at perimeter | Firewall logs |

---

## Intelligence Sources

### Reports Mentioning This IOC
1. [Report Title] - [Vendor] - [Date] - [URL]
2. [Report Title] - [Vendor] - [Date] - [URL]

### Community Intelligence
- OSINT Source 1: [Details]
- OSINT Source 2: [Details]

### Internal References
- Incident Report: [[Incident-YYYY-MM-DD]]
- Investigation Notes: [[Investigation-Notes]]

---

## Notes & Comments

### Analysis Notes
[Add any additional context, analysis, or observations]

### Attribution Notes
[Notes on threat actor attribution]

### False Positive Risk
**Likelihood:** High / Medium / Low  
**Reason:** [Why this might be a false positive]

### Expiration
**Expected Lifetime:** Days / Weeks / Months / Permanent  
**Review Date:** YYYY-MM-DD  
**Expiration Date:** YYYY-MM-DD (if applicable)

---

## Metadata

**Tags:**  
`#ioc` `#ioc/ip` `#active` `#high-priority` `#c2-server` `#malware/[family-name]`

**IOC Type:** Network Indicator - IP Address  
**Confidence Level:** High / Medium / Low  
**Threat Level:** Critical / High / Medium / Low  
**Sharing:** TLP:WHITE / TLP:GREEN / TLP:AMBER / TLP:RED

**Submitted By:** [Your name/team]  
**Submitted Date:** YYYY-MM-DD  
**Last Verified:** YYYY-MM-DD  
**Verified By:** [Name]

---

## Quick Links
- [[IOC-Dashboard]] - Return to IOC Dashboard
- [[APT-Index]] - Related threat actors
- [[Malware-Index]] - Related malware
- [[Campaign-Index]] - Related campaigns