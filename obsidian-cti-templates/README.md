# 🛡️ Obsidian Cyber Threat Intelligence Templates

> Professional-grade templates for threat intelligence analysts using Obsidian.md

![Obsidian](https://img.shields.io/badge/Obsidian-7C3AED?style=flat&logo=obsidian&logoColor=white)
![CTI](https://img.shields.io/badge/CTI-Threat%20Intelligence-red)
![License](https://img.shields.io/badge/License-MIT-blue.svg)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)

A comprehensive collection of Obsidian templates designed for cybersecurity threat intelligence analysts, incident responders, and security operations teams. These templates help you track threat actors, campaigns, malware, and indicators of compromise (IOCs) in a structured, interconnected knowledge base.

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Templates Included](#templates-included)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Template Usage](#template-usage)
- [Best Practices](#best-practices)
- [Integrations](#integrations)
- [Contributing](#contributing)
- [License](#license)

## 🎯 Overview

This repository contains professionally-designed Markdown templates for use with [Obsidian.md](https://obsidian.md), a powerful knowledge base and note-taking application. These templates are specifically crafted for:

- **Threat Intelligence Analysts** tracking APT groups and campaigns
- **Incident Response Teams** documenting investigations
- **Security Operations Centers (SOCs)** maintaining IOC databases
- **Malware Analysts** documenting technical analysis
- **Security Researchers** organizing threat research

### Why Obsidian for CTI?

- **🔗 Bidirectional Linking**: Connect threat actors to campaigns, malware, and IOCs
- **📊 Graph View**: Visualize relationships between threats
- **🏷️ Tagging System**: Organize intelligence by type, severity, and status
- **🔍 Full-Text Search**: Instantly find any piece of intelligence
- **📱 Cross-Platform**: Desktop (Windows, Mac, Linux) and mobile
- **🔒 Privacy**: Local-first, your data stays on your machine
- **🎨 Customizable**: Extensive plugin ecosystem and theming

## ✨ Features

### 🎯 Core Capabilities

- **11 Professional Templates** covering all aspects of threat intelligence
- **MITRE ATT&CK Integration** with pre-built technique mappings
- **IOC Tracking** for IPs, domains, hashes, and URLs
- **Campaign Documentation** with timeline and attribution
- **Malware Analysis** with technical details and behavioral indicators
- **Detection Rules** including Sigma, YARA, and Snort signatures
- **Intelligence Requirements** framework for prioritizing research
- **TLP Classification** support for information sharing

### 📊 Template Features

- ✅ Pre-structured sections for comprehensive documentation
- ✅ Checkbox lists for systematic analysis
- ✅ Table templates for organized data presentation
- ✅ MITRE ATT&CK tactic and technique mapping
- ✅ Metadata fields for tagging and classification
- ✅ Status indicators with emoji for quick visual reference
- ✅ Internal linking structure for knowledge graph building
- ✅ Detection rule format support (YARA, Sigma, Snort, Suricata)
- ✅ Sandbox analysis integration sections
- ✅ Timeline tracking for threat evolution

## 📦 Templates Included

### 1. **APT Group Profile Template** (`APT-Group-Template.md`)
Comprehensive template for documenting Advanced Persistent Threat groups.

**Sections:**
- Basic information and attribution
- Targeting (sectors, geography, victim selection)
- Complete MITRE ATT&CK mapping
- Malware arsenal and tools
- Infrastructure analysis
- IOCs (network, file, behavioral)
- Notable campaigns
- Detection rules (Sigma, YARA, Snort)
- Defensive recommendations
- Intelligence sources and timeline

**Use Cases:**
- Document nation-state threat actors
- Track APT group evolution
- Share threat intelligence with stakeholders
- Support threat hunting operations

### 2. **Campaign Tracking Template** (`Campaign-Tracking-Template.md`)
Track active and historical threat campaigns with detailed attribution.

**Sections:**
- Campaign overview and executive summary
- Attribution and confidence assessment
- Victim profiling and targeting
- Complete attack chain analysis
- TTPs and MITRE ATT&CK mapping
- Malware and tools inventory
- Infrastructure timeline
- Comprehensive IOC tracking
- Detection and response strategies
- Impact assessment
- Intelligence sharing documentation

**Use Cases:**
- Monitor ongoing threat campaigns
- Analyze attack patterns
- Coordinate incident response
- Share intelligence with ISACs

### 3. **CTI Threat Actor Profile** (`CTI_Threat_Actor_Profile.md`)
Structured template for formal threat actor intelligence reports.

**Sections:**
- Executive summary with key points
- Assessment and change analysis
- Actor narrative (TTPs, infrastructure, victims)
- Timeline of activity (with Chronos plugin support)
- Intelligence gaps identification
- MITRE ATT&CK table with D3FEND countermeasures
- Victim tracking
- IOC tables (malware, network, system artifacts)
- CVE tracking with patch status
- Detection signatures
- Threat actor motivations and specializations
- Capability assessment
- Probability matrix
- References

**Use Cases:**
- Create formal intelligence reports
- Briefing executives and stakeholders
- Strategic threat assessments
- Long-term threat tracking

### 4. **Intelligence Requirements** (`Intelligence_Requirements.md`)
Framework for defining and tracking intelligence collection priorities.

**Sections:**
- Pre-defined intelligence questions
- Answer and action tracking
- Expandable sub-pages for detailed analysis
- Risk-focused questions

**Use Cases:**
- Drive intelligence collection efforts
- Prioritize research activities
- Align CTI with business objectives
- Track intelligence gaps

### 5. **IOC - Hash Template** (`IOC-Hash-Template.md`)
Comprehensive file hash indicator tracking with analysis details.

**Sections:**
- File identification (SHA256, MD5, SHA1, SSDEEP, Imphash)
- File metadata (type, size, compile time)
- Threat context and classification
- Static analysis (PE info, strings, signatures)
- Dynamic analysis (process, file, registry, network activity)
- Sandbox analysis links (VT, Any.Run, Hybrid Analysis, Joe Sandbox)
- YARA matches
- Related indicators
- Detection rules (YARA, Sigma, EDR)
- Distribution and prevalence
- Remediation guidance

**Use Cases:**
- Track malicious file hashes
- Document malware analysis
- Create detection rules
- Share IOCs with threat intelligence platforms

### 6. **IOC - IP Address Template** (`IOC-IP-Template.md`)
Track malicious IP addresses with geolocation and reputation data.

**Sections:**
- Basic IP information
- Threat context and classification
- Geographic and network details
- Technical details (ports, services, SSL certs)
- Reputation scores (VirusTotal, AbuseIPDB)
- Observed activity and attack patterns
- Related indicators
- Detection and response (firewall rules, IDS signatures, SIEM queries)
- Timeline of activity
- Affected systems tracking

**Use Cases:**
- C2 server tracking
- Network threat hunting
- Firewall rule creation
- Incident response

### 7. **IP Tracking Template** (`IP.md`)
Simplified IP address tracking template.

**Fields:**
- IP address
- Associated actor
- Registration details
- Exit location
- Tags
- Reference URLs

**Use Cases:**
- Quick IP documentation
- Infrastructure mapping
- VPN/proxy tracking

### 8. **Malware Analysis Template** (`Malware-Analysis-Template.md`)
In-depth malware analysis documentation with technical details.

**Sections:**
- Executive summary
- Classification and distribution model
- Attribution
- Complete technical analysis
- Capabilities and features inventory
- Attack chain visualization
- C2 architecture and communication
- Comprehensive MITRE ATT&CK mapping
- IOCs (network, file, registry, mutex)
- Behavioral indicators
- Detection rules (Sigma, YARA, Snort, EDR queries)
- Sandbox analysis results
- Mitigation and remediation
- Decryption/recovery (for ransomware)
- Timeline and intelligence sources

**Use Cases:**
- Document malware samples
- Create detection signatures
- Support incident response
- Share technical intelligence

### 9. **Campaign Template** (`Template.md`)
Streamlined threat actor campaign documentation.

**Sections:**
- Summary
- Modus operandi with MITRE tactics
- Distribution methods
- Initial access through impact
- Ransom note (if applicable)
- Victimology
- Tools and infrastructure
- Custom malware
- IOCs (DLS, C2 domains, IPs, URLs)

**Use Cases:**
- Quick campaign documentation
- Operational threat tracking
- Daily briefings

### 10. **URL Tracker** (`URL_Tracker.md`)
Track and categorize malicious or suspicious URLs.

**Fields:**
- Repository/resource name
- URL link
- Description
- Tags

**Use Cases:**
- Phishing URL tracking
- Malicious site documentation
- Resource bookmarking

### 11. **GitHub Link Template** (`github_link.md`)
Track security-related GitHub repositories.

**Fields:**
- Repository name
- GitHub URL
- Description
- Tags

**Use Cases:**
- Track open-source security tools
- Document proof-of-concepts
- Monitor threat actor repositories

## 🚀 Installation

### Prerequisites

- **Obsidian.md** (Download from [obsidian.md](https://obsidian.md))
- Basic familiarity with Markdown
- Understanding of threat intelligence concepts (recommended)

### Quick Install

**Option 1: Download ZIP**
1. Download the latest release from [Releases](https://github.com/yourusername/obsidian-cti-templates/releases)
2. Extract the ZIP file
3. Copy the `templates` folder to your Obsidian vault

**Option 2: Git Clone**
```bash
cd /path/to/your/obsidian/vault
git clone https://github.com/yourusername/obsidian-cti-templates.git
```

**Option 3: Manual Download**
1. Browse to the [templates folder](templates/)
2. Download individual templates you need
3. Place them in your vault's templates folder

### Obsidian Configuration

1. **Enable Templates Plugin:**
   - Settings → Core Plugins → Templates → Enable
   - Set template folder location: `templates` (or your chosen location)

2. **Configure Template Hotkeys** (Optional):
   - Settings → Hotkeys → Search "Insert template"
   - Assign keyboard shortcut (e.g., `Ctrl+T` or `Cmd+T`)

3. **Recommended Plugins:**
   - **Dataview**: For creating dynamic IOC dashboards
   - **Templater**: For advanced template functionality
   - **Obsidian Git**: For version control
   - **Calendar**: For timeline visualization
   - **Graph Analysis**: For threat relationship mapping
   - **Tag Wrangler**: For managing tags
   - **Chronos**: For timeline visualization (used in CTI Threat Actor Profile)

## 🎬 Quick Start

### Creating Your First Threat Intelligence Note

1. **Create a New Note:**
   - Press `Ctrl+N` (or `Cmd+N` on Mac)
   - Name your note (e.g., "APT29 - Cozy Bear")

2. **Insert Template:**
   - Press `Ctrl+T` (or use Command Palette: `Ctrl+P` → "Insert template")
   - Select "APT-Group-Template"

3. **Fill in Information:**
   - Replace placeholder text with actual intelligence
   - Use `[[double brackets]]` to link to other notes
   - Add `#tags` for categorization
   - Update status indicators

4. **Link Related Intelligence:**
   - Create related IOCs, malware, and campaign notes
   - Link them using `[[Note Name]]` syntax
   - Build your threat intelligence graph

### Example Workflow

**Tracking a New Campaign:**

1. Create a new note: "Operation CloudHopper"
2. Use `Campaign-Tracking-Template.md`
3. Document the campaign details
4. Create linked notes for:
   - Threat Actor: `[[APT10]]` using APT-Group-Template
   - Malware: `[[Quasar RAT]]` using Malware-Analysis-Template
   - IOCs: `[[192.168.1.1]]` using IOC-IP-Template
5. View relationships in Graph View

## 📖 Template Usage

### General Guidelines

**Placeholders:**
- `YYYY-MM-DD`: Replace with actual dates
- `[Description]`: Replace with specific information
- `XX / XXX`: Replace with actual numbers
- `___________`: Fill in custom values
- Checkboxes `[ ]`: Check relevant items

**Status Indicators:**
- 🔴 Active/Critical/Malicious
- 🟡 Monitoring/High/Suspicious
- 🟢 Historical/Medium/Clean
- ⚪ Low/Informational

**TLP Classifications:**
- **TLP:RED**: Not for disclosure, restricted to specific recipients
- **TLP:AMBER**: Limited disclosure, recipients only
- **TLP:GREEN**: Community wide disclosure
- **TLP:WHITE**: Unlimited disclosure

### MITRE ATT&CK Integration

Templates include pre-formatted MITRE ATT&CK tactic and technique sections:

```markdown
**Initial Access:**
- [TA0001] - [Technique Name] - [T####]

**Execution:**
- [TA0002] - [Technique Name] - [T####]
```

**Resources:**
- MITRE ATT&CK Matrix: https://attack.mitre.org/
- ATT&CK Navigator: https://mitre-attack.github.io/attack-navigator/

### Internal Linking Best Practices

1. **Use Descriptive Names:**
   - Good: `[[APT29 - Cozy Bear]]`
   - Avoid: `[[threat1]]`

2. **Create Placeholder Links:**
   - Link to notes that don't exist yet: `[[Future-Malware-Analysis]]`
   - Obsidian will create them when you click

3. **Use Aliases:**
   - `[[APT29 - Cozy Bear|APT29]]` displays as "APT29"

4. **Link Patterns:**
   - APT Groups: `[[APT-Group-Name]]`
   - Campaigns: `[[Campaign-Name]]`
   - Malware: `[[Malware-Family-Name]]`
   - IOCs: `[[IOC-Type-Value]]` (e.g., `[[IOC-IP-192.168.1.1]]`)

### Tagging Strategy

**Tag Structure:**
```
#ioc/ip               # IOC type: IP address
#ioc/hash             # IOC type: file hash
#ioc/domain           # IOC type: domain

#apt/apt29            # APT group identifier
#malware/emotet       # Malware family

#status/active        # Current status
#status/historical    # Historical entry

#priority/critical    # Priority level
#priority/high
#priority/medium

#sector/financial     # Target sector
#sector/government

#ttps/t1566           # MITRE technique
```

## 💡 Best Practices

### Organization

1. **Folder Structure:**
```
vault/
├── APT Groups/
├── Campaigns/
├── Malware/
├── IOCs/
│   ├── IPs/
│   ├── Domains/
│   ├── Hashes/
│   └── URLs/
├── Intelligence Requirements/
├── Daily Notes/
└── templates/
```

2. **Naming Conventions:**
   - APT Groups: `APT29 - Cozy Bear`
   - Campaigns: `Campaign - Operation CloudHopper`
   - Malware: `Malware - Emotet`
   - IOCs: `IOC-IP-192.168.1.1`, `IOC-Hash-[first8chars]`

3. **Regular Maintenance:**
   - Weekly: Update active threats
   - Monthly: Review and archive old IOCs
   - Quarterly: Update intelligence requirements

### Quality Intelligence

1. **Source Attribution:**
   - Always cite sources
   - Include report dates and URLs
   - Note confidence levels

2. **Confidence Assessment:**
   - High: Multiple reliable sources, confirmed
   - Medium: Single reliable source or multiple unconfirmed
   - Low: Unverified or single unreliable source

3. **Keep it Updated:**
   - Add "Last Updated" dates
   - Schedule regular reviews
   - Archive outdated information

4. **Link Everything:**
   - Connect related threats
   - Build knowledge graph
   - Enable pattern discovery

### Collaboration

1. **Version Control:**
   - Use Obsidian Git plugin for team collaboration
   - Commit changes regularly
   - Write meaningful commit messages

2. **Sharing Intelligence:**
   - Respect TLP classifications
   - Export to PDF for external sharing
   - Use Obsidian Publish for team access

3. **Review Process:**
   - Peer review new intelligence
   - Validate IOCs before sharing
   - Document review status

## 🔌 Integrations

### Threat Intelligence Platforms

**VirusTotal:**
- Copy IOC hashes directly to VT
- Link sandbox reports in templates
- Track detection rates

**MISP:**
- Export IOCs to MISP format
- Import MISP events as Obsidian notes
- Synchronize threat intelligence

**OpenCTI:**
- Map Obsidian notes to OpenCTI entities
- Export STIX bundles
- Import threat reports

### SIEM/EDR Integration

**Splunk:**
- Copy SIEM queries from templates
- Create saved searches from detection rules
- Link to Splunk searches

**Elastic:**
- Use KQL queries from templates
- Create detection rules
- Link to Kibana dashboards

**Microsoft Sentinel:**
- Export hunting queries
- Create analytics rules
- Link to incident investigations

### Automation

**Example: IOC Enrichment Script**
```python
# Python script to enrich IP IOCs with VirusTotal data
import obsidiantools
import requests

def enrich_ip_ioc(ip_address):
    # Fetch VT data
    vt_data = get_virustotal_data(ip_address)
    
    # Update Obsidian note
    note_path = f"IOCs/IPs/IOC-IP-{ip_address}.md"
    update_obsidian_note(note_path, vt_data)
```

## 📚 Additional Resources

### Obsidian Resources
- [Obsidian Documentation](https://help.obsidian.md/)
- [Obsidian Forum](https://forum.obsidian.md/)
- [Obsidian Discord](https://discord.gg/obsidianmd)

### Threat Intelligence Resources
- [MITRE ATT&CK](https://attack.mitre.org/)
- [MITRE D3FEND](https://d3fend.mitre.org/)
- [Cyber Kill Chain](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html)
- [Diamond Model](https://www.activeresponse.org/the-diamond-model/)
- [STIX/TAXII](https://oasis-open.github.io/cti-documentation/)

### CTI Frameworks
- [Intelligence Cycle](https://en.wikipedia.org/wiki/Intelligence_cycle)
- [F3EAD](https://www.ctintelligence.com/f3ead-framework/)
- [TLP Protocol](https://www.first.org/tlp/)

## 🤝 Contributing

We welcome contributions from the security community!

### How to Contribute

1. **Fork the Repository**
2. **Create a Feature Branch:** `git checkout -b feature/new-template`
3. **Make Your Changes**
4. **Test Your Templates**
5. **Commit:** `git commit -m "Add: New CVE tracking template"`
6. **Push:** `git push origin feature/new-template`
7. **Open a Pull Request**

### Contribution Ideas

- 📝 New templates (CVE tracking, Threat Hunting, IR documentation)
- 🔧 Template improvements and enhancements
- 📖 Documentation updates
- 🎨 Example vaults and use cases
- 🔌 Integration scripts and tools
- 🌍 Translations

### Guidelines

- Follow existing template structure
- Include comprehensive sections
- Add usage examples
- Document all fields
- Test in Obsidian before submitting
- Update README if adding new templates

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

**Summary:**
- ✅ Commercial use allowed
- ✅ Modification allowed
- ✅ Distribution allowed
- ✅ Private use allowed
- ❌ No liability
- ❌ No warranty

## 🙏 Acknowledgments

These templates incorporate industry best practices from:
- MITRE ATT&CK Framework
- SANS Institute CTI resources
- Cyber Threat Intelligence methodologies
- Security community contributions
- Real-world threat intelligence operations

## 📞 Support

- **Issues:** [GitHub Issues](https://github.com/yourusername/obsidian-cti-templates/issues)
- **Discussions:** [GitHub Discussions](https://github.com/yourusername/obsidian-cti-templates/discussions)
- **Email:** your-email@example.com (for security concerns only)

## 🗺️ Roadmap

### Version 1.0 (Current)
- ✅ Core CTI templates
- ✅ MITRE ATT&CK integration
- ✅ IOC tracking templates
- ✅ Detection rule formats

### Version 1.1 (Planned)
- [ ] CVE tracking template
- [ ] Threat hunting playbook template
- [ ] Incident response documentation template
- [ ] Daily intelligence briefing template

### Version 2.0 (Future)
- [ ] Dataview queries for dynamic dashboards
- [ ] Templater scripts for automation
- [ ] STIX 2.1 export functionality
- [ ] Integration with threat intel APIs

## ⭐ Star History

If you find these templates useful, please consider starring the repository!

---

**Version:** 1.0.0  
**Last Updated:** November 2025  
**Maintained by:** Security Community

🛡️ **Stay vigilant. Stay informed. Stay secure.**
