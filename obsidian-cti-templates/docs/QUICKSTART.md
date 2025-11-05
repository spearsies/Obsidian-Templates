# 🚀 Quick Start Guide

Get up and running with Obsidian CTI Templates in 10 minutes!

## Step 1: Install Obsidian (2 minutes)

1. **Download Obsidian:**
   - Visit [https://obsidian.md](https://obsidian.md)
   - Download for your platform (Windows, Mac, or Linux)
   - Install the application

2. **Create a Vault:**
   - Launch Obsidian
   - Click "Create new vault"
   - Name it: "Threat Intelligence" (or your preference)
   - Choose location on your computer
   - Click "Create"

## Step 2: Install Templates (3 minutes)

### Method 1: Download and Extract
1. Download this repository as ZIP
2. Extract the `templates` folder
3. Copy it to your Obsidian vault folder

### Method 2: Git Clone
```bash
cd /path/to/your/vault
git clone https://github.com/yourusername/obsidian-cti-templates.git
cp -r obsidian-cti-templates/templates ./
```

### Method 3: Manual Download
1. Go to the [templates folder](../templates/)
2. Download templates you need
3. Place them in `/your-vault/templates/`

## Step 3: Configure Obsidian (3 minutes)

### Enable Templates Plugin
1. Open Settings (gear icon or `Ctrl+,`)
2. Navigate to: **Core plugins**
3. Enable **Templates**
4. Click **Templates** settings
5. Set **Template folder location** to: `templates`
6. (Optional) Set **Date format** to: `YYYY-MM-DD`
7. (Optional) Set **Time format** to: `HH:mm`

### Set Up Hotkey (Optional but Recommended)
1. Go to Settings → **Hotkeys**
2. Search for: "Insert template"
3. Click the **+** button
4. Press your preferred hotkey (e.g., `Ctrl+T` or `Cmd+T`)

## Step 4: Create Your First Note (2 minutes)

### Track an APT Group

1. **Create New Note:**
   - Press `Ctrl+N` (Windows/Linux) or `Cmd+N` (Mac)
   - Or click the "New note" icon

2. **Name Your Note:**
   - Type: `APT29 - Cozy Bear`
   - Press Enter

3. **Insert Template:**
   - Press `Ctrl+T` (or your hotkey)
   - Select: `APT-Group-Template`
   - Click or press Enter

4. **Fill in Information:**
   - Replace `APT##` with `APT29`
   - Add aliases: Cozy Bear, The Dukes, etc.
   - Fill in attribution: Russia, SVR
   - Update status, dates, and key characteristics

5. **Save:**
   - Obsidian auto-saves, but you can press `Ctrl+S` to be sure

### Example Entry

```markdown
# APT Group Profile Template

> **Status:** 🔴 Active
> **Last Updated:** 2024-11-05
> **Confidence:** High

## Basic Information

**APT Designation:** APT29 / Cozy Bear
**Alternative Names:**
- The Dukes
- Cozy Duke
- Office Monkeys

**Attribution:**
- **Nation-State:** Russia
- **Suspected Affiliation:** SVR (Foreign Intelligence Service)
- **Confidence Level:** High

**First Observed:** 2008-09-01
**Last Activity:** 2024-11-01
**Current Status:** Active
```

## Step 5: Create Linked Intelligence (Bonus)

### Add an IOC

1. **Create New Note:** `IOC-IP-185.220.101.1`
2. **Insert Template:** `IOC-IP-Template`
3. **Link to APT29:**
   ```markdown
   **Associated Threats:**
   - **Threat Actor:** [[APT29 - Cozy Bear]]
   ```

### Add a Malware Sample

1. **Create New Note:** `Malware - WellMess`
2. **Insert Template:** `Malware-Analysis-Template`
3. **Link to APT29:**
   ```markdown
   **Associated Threat Actors:**
   - [[APT29 - Cozy Bear]] - Primary user
   ```

### View Your Graph

1. Press `Ctrl+G` or click the graph icon
2. See connections between APT29, IOCs, and malware
3. Click nodes to navigate

## Essential Keyboard Shortcuts

| Action | Windows/Linux | Mac |
|--------|---------------|-----|
| New note | `Ctrl+N` | `Cmd+N` |
| Insert template | `Ctrl+T` | `Cmd+T` |
| Quick switcher | `Ctrl+O` | `Cmd+O` |
| Command palette | `Ctrl+P` | `Cmd+P` |
| Search | `Ctrl+Shift+F` | `Cmd+Shift+F` |
| Graph view | `Ctrl+G` | `Cmd+G` |
| Settings | `Ctrl+,` | `Cmd+,` |
| Toggle edit/preview | `Ctrl+E` | `Cmd+E` |

## Recommended Plugins

### Install from Community Plugins

1. Settings → **Community plugins** → **Turn on community plugins**
2. Click **Browse** 
3. Search and install:

**Essential:**
- **Dataview**: Create dynamic dashboards
- **Templater**: Advanced templating
- **Tag Wrangler**: Manage tags easily

**Useful:**
- **Calendar**: Timeline visualization
- **Obsidian Git**: Version control
- **Advanced Tables**: Better table editing
- **Mind Map**: Visualize connections

## Common Tasks

### Search for IOCs
```
Press Ctrl+Shift+F
Type: tag:#ioc
```

### Find Active Threats
```
Press Ctrl+Shift+F
Type: "Status:** 🔴 Active"
```

### List All APT Groups
```
Press Ctrl+Shift+F
Type: tag:#apt
```

## Tips for Success

1. **Start Small:** Begin with 2-3 threat actors you know well
2. **Link Everything:** Use `[[brackets]]` to connect related notes
3. **Use Tags:** Consistent tagging makes searching easier
4. **Update Regularly:** Set reminders to update active threats
5. **Explore Graph:** Use graph view to discover connections
6. **Backup:** Use Obsidian Sync or Git for backups

## Example Workflows

### Daily Intelligence Update

1. Open Intelligence Requirements note
2. Check for new threats matching your requirements
3. Create new notes for threats found
4. Link to existing notes
5. Update "Last Updated" fields
6. Tag with priority levels

### Incident Response

1. Create new note: "Incident - [Date] - [Name]"
2. Use Campaign Tracking Template
3. Document affected systems
4. Extract and document IOCs
5. Link to related threat actors/malware
6. Create detection rules
7. Share with team (export to PDF)

### Threat Hunting

1. Review Intelligence Requirements
2. Search for related IOCs: `tag:#ioc`
3. Check active campaigns: `Status: 🔴 Active`
4. Create hunting queries from templates
5. Document findings
6. Link new discoveries to existing intelligence

## Troubleshooting

**Templates Not Showing?**
- Check template folder location in settings
- Ensure files are in the correct folder
- Restart Obsidian

**Can't Insert Template?**
- Make sure Templates plugin is enabled
- Check if hotkey is configured
- Use Command Palette: `Ctrl+P` → "Insert template"

**Links Not Working?**
- Use exact note names in `[[brackets]]`
- Ensure the linked note exists
- Check for typos

**Graph View Empty?**
- Create some notes first
- Add internal links using `[[note name]]`
- Check graph view filters

## Next Steps

1. ✅ Read the [full README](../README.md)
2. ✅ Explore all [templates](../templates/)
3. ✅ Check out [best practices](BEST_PRACTICES.md)
4. ✅ Join [Obsidian community](https://obsidian.md/community)
5. ✅ Customize templates for your needs

## Need Help?

- **Documentation:** [README.md](../README.md)
- **GitHub Issues:** Report problems or ask questions
- **Obsidian Forum:** [forum.obsidian.md](https://forum.obsidian.md)
- **Discord:** [discord.gg/obsidianmd](https://discord.gg/obsidianmd)

---

**Time to Intelligence:** 10 minutes ✅  
**Templates Installed:** 11 professional templates ✅  
**Ready to Track Threats:** YES 🛡️

Happy threat hunting!
