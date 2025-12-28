<div align="center">

<img src="assets/nullascendIcon.png" alt="NULLASCEND Logo" width="200"/>

# NULLASCEND

</div>

<div align="center">

by:

```
  ▄▄▄                                                                
▄██▀▀▀                   █▄                            █▄            
██ ▄▀█▄                  ██       ▄                   ▄██▄      ▄    
██   ██ ▀██ ██▀ ▄▀▀█▄ ▄████ ▄▀▀█▄ ███▄███▄ ▄▀▀█▄ ▄██▀█ ██ ▄███▄ ████▄
██  ▄██   ███   ▄█▀██ ██ ██ ▄█▀██ ██ ██ ██ ▄█▀██ ▀███▄ ██ ██ ██ ██   
 ▀███▀  ▄██ ██▄▄▀█▄██▄█▀███▄▀█▄██▄██ ██ ▀█▄▀█▄███▄▄██▀▄██▄▀███▀▄█▀   
```

**Linux Privilege Escalation Enumeration Script**

*Rapid, low-noise enumeration of core privilege escalation vectors*

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Bash](https://img.shields.io/badge/bash-5.0%2B-green.svg)](https://www.gnu.org/software/bash/)
[![Platform](https://img.shields.io/badge/platform-linux-lightgrey.svg)](https://www.linux.org/)

</div>

---

##  Overview

**NULLASCEND** is a Linux privilege escalation enumeration script inspired by [LinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS), designed and developed by **0xadamastor** to strengthen Bash scripting knowledge and provide a practical tool for security assessments.

The script performs comprehensive enumeration of common privilege escalation vectors on Linux systems, with an optional auto-exploitation mode for rapid testing in controlled environments.

##  Legal Disclaimer

**FOR AUTHORIZED SECURITY ASSESSMENTS ONLY**

This tool is intended for:
- Authorized penetration testing
- Security research in controlled environments
- Educational purposes on systems you own
- CTF competitions and security labs

**Unauthorized use is illegal.** Always obtain explicit written permission before running this script on any system you don't own.

## AND IF YOU ARE ASKING YOURSELF:

**WHY SOULD I USE THIS ONE INSTEAD OF LINPEAS?**

Because **NULLASCEND** is focused on **learning, transparency, and control** rather than being a drop-and-run automated tool.  
Every check is readable, understandable, and hackable making it ideal for study, labs, and skill-building. 

>Hacking isn’t about automation or flashy scripts.


>It’s about control, curiosity, and refusing to run what you don’t understand.

### Enumeration Modules

- **System Context**: Kernel version, OS info, user details, outdated kernel detection
- **SUID/SGID Binaries**: Detection of dangerous SUID/SGID binaries with GTFOBins references
- **Sudo Configuration**: Analysis of sudo rules, NOPASSWD entries, and vulnerable sudo versions (CVE-2021-3156)
- **Cron Jobs**: User crontabs, system cron, writable cron files and directories, systemd timers
- **Linux Capabilities**: Detection of dangerous capabilities (cap_setuid, cap_dac_override, etc.)
- **Writable Sensitive Files**: /etc/passwd, /etc/shadow, /etc/sudoers, systemd services
- **PATH Configuration**: Writable PATH directories, LD_PRELOAD settings
- **Credential Artifacts**: SSH keys, shell history, cloud credentials (AWS, Docker, Kubernetes), database history

### Auto-Exploitation Mode

When enabled with `--auto`, NULLASCEND can automatically attempt exploitation of discovered vectors:
- SUID binary exploitation
- Sudo privilege escalation
- Writable file modification
- Cron job injection
- PATH hijacking
- Capability abuse

##  Usage

### Basic Enumeration

```bash
# Standard enumeration
./enum.sh

# Quiet mode (findings only)
./enum.sh -q

# Verbose mode (show all SUID binaries)
./enum.sh -v

# Save output to file
./enum.sh -o results.txt
```

### Auto-Exploitation Mode

```bash
# Enable auto-exploitation (requires confirmation)
./enum.sh --auto

# Combine with output file
./enum.sh --auto -o exploit_results.txt
```

### Command-Line Options

| Option | Description |
|--------|-------------|
| `-o FILE` | Save output to specified file |
| `-q` | Quiet mode - show findings only |
| `-v` | Verbose mode - show all SUID binaries including standard ones |
| `--auto` | Enable auto-exploitation (requires user confirmation) |
| `-h, --help` | Display help message |

##  Output Severity Levels

The script categorizes findings by severity:

- **CRITICAL** : Immediate privilege escalation possible (writable /etc/passwd, unrestricted sudo, etc.)
- **HIGH** : Direct escalation vectors (dangerous SUID binaries, exploitable sudo commands)
- **MEDIUM** : Potential escalation paths (readable shadow file, credential artifacts)
- **LOW** : Informational findings requiring additional context
- **INFO** : General information and recommendations

##  Enumeration Highlights

### SUID/SGID Detection

Identifies dangerous SUID binaries from a curated list including:
- Shell interpreters (bash, sh, zsh)
- Text editors (vim, nano, less)
- Scripting languages (python, perl, ruby, php, node)
- System utilities (find, systemctl, docker)

Standard SUID binaries (passwd, su, mount) are filtered unless verbose mode is enabled.

### Credential Discovery

Searches for credentials in:
- Shell history files (.bash_history, .zsh_history)
- Database history (.mysql_history, .psql_history)
- Cloud provider configs (AWS, Docker, Kubernetes)
- Version control (.git-credentials, .netrc)
- SSH keys and authorized_keys files

### GTFOBins Integration

Provides direct links to [GTFOBins](https://gtfobins.github.io/) for exploitable binaries, streamlining the exploitation process.

##  Learning Path

This script was developed as a hands-on learning project to master:
- Advanced Bash scripting techniques
- Linux privilege escalation methodology
- Security enumeration best practices
- GTFOBins exploitation patterns

Inspired by industry-standard tools like LinPEAS while maintaining a focus on clarity and educational value.

##  Contributing

Contributions are welcome! Areas for improvement:
- New exploitation techniques
- Performance optimizations
- Better detection logic
- Extended platform support

Please open an issue or submit a pull request.

##  References

- [GTFOBins](https://gtfobins.github.io/) - Unix binaries exploitation
- [HackTricks](https://book.hacktricks.xyz/) - Privilege escalation techniques
- [LinPEAS](https://github.com/carlospolop/PEASS-ng) - Inspiration for this project
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) - Security payloads and bypasses

## License

This project is **source-available** for educational purposes.  
You may read and modify the code, but **redistribution or publication is strictly prohibited**.


##  Author

**0xadamastor**

Created for security research, penetration testing practice, and continuous learning in offensive security.

<div align="center">

<img src="assets/0xadamastorIcon.png" alt="NULLASCEND Logo" width="200"/>

---

<div align="center">

*Stay curious, stay learning, stay ethical, and most importantly, break things with purpose...*

</div>

