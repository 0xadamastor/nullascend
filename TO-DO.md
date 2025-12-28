## NULLASCEND — Language & Lab Coverage TODO

### Core Languages

- [x] **Bash / sh**
  - [x] Cron jobs
  - [x] PATH hijacking
  - [x] Wildcard injection
  - [x] Environment variable abuse

- [ ] **Python**
  - [ ] Sudo misconfiguration
  - [ ] Import hijacking
  - [ ] Writable modules
  - [ ] Virtualenv abuse

- [ ] **Perl**
  - [ ] Legacy root scripts
  - [ ] SUID Perl binaries
  - [ ] PATH / ENV abuse

---

### Extended Languages 

- [ ] **Ruby**
  - [ ] Sudo Ruby scripts
  - [ ] `$LOAD_PATH` hijacking
  - [ ] Writable gems

- [ ] **Node.js**
  - [ ] Sudo npm scripts
  - [ ] `require()` hijacking
  - [ ] PATH abuse
  - [ ] CI/CD misconfigurations

- [ ] **PHP (CLI)**
  - [ ] Root cron jobs
  - [ ] Writable include paths
  - [ ] `auto_prepend_file` abuse

---

### Auxiliary / Legacy Languages

- [ ] **Awk / Sed**
  - [ ] Cron one-liners
  - [ ] PATH hijack

- [ ] **C (Compiled Helpers)**
  - [ ] SUID binaries
  - [ ] `getenv()` abuse
  - [ ] Insecure temp files

- [ ] **Java**
  - [ ] Writable classpath
  - [ ] Root cron JARs

---

### Modern / Advanced Targets

- [ ] **Go**
  - [ ] Insecure helper binaries
  - [ ] PATH execution issues

- [ ] **Container-specific**
  - [ ] World-writable volumes
  - [ ] Entrypoint abuse
  - [ ] Docker socket exposure

---

### Tooling Improvements

- [ ] Parse `PATH=` inside cron jobs
- [ ] Detect writable cron PATH directories
- [ ] Correlate language → GTFOBins
- [ ] Improve severity scoring
- [ ] Add test labs for each vuln class

---

### Hey curious one

Curious enough to make it this far?  
Want to help improve **NULLASCEND**?

**Send a pull request.**  
Ideas, code, labs, or improvements, all contributions are welcome.

Let's not build skids together.
