
## Beta Nuclei Adapter

```
                ┌───────────────────────────────
                │ Start: nuclei_scanner.sh
                └───────────────────────────────
                              │
                              ▼
            ┌─────────────────────────────────
            │ 1. Parse CLI Arguments (getopts)
            └─────────────────────────────────
                              │
                              ▼
         ┌────────────────────────────────────
         │ 2. Prepare Environment
         │   • mkdir -p OUTPUT_DIR
         │   • init LOG_FILE
         │   • set default TEMPLATE_DIR
         └────────────────────────────────────
                              │
                              ▼
   ┌────────────────────────────────────────────
   │ 3. Ensure Tools & Repos
   │   • Install (subfinder, gauplus, nuclei, httpx, uro)
   │   • Clone ParamSpider & nuclei-templates
   └────────────────────────────────────────────
                              │
                              ▼
   ┌────────────────────────────────────────────
   │ 4. Choose Target Flow
   │
   │  If DOMAIN (-d) given:
   │    a) normalize_target
   │    b) collect_subdomains → SUBFILE
   │    c) collect_urls (ParamSpider + gauplus) → RAWFILE
   │    d) dedupe_urls (sort | uro) → VALIDFILE
   │    e) run_nuclei (httpx | nuclei) → results.txt
   │
   │  Else if FILE (-f) given:
   │    Loop each line through steps a–e
   └────────────────────────────────────────────
                              │
                              ▼
   ┌────────────────────────────────────────────
   │ 5. Cleanup & Exit
   │   • Remove temp files (unless –k)
   │   • Log “Scan complete. Results in …”
   └────────────────────────────────────────────
                              │
                              ▼
                         ┌───────────
                         │ Done
                         └───────────
```

**Step-by-Step Table**

| Phase   | Step                      | What Happens                                                                                                                            |
| ------- | ------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| **1.**  | Parse CLI Arguments       | Read flags (`-d`, `-f`, `-o`, `-t`, `-r`, `-v`, `-k`, `-h`) via `getopts`.                                                              |
| **2.**  | Prepare Environment       | Create output dir, init log file, default templates path.                                                                               |
| **3.**  | Ensure Tools & Repos      | Install missing tools; clone ParamSpider & nuclei-templates if absent.                                                                  |
| **4a.** | Single-Domain Flow (`-d`) | a) Normalize URL<br> b) Subfinder → subdomains<br> c) ParamSpider+Gauplus → URLs<br> d) Dedupe via `uro`<br> e) `httpx` + `nuclei` scan |
| **4b.** | Batch File Flow (`-f`)    | Loop each line in file through steps a–e, aggregating results.                                                                          |
| **5.**  | Cleanup & Exit            | Remove intermediate files (unless `-k`); final log message.                                                                             |

