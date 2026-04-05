## Linux Ambient Capabilities

Ambient capabilities allow unprivileged processes to inherit capabilities across `execve()` calls — something traditional inherited capabilities alone cannot do for non-privileged binaries.

**Reference:** [HackTricks – Linux Capabilities](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-capabilities)

---

### What Are Ambient Capabilities?

Linux capabilities are broken into sets: **permitted**, **effective**, **inheritable**, **bounding**, and **ambient**. The ambient set (added in kernel 4.3) allows capabilities to be preserved across `execve()` even when the target binary has no special file capabilities set.

---

### Demo: Spawning a Shell with Inherited Capabilities

The following program raises a configurable set of capabilities into the ambient set, then execs a child process — which inherits them automatically.

#### `ambient.c`

```c
/*
 * Ambient Capability Demo
 *
 * Compile:
 *   gcc -Wl,--no-as-needed -lcap-ng -o ambient ambient.c
 *
 * Grant capabilities to the binary:
 *   sudo setcap cap_setpcap,cap_net_raw,cap_net_admin,cap_sys_nice+eip ambient
 *
 * Usage:
 *   ./ambient /bin/bash
 *   ./ambient -c 13,12,23 /bin/bash   # custom cap numbers
 */

#include <errno.h>
#include <linux/capability.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <cap-ng.h>

/* Raise a single capability into the ambient set */
static void set_ambient_cap(int cap) {
  capng_get_caps_process();

  if (capng_update(CAPNG_ADD, CAPNG_INHERITABLE, cap)) {
    fprintf(stderr, "Cannot add cap %d to inheritable set\n", cap);
    exit(2);
  }

  capng_apply(CAPNG_SELECT_CAPS);

  /* Kernel requires the two trailing zeros */
  if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0)) {
    perror("Cannot raise ambient cap");
    exit(1);
  }
}

static void usage(const char *me) {
  fprintf(stderr, "Usage: %s [-c cap,cap,...] <program> [args...]\n", me);
  exit(1);
}

/* Default capability set if -c is not specified */
static int default_caplist[] = {
  CAP_NET_RAW,    /* 13 - raw socket access    */
  CAP_NET_ADMIN,  /* 12 - network config       */
  CAP_SYS_NICE,   /* 23 - process scheduling   */
  -1
};

/* Parse a comma-separated list of capability numbers */
static int *get_caplist(const char *arg) {
  int i = 1;
  int *list = NULL;
  char *dup = strdup(arg);
  char *tok;

  for (tok = strtok(dup, ","); tok; tok = strtok(NULL, ",")) {
    list = realloc(list, (i + 1) * sizeof(int));
    if (!list) {
      perror("out of memory");
      exit(1);
    }
    list[i - 1] = atoi(tok);
    list[i] = -1;
    i++;
  }

  free(dup);
  return list;
}

int main(int argc, char **argv) {
  int i;
  int *caplist = NULL;
  int cmd_index = 1; /* index into argv where the target command starts */

  if (argc < 2)
    usage(argv[0]);

  if (strcmp(argv[1], "-c") == 0) {
    if (argc <= 3)
      usage(argv[0]);
    caplist = get_caplist(argv[2]);
    cmd_index = 3;
  }

  if (!caplist)
    caplist = default_caplist;

  for (i = 0; caplist[i] != -1; i++) {
    printf("Raising cap %d into ambient set\n", caplist[i]);
    set_ambient_cap(caplist[i]);
  }

  printf("Execing: %s\n", argv[cmd_index]);
  execv(argv[cmd_index], argv + cmd_index);
  perror("execv failed");
  return 1;
}
```

---

### Build & Run

```bash
# 1. Compile
gcc -Wl,--no-as-needed -lcap-ng -o ambient ambient.c

# 2. Grant the binary the caps it needs to raise
sudo setcap cap_setpcap,cap_net_raw,cap_net_admin,cap_sys_nice+eip ambient

# 3. Spawn a shell with those caps inherited
./ambient /bin/bash
```

---

### Verify Inside the Child Shell

Once inside the spawned shell, confirm the capabilities are active:

```bash
capsh --print
```

Expected output (even as a regular user):

```text
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```

> A normal unprivileged shell would show an empty `Current:` set. The ambient mechanism is what populates it here.

---

### Dropping Capabilities: Verification with `capsh`

You can confirm capabilities matter by stripping one and observing the effect:

```bash
# tcpdump requires CAP_NET_RAW — this should fail
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```

---

### Key Takeaways

| Concept | Detail |
|---|---|
| **Ambient set** | Caps preserved across `execve()` without file caps on the target |
| **Inheritable set** | Must be set first; ambient is a subset of it |
| **`PR_CAP_AMBIENT_RAISE`** | The `prctl` call that moves a cap into the ambient set |
| **Kernel requirement** | Process must already have the cap in both permitted & inheritable sets |
| **Security implication** | Child processes (e.g. shells) gain real capabilities — use carefully |
