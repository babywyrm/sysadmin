/*
 * ambient.c — Ambient capability test harness
 *
 * Raises a set of Linux capabilities into the ambient set, then
 * exec's the supplied program so it inherits them without needing
 * a setuid/setcap binary of its own.
 *
 * Original: https://gist.github.com/tomix86/32394a43be70c337cbf1e0c0a56cbd8d
 *
 * Build & setup:
 *   $ gcc -Wall -Wextra -o ambient ambient.c -lcap-ng
 *   $ sudo setcap cap_setpcap,cap_net_raw,cap_net_admin,cap_sys_nice+eip ambient
 *
 * Usage:
 *   ./ambient [-c <cap1,cap2,...>] <program> [args...]
 *
 * Examples:
 *   ./ambient /bin/bash                # shell with default caps
 *   ./ambient -c 13,14,23 /bin/bash   # shell with explicit cap numbers
 */

#include <errno.h>
#include <linux/capability.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <cap-ng.h>

/* --------------------------------------------------------------------------
 * Constants
 * -------------------------------------------------------------------------- */

/** Sentinel value that terminates a capability list. */
#define CAP_LIST_END (-1)

/** Default capabilities raised when -c is not supplied. */
static const int DEFAULT_CAPS[] = {
    CAP_NET_RAW,
    CAP_NET_ADMIN,
    CAP_SYS_NICE,
    CAP_LIST_END,
};


/* --------------------------------------------------------------------------
 * Capability helpers
 * -------------------------------------------------------------------------- */

/**
 * set_ambient_cap - Add @cap to the process ambient set.
 *
 * Steps:
 *  1. Read current capabilities from the kernel.
 *  2. Add @cap to the inheritable set (required before raising ambient).
 *  3. Apply the updated inheritable set.
 *  4. Raise @cap in the ambient set via prctl(2).
 *
 * Exits the process on any failure.
 */
static void set_ambient_cap(int cap)
{
    capng_get_caps_process();

    if (capng_update(CAPNG_ADD, CAPNG_INHERITABLE, cap) != 0) {
        fprintf(stderr, "error: cannot add cap %d to inheritable set\n", cap);
        exit(EXIT_FAILURE);
    }

    capng_apply(CAPNG_SELECT_CAPS);

    /* prctl requires the two trailing zeros — the kernel validates them. */
    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0) != 0) {
        fprintf(stderr, "error: cannot raise ambient cap %d: %s\n",
                cap, strerror(errno));
        exit(EXIT_FAILURE);
    }
}

/**
 * parse_caplist - Parse a comma-separated string of capability numbers.
 *
 * Returns a heap-allocated, CAP_LIST_END-terminated int array.
 * The caller is responsible for freeing it.
 * Exits on memory allocation failure or if no valid tokens are found.
 */
static int *parse_caplist(const char *arg)
{
    /* Work on a copy because strtok mutates its input. */
    char *buf = strdup(arg);
    if (!buf) {
        perror("error: strdup");
        exit(EXIT_FAILURE);
    }

    int  count = 0;
    int *list  = NULL;

    for (char *tok = strtok(buf, ","); tok != NULL; tok = strtok(NULL, ",")) {
        int *tmp = realloc(list, (count + 2) * sizeof(int));
        if (!tmp) {
            perror("error: realloc");
            free(list);
            free(buf);
            exit(EXIT_FAILURE);
        }
        list = tmp;
        list[count++] = atoi(tok);
        list[count]   = CAP_LIST_END;
    }

    free(buf);

    if (count == 0) {
        fprintf(stderr, "error: -c requires at least one capability number\n");
        exit(EXIT_FAILURE);
    }

    return list;
}


/* --------------------------------------------------------------------------
 * CLI
 * -------------------------------------------------------------------------- */

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [-c <cap,...>] <program> [args...]\n"
        "\n"
        "  -c <cap,...>   Comma-separated capability numbers to raise.\n"
        "                 Defaults to: CAP_NET_RAW(%d), CAP_NET_ADMIN(%d),\n"
        "                              CAP_SYS_NICE(%d)\n"
        "\n"
        "The supplied <program> is exec'd with the requested capabilities\n"
        "present in its ambient set.\n",
        prog,
        CAP_NET_RAW, CAP_NET_ADMIN, CAP_SYS_NICE);
    exit(EXIT_FAILURE);
}


/* --------------------------------------------------------------------------
 * main
 * -------------------------------------------------------------------------- */

int main(int argc, char *argv[])
{
    if (argc < 2)
        usage(argv[0]);

    const int  *caplist   = DEFAULT_CAPS;
    int         exec_idx  = 1;   /* argv index of the program to exec */
    int         free_caps = 0;   /* whether we own the caplist allocation */

    /* Parse optional -c flag. */
    if (strcmp(argv[1], "-c") == 0) {
        if (argc < 4)   /* need: -c <caps> <program> */
            usage(argv[0]);

        caplist   = parse_caplist(argv[2]);
        free_caps = 1;
        exec_idx  = 3;
    }

    /* Raise each capability into the ambient set. */
    for (int i = 0; caplist[i] != CAP_LIST_END; i++) {
        printf("[*] raising ambient cap %d\n", caplist[i]);
        set_ambient_cap(caplist[i]);
    }

    if (free_caps)
        free((void *)caplist);

    printf("[*] exec'ing %s\n", argv[exec_idx]);
    execv(argv[exec_idx], argv + exec_idx);

    /* execv only returns on failure. */
    fprintf(stderr, "error: execv(%s): %s\n", argv[exec_idx], strerror(errno));
    return EXIT_FAILURE;
}
