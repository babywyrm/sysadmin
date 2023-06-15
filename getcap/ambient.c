/*
 * Test program for the ambient capabilities
 *
 *   https://gist.github.com/tomix86/32394a43be70c337cbf1e0c0a56cbd8d
 *
 * You need to install libcap-ng-dev first, then compile using:
 *  $ gcc -o ambient ambient.c -lcap-ng && sudo setcap cap_setpcap,cap_net_raw,cap_net_admin,cap_sys_nice+eip ambient
 *
 * To get a shell with additional caps that can be inherited do:
 *
 * ./ambient /bin/bash
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/prctl.h>
#include <linux/capability.h>
#include <cap-ng.h>

static void set_ambient_cap(int cap)
{
	int rc;

	capng_get_caps_process();
	rc = capng_update(CAPNG_ADD, CAPNG_INHERITABLE, cap);
	if (rc) {
		printf("Cannot add inheritable cap\n");
		exit(2);
	}
	capng_apply(CAPNG_SELECT_CAPS);

	/* Note the two 0s at the end. Kernel checks for these */
	if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0)) {
		perror("Cannot set cap");
		exit(1);
	}
}

void usage(const char *me) {
	printf("Usage: %s [-c caps] new-program new-args\n", me);
	exit(1);
}

int default_caplist[] = {CAP_NET_RAW, CAP_NET_ADMIN, CAP_SYS_NICE, -1};

int *get_caplist(const char *arg) {
	int i = 1;
	int *list = NULL;
	char *dup = strdup(arg), *tok;

	for (tok = strtok(dup, ","); tok; tok = strtok(NULL, ",")) {
		list = realloc(list, (i + 1) * sizeof(int));
		if (!list) {
			perror("out of memory");
			exit(1);
		}
		list[i-1] = atoi(tok);
		list[i] = -1;
		i++;
	}
	return list;
}

int main(int argc, char **argv)
{
	int rc, i, gotcaps = 0;
	int *caplist = NULL;
	int index = 1; // argv index for cmd to start

	if (argc < 2)
		usage(argv[0]);

	if (strcmp(argv[1], "-c") == 0) {
		if (argc <= 3) {
			usage(argv[0]);
		}
		caplist = get_caplist(argv[2]);
		index = 3;
	}

	if (!caplist) {
		caplist = (int *)default_caplist;
	}

	for (i = 0; caplist[i] != -1; i++) {
		printf("adding %d to ambient list\n", caplist[i]);
		set_ambient_cap(caplist[i]);
	}

	printf("Ambient forking shell\n");
	if (execv(argv[index], argv + index))
		perror("Cannot exec");

	return 0;
}
