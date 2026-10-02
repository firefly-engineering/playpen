/*
 * Load generator for #34: an "agent" that hammers Landlock denials.
 * Each process enters its own domain (handles READ_FILE, no rules) and opens
 * /etc/hostname in a loop, optionally sleeping SLEEP_US between attempts.
 *
 *   flood PROCS SECONDS [SLEEP_US]
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	int procs = argc > 1 ? atoi(argv[1]) : 4;
	int secs = argc > 2 ? atoi(argv[2]) : 10;
	int sleep_us = argc > 3 ? atoi(argv[3]) : 0;

	for (int p = 0; p < procs; p++) {
		if (fork())
			continue;
		struct landlock_ruleset_attr attr = {
			.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE,
		};
		int rs = syscall(SYS_landlock_create_ruleset, &attr, sizeof(attr), 0);
		prctl(PR_SET_NAME, "agent-flood", 0, 0, 0);
		if (rs < 0 || prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) ||
		    syscall(SYS_landlock_restrict_self, rs, 0))
			_exit(2);
		time_t end = time(NULL) + secs;
		long count = 0;
		while (time(NULL) < end) {
			int fd = open("/etc/hostname", O_RDONLY);
			if (fd >= 0)
				close(fd);
			count++;
			if (sleep_us)
				usleep(sleep_us);
		}
		fprintf(stderr, "flood[%d]: %ld denials\n", p, count);
		_exit(0);
	}
	while (wait(NULL) > 0)
		;
	return 0;
}
