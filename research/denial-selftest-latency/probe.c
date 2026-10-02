/*
 * Denial-channel self-test latency probe for #34.
 *
 * Provokes one Landlock LANDLOCK_ACCESS denial in a throwaway child domain and
 * times how long until a record carrying the probe's nonce becomes visible to
 * a reader.  One measurement per iteration, one CSV line per measurement.
 *
 *   probe -r journal|jpoll|kmsg|journalctl -n N -t TIMEOUT_MS [-g GAP_MS]
 *         [-s SLEEP_MS] [-v]
 *
 * journal    sd_journal_wait() on the system journal (inotify wake-up)
 * jpoll      sd_journal_next() every GAP ms, no wait (mmap visibility)
 * kmsg       read /dev/kmsg directly (needs CAP_SYSLOG if dmesg_restrict=1)
 * journalctl re-run journalctl -g NONCE every GAP ms (the naive implementation)
 * SLEEP_MS   pause between iterations (lets the printk ratelimit window refill)
 *
 * Build against the uapi headers of the *running* kernel (Ubuntu 24.04 ships
 * 6.8 userspace headers, which predate the ABI 7 audit flags):
 *   gcc -O2 -Wall -include /usr/src/linux-headers-$(uname -r)/include/uapi/linux/landlock.h \
 *       -o probe probe.c -lsystemd
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <systemd/sd-journal.h>

static int64_t now_us(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	return (int64_t)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

/* Child: enter a fresh domain that handles READ_FILE with no rules, then try
 * to read the marker.  Default restrict_self flags (0) log same-exec denials
 * on ABI >= 7.  Reports the pre-open timestamp and errno over the pipe. */
static void provoke(const char *marker, int wfd)
{
	struct landlock_ruleset_attr attr = {
		.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE,
	};
	int rs, fd;
	int64_t msg[2];

	prctl(PR_SET_NAME, "pp-selftest", 0, 0, 0);
	rs = syscall(SYS_landlock_create_ruleset, &attr, sizeof(attr), 0);
	if (rs < 0 || prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) ||
	    syscall(SYS_landlock_restrict_self, rs, 0)) {
		perror("landlock");
		_exit(2);
	}
	msg[0] = now_us();
	fd = open(marker, O_RDONLY | O_CLOEXEC);
	msg[1] = fd < 0 ? errno : 0;
	if (write(wfd, msg, sizeof(msg)) != sizeof(msg))
		_exit(3);
	_exit(0);
}

/* ---- readers: each returns 1 when the nonce is seen, filling *seen_us ---- */

static sd_journal *j;

static void journal_arm(void)
{
	if (!j && sd_journal_open(&j, SD_JOURNAL_LOCAL_ONLY | SD_JOURNAL_SYSTEM) < 0) {
		fprintf(stderr, "sd_journal_open failed\n");
		exit(1);
	}
	sd_journal_seek_tail(j);
	sd_journal_previous(j); /* position on the last entry */
}

static int journal_find(const char *nonce, int64_t deadline, int poll_ms,
			int64_t *seen, int64_t *recv, char *transport, char *line,
			size_t linesz)
{
	for (;;) {
		int r = sd_journal_next(j);
		if (r > 0) {
			const void *d;
			size_t l;
			uint64_t rt;
			if (sd_journal_get_data(j, "MESSAGE", &d, &l) < 0)
				continue;
			if (!memmem(d, l, nonce, strlen(nonce)))
				continue;
			*seen = now_us();
			sd_journal_get_realtime_usec(j, &rt);
			*recv = (int64_t)rt;
			snprintf(line, linesz, "%.*s", (int)(l > 8 ? l - 8 : 0),
				 (const char *)d + 8);
			if (sd_journal_get_data(j, "_TRANSPORT", &d, &l) >= 0)
				snprintf(transport, 16, "%.*s", (int)(l - 11),
					 (const char *)d + 11);
			return 1;
		}
		int64_t left = deadline - now_us();
		if (left <= 0)
			return 0;
		if (poll_ms)
			usleep(poll_ms * 1000);
		else
			sd_journal_wait(j, left);
	}
}

static int kfd = -1;

static void kmsg_arm(void)
{
	if (kfd < 0 && (kfd = open("/dev/kmsg", O_RDONLY | O_NONBLOCK)) < 0) {
		perror("/dev/kmsg");
		exit(1);
	}
	lseek(kfd, 0, SEEK_END);
}

static int kmsg_find(const char *nonce, int64_t deadline, int64_t *seen,
		     char *line, size_t linesz)
{
	char buf[2048];
	for (;;) {
		ssize_t n = read(kfd, buf, sizeof(buf) - 1);
		if (n > 0) {
			buf[n] = 0;
			if (strstr(buf, nonce)) {
				*seen = now_us();
				snprintf(line, linesz, "%s", buf);
				line[strcspn(line, "\n")] = 0;
				return 1;
			}
			continue;
		}
		if (n < 0 && errno == EPIPE)
			continue; /* overwritten records; keep reading */
		int64_t left = deadline - now_us();
		if (left <= 0)
			return 0;
		struct pollfd p = { .fd = kfd, .events = POLLIN };
		poll(&p, 1, (int)(left / 1000) + 1);
	}
}

/* The naive implementation: re-run journalctl every GAP ms. */
static int journalctl_find(const char *nonce, int64_t t0, int64_t deadline,
			   int gap_ms, int64_t *seen, char *line, size_t linesz)
{
	char cmd[256];
	snprintf(cmd, sizeof(cmd),
		 "journalctl -q --no-pager -o cat --since=@%lld -g '%s' 2>/dev/null",
		 (long long)(t0 / 1000000 - 1), nonce);
	for (;;) {
		FILE *f = popen(cmd, "r");
		int hit = f && fgets(line, linesz, f) != NULL;
		if (f)
			pclose(f);
		if (hit) {
			*seen = now_us();
			line[strcspn(line, "\n")] = 0;
			return 1;
		}
		if (now_us() >= deadline)
			return 0;
		usleep(gap_ms * 1000);
	}
}

int main(int argc, char **argv)
{
	const char *reader = "journal";
	int n = 100, timeout_ms = 5000, gap_ms = 50, sleep_ms = 0, verbose = 0, c;

	while ((c = getopt(argc, argv, "r:n:t:g:s:v")) != -1) {
		switch (c) {
		case 'r': reader = optarg; break;
		case 'n': n = atoi(optarg); break;
		case 't': timeout_ms = atoi(optarg); break;
		case 'g': gap_ms = atoi(optarg); break;
		case 's': sleep_ms = atoi(optarg); break;
		case 'v': verbose = 1; break;
		default: return 64;
		}
	}
	printf("iter,reader,found,errno,latency_us,journal_recv_minus_t0_us,transport\n");
	for (int i = 0; i < n; i++) {
		char nonce[48], marker[96], line[2048] = "", transport[16] = "-";
		int pfd[2], status;
		int64_t msg[2], seen = 0, recv = 0, deadline;
		int found = 0;

		snprintf(nonce, sizeof(nonce), "ppst-%d-%d-%lld", getpid(), i,
			 (long long)now_us());
		snprintf(marker, sizeof(marker), "/tmp/%s", nonce);
		close(open(marker, O_CREAT | O_WRONLY | O_CLOEXEC, 0644));

		if (i && sleep_ms)
			usleep(sleep_ms * 1000);
		if (!strcmp(reader, "journal") || !strcmp(reader, "jpoll"))
			journal_arm();
		else if (!strcmp(reader, "kmsg"))
			kmsg_arm();

		if (pipe2(pfd, O_CLOEXEC))
			return 1;
		if (fork() == 0)
			provoke(marker, pfd[1]);
		close(pfd[1]);
		if (read(pfd[0], msg, sizeof(msg)) != sizeof(msg))
			return 1;
		close(pfd[0]);
		wait(&status);

		deadline = msg[0] + (int64_t)timeout_ms * 1000;
		if (!strcmp(reader, "journal") || !strcmp(reader, "jpoll"))
			found = journal_find(nonce, deadline,
					     strcmp(reader, "jpoll") ? 0 : gap_ms,
					     &seen, &recv, transport, line,
					     sizeof(line));
		else if (!strcmp(reader, "kmsg"))
			found = kmsg_find(nonce, deadline, &seen, line, sizeof(line));
		else
			found = journalctl_find(nonce, msg[0], deadline, gap_ms, &seen,
						line, sizeof(line));
		printf("%d,%s,%d,%lld,%lld,%lld,%s\n", i, reader, found,
		       (long long)msg[1], found ? (long long)(seen - msg[0]) : -1LL,
		       recv ? (long long)(recv - msg[0]) : -1LL, transport);
		if (verbose && found)
			fprintf(stderr, "record: %s\n", line);
		fflush(stdout);
		unlink(marker);
	}
	return 0;
}
