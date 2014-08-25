/*
 * sexytest-simple.c -- sequential read/write test for sexywrap
 *
 * Synopsis:
 *   sexytest-simple -Rrw <chunk-size> [-m <max>] <iscsi-url>
 *
 * This is the backend program of sexytest-wrapper.sh.  It runs through
 * <iscsi-url> reading/writing <chunk-size> bytes at the same time.
 * This size is arbitrary and doesn't need to be a multiple or divisor
 * of the target device's blocksize.  <max> makes the program stop after
 * that many read()s/write()s.  This can be useful for debugging.
 *
 * An operation mode must be chosen:
 * -R just verifies that read()s are executed without error.
 * -r writes the read contents to the standard output.
 * -w writes the standard input to the iSCSI target sequentially.
 *
 * Every five seconds progress is printed on the standard error.  If the chunk
 * size is low (< 10 bytes) the test can be very slow.  When finished the # of
 * bytes read from or written to the target is printed on the standard error.
 *
 * libsexywrap.so/sexywrap is expected to be in the current working directory.
 * It is loaded in run-time, so the program needs to be compiled with -pthread
 * and linked with -ldl.
 */
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <time.h>
#include <dlfcn.h>

static ssize_t (*sw_read)(int, void *, size_t);
static ssize_t (*sw_write)(int, void const *, size_t);

static size_t test(int rfd, int wfd, size_t sbuf)
{
	ssize_t n, m;
	char buf[sbuf];

	if ((n = sw_read(rfd, buf, sizeof(buf))) < 0)
	{
		fprintf(stderr, "read: %m\n");
		return 0;
	} else if (n == 0)
	{
		fputs("eof\n", stderr);
		return 0;
	} else if (n < sizeof(buf))
		fprintf(stderr, "short read %zd\n", n);

	if (wfd >= 0)
	{
		if ((m = sw_write(wfd, buf, n)) < 0)
		{
			fprintf(stderr, "write: %m\n");
			return 0;
		} else if (n != m)
		{
			fprintf(stderr, "short write %zd\n", m);
			return 0;
		}
	}

	return n;
}

static void usage(char const *opt)
{
	if (opt)
		return;
	fprintf(stderr, "usage: "
		"sexytest-simple -Rrw <chunk-size> [-m <max>] <iscsi-url>\n");
	exit(1);
}

int main(int argc, char const *argv[])
{
	void *lib;
	int (*sw_open)(char const *, int);
	int kind, fd;
	char const *url;
	unsigned sbuf, max, i;
	size_t cnt;
	time_t prev, now;

	usage(argv[1]);
	if (!strcmp(argv[1], "-R"))
		kind = 'R';
	else if (!strcmp(argv[1], "-r"))
		kind = 'r';
	else if (!strcmp(argv[1], "-w"))
		kind = 'w';
	else
		usage(NULL);
	argv++;

	usage(argv[1]);
	sbuf = atoi(argv[1]);
	argv++;

	usage(argv[1]);
	if (!strcmp(argv[1], "-m"))
	{
		argv++;
		usage(argv[1]);
		max = atoi(argv[1]);
		argv++;
	}

	usage(argv[1]);
	url = argv[1];

	if (!(lib = dlopen("./libsexywrap.so", RTLD_LAZY)))
		lib = dlopen("./sexywrap", RTLD_LAZY);
	assert(lib != NULL);
	sw_open = dlsym(lib, "open");
	assert(sw_open != NULL);
	sw_read = dlsym(lib, "read");
	assert(sw_read != NULL);
	if (kind == 'w')
	{
		sw_write = dlsym(lib, "write");
		assert(sw_write != NULL);
	} else
		sw_write = write;

	cnt = 0;
	time(&prev);
	fd = sw_open(url, kind == 'w' ? O_WRONLY : O_RDONLY);
	assert(fd >= 0);
	for (i = 0; !max || i < max; i++)
	{
		size_t n;

		if (kind == 'R')
			n = test(fd, -1, sbuf);
		else if (kind == 'r')
			n = test(fd, STDOUT_FILENO, sbuf);
		else
			n = test(STDIN_FILENO, fd, sbuf);
		if (!n)
			break;
		cnt += n;

		time(&now);
		if (now - prev >= 5)
		{
			fprintf(stderr, "cnt: %ld\n", cnt);
			prev = now;
		}
	}

	close(fd);
	fprintf(stderr, "cnt: %ld\n", cnt);

	return 0;
}

/* End of sexytest-simple.c */
