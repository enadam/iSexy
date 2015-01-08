/*
 * sexytest-seq.c -- sequential read/write test for sexywrap
 *
 * Synopsis:
 *   sexytest-seq -Rrw <buffer-size> [-m <max>] <iscsi-url>
 *
 * Open <iscsi-url> and run through it reading or writing <buffer-size>
 * bytes every operation.  This size is arbitrary and doesn't need to be
 * a multiple or divisor of the target device's blocksize.  <max> makes
 * the program stop after that many read()s/write()s.  This can be useful
 * for debugging.
 *
 * An operation mode must be chosen:
 *   -R just verifies that read()s are executed without error
 *   -r writes the read contents to the standard output
 *   -w writes the standard input to the iSCSI target sequentially
 *
 * Every five seconds progress is printed on the standard error.  If the
 * buffer size is low (< 10 bytes) the test can be very slow.  When finished
 * the # of bytes read from or written to the target is printed on the
 * standard error.
 *
 * This program is driven by sexytest-seq.sh and should be executed by
 * sexywrap.
 */

/* Include files */
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <time.h>

/* Program code */
/* Print the usage of the program if $opt is NULL (command line argument
 * missing). */
static void usage(char const *opt)
{
	if (opt)
		return;
	fprintf(stderr, "usage: "
		"sexytest-seq -Rrw <buffer-size> [-m <max>] <iscsi-url>\n");
	exit(1);
} /* usage */

/*
 * Do a test operation: read $sbuf bytes from $rfd and if $wfd is given
 * write the buffer there.  Either $rfd or $wfd can be an iSCSI or a
 * regular file descriptor.  In the latter case sexywrap is expected
 * to redirect to libc's standard read()/write().
 */
static size_t test_op(int rfd, int wfd, size_t sbuf)
{
	ssize_t n, m;
	char buf[sbuf];

	/* Read $sbuf bytes.  It's possible that less than that much
	 * data is available. */
	if ((n = read(rfd, buf, sizeof(buf))) < 0)
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
	{	/* Write $n bytes of $buf to $wfd.  We expect that the
		 * buffer is fully written. */
		if ((m = write(wfd, buf, n)) < 0)
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
} /* test_op */

/* The main function */
int main(int argc, char const *argv[])
{
	int kind, fd;
	char const *url;
	unsigned sbuf, max, i;
	size_t cnt;
	time_t prev, now;

	/* Parse the command line. */
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

	/* <buffer-size> */
	usage(argv[1]);
	sbuf = atoi(argv[1]);
	argv++;

	/* -m */
	usage(argv[1]);
	if (!strcmp(argv[1], "-m"))
	{
		argv++;
		usage(argv[1]);
		max = atoi(argv[1]);
		argv++;
	}

	/* <iscsi-url> */
	usage(argv[1]);
	url = argv[1];

	/* Run the test until $max or end of file is reached. */
	cnt = 0;
	time(&prev);
	fd = open(url, kind == 'w' ? O_WRONLY : O_RDONLY);
	assert(fd >= 0);
	for (i = 0; !max || i < max; i++)
	{
		size_t n;

		/* Do the appropriate test operation. */
		if (kind == 'R')
			n = test_op(fd, -1, sbuf);
		else if (kind == 'r')
			n = test_op(fd, STDOUT_FILENO, sbuf);
		else
			n = test_op(STDIN_FILENO, fd, sbuf);
		if (!n) /* End of file */
			break;
		cnt += n;

		/* Print progress if at least 5 seconds passed
		 * since the last printout. */
		time(&now);
		if (now - prev >= 5)
		{
			fprintf(stderr, "cnt: %ld\n", cnt);
			prev = now;
		}
	} /* test round */

	/* Done */
	close(fd);
	fprintf(stderr, "cnt: %ld\n", cnt);
	return 0;
} /* main */

/* End of sexytest-seq.c */
