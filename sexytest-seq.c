/*
 * sexytest-seq.c -- sequential read/write test for sexywrap
 *
 * Synopsis:
 *   sexytest-seq -rw [-m <max>] <iscsi-url> {<disk>|-N} [<buffer-size>]...
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
 * buffer size is low (< 16 bytes) the test can be very slow.  When finished
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
#include <sys/stat.h>

/* Program code */
/* Print the usage of the program if $opt is NULL (command line argument
 * missing). */
static void usage(char const *opt, int exitcode)
{
	if (opt)
		return;
	fprintf(stderr, "usage: "
		"sexytest-seq -rw [-m <max>] <iscsi-url> {<disk>|-N} "
		"[<buffer-size>]...\n");
	exit(exitcode);
} /* usage */

/* The main function */
int main(int argc, char const *argv[])
{
	char test;
	off_t size;
	unsigned max;
	char const *url;
	int hdisk, hiscsi;

	/* Parse the command line. */
	usage(argv[1], 0);
	if (!strcmp(argv[1], "-r"))
		test = 'r';
	else if (!strcmp(argv[1], "-w"))
		test = 'w';
	else
		usage(NULL, 1);
	argv++;

	/* -m | -h */
	max = 0;
	usage(argv[1], 1);
	if (!strcmp(argv[1], "-m"))
	{
		argv++;
		usage(argv[1], 1);
		max = atoi(argv[1]);
		argv++;
	} else if (!strcmp(argv[1], "-h"))
		usage(NULL, 0);

	/* <iscsi-url> */
	usage(argv[1], 1);
	url = argv[1];
	argv++;

	/* <disk> */
	usage(argv[1], 1);
	if (strcmp(argv[1], "-N"))
	{
		struct stat sb;

		assert((hdisk = open(argv[1], O_RDONLY)) >= 0);
		assert(!fstat(hdisk, &sb));
		size = sb.st_size;
	} else
	{	/* Don't verify against $hdisk. */
		hdisk = -1;
		size = 0;
	}
	argv++;

	/* Run a test round for each <buffer-size>. */
	for (; argv[1]; argv++)
	{
		off_t cnt;
		FILE *tmpwrite;
		struct stat sb;
		char *buf, *disk;
		time_t prev, now;
		unsigned sbuf, i;

		/* Allocate $buf and $disk, rewind $hdisk and create
		 * $tmpwrite (for -w). */
		tmpwrite = NULL;
		sbuf = atoi(argv[1]);
		assert((buf = malloc(sbuf)) != NULL);
		if (hdisk >= 0)
		{
			assert((disk = malloc(sbuf)) != NULL);
			assert(lseek(hdisk, 0, SEEK_SET) == 0);
			if (test == 'w')
				assert((tmpwrite = tmpfile()) != NULL);
		} else
			disk = NULL;

		/* open($url) and get/verify its $size */
		assert((hiscsi = open(url,
			test == 'w' ? O_WRONLY : O_RDONLY)) >= 0);
		assert(!fstat(hiscsi, &sb));
		if (hdisk < 0)
			size = sb.st_size;
		else
			assert(sb.st_size == size);
		printf("Testing %s with bufsize = %u...\n",
			test == 'r' ? "reading" : "writing", sbuf);

		/* Read/write $sbuf until $max or end of file is reached. */
		cnt = 0;
		time(&prev);
		for (i = 0; (!max || i < max) && cnt < size; i++)
		{
			unsigned n;

			/* $n <- the expected/maximal I/O size */
			n = cnt + sbuf <= size ? sbuf : size - cnt;
			if (test == 'r')
			{
				assert(read(hiscsi, buf, sbuf) == n);
				if (disk)
				{	/* Verify $buf against $hdisk. */
					assert(hdisk >= 0);
					assert(read(hdisk, disk, sbuf) == n);
					assert(!memcmp(buf, disk, n));
				}
			} else
			{	/* $test == 'w' */
				unsigned o;

				/* Randomize and write out $buf. */
				for (o = 0; o < sbuf; o++)
					buf[o] = rand();
				assert(write(hiscsi, buf, sbuf) == n);
				if (tmpwrite)
					assert(fwrite(buf, n, 1, tmpwrite)
						== 1);
			} /* $test */

			/* Print progress if at least 5 seconds passed
			 * since the last printout. */
			cnt += n;
			time(&now);
			if (now - prev >= 5)
			{
				printf("  cnt: %ld\n", cnt);
				prev = now;
			}
		} /* test round */

		if (tmpwrite)
		{	/* Verify that $tmpwrite == $disk. */
			ssize_t n;
			assert(hdisk >= 0 && disk != NULL);

			/* Let's write until $hdisk is supposedly
			 * written back by the iSCSI daemon. */
			printf("  verifying");
			fflush(stdout);
			sleep(3);
			puts("...");

			/* Read and compare $sbuf bytes a time. */
			rewind(tmpwrite);
			do
			{
				n = read(hdisk, disk, sbuf);
				assert(n >= 0 && n <= sbuf);
				assert(fread(buf, 1, n, tmpwrite) == n);
				assert(!memcmp(disk, buf, n));
			} while (n >= sbuf);
			fclose(tmpwrite);
		} /* compare $tmpwrite with $hdisk */

		/* We could reuse $hiscsi, but let's keep test rounds
		 * separate.  Print $cnt just to be sure. */
		free(buf);
		free(disk);
		assert(!close(hiscsi));
		printf("  cnt: %ld\n", cnt);
	} /* for each <buffer-size> */

	/* Done */
	return 0;
} /* main */

/* End of sexytest-seq.c */
