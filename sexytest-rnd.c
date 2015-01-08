/*
 * sexytest-rnd.c -- exercise sexywrap by doing random I/O operations
 *
 * This test is similar to sexytest-seq in that it goes through the disk,
 * but it also varies the operation (read()/write()/lseek()) and the length
 * of it randomly.
 *
 * Synopsis:
 *   sexytest-rnd [-vqN] [-n <rounds>] [-s <seed>] [-o <optimum>] <iscsi-url>
 *
 * Options:
 * -v		Increase the verbosity level.  When it's 0 (the default),
 *		only progress information is written to stdout.  If it's
 *		greater than that also the test operations are logged.
 *		At higher levels, some other debug information is printed
 *		relating to the choice of the size of the test operations.
 * -q		Decrease the verbosity level.
 * -N		Do not read/write the disk, just print the test operations.
 *		Implies -v.
 * -n <rounds>	Perform that many rounds of testing.  A round starts at the
 *		beginning of the disk and takes until the last bytes are
 *		reached.  Then the whole disk is read and compared with
 *		the internal buffer, verifying that the disks content is
 *		as expected.
 * -s <seed>	Operations and I/O sizes are chosen randomly.  Giving this
 *		<seed> you can repeat test sequences.  Every time a round
 *		begins the appropriate seed is shown, so you can start off
 *		from that point.  If this <seed> is not specified it is
 *		initialized from the system clock.
 * -o <optimum>	Specify the optimal number of blocks for an I/O operation
 *		on the iSCSI target obtainable with sexycat -s ... -N.
 *		If provided I/O sizes around this value will also be tried.
 *
 * <iscsi-url> is the target on which the tests are performed.
 * Its contents are overwritten, so take care.
 */

/* Include files */
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include <time.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/stat.h>

/* Macros */
/* We need a private random state, so we can reliably repeat the same
 * test sequence without interfering other users of rand(). */
#define rand()			rand_r(&Rnd_state)

/* Private variables */
/*
 * $Rnd_state is initialized either from the -s command line option
 * or from the milliseconds part of the current time.
 *
 * If $Opt_verbosity is 0 (the default), only progress information
 * is printed.  If it's greater than that test operations are printed.
 * If it's higher than 1, some other debug information is printed
 * relating to the choice of the size of the test operations.
 */
static unsigned Rnd_state;
static unsigned Opt_verbosity;

/* Private functions */
/* Return a sample of a normal distribution in the range of $avg +- $diff. */
static double normal(unsigned avg, unsigned diff)
{
	unsigned i;
	double rnd;

	/* This is a "12-section eleventh-order polynomial approximation
	 * to the normal distribution" from Wikipedia. */
	rnd = 0;
	for (i = 0; i < 12; i++)
		rnd += (double)rand() / RAND_MAX;
	rnd -= 6.0;

	/* Wikipedia claims that $rnd is in (-6,+6), but practice shows
	 * that it's rather (-3,+3). */
	rnd *= (double)diff / 3.0;
	rnd += (double)avg;

	/* Make sure $avg-$diff <= $rnd <= $avg+$diff. */
	if (rnd <= avg - diff)
		return avg - diff;
	else if (rnd >= avg + diff)
		return avg + diff;
	else
		return rnd;

	return rnd;
} /* normal */

/* Do a random read()/write()/lseek() operation on $fd, and return
 * the new [would-be] file position. */
static off_t test_op(int fd, char *disk, off_t size, off_t pos, unsigned n)
{
	char *buf;
	unsigned m, i;

	/* $m := the effective I/O size, bounded by the $disk $size. */
	m = pos + n <= size ? n : size - pos;

	/* Choose an operation. */
	switch (rand() % 3)
	{
	case 0: /* read($n) bytes and compare them with $disk. */
		if (Opt_verbosity > 0)
			printf("  read(&disk[%ld], %u) -> %ld\n",
				pos, n, pos+m);
		if (disk)
		{	/* read() shouldn't read more than $m bytes. */
			assert((buf = malloc(m)) != NULL);
			assert(read(fd, buf, n) == m);
			assert(memcmp(&disk[pos], buf, m) == 0);
			free(buf);
		}
		break;
	case 1: /* write($n) random bytes. */
		if (Opt_verbosity > 0)
			printf("  write(&disk[%ld], %u) -> %ld\n",
				pos, n, pos+m);
		if (disk)
		{
			assert((buf = malloc(n)) != NULL);
			for (i = 0; i < n; i++)
			{	/* Update $disk, but take care not to
				 * overflow it. */
				buf[i] = rand();
				if (i < m)
					disk[pos+i] = buf[i];
			}
			assert(write(fd, buf, n) == m);
			free(buf);
		} else
		{	/* Roll rand() as we would if we had a $disk
			 * in order to get the same sequence of numbers. */
			for (i = 0; i < n; i++)
				rand();
		}
		break;
	default: /* seek($m) bytes forward.  We may reach the end of disk. */
		if (Opt_verbosity > 0)
			printf("  seek(%ld + %u) -> %ld\n", pos, n, pos+m);
		if (disk)
			assert(lseek(fd, m, SEEK_CUR) == pos + m);
		break;
	}

	/* Return the actual advancement of $pos. */
	return m;
} /* test_op */

/* Do random read()/write()/lseek() operations from the start of the disk
 * continuously until its last byte is reached. */
static void test_round(int fd, char *disk, off_t size,
	unsigned blocksize, unsigned optimum)
{
	unsigned nops;
	off_t jump, pos;

	/* jump := the position from which the next operation will be taken
	 * until the end of disk.  $jump may be > $size, in which case no
	 * such operation will be performed in this round. */
	nops = 0;
	jump = rand() % (2*size);
	assert(lseek(fd, pos = 0, SEEK_SET) == 0);
	do
	{	/* Until the end of the disk is reached. */
		unsigned n;

		if (pos < jump)
		{	/* Regular case: move some bytes forward. */
			static const double opt_least = 0.01;
			static const double opt_most  = 0.05;
			static const unsigned scale   = 1000;
			double opt_ival, ival;

			/* Choose a random I/O size.  We have 2-3-4 sizes
			 * dependin on $blocksize and $optimum. */
			n = blocksize == 512 ? 2 : 3;
			if (optimum > 1)
			{	/*
				 * We have a $scale.  If rand() falls into
				 * [0..$opt_ival], $optimum will be chosen.
				 * The probability of that depends on the
				 * current $pos, which selects a value of
				 * a linear function [$opt_most..$opt_least].
				 * All other I/O sizes have the same $ival
				 * so that $scale == $opt_ival + $ival*$n.
				 */
				opt_ival = (opt_least-opt_most) * pos;
				opt_ival /= size;
				opt_ival *= scale;
				opt_ival += opt_most*scale;
				ival = ((double)scale - opt_ival) / n;
			} else
			{	/* $ival:s are evenly distributed into
				 * $n pieces of $scale. */
				opt_ival = 0;
				ival = (double)scale / n;
			}
			n = rand() % scale;

			/* $n <- the chosen I/O size */
			if (n < opt_ival)
			{
				if (Opt_verbosity > 1)
					printf("    OPTIMUM %u/%f\n",
						n, opt_ival);
				n = optimum * blocksize;
			} else if (n < opt_ival + ival)
				n = 16;
			else if (n < opt_ival + 2*ival)
				n = 512;
			else
				n = blocksize;

			/* Every once and then vary the I/O size so that
			 * $pos+$n will be dividable by $n.  Otherwise add
			 * a small +/- 16 bytes jitter to it. */
			if (!(rand() % 5))
			{
				if (Opt_verbosity > 1)
					printf("    ALIGNED %u", n);
				n -= pos % n;
				if (Opt_verbosity > 1)
					printf(" -> %u\n", n);
			} else
				n = round(normal(n, 16));
		} else
		{	/* Perform I/O until the end of disk. */
			n = size - pos;
			if (Opt_verbosity > 1)
				printf("    EOD (%u)\n", n);
		}

		/* Do the operation and get the expected new file position. */
		pos += test_op(fd, disk, size, pos, n);
		if (disk)
			/* Verify that we're at $pos. */
			assert(lseek(fd, 0, SEEK_CUR) == pos);
		nops++;
	} while (pos < size);

	printf("...performed %u operations\n", nops);

	if (disk)
	{	/* Compare $disk with $real:ity. */
		char *real;
		unsigned n;

		if (Opt_verbosity > 0)
			puts("Verifying disk contents...");
		assert(lseek(fd, 0, SEEK_SET) == 0);

		/* Compare $optimum bytes at once. */
		optimum *= blocksize;
		assert((real = malloc(optimum)) != NULL);
		for (; size > 0; disk += n, size -= n)
		{
			n = optimum <= size ? optimum : size;
			assert(read(fd, real, optimum) == n);
			assert(!memcmp(disk, real, n));
		}
		free(real);
	}
} /* test_round */

/* The main function */
int main(int argc, char *argv[])
{
	int fd;
	off_t size;
	char *disk;
	struct stat sb;
	int optchar, nop;
	unsigned nrounds, i;
	unsigned blocksize, optimum;

	/* Parse the command line. */
	i = nop = 0;
	nrounds = 1;
	optimum = 1;
	while ((optchar = getopt(argc, argv, "vqNn:s:o:")) != EOF)
		switch (optchar)
		{
		case 'v':
			Opt_verbosity++;
			break;
		case 'q':
			if (Opt_verbosity)
				Opt_verbosity--;
			break;
		case 'N':
			nop = 1;
			if (!Opt_verbosity)
				Opt_verbosity++;
			break;
		case 'n':
			nrounds = atoi(optarg);
			break;
		case 's':
			i = atoi(optarg);
			break;
		case 'o':
			if (!(optimum = atoi(optarg)))
				optimum = 1;
			break;
		default:
			exit(1);
		}

	/* Print usage? */
	if (!argv[optind])
	{
		puts("usage: sexytest-rnd [-vqN] [-n <rounds>] [-s <seed>] "
			"[-o <optimum>] <iscsi-url>");
		exit(0);
	}

	/* Initialize $Rnd_state.  We need to use a private rand_r() state
	 * because libiscsi itself uses rand(), altering our random numbers
	 * unpredictably. */
	if (!i)
	{
		struct timeval tv;

		gettimeofday(&tv, NULL);
		Rnd_state = tv.tv_usec;
	} else
		Rnd_state = i;

	/* Open the iSCSI device and get its $size and $blocksize
	 * (these are necessary even in we're in $nop mode). */
	assert((fd = open(argv[optind++], O_RDWR)) >= 0);
	assert(!fstat(fd, &sb));
	size = sb.st_size;
	blocksize = sb.st_blksize;

	/* If we're not $nop, read the $disk entirely. */
	if (!nop)
	{
		if (Opt_verbosity > 0)
			puts("Reading the entire disk...");
		assert((disk = malloc(size)) != NULL);
		assert(read(fd, disk, size) == size);
	} else
		disk = NULL;

	if (nop)
		puts("No operation");
	else
		printf("PID: %d\n", getpid());

	/* Do the test rounds.  All rounds start from the beginning
	 * of the disk, do random read()s, write()s and lseek()s,
	 * until the end of the disk is reached. */
	for (i = 0; i < nrounds; i++)
	{
		printf("Round %u (seed: %u)...\n", 1+i, Rnd_state);
		test_round(fd, disk, size, blocksize, optimum);
	}

	/* Done */
	free(disk);
	close(fd);
	return 0;
} /* main */

/* End of sexytest-rnd.c */
