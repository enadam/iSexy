/*
 * sexycat.c -- iSCSI disk dumper {{{
 *
 * Synopsis:
 *   sexycat [<options>] { [<source>] [<destination>] | [ -x <program> ] }
 *
 * Where <source> can be:
 *   -s <iscsi-url>		Specifies the remote iSCSI source to dump.
 *   -S <file-name>		Upload the local <file-name> to the remote
 *				iSCSI destination.
 *   -S -			Read the standard input.  This is the default
 *				if none of -sS is specified.
 * and <destination> is either:
 *   -d <iscsi-url>		The remote iSCSI destination to write to.
 *   -D <file-name>		Download the remote iSCSI source to this
 *				<file-name>.  Unless -O is in effect the
 *				file won't be overwritten.  If the file is
 *				seekable (ie. it's a regular file) its size
 *				is set to the capacity of the iSCSI source.
 *				WARNING (XXX): if the file is non-seekable
 *				and you're copying multi-gigabyte disks,
 *				you'll likely run out of memory.
 *   -D -			Dump the source iSCSI disk to the standatrd
 *				output.  This is the default is none of -dD
 *				is specified.
 *
 * If not in -x mode,  either the <source> or the <destination> must be
 * an iSCSI target.  If both -sd are specified the source iSCSI disk is
 * directly copied to the destination disk.  Otherwise:
 *
 *   -x <program> [<args>...]	Launch <program> and override its file I/O
 *				syscalls so that they can be used with iSCSI
 *				URLs transparently.  This is only possible
 *				if sexycat is built as part of sexywrap,
 *				and a dual library/executable was created.
 *				In this mode all <options> but -i are ignored.
 *				Example: sexywrap -x cat <iscsi-url> > ide.
 *
 * Possible <options> are:
 *   -i <src-initiator-name>	Log in to the source iSCSI target with this
 *				IQN.  If left unspecified a hardcoded default
 *				is used.  Ignored the the source is a local
 *				file.
 *   -I <dst-initiator-name>	Log in to the destination iSCSI target with
 *				this IQN.  If left unspecified the source's
 *				initiator name is used.  Otherwise if the
 *				argument is an empty string the same hardeced
 *				default is used as for <src-initiator-name>.
 *				Ignored if the destination is a local file.
 *   -N				Don't do any I/O, just connect to the iSCSI
 *				device(s) and log in and print the capacity
 *				of the iSCSI target(s).
 *   -O				Overwrite the local destination <file-name>.
 *   -V				Before starting downloading ensure that the
 *				necessary free disk space is available.
 *   -v				Be more verbose:
 *				-- at level 2 it's printed when a block is
 *				   being re-read or rewritten due to a fault
 *				The default level is 1.
 *   -q				Be less verbose.  At verbosity level 0 all
 *				informational output is suppressed.
 *   -p {<secs>|<millissecs>ms}	Report progress (block number being read,
 *				last block that has been read and written)
 *				every so often.  If no progress was made
 *				since the last time it had been reported,
 *				it's suppressed, unles 10 * <seconds> have
 *				passed.
 *   -fF <fallback-blocksize>	If the iSCSI target's block size cannot be
 *				determined, suppose the given value instead
 *				of the default 512 bytes.  -F only sets the
 *				destination target's, -f sets it for both.
 *				If you only want to set it for the source,
 *				specify -F 0 explicitly after -f.
 *   -cC <chunk-size>		Read/write <chunk-size> blocks of data at once
 *				if possible.  If not specified the server is
 *				queried for its preference.  -c and -C are in
 *				the same relation as -f and -F.
 *   -mM <max-reqs>		The maximum number of parallel requests
 *				to iSCSI targets.  If the connection breaks,
 *				this number is reduced by the factor which
 *				can be specified with -R.  Ignored when
 *				the endpoint is a local file, otherwise
 *				the default is 32.  -m and -M are in the
 *				same relation as -f and -F.
 *   -b <min-output-batch>	Collect at least this number of input chunks
 *				before writing them out.  Writing of larger
 *				batches can be more efficient.  Only effective
 *				if the destination is a local file, otherwise
 *				the default is 32.
 *   -B <max-output-batch>	Write the output batch if this many input
 *				chunks has been collected.  Only effective
 *				if the destination is a local file, otherwise
 *				the default is 64.
 *   -r <retry-delay>		If reading or writing a chunk is failed,
 *				wait <retry-delay> milliseconds before
 *				retrying.  The default is three seconds.
 *   -R <degradation-percent>	When the connection breaks with an iSCSI
 *				device it's supposed to be caused by the
 *				too high amount of parallel iSCSI requests
 *				(at least this is the case with istgt).
 *				This case the maximimum number of requests
 *				(which can be specified with -mM) is reduced
 *				to this percent.  The value must be between
 *				0..100, and the default is 50%.
 *
 * <iscsi-url> is iscsi://<host>[:<port>]/<target-name>/<LUN>.
 * <host> can either be a hostname or an IPv4 or IPv6 address.
 * <target-name> is the target's IQN.  An example for <iscsi-url> is:
 * iscsi://localhost/iqn.2014-07.net.nsn-net.timmy:omu/1
 * (If you get Connection refused unexpectedly, the reason could be that
 *  libiscsi tries to connect to the localhost's IPv6 address.  To fix it
 *  edit /etc/gai.conf so that it includes "precedence ::ffff:0:0/96 100".)
 *
 * To increase effeciency I/O with iSCSI devices and seekable local files
 * can be done out-of-order, that is, a source block $n may be read/written
 * later than $m even if $n < $m.  Operations are done in chunks, whose size
 * is the same as the source or destination iSCSI device's block size.
 * (This could be improved in the future.)  Requests are sent parallel,
 * with a backoff strategy if the server feels overloaded.
 *
 * TODO max total size of $output_st::tasks (XXX)
 * TODO input: skip, nblocks
 * TODO output: seek
 * TODO end-to-end checksum
 * TODO checksum per every nth block/chunk
 * TODO request timeout (don't trust the server)
 * TODO remote_to_local: force non-seekable
 * TODO use readcapacity16 et al.
 * TODO full documentation
 * TODO document the $LIBISCSI_* environment variables
 * TODO make $Info line-buffered if it's redirected to stderr
 * TODO clarify when to use warn() + return 0 vs. die()
 *
 * Dependecies: libiscsi
 * Compilation: cc -Wall -O2 -s -lrt -liscsi sexycat.c -o sexycat
 *
 * The silly `sexy' name refers to the connection with SCSI, which originally
 * was proposed to be pronounced like that.
 *
 * This program is a very far descendent of iscsi-dd.c from libiscsi-1.4.0,
 * so it can be considered a derivative work, inheriting the licensing terms,
 * thus being covered by the GNU GPL v2.0+.
 * }}}
 */

/* Configuration */
/* For POLLRDHUP */
#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

/* If we're not built as a part of sexywrap, we're building sexycat. */
#ifndef SEXYWRAP
# define SEXYCAT
#endif

#if defined(SEXYWRAP) && defined(SEXYCAT) && !defined(__PIE__)
# error "You need to build sexywrap+sexycat with -shared -pie -fPIE"
#endif

/* Include files {{{ */
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <errno.h>
#include <assert.h>

#include <string.h>
#include <stdio.h>
#include <time.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>

#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/statvfs.h>

#include <linux/limits.h>

#include <iscsi.h>
#include <scsi-lowlevel.h>
/* }}} */

/* Standard definitions {{{ */
/* Defaults */
#define DFLT_INITIAL_MAX_ISCSI_REQS	32
#define DFLT_INITIAL_MAX_OUTPUT_QUEUE	(DFLT_INITIAL_MAX_ISCSI_REQS * 2)
#define DFLT_MIN_OUTPUT_BATCH		(DFLT_INITIAL_MAX_OUTPUT_QUEUE / 2)

#define DFLT_ISCSI_MAXREQS_DEGRADATION	50
#define DFLT_ISCSI_REQUEST_RETRY_PAUSE	(3 * 1000)
/* }}} */

/* Macros {{{ */
/* Return the number of elements in $ary. */
#define MEMBS_OF(ary)			(sizeof(ary) / sizeof((ary)[0]))

/* Shortcuts */
#ifdef LIBISCSI_API_VERSION
# define LBA_OF(task)			(((struct scsi_read10_cdb const *)((task)->ptr))->lba)
#else /* libiscsi 1.4 */
# define LBA_OF(task)			((task)->params.read10.lba)
#endif

/*
 * IS_SEXYWRAP():	return whether we're operating on behalf of sexywrap
 * LOCAL_TO_REMOTE():	return whether we're called by sexywrap::write()
 *			or if we're uploading a local file to an iSCSI device
 * REMOTE_TO_LOCAL():	return whether we're called by sexywrap::read()
 *			or if we're downloading an iSCSI disk to a local file
 * REMOTE_TO_REMOTE():	return whether we're copying an iSCSI disk to another
 *			can't be the case if IS_SEXYWRAP()
 */
#if !defined(SEXYWRAP)
# define IS_SEXYWRAP(input)		0
# define LOCAL_TO_REMOTE(input)		(!(input)->src->iscsi)
# define REMOTE_TO_LOCAL(input)		(!(input)->dst->iscsi)
#elif !defined(SEXYCAT)
# define IS_SEXYWRAP(input)		1
# define LOCAL_TO_REMOTE(input)		(!(input)->src)
# define REMOTE_TO_LOCAL(input)		(!(input)->dst)
#else /* SEXYCAT && SEXYWRAP */
# define IS_SEXYWRAP(input)		(!(input)->src||!(input)->dst)
# define LOCAL_TO_REMOTE(input)		(!(input)->src||!(input)->src->iscsi)
# define REMOTE_TO_LOCAL(input)		(!(input)->dst||!(input)->dst->iscsi)
#endif
#define REMOTE_TO_REMOTE(input)		\
	(!LOCAL_TO_REMOTE(input) && !REMOTE_TO_LOCAL(input))

/* What to do with informational messages. */
#if !defined(SEXYWRAP)
# define info(fmt, ...)			fprintf(Info, fmt "\n", __VA_ARGS__)
#elif !defined(SEXYCAT)
  /* sexywrap doesn't need them. */
# define info(fmt, ...)			/* NOP */
#else /* SEXYCAT && SEXYWRAP */
# define info(fmt, ...)			\
do					\
{					\
	assert(Info != NULL);		\
	fprintf(Info, fmt "\n", __VA_ARGS__);	\
} while (0)
#endif
/* }}} */

/* Type definitions {{{ */
/* Currently we're limited to 2 TiB because we're using read10/write10,
 * but this may change in the future. */
typedef unsigned scsi_block_addr_t;
typedef unsigned scsi_block_count_t;

/* Type of function called back when a chunk has been read or written. */
typedef void (*callback_t)(struct iscsi_context *iscsi, int status,
	void *command_data, void *private_data);

/* Represents an iSCSI/local source/destination. */
struct endpoint_st
{
	/* Is this the source or destination endpoint?  Used for loggging. */
	char const *which;

	union
	{
		/* Input/output file name if the endpoint is local. */
		char const *fname;

		struct
		{	/* Order is important, $url must be the first member
			   of the structure; see destroy_endpoint() why. */
			struct iscsi_url *url;

			/* The $initiator name to use for log in to $url. */
			char const *initiator;
		};
	};

	/*
	 * NULL if the target is local.  This case $fname either designates
	 * the input/output file name, or standard input/output if it's NULL.
	 */
	struct iscsi_context *iscsi;

	/* Designates the current maximum number of parallel iSCSI requests,
	 * which may be decreased by $Opt_maxreqs_degradation.  Zero in case
	 * of local input/output. */
	unsigned maxreqs;

	/* The destination's block size if it's an iSCSI device,
	 * otherwise the source device's block size. */
	unsigned blocksize;

	union
	{
		/* Used for remote targets. */
		struct
		{
			/* The number of blocks of the target. */
			scsi_block_count_t nblocks;

			/*
			 * $optimum is the number of blocks the target
			 * likes to transfer in a request.  Whenever
			 * possible we try to size our chunks to carry
			 * that many blocks of information.
			 *
			 * $granuality is also a preference of the target.
			 * If we need to transfer less than $optimum blocks,
			 * we try to request <integer>*$granuality number
			 * of them.  If we need even less, we just request
			 * the exact number.
			 *
			 * $maximum is the maximum number of blocks that
			 * can be requested at once.  It can be zero if
			 * it wasn't specified; this case there's no upper
			 * limit.  This value is not used during operation.
			 */
			scsi_block_count_t optimum, maximum, granuality;
		};

		/*
		 * This field is used for local destination.  If a file
		 * is $seekable, we'll use pwrite[v]() to write blocks
		 * out-of-order.  Otherwise they're written sequentially
		 * with write[v]().
		 */
		int seekable;
	};
};

/* Represents a unit of data being read or written in a single request.
 * The chunk size can vary, but it's never less than the block size of
 * the target or larger than the target's optimal transfer size. */
struct input_st;
struct chunk_st
{
	/* If the chunk is unused (not reading or writing), points to the
	 * next chunk in the input_st::unused chain. */
	struct chunk_st *next;

	/* All chunks link to the same input_st. */
	struct input_st *input;

	/* Starting address of the block(s) being read or written
	 * in this chunk. */
	scsi_block_addr_t address;

	/* If the chunk is failed, the number of milliseconds until retry.
	 * This is recalculated by restart_requests().  Zero for unused
	 * chunks. */
	unsigned time_to_retry;

	/* The data carried by this chunk. */
	union
	{
		/* Created by libiscsi and used by remote_to_local()
		 * and remote_to_remote(). */
		struct scsi_task *read_task;

		struct
		{
			/* The size of buffer referred by $rbuf or $wbuf.
			 * For $read_task, this information is contained
			 * therein. */
			size_t sbuf;

			union
			{
				/* Used by sexywrap and points to
				 * a separately allocated buffer. */
				void const *wbuf;

				/* Used by local_to_remote() and designates
				 * the beginning of the buffer allocated
				 * together with the containing chunk_st. */
				unsigned char rbuf[0];
			} u;
		};
	};
};

/* Encapsulates all state information needed for writing.  In theory
 * this struct could be a union at the moment, but this may change
 * in the future. */
struct output_st
{
	union
	{
		/* The number of outstanding write requests.  Zero if the
		 * destination is local. */
		unsigned nreqs;

		/* These are only used for local destination.  This case
		 * the output is done in batches with (p)writev(). */
		struct
		{
			/*
			 * The capacity of $iov and $tasks, thus telling
			 * the maximum number of buffers in the batch.
			 * Initially it's $Opt_max_output_queue, but it
			 * may be increased indefinitely during operation.
			 */
			unsigned max;

			/* The actual number of buffers in the batch. */
			unsigned enqueued;

			/*
			 * When a chunk is read it's placed in $tasks.
			 * This is a packed array, no holes are allowed.
			 * When the batch is flushed the buffers are
			 * copied to $iov, a preallocated iovec array.
			 */
			struct iovec *iov;
			struct scsi_task **tasks;
		};
	};
};

/* The main structure of the program, stringing all structures together. */
struct input_st
{
	/* Number of parallel read requests.  Zero if the input is a
	 * local file. */
	unsigned nreqs;

	/*
	 * In REMOTE_TO_*() modes $top_block is the address of the lowest
	 * unread source block; in LOCAL_TO_REMOTE() mode it's the address
	 * of the highest block being or having been written.  Reading or
	 * writing continues $until is reached.  
	 */
	scsi_block_addr_t top_block, until;

	/*
	 * $unused is a list of preallocated chunks ready for reading.
	 * $nunused is the number of chunks in the list; it's only used
	 * by free_surplus_unused_chunks().
	 *
	 * $failed is a list of chunks whose reading _or_ writing failed
	 * and needs to be retried.  $last_failed points to the last
	 * element of the list; it's only used by chunk_failed() in order
	 * to be able to append a new chunk to the end of of list quickly.
	 */
	unsigned nunused;
	struct chunk_st *unused;
	struct chunk_st *failed, *last_failed;

	/* Links to all other structures. */
	struct output_st *output;
	struct endpoint_st *src, *dst;
};
/* }}} */

/* Function prototypes {{{ */
static void __attribute__((noreturn)) usage(void);
static void warnv(char const *fmt, va_list *args);
static void __attribute__((format(printf, 1, 2)))
	warn(char const *fmt, ...);
static void __attribute__((nonnull(1)))
	warn_errno(char const *op);
static void __attribute__((nonnull(2)))
	warn_iscsi(char const *op, struct iscsi_context *iscsi);
static void __attribute__((noreturn, format(printf, 1, 2)))
	die(char const *fmt, ...);

static int get_inode(int fd, ino_t *inodep);
static unsigned timediff(
	struct timespec const *later,
	struct timespec const *earlier);
static void report_progress(void);

static void *__attribute__((malloc)) xmalloc(size_t size);
static void xrealloc(void *ptrp, size_t size);
static int xpoll(struct pollfd *pfd, unsigned npolls);
static int xfpoll(struct pollfd *pfd,unsigned npolls,struct input_st *input);
static int xread(int fd, unsigned char *buf, size_t sbuf, size_t *nreadp);
static int xpwritev(int fd, struct iovec *iov, unsigned niov,
	off_t offset, int seek);

static int is_connection_error(
	struct iscsi_context *iscsi, char const *which,
	unsigned revents);
static int is_iscsi_error(
	struct iscsi_context *iscsi, struct scsi_task *task,
	char const *op, int status);
static int run_iscsi_event_loop(struct iscsi_context *iscsi,
	unsigned events);

#ifdef SEXYCAT
static void add_output_chunk(struct chunk_st *chunk);
static void add_to_output_iov(struct output_st *output,
	struct scsi_task *task, unsigned niov);
static int process_output_queue(int fd,
	struct endpoint_st const *dst, struct output_st *output,
	int more_to_come);
#endif /* SEXYCAT */

static void chunk_written(struct iscsi_context *iscsi, int status,
	void *command_data, void *private_data);
static void chunk_read(struct iscsi_context *iscsi, int status,
	void *command_data, void *private_data);
static size_t read_chunk_size(
	struct endpoint_st const *src, struct endpoint_st const *dst,
	scsi_block_addr_t from, scsi_block_addr_t until);
static int restart_requests(struct input_st *input,
	callback_t read_cb, callback_t write_cb);
static int start_iscsi_read_requests(struct input_st *input,
	callback_t read_cb);

static void free_chunks(struct chunk_st *chunk);
static void free_surplus_unused_chunks(struct input_st *input);
static void reduce_maxreqs(struct endpoint_st *endp);
static void return_chunk(struct chunk_st *chunk);
static void take_chunk(struct chunk_st *chunk);
static void chunk_failed(struct chunk_st *chunk);

static void done_input(struct input_st *input);
static int init_input(struct input_st *input, struct output_st *output,
	struct endpoint_st *src, struct endpoint_st *dst);

static void endpoint_connected(struct iscsi_context *iscsi, int status,
	void *command_data, void *private_data);
static int connect_endpoint(struct iscsi_context *iscsi,
	struct iscsi_url *url);
static int reconnect_endpoint(struct endpoint_st *endp);

static struct scsi_task *read_endpoint(struct endpoint_st const *endp,
	scsi_block_addr_t block, size_t chunk_size,
	callback_t read_cb, struct chunk_st *chunk);
static struct scsi_task *write_endpoint(struct endpoint_st const *endp,
	scsi_block_addr_t block, void const *buf, size_t sbuf,
	callback_t write_cb, struct chunk_st *chunk);

static void destroy_endpoint(struct endpoint_st *endp);
static void print_endpoint(struct endpoint_st const *endp);
static void calibrate_endpoint(struct endpoint_st *endp,
	scsi_block_count_t desired_optimum);
static int stat_endpoint(struct endpoint_st *endp,
	unsigned fallback_blocksize);
static int init_endpoint(struct endpoint_st *endp, char const *url,
	unsigned fallback_blocksize);

#ifdef SEXYCAT
static int local_to_remote(struct input_st *input);
static int open_output(struct endpoint_st *dst, struct endpoint_st const *src,
	int overwrite, int check_free_space);
static int remote_to_local(struct input_st *input,
	int overwrite, int check_free_space);
static int remote_to_remote(struct input_st *input);
#endif /* SEXYCAT */
/* }}} */

/* Private variables {{{ */
/* User controls {{{ */
/* -vqp */
/* By default $Opt_verbosity is 1.  $Opt_progress is in milliseconds. */
static int Opt_verbosity, Opt_progress;

/* -bB */
#ifdef SEXYCAT
static unsigned Opt_min_output_batch = DFLT_MIN_OUTPUT_BATCH;
static unsigned Opt_max_output_queue = DFLT_INITIAL_MAX_OUTPUT_QUEUE;
#endif

/* -rR */
static unsigned Opt_request_retry_time  = DFLT_ISCSI_REQUEST_RETRY_PAUSE;
static unsigned Opt_maxreqs_degradation = DFLT_ISCSI_MAXREQS_DEGRADATION;
/* }}} */

/*
 * For diagnostic output.  $Info is the FILE on which informational messages
 * like progress are printed.  $Basename is used in error reporting.  It is
 * set up for sexywrap by default, but if we're sexycat, that's changed in
 * main() right away.
 */
static char const *Basename = "sexywrap";
static __attribute__((unused)) FILE *Info;

/*
 * -- $Start: when the program was started; used by report_progress()
 *    to show the timestamp
 * -- $Last_report: the last time report_progress() printed something
 * -- $Now: the current time after the invocation of xfpoll()
 *
 * All of these times are from clock_gettime().  $Last_report and $Now
 * are used by report_progress() to decide whether it's time to wake up.
 * $Now is also used by xfpoll() to maintain the retry timers of chunks.
 */
static struct timespec Start, Last_report, Now;

/*
 * The latest blocks being/having been read/written.  $Last values are
 * updated by start_iscsi_read_requests() ($reading), chunk_read() ($red),
 * and chunk_written() ($written).  $Prev:ious reported values are saved
 * in order report_progress() not to repeat itself too often.
 */
static struct
{
	scsi_block_addr_t reading, red;
	scsi_block_addr_t writing, written;
} Prev, Last;
/* }}} */

/* Program code */
void usage(void)
{
	printf("usage: %s [-vq] [-p <progress>] "
		"[-fF <fallback-blocksize>] "
		"[-cC <chunk-size>] "
		"[-mM <max-requests> "
		"[-r <retry-pause>] [-R <request-degradation>] "
		"[-bB <batch-size>] "
		"[-i <initiator>] [-N] "
#ifdef SEXYWRAP
		"[-x <program> [<args>...]] "
#endif
		"[-sS <source>] [-OV] [-dD <destination>]\n",
		Basename);
	exit(0);
}

void warnv(char const *fmt, va_list *args)
{
#ifdef SEXYWRAP
	/* It's possible, though unlikely that the program
	 * we're preloaded by cleared $stderr. */
	if (!stderr)
		return;
#endif

	/* If $stdout and $stderr are redirected to the same file,
	 * make sure that they're not mixed up because $stdout is
	 * buffered. */
	if (Info && Info != stderr)
		fflush(Info);

	fprintf(stderr, "%s: ", Basename);
	vfprintf(stderr, fmt, *args);
	putc('\n', stderr);
}

void warn(char const *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	warnv(fmt, &args);
	va_end(args);
}

void warn_errno(char const *op)
{
#ifdef SEXYWRAP
	if (!stderr)
		return;
#endif
	if (Info && Info != stderr)
		fflush(Info);
	fprintf(stderr, "%s: %s: %m\n", Basename, op);
}

void warn_iscsi(char const *op, struct iscsi_context *iscsi)
{
#ifdef SEXYWRAP
	if (!stderr)
		return;
#endif
	if (Info && Info != stderr)
		fflush(Info);
	if (op)
		fprintf(stderr, "%s: %s: %s\n", Basename, op,
			iscsi_get_error(iscsi));
	else
		fprintf(stderr, "%s: %s\n", Basename,
			iscsi_get_error(iscsi));
}

void die(char const *fmt, ...)
{
	va_list args;

	if (fmt)
	{
		va_start(args, fmt);
		warnv(fmt, &args);
		va_end(args);
	}

	exit(1);
}

/*
 * Return the i-node number of $fd.  If *$inodep != 0 and it differs from
 * the current value, *$inodep is updated and 1 is returned.   Otherwise
 * (also in case of error) returns 0.  If !*$inodep, the retrieved number
 * is saved.  Used to find out whether libiscsi reconnected to the target
 * in its event loop.
 */
int get_inode(int fd, ino_t *inodep)
{
	struct stat sb;

	if (fstat(fd, &sb) < 0)
	{	/* Couldn't get the i-node number. */
		warn_errno("fstat");
		return 0;
	} else if (*inodep == 0)
	{	/* This is probably the first time we query it. */
		*inodep = sb.st_ino;
		return 0;
	} else if (*inodep != sb.st_ino)
	{	/* The previous and the current numbers differ. */
		*inodep = sb.st_ino;
		return 1;
	} else	/* The i-node number hasn't changed. */
		return 0;
} /* get_inode */

/* Return $later - $earlier in ms.  It is assumed that $later >= $earlier. */
unsigned timediff(struct timespec const *later,
	struct timespec const *earlier)
{
	const unsigned ms_per_sec = 1000;
	const long ns_per_ms = 1000000;
	unsigned diff;

	/* Verify the precondition. */
	if (later->tv_sec != earlier->tv_sec)
		assert(later->tv_sec > earlier->tv_sec);
	else 
		assert(later->tv_nsec >= earlier->tv_nsec);

	diff  = (later->tv_sec  - earlier->tv_sec)  * ms_per_sec;
	diff += (later->tv_nsec - earlier->tv_nsec) / ns_per_ms;

	return diff;
} /* timediff */

/* Print $Last if $Opt_progress has passed since the previous report.
 * Called by xpoll() and xfpoll(). */
void report_progress(void)
{
#ifdef SEXYCAT
	unsigned diff, hours, mins, secs;

	if (!Opt_progress)
		return;
	if (!Start.tv_sec && !Start.tv_nsec)
		return;

	assert(Now.tv_sec || Now.tv_nsec);
	diff = timediff(&Now, Last_report.tv_sec || Last_report.tv_nsec
		? &Last_report : &Start);
	if (diff < Opt_progress)
		/* $Opt_progress hasn't passed since $Last_report. */
		return;
	if (diff < 10 * Opt_progress
			&& Last.reading == Prev.reading
			&& Last.red == Prev.red
			&& Last.written == Prev.written)
		/* $Opt_progress has passed, but the values didn't change,
		 * don't report unless 10*$Opt_progress has passed. */
		return;

	/* $diff := $Now - $Start.  Don't recalculate it if we used
	 * $Start earlier. */
	if (Last_report.tv_sec || Last_report.tv_nsec)
		diff = timediff(&Now, &Start);

	/* $diff -> $hours:$mins:$secs */
	diff /= 1000;
	hours = diff / (60*60);
	diff %= 60*60;
	mins = diff / 60;
	secs = diff % 60;

	info("[%.2u:%.2u:%.2u] "
	     	"reading #%u, have read #%u, writing #%u, written #%u",
		hours, mins, secs,
		Last.reading, Last.red, Last.writing, Last.written);
	Prev = Last;
	Last_report = Now;
#endif /* SEXYCAT */
} /* report_progress */

#ifdef SEXYCAT
void *xmalloc(size_t size)
{
	void *ptr;

	if (!(ptr = malloc(size)))
		die("malloc(%zu): %m", size);

	return ptr;
}

void xrealloc(void *ptrp, size_t size)
{
	void *ptr;

	ptr = *(void **)ptrp;
	if (!(ptr = realloc(ptr, size)))
		die("realloc(%zu): %m", size);
	*(void **)ptrp = ptr;
}
#endif /* SEXYCAT */

/* On failure $errno is set. */
int xpoll(struct pollfd *pfd, unsigned npolls)
{
	int ret;

	for (;;)
	{	/* Sleep at most $Opt_progress if progress reporting
		 * is enabled. */
		if (Opt_progress)
		{
			ret = poll(pfd, npolls, Opt_progress);
			clock_gettime(CLOCK_MONOTONIC, &Now);
			report_progress();
		} else	/* We can sleep indefinitely long. */
			ret = poll(pfd, npolls, -1);
		if (ret > 0)
			return ret;
		if (ret < 0 && errno != EINTR)
			return 0;
	} /* while EINTR */
}

/* As a side-effect $Now is updated.  On failure $errno is set. */
int xfpoll(struct pollfd *pfd, unsigned npolls, struct input_st *input)
{
	int ret, eintr;

	/* If we don't have failed chunks we can wait indefinitely
	 * and we won't have to update any chunk_st::time_to_retry:es. */
	if (!input->failed)
		return xpoll(pfd, npolls) ? 1 : -1;

	/* poll() as long as it returns EINTR. */
	do
	{
		struct timespec since;
		struct chunk_st *chunk;
		unsigned timeout, elapsed;

		/*
		 * Measure the time since we were called last time.
		 * Sleep at most $timeout milliseconds, which is either
		 * the expiration of the oldest failed chunk, or the
		 * time to the next progress report.
		 */
		since = Now.tv_sec || Now.tv_nsec ? Now : Start;
		timeout = input->failed->time_to_retry;
		if (Opt_progress && timeout > Opt_progress)
			timeout = Opt_progress;
		ret = poll(pfd, npolls, timeout);
		eintr = ret < 0 && errno == EINTR;

		/* Get the $elapsed time $since. */
		clock_gettime(CLOCK_MONOTONIC, &Now);
		elapsed = timediff(&Now, &since);
		report_progress();

		/* Subtract the elapsed time from all failed chunks. */
		for (chunk = input->failed; chunk; chunk = chunk->next)
			if (chunk->time_to_retry > elapsed)
				chunk->time_to_retry -= elapsed;
			else
				chunk->time_to_retry = 0;
	} while (eintr);

	return ret;
}

#ifdef SEXYCAT
/*
 * Read $fd until $buf is filled with $sbuf bytes.  Only returns less
 * than that if EOF is reached or an error is ecountered.  This latter
 * case $errno is propagated and 0 is returned.  Otherwise 1 is returned
 * and the number of bytes actually read is stored in *$nreadp.
 *
 * TODO Since this function can block, processing of iSCSI management
 *      messages (pings) can be delayed indefinitely.
 */
int xread(int fd, unsigned char *buf, size_t sbuf, size_t *nreadp)
{
	*nreadp = 0;
	while (*nreadp < sbuf)
	{
		ssize_t n;

		n = read(fd, &buf[*nreadp], sbuf - *nreadp);
		if (n > 0)
			*nreadp += n;
		else if (n == 0 || errno == ESPIPE)
			return 1;
		else if (errno != EAGAIN && errno != EINTR
				&& errno != EWOULDBLOCK)
			return 0;
	} /* until $buf is filled */

	return 1;
} /* xread */

/* Writes the full $iov to $fd.  On error 0 is returned and $errno is set. */
int xpwritev(int fd, struct iovec *iov, unsigned niov, off_t offset, int seek)
{
	/* Return right away if there's nothing to write. */
	assert(fd >= 0);
	assert(niov > 0);

	/* Write until all of $iov is written out. */
	for (;;)
	{
		int ret;

		ret = seek
			? niov > 1
				? pwritev(fd, iov, niov, offset)
				: pwrite(fd, iov[0].iov_base, iov[0].iov_len,
					offset)
			: niov > 1
				? writev(fd, iov, niov)
				: write(fd, iov[0].iov_base, iov[0].iov_len);
		if (ret < 0)
		{
			if (errno != EAGAIN && errno != EINTR
					&& errno != EWOULDBLOCK)
				return 0;
			continue;
		}

		if (seek)
			offset += ret;

		/* Skip $iov:s we've just written. */
		while (ret >= iov->iov_len)
		{
			ret -= iov->iov_len;
			iov++;
			niov--;
			if (!niov)
				/* We've written out everything. */
				return 1;
		}

		/* We need to write more. */
		iov->iov_len  -= ret;
		iov->iov_base += ret;
	}
} /* xpwritev */
#endif /* SEXYCAT */

int is_connection_error(struct iscsi_context *iscsi, char const *which,
	unsigned revents)
{
	int error;
	socklen_t serror;

	if (!(revents & (POLLNVAL|POLLERR|POLLHUP|POLLRDHUP)))
		return 0;
	if (!which)
		return 1;

	serror = sizeof(error);
	if (revents & POLLNVAL)
		warn("connection to iSCSI %s is closed unexpectedly", which);
	else if (!(revents & POLLERR))
		warn("iSCSI %s closed the connection", which);
	else if (!getsockopt(iscsi_get_fd(iscsi), SOL_SOCKET, SO_ERROR,
			&error, &serror) && error)
		warn("iSCSI %s: %s", which, strerror(error));
	else if (revents & (POLLHUP|POLLRDHUP))
		warn("iSCSI %s closed the connection", which);
	else
		warn("iSCSI %s: unknown socket error", which);

	return 1;
}

int is_iscsi_error(struct iscsi_context *iscsi, struct scsi_task *task,
	char const *op, int status)
{
	if (status == SCSI_STATUS_GOOD)
		return 0;
	else if (status == SCSI_STATUS_CHECK_CONDITION)
		warn("%s: sense key:%d ascq:%04x",
			op, task->sense.key, task->sense.ascq);
	else if (status != SCSI_STATUS_CANCELLED)
		warn_iscsi(op, iscsi);
	return 1;
}

int run_iscsi_event_loop(struct iscsi_context *iscsi, unsigned events)
{
	if (iscsi_service(iscsi, events) != 0)
	{
		warn_iscsi(NULL, iscsi);
		return 0;
	} else
		return 1;
}

#ifdef SEXYCAT
void add_output_chunk(struct chunk_st *chunk)
{
	unsigned i;
	struct output_st *output = chunk->input->output;

	/* Make room for $chunk in $output->tasks if it's full. */
	if (output->enqueued >= output->max)
	{
		unsigned n;

		/* $output->tasks is either unallocated or we've used up
		 * all the free entries.  Allocate it or 25% more. */
		n = output->max
			? output->max + output->max/4
			: Opt_max_output_queue;
		xrealloc(&output->tasks, sizeof(*output->tasks) * n);
		memset(&output->tasks[output->enqueued], 0,
			sizeof(*output->tasks) * (n-output->max));
		xrealloc(&output->iov, sizeof(*output->iov) * n);
		output->max = n;
	}

	/* Find a place for $chunk in $output->tasks in which buffers
	 * are ordered by LBA. */
	assert(output->enqueued < output->max);
	for (i = output->enqueued; i > 0; i--)
		if (LBA_OF(output->tasks[i-1]) < chunk->address)
			break;

	/* Insert $chunk->read_task into $output->tasks[$i]. */
	memmove(&output->tasks[i+1], &output->tasks[i],
		sizeof(*output->tasks) * (output->enqueued - i));
	output->tasks[i] = chunk->read_task;
	chunk->read_task = NULL;
	output->enqueued++;

	if (Last.writing < chunk->address)
		Last.writing = chunk->address;

	/* Return $chunk to the list of unused chunks. */
	return_chunk(chunk);
}

void add_to_output_iov(struct output_st *output,
	struct scsi_task *task, unsigned niov)
{
	assert(niov < output->max);
	output->iov[niov].iov_base = task->datain.data;
	output->iov[niov].iov_len  = task->datain.size;
}

int process_output_queue(int fd,
	struct endpoint_st const *dst, struct output_st *output,
	int more_to_come)
{
	int need_to_seek;
	unsigned niov, ntasks;
	scsi_block_addr_t block;
	struct scsi_task **tasks, **from, **t;

	/*
	 * $niov	:= the number of buffers in the current batch
	 * $block	:= the next block we expect in the batch
	 * $tasks	:= where to take from the next buffer of the batch
	 * $ntasks	:= how many buffers till the end of $output->tasks
	 * $from	:= the first buffer in the batch
	 * $need_to_seek := whether the current position of $fd is $first
	 */
	niov = 0;
	need_to_seek = 0;
	if (!(ntasks = output->enqueued))
		return 0;
	tasks = from = output->tasks;
	block = LBA_OF(from[0]);
	if (!dst->seekable && !(!Last.written && !block)
			&& block != Last.written + 1)
		/* We have a non-seekable destination and the first
		 * $block is not the next one, so we can't write. */
		return 0;
	memset(&output->iov[0], 0, sizeof(*output->iov) * output->max);

	/* Send all of $output->enqueued batches. */
	assert(output->max > 0);
	for (;;)
	{
		/* Add a new (possibly the first) buffer to the batch. */
		assert(ntasks > 0);
		if (fd >= 0)
			add_to_output_iov(output, tasks[0], niov);
		niov++;

		/* Move $block forward by the number of blocks
		 * carried by $tasks[0]. */
		assert(tasks[0]->datain.size % dst->blocksize == 0);
		block += tasks[0]->datain.size / dst->blocksize;

		tasks++;
		ntasks--;

		/* Do we have enough buffers in the batch or continue? */
		if (niov >= output->max)
		{	/* $output->iov has reached its maximal capacity,
			 * we need to flush it.  Fall through. */
		} else if (!ntasks)
		{	/* We've run out of output.  Flush or break? */
			if (niov < Opt_min_output_batch && more_to_come)
				/* Too little output to flush and there's
				 * $more_to_come. */
				break;
			/* Fall through. */
		} else if (LBA_OF(tasks[0]) < block)
		{	/* Repeated/overlapping chunk, should not happen. */
			assert(0);
		} else if (LBA_OF(tasks[0]) == block)
		{	/* Found the next buffer in $output->tasks. */
			continue;
		} else if (niov >= Opt_min_output_batch)
		{	/* The current batch has finished and there's
			 * enough output to flush.  Fall through. */
		} else if (dst->seekable)
		{	/* The current batch is too small to output,
			 * but we can jump to the next one, because
			 * the output is $seekable. */
			/* The next batch starts from &tasks[0]. */
			from = tasks;
			niov = 0;
			block = LBA_OF(from[0]);

			/* Since there's a gap between the previous and this
			 * new batch we need to seek to $first when flushing
			 * the new batch. */
			need_to_seek = 1;

			/* Go gather buffers. */
			continue;
		} else	/* The batch we could possibly output is too small,
			 * and we can't output the next one, because the
			 * output is not seekable.  Wait for more output. */
			break;

		/* Flush $output->iov. */
		assert(niov > 0);
		if (fd < 0)
			/* We would have flushed something. */
			return 1;

		/* Write the buffers to $fd. */
		assert(tasks > from);
		if (!xpwritev(fd, output->iov, niov,
				(off_t)dst->blocksize * LBA_OF(from[0]),
				need_to_seek))
			die("%s: %m", dst->fname ? dst->fname : "(stdout)");

		/* Delete output buffers [$from..$tasks[. */
		for (t = from; t < tasks; t++)
			scsi_free_scsi_task(*t);
		if (Last.written < block - 1)
			Last.written = block - 1;
		memmove(from, tasks, sizeof(*tasks) * ntasks);
		output->enqueued -= tasks - from;
		memset(&output->tasks[output->enqueued], 0,
			sizeof(*output->tasks));

		/* Are we done with all $tasks? */
		if (!ntasks)
			break;

		/* Now $from points at the first unvisited task.
		 * Continue from that point. */
		tasks = from;
		block = LBA_OF(from[0]);
		if (!dst->seekable && block != Last.written + 1)
			/* The next $block is not the subsequent one. */
			break;

		/* Keep $need_to_seek, because pwrite*() doesn't change
		 * the file offset. */
		niov = 0;
	} /* until all batches are output or skipped */

	return 0;
}
#endif /* SEXYCAT */

#ifdef SEXYCAT
void chunk_written(struct iscsi_context *iscsi, int status,
	void *command_data, void *private_data)
{
	struct scsi_task *task = command_data;
	struct chunk_st *chunk = private_data;
	struct input_st *input = chunk->input;

	assert(task != NULL);
	assert(chunk != NULL);

	if (!LOCAL_TO_REMOTE(input))
	{
		assert(REMOTE_TO_REMOTE(input));
		assert(chunk->read_task);
	}

	assert(input->output->nreqs > 0);
	input->output->nreqs--;

	if (is_iscsi_error(iscsi, task, "write10", status))
	{
		scsi_free_scsi_task(task);
		chunk_failed(chunk);
		return;
	} else
		scsi_free_scsi_task(task);

	assert(chunk->address <= Last.writing);
	assert(Last.written <= Last.writing);
	if (Last.written < chunk->address)
		Last.written = chunk->address;

	chunk->address = 0;
	assert(!chunk->time_to_retry);
	if (REMOTE_TO_REMOTE(input))
	{
		scsi_free_scsi_task(chunk->read_task);
		chunk->read_task = NULL;
	}
	return_chunk(chunk);
}

void chunk_read(struct iscsi_context *iscsi, int status,
	void *command_data, void *private_data)
{
	struct scsi_task *task = command_data;
	struct chunk_st *chunk = private_data;
	struct endpoint_st *dst = chunk->input->dst;

	assert(chunk != NULL);
	assert(!LOCAL_TO_REMOTE(chunk->input));
	assert(!chunk->read_task);

	assert(task != NULL);

#ifdef LIBISCSI_API_VERSION
	/* libiscsi won't need this pointer anymore, so we can use it
	 * to store the task's scsi_read10_cdb.  This will be freed by
	 * scsi_free_scsi_task() automagically. */
	task->ptr = scsi_cdb_unmarshall(task, SCSI_OPCODE_READ10);
#endif
	assert(LBA_OF(task) == chunk->address);

	assert(chunk->input->nreqs > 0);
	chunk->input->nreqs--;

	if (is_iscsi_error(iscsi, task, "read10", status))
	{
		scsi_free_scsi_task(task);
		chunk_failed(chunk);
		return;
	}

	assert(chunk->address <= Last.reading);
	assert(Last.red <= Last.reading);
	if (Last.red < chunk->address)
		Last.red = chunk->address;

	chunk->read_task = task;
	assert(!chunk->time_to_retry);
	if (REMOTE_TO_LOCAL(chunk->input))
	{
		add_output_chunk(chunk);
		return;
	}

	assert(REMOTE_TO_REMOTE(chunk->input));
	if (chunk->input->src->blocksize != dst->blocksize)
	{	/* Translate source address to destination address. */
		off_t n;

		n = (off_t)chunk->address * chunk->input->src->blocksize;
		assert(n % dst->blocksize == 0);
		chunk->address = n / dst->blocksize;
	}

	if (!(chunk->input->output->nreqs < chunk->input->dst->maxreqs))
	{	/* Maximum outstanding write requests reached,
		 * write $chunk later. */
		chunk_failed(chunk);
		return;
	}

	if (Last.writing < chunk->address)
		Last.writing = chunk->address;

	if (!write_endpoint(dst, chunk->address,
		task->datain.data, task->datain.size,
		chunk_written, chunk))
	{
		warn_iscsi("write10", dst->iscsi);
		die(NULL);
	} else
		chunk->input->output->nreqs++;
}
#endif /* SEXYCAT */

/* Return the optimal number of bytes to read/write [$from..$until[ blocks
 * taking the target's optimal transfer size and granuality into account. */
size_t read_chunk_size(
	struct endpoint_st const *src, struct endpoint_st const *dst,
	scsi_block_addr_t from, scsi_block_addr_t until)
{
	scsi_block_count_t nblocks;
	struct endpoint_st const *endp;

	assert(from < until);
	if (src && !src->iscsi)
		src = NULL;
	if (dst && !dst->iscsi)
		dst = NULL;
	assert(src || dst);

	endp = src ? src : dst;
	assert(endp->optimum > 0);
	assert(endp->granuality > 0);

	if (src && dst)
	{	/* We also have to take $dst into account. */
		size_t n;

		/* We have precisely two choices: either read $src->optimum
		 * blocks or $until end of the source disk. */
		nblocks = until - from;
		if (nblocks > src->optimum)
			nblocks = src->optimum;

		/* $src->optimum was chosen so that it's a multiply
		 * of $dst->blocksize, so $nblocks must be suitable. */
		n = (size_t)src->blocksize * nblocks;
		assert(n % dst->blocksize == 0);
		return n;
	} else
	{	/* We have a single $endp:oint to consider. */
		/* If $from is not at $optimum boundary, progress until
		 * that point. Otherwise read/write the $optimum number
		 * of blocks. */
		nblocks = from % endp->optimum;
		nblocks = nblocks > 0
			? endp->optimum - nblocks
			: endp->optimum;

		/* Make sure we're not reading/writing
		 * beyond the target's capacity. */
		if (from + nblocks > until)
		    nblocks = until - from;

		/* If $nblocks is not optimal, try to make it
		 * a multiple of $granuality. */
		if (nblocks % endp->optimum != 0
				&& nblocks > endp->granuality
				&& nblocks % endp->granuality > 0)
			nblocks -= nblocks % endp->granuality;

		assert(nblocks > 0);
		return (size_t)endp->blocksize * nblocks;
	}
} /* read_chunk_size */

int restart_requests(struct input_st *input,
	callback_t read_cb, callback_t write_cb)
{
	struct chunk_st *prev, *chunk, *next;
	struct output_st *output = input->output;
	struct endpoint_st *src = input->src;
	struct endpoint_st *dst = input->dst;

	/* Do we have anything to do? */
	if (!(chunk = input->failed))
		return 1;

	/* Can we send any requests at all? */
	if (!(input->nreqs < src->maxreqs || output->nreqs < dst->maxreqs))
		return 1;

	prev = NULL;
	do
	{	/* As long as we have failed requests which have reached
		 * $time_to_retry.  Since the list is ordered, the first time
		 * we meet a $chunk still not ready to retry, we can stop. */
		if (chunk->time_to_retry)
			break;

		/* Reissue the failed request if possible. */
		next = chunk->next;
		if (!LOCAL_TO_REMOTE(input) && !chunk->read_task)
		{	/* Re-read */
			if (!(input->nreqs < src->maxreqs))
			{	/* Max number of reqs reached. */
				prev = chunk;
				continue;
			}

			if (Opt_verbosity > 1)
				info("re-reading source block %u",
					chunk->address);
			if (!read_endpoint(src, chunk->address,
				read_chunk_size(src, dst,
					chunk->address, input->until),
				read_cb, chunk))
			{	/* It must be some fatal error, eg. OOM. */
				warn_iscsi("read10", src->iscsi);
				return 0;
			} else
				input->nreqs++;
		} else	/* LOCAL_TO_REMOTE() || $chunk->read_task */
		{	/* Rewrite */
			size_t sbuf;
			unsigned char const *buf;

			assert(!REMOTE_TO_LOCAL(input));
			if (!(output->nreqs < dst->maxreqs))
			{	/* Max number of reqs reached. */
				prev = chunk;
				continue;
			}

			if (Opt_verbosity > 1)
				info("rewriting source block %u",
					chunk->address);

			if (IS_SEXYWRAP(input))
			{	/* $buf points to some user buffer. */
				buf  = chunk->u.wbuf;
				sbuf = chunk->sbuf;
			} else if (LOCAL_TO_REMOTE(input))
			{	/* In this mode the buffer comes right after
				 * the struct chunk_st. */
				buf  = chunk->u.rbuf;
				sbuf = chunk->sbuf;
			} else
			{	/* REMOTE_TO_REMOTE() */
				buf  = chunk->read_task->datain.data;
				sbuf = chunk->read_task->datain.size;
			}

			if (!write_endpoint(dst,
				chunk->address, buf, sbuf,
				write_cb, chunk))
			{	/* Uncorrectable error. */
				warn_iscsi("write10", dst->iscsi);
				return 0;
			} else
				output->nreqs++;
		} /* what to do with $chunk */

		/* Unlink $chunk from the $failed chain and update $prev,
		 * $input->failed and $input->last_failed. */
		chunk->next = NULL;
		if (!prev)
		{	/* $chunk is the first in the list. */
			assert(chunk == input->failed);
			input->failed = next;
		} else
		{
			assert(chunk != input->failed);
			prev->next = next;
		}
		if (chunk == input->last_failed)
			input->last_failed = prev;
	} while ((chunk = next) != NULL);

	return 1;
}

int start_iscsi_read_requests(struct input_st *input, callback_t read_cb)
{
	struct endpoint_st *src = input->src;

	/* Issue new read requests as long as we can. */
	assert(!LOCAL_TO_REMOTE(input));
	while (input->unused
		&& input->nreqs < src->maxreqs
		&& input->top_block < input->until)
	{
		struct chunk_st *chunk;
		size_t this_chunk_size;

		chunk = input->unused;
		assert(!chunk->read_task);
		assert(!chunk->time_to_retry);

		this_chunk_size = read_chunk_size(src, input->dst,
			input->top_block, input->until);
		if (!read_endpoint(src, input->top_block,
			this_chunk_size, read_cb, chunk))
		{
			warn_iscsi("read10", src->iscsi);
			return 0;
		}

		chunk->address = input->top_block;
		input->top_block += this_chunk_size / src->blocksize;

		assert(!Last.reading || Last.reading < chunk->address);
		Last.reading = chunk->address;

		/* Detach $chunk from $input->unused. */
		input->nreqs++;
		take_chunk(chunk);
	} /* read until no more $input->unused chunks left */

	return 1;
}

/* Preserves $errno. */
void free_chunks(struct chunk_st *chunk)
{
	int serrno;

	serrno = errno;
	while (chunk)
	{
		struct chunk_st *next;

		next = chunk->next;
		if (REMOTE_TO_REMOTE(chunk->input) && chunk->read_task)
			scsi_free_scsi_task(chunk->read_task);
		free(chunk);
		chunk = next;
	}
	errno = serrno;
}

void free_surplus_unused_chunks(struct input_st *input)
{
	unsigned maxreqs;
	struct chunk_st *chunk;

	/* Free $input->unused until $input->nunused drops to $maxreqs. */
	maxreqs = 0;
	if (input->src)
		maxreqs += input->src->maxreqs;
	if (input->dst)
		maxreqs += input->dst->maxreqs;
	assert(maxreqs >= 1);
	while (input->nunused > maxreqs)
	{
		chunk = input->unused;
		assert(chunk != NULL);
		assert(LOCAL_TO_REMOTE(chunk->input) || !chunk->read_task);
		input->unused = chunk->next;
		free(chunk);
		input->nunused--;
	}
}

void reduce_maxreqs(struct endpoint_st *endp)
{
	unsigned maxreqs;

	/* Decrease the maximum number of outstanding requests? */
	if (!Opt_maxreqs_degradation || Opt_maxreqs_degradation == 100)
		return;
	assert(Opt_maxreqs_degradation < 100);

	/* Calculate the new $maxreqs of $endp. */
	maxreqs = endp->maxreqs;
	if (maxreqs <= 1)
		return;
	maxreqs *= Opt_maxreqs_degradation;
	maxreqs /= 100;
	if (!maxreqs)
		maxreqs++;
	else if (maxreqs == endp->maxreqs)
		maxreqs--;
	endp->maxreqs = maxreqs;

	if (endp->which)
		info("%s target: number of maximal "
			"outstanding requests reduced to %u",
			endp->which, endp->maxreqs);
}

void return_chunk(struct chunk_st *chunk)
{
	struct input_st *input = chunk->input;

	chunk->next = input->unused;
	input->unused = chunk;
	input->nunused++;
}

void take_chunk(struct chunk_st *chunk)
{
	struct input_st *input = chunk->input;

	assert(chunk == input->unused);
	assert(input->nunused > 0);
	input->nunused--;
	input->unused = chunk->next;
	chunk->next = NULL;
}

/* Append $chunk to $input->failed. */
void chunk_failed(struct chunk_st *chunk)
{
	struct input_st *input = chunk->input;

	assert(!chunk->next);

	if (!input->failed)
	{
		assert(!input->last_failed);
		input->failed = chunk;
	} else
	{
		assert(input->last_failed);
		assert(!input->last_failed->next);
		input->last_failed->next = chunk;
	}

	input->last_failed = chunk;
	chunk->time_to_retry = Opt_request_retry_time;
}

/* Free resources allocated by init_input().  $errno is preserved. */
void done_input(struct input_st *input)
{
	free_chunks(input->unused);
	free_chunks(input->failed);
	input->unused = input->failed = NULL;
}

/* Initialize $input with $src, $dst and $output, and allocate the right
 * number of $input->input chunks.  Either of $src or $dst can be NULL.
 * On error 0 is returned and $errno is set.  Otherwise 1 is returned. */
int init_input(struct input_st *input, struct output_st *output,
	struct endpoint_st *src, struct endpoint_st *dst)
{
	unsigned nchunks;
	size_t max_chunk_size;
	struct chunk_st *chunk;

	memset(input, 0, sizeof(*input));
	input->src = src;
	input->dst = dst;
	input->output = output;

	/* If we're copying a local file to a remote target the input buffer
	 * is allocated together with the $chunk, the maximum size of which
	 * is the optimal transfer size of the destination device. */
	max_chunk_size = sizeof(*chunk);
	if (!IS_SEXYWRAP(input) && LOCAL_TO_REMOTE(input))
	{	/* Discount sizeof(wbuf). */
		max_chunk_size -= sizeof(chunk->u);
		max_chunk_size += (size_t)dst->blocksize * dst->optimum;
	}

	/* Create $input->input chunks. */
	nchunks = 0;
	if (src && src->iscsi)
		nchunks += src->maxreqs;
	if (dst && dst->iscsi)
		nchunks += dst->maxreqs;
	for (; nchunks > 0; nchunks--)
	{
		if (!(chunk = malloc(max_chunk_size)))
		{
			free_chunks(input->unused);
			return 0;
		} else
			memset(chunk, 0, max_chunk_size);

		chunk->input = input;
		return_chunk(chunk);
	} /* until $nchunks unused chunks are created */

	/* These are zero when the program starts... */
	if (IS_SEXYWRAP(input))
	{	/* ...but need to be cleared again when sexywrap
		 * uses us the next time. */
		memset(&Prev, 0, sizeof(Prev));
		memset(&Last, 0, sizeof(Last));
		memset(&Last_report, 0, sizeof(Last_report));
		memset(&Now, 0, sizeof(Now));
	}

	return 1;
} /* init_input */

void endpoint_connected(struct iscsi_context *iscsi, int status,
	void *command_data, void *private_data)
{
	int *connected = private_data;
	*connected = status == SCSI_STATUS_GOOD;
}

int connect_endpoint(struct iscsi_context *iscsi, struct iscsi_url *url)
{
	int connected;

	iscsi_set_targetname(iscsi, url->target);
	iscsi_set_session_type(iscsi, ISCSI_SESSION_NORMAL);

	connected = -1;
	if (iscsi_full_connect_async(iscsi, url->portal, url->lun,
		endpoint_connected, &connected) != 0)
	{
		warn_iscsi("connect", iscsi);
		return 0;
	}

	do
	{
		struct pollfd pfd;

		pfd.fd = iscsi_get_fd(iscsi);
		pfd.events = iscsi_which_events(iscsi);
		if (!xpoll(&pfd, MEMBS_OF(&pfd)))
		{
			warn_errno("poll");
			return 0;
		} else if (!run_iscsi_event_loop(iscsi, pfd.revents))
		{	/* run_iscsi_event_loop() has logged the error. */
			return 0;
		} else if (!connected)
		{
			warn("connect: %s: %s: %s",
				url->portal, url->target,
				iscsi_get_error(iscsi));
			return 0;
		}
	} while (connected < 0);

	return 1;
}

int reconnect_endpoint(struct endpoint_st *endp)
{
	if (endp->which)
		warn("reconnecting to %s target...", endp->which);

	iscsi_destroy_context(endp->iscsi);
	if (!(endp->iscsi = iscsi_create_context(endp->initiator)))
	{
		warn_errno("iscsi_create_context()");
		return 0;
	} else
		return connect_endpoint(endp->iscsi, endp->url);
}

int run_endpoint(struct endpoint_st *endp, unsigned events)
{
	if (is_connection_error(endp->iscsi, endp->which, events))
		return reconnect_endpoint(endp);
	else	/* This may reconnect too. */
		return run_iscsi_event_loop(endp->iscsi, events);
}

/* Convenience wrapper around iscsi_read10_task(). */
struct scsi_task *read_endpoint(struct endpoint_st const *endp,
	scsi_block_addr_t block, size_t chunk_size,
	callback_t read_cb, struct chunk_st *chunk)
{
	assert(read_cb != NULL);
	assert(chunk_size >= endp->blocksize);
	assert(chunk_size % endp->blocksize == 0);

#ifdef LIBISCSI_API_VERSION
	return iscsi_read10_task(
		endp->iscsi, endp->url->lun,
		block, chunk_size, endp->blocksize,
		0, 0, 0, 0, 0,
		read_cb, chunk);
#else	/* old libiscsi */
	return iscsi_read10_task(
		endp->iscsi, endp->url->lun,
		block, chunk_size, endp->blocksize,
		read_cb, chunk);
#endif
} /* read_endpoint */

/* Convenience wrapper around iscsi_write10_task(). */
struct scsi_task *write_endpoint(struct endpoint_st const *endp,
	scsi_block_addr_t block, void const *buf, size_t sbuf,
	callback_t write_cb, struct chunk_st *chunk)
{
	assert(write_cb != NULL);
	assert(sbuf >= endp->blocksize);
	assert(sbuf % endp->blocksize == 0);

#ifdef LIBISCSI_API_VERSION
	return iscsi_write10_task(
		endp->iscsi, endp->url->lun,
	       	block, (void *)buf, sbuf,
		endp->blocksize,
		0, 0, 0, 0, 0,
		write_cb, chunk);
#else	/* old libiscsi */
	return iscsi_write10_task(
		endp->iscsi, endp->url->lun,
		(void *)buf, sbuf, block,
		0, 0,
		endp->blocksize,
		write_cb, chunk);
#endif
} /* write_endpoint */

#ifdef SEXYCAT
void destroy_endpoint(struct endpoint_st *endp)
{
	if (endp->iscsi)
	{
		iscsi_destroy_context(endp->iscsi);
		endp->iscsi = NULL;
	} else	/* This is actually $endp->fname. */
		endp->url = NULL;

	if (endp->url)
	{
		iscsi_destroy_url(endp->url);
		endp->url = NULL;
	}
}

/* Print the target's capacity and characteristics. */
void print_endpoint(struct endpoint_st const *endp)
{
	printf("%s target: nblocks=%u, blocksize=%u, "
		"granuality=%u, optimum=%u, maximum=%u\n",
		endp->which, endp->nblocks, endp->blocksize,
		endp->granuality, endp->optimum, endp->maximum);
} /* print_endpoint */
#endif /* SEXYCAT */

/* Calculate the optimal transfer size based on the target's preferences.
 * $endp is assumed to be initialized with stat_endpoint(). */
void calibrate_endpoint(struct endpoint_st *endp,
	scsi_block_count_t desired_optimum)
{
	/* The fallback optimal transfer size in bytes. */
	const size_t dflt_optimum = 1024*1024;

	if (desired_optimum)
		/* User gave a $desired_optimum, override the device's. */
		endp->optimum = desired_optimum;

	/*
	 * Adjust $endp->optimum and $granuality, honoring $maximum
	 * if provided.
	 *
	 * optimum	maximum		granuality {{{
	 * 0		0		0		[0]
	 * 0		0		1		[1]
	 * 0		1		0		[2]
	 * 0		1		1		[2]
	 * 1		1		0		[3]
	 * 1		1		1		[3]
	 * 1		0		0		[4]
	 * 1		0		1		[5]
	 *
	 * (0) zero
	 * (1) non-zero (provided by the device) }}}
	 */
	if (!endp->optimum && !endp->maximum && !endp->granuality)
	{	/* [0] No usable information returned, calibrate
		 * $endp->optimum to be close to $dflt_optimum
		 * while honoring $endp->blocksize. */
		endp->optimum = dflt_optimum >= endp->blocksize*2
			? dflt_optimum / endp->blocksize
			: 1;
		/* All $optimum, $maximum and $granuality are set. */
	} else if (!endp->optimum && !endp->maximum)
	{	/* [1] We only have $endp->granuality. */
		size_t granuality;

		/* Calibrate $optimum to be ~$dflt_optimum,
		 * but respect $endp->granuality. */
		granuality = (size_t)endp->blocksize * endp->granuality;
		if (granuality >= dflt_optimum)
			/* $optimum <- >= $dflt_optimum */
			endp->optimum = endp->granuality;
		else if (dflt_optimum >= granuality*2)
		{	/* $optimum <- <integer>*$endp->granuality */
			endp->optimum  = dflt_optimum / granuality;
			endp->optimum *= endp->granuality;
		} else	/* $dflt_optimum < 2*$granuality */
			endp->optimum = endp->granuality;
		/* $optimum is set, $granuality was provided. */
	} else if (!endp->optimum)
	{	/* [2] We must have $endp->maximum. */
		if (!endp->granuality)
		{	/* Neither $optimum nor $granuality is specified. */
			endp->granuality = 1;
			endp->optimum = endp->maximum;
		} else if (endp->granuality >= endp->maximum)
		{	/* $endp->granuality is too large. */
			endp->optimum = endp->maximum;
			endp->granuality = endp->maximum;
		} else if (endp->granuality*2 < endp->maximum)
		{	/* $optimum = <integer> * $granuality */
			endp->optimum  = endp->maximum;
			endp->optimum /= endp->granuality;
		} else	/*   $granuality <= $maximum, but
			 * 2*$granuality >  $maximum */
			endp->optimum = endp->granuality;
		/* $optimum is set, $granuality is verified/set. */
	} else if (endp->maximum)
	{	/* [3] We have $endp->optimum, verify it. */
		if (endp->optimum > endp->maximum)
			endp->optimum = endp->maximum;

		/* Verify/set $endp->granuality. */
		if (!endp->granuality)
			endp->granuality = endp->optimum;
		else if (endp->granuality > endp->maximum)
			endp->granuality = endp->optimum;

		/* Both $optimum and $granuality are verified/set. */
	} else if (!endp->granuality)
	{	/* [4] We do _not_ have $endp->maximum. */
		endp->granuality = endp->optimum;
		/* $optimum was provided, $granuality is set. */
	} else	/* [5] */
		/* Both $optimum and $granuality were provided. */;

	/* $maximum might not be set, but if it is, it's enforced.
	 * $granuality could be > than $optimum, even though that
	 * doesn't make much sense. */
	assert(endp->optimum > 0);
	assert(endp->granuality > 0);
	if (endp->maximum)
	{
		assert(endp->optimum <= endp->maximum);
		assert(endp->granuality <= endp->maximum);
	}
} /* calibrate_endpoint */

/* Get the target endpoint's capacity and characteristics. */
int stat_endpoint(struct endpoint_st *endp, unsigned fallback_blocksize)
{
	struct scsi_task *task;
	struct scsi_readcapacity10 *cap;
	struct scsi_inquiry_block_limits *__attribute__((unused)) inq;

	/* Retrieve the $endp:oint's capacity. */
	if (!(task = iscsi_readcapacity10_sync(endp->iscsi, endp->url->lun,
		0, 0)))
	{
		warn_iscsi("readcapacity10", endp->iscsi);
		return 0;
	} else if (task->status != SCSI_STATUS_GOOD
		|| !(cap = scsi_datain_unmarshall(task)))
	{
		scsi_free_scsi_task(task);
		warn_errno("readcapacity10");
		return 0;
	}

	/* Get $blocksize and $nblocks. */
	if (!cap->block_size)
	{
		endp->blocksize = fallback_blocksize;
		if (!endp->blocksize)
			endp->blocksize = 512;
		if (Opt_verbosity > 0)
			warn("%s target reported zero blocksize, "
				"using %u instead",
				endp->which ? endp->which : "iSCSI",
				endp->blocksize);
	} else
		endp->blocksize = cap->block_size;
	endp->nblocks = cap->lba + 1;
	scsi_free_scsi_task(task);

	/* Get $endp->optimum, $maximum and $granuality. */
	if ((task = iscsi_inquiry_sync(endp->iscsi, endp->url->lun,
			1, SCSI_INQUIRY_PAGECODE_BLOCK_LIMITS, sizeof(*inq)))
		&& (inq = scsi_datain_unmarshall(task)))
	{	/* These are the raw values, which will be the input
		 * of calibrate_endpoint(). */
		endp->optimum = inq->opt_xfer_len;
		endp->maximum = inq->max_xfer_len;
		endp->granuality = inq->opt_gran;
	} else
	{	/*
		 * We can't know whether we've suffered a local (OOM)
		 * or a remote error (command not understood), but the
		 * former is less likely, so take it as if all zeroes
		 * were returned.
		 */
		warn_iscsi("inquiry", endp->iscsi);
		assert(!endp->optimum);
		assert(!endp->maximum);
		assert(!endp->granuality);
	}

	if (task)
		scsi_free_scsi_task(task);

	return 1;
}

#ifdef SEXYCAT
int init_endpoint(struct endpoint_st *endp, char const *url,
	unsigned fallback_blocksize)
{
	/* Create $endp->iscsi and connect to $endp->url. */
	if (!(endp->iscsi = iscsi_create_context(endp->initiator)))
	{
		warn_errno("iscsi_create_context()");
		return 0;
	} else if (!(endp->url = iscsi_parse_full_url(endp->iscsi, url)))
	{
		warn_iscsi(NULL, endp->iscsi);
		destroy_endpoint(endp);
		return 0;
	} else if (!connect_endpoint(endp->iscsi, endp->url)
		|| !stat_endpoint(endp, fallback_blocksize))
	{
		destroy_endpoint(endp);
		return 0;
	}

	return 1;
}
#endif /* SEXYCAT */

#ifdef SEXYCAT /* {{{ */
/* Upload a local file to a remote iSCSI target. {{{ */
int local_to_remote(struct input_st *input)
{
	int eof;
	ino_t iscsi_dst_ino;
	struct pollfd pfd[2];
	struct endpoint_st *src = input->src;
	struct endpoint_st *dst = input->dst;

	/* Open the input file. */
	if (!src->fname || !strcmp(src->fname, "-"))
	{	/* Input is stdin. */
		src->fname = NULL;
		pfd[0].fd = STDIN_FILENO;
	} else if ((pfd[0].fd = open(src->fname, O_RDONLY)) < 0)
	{
		warn_errno(src->fname);
		return 0;
	}

	/* Loop until all of $src is written out. */
	eof = 0;
	iscsi_dst_ino = 0;
	pfd[1].fd = iscsi_get_fd(dst->iscsi);
	get_inode(pfd[1].fd, &iscsi_dst_ino);
	for (;;)
	{
		int ret;

		/* Recreate failed iSCSI write requests,
		 * but don't send them to $dst just yet. */
		if (!restart_requests(input, NULL, chunk_written))
			return 0;

		/* Done if !pending && (eof || disk full) */
		if (!input->output->nreqs && !input->failed)
		{
			if (eof)
				break;
			if (!(input->top_block < input->until))
				break;
		}

		/* POLLIN <=> !eof && can request && !disk full */
		pfd[0].events = !eof
			&& input->unused
			&& (input->top_block < input->until)
			? POLLIN : 0;
		pfd[1].events = iscsi_which_events(dst->iscsi);
		if ((ret = xfpoll(pfd, MEMBS_OF(pfd), input)) < 0)
		{
			warn_errno("poll");
			return 0;
		} else if (!ret)
			continue;

		/* Read $src if we can and create an iSCSI write request. */
		if (pfd[0].revents & POLLIN)
		{	/* We must have been waiting for POLLIN. */
			size_t max_chunk_size;
			struct chunk_st *chunk;

			/* $chunk <- read($src, $max_chunk_size) */
			assert(pfd[0].events & POLLIN);
			assert(input->unused != NULL);
			chunk = input->unused;
			max_chunk_size = read_chunk_size(NULL, dst,
				input->top_block, input->until);
			assert(max_chunk_size
				<= (size_t)dst->blocksize * dst->optimum);
			if (!xread(pfd[0].fd, chunk->u.rbuf,
				max_chunk_size, &chunk->sbuf))
			{
				warn_errno(src->fname
					? src->fname : "(stdin)");
				return 0;
			} else if (chunk->sbuf % dst->blocksize > 0)
			{	/* We can't write a partial block.
				 * Take it as $eof. */
				warn("last %zu bytes of input dropped",
					chunk->sbuf % dst->blocksize);
				assert(chunk->sbuf < max_chunk_size);
				chunk->sbuf -= chunk->sbuf % dst->blocksize;
				eof = 1;
			} else	/* It may or may not be $eof. */
				assert(chunk->sbuf <= max_chunk_size);

			/* Is it $eof on $src? */
			if (chunk->sbuf > 0)
			{	/* Remove $chunk from $input->unused. */
				take_chunk(chunk);
				chunk->address = input->top_block;
				input->top_block +=
					chunk->sbuf / dst->blocksize;

				/* We needn't check whether $dst->maxreqs is
				 * exceeded, because this case we would have
				 * been out of $input->unused chunks. */
				assert(input->output->nreqs
					< input->dst->maxreqs);

				assert(!Last.writing
					|| Last.writing < chunk->address);
				Last.writing = chunk->address;

				/* Create the iSCSI write request. */
				if (!write_endpoint(dst, chunk->address,
					chunk->u.rbuf, chunk->sbuf,
					chunk_written, chunk))
				{
					warn_iscsi("write10", dst->iscsi);
					die(NULL);
				} else
					input->output->nreqs++;
			} else /* We didn't read anything. */
				eof = 1;
		} /* read from $src */

		/* Is EOF on $src reached? */
		if (pfd[0].revents & (POLLHUP|POLLRDHUP))
			eof = 1;

		/* Try to (re)send the iSCSI write requests. */
		if (!run_endpoint(dst, pfd[1].revents))
		    return 0;

		/* It's possible that run_iscsi_event_loop() did a reconnect
		 * behind our back.  In this case the inode of the descriptor
		 * of the target must have changed.  Check this condition. */
		if (get_inode(pfd[1].fd, &iscsi_dst_ino))
		{
			warn("reconnected to destination target");
			reduce_maxreqs(dst);
		}

		free_surplus_unused_chunks(input);
	} /* until $eof is reached and everything is written out */

	if (Opt_verbosity > 0)
		info("written %u blocks", input->until);

	/* Close the input file if we opened it.  (It feels wrong to close
	 * stdin, because the standard file descriptors are supposed to be
	 * open all the times.) */
	if (src->fname)
		close(pfd[0].fd);

	return 1;
} /* local_to_remote }}} */

/* Download from a remote iSCSI target to a local file. {{{ */
int open_output(struct endpoint_st *dst, struct endpoint_st const *src,
	int overwrite, int check_free_space)
{
	struct stat sb;
	int fd, deletable;

	/* Open the output file.  Fail if the file already exists and we
	 * weren't invoked with -O and the file is a regular one (not a
	 * pipe or a device node). */
	deletable = 0;
	memset(&sb, 0, sizeof(sb));
	if (!dst->fname || !strcmp(dst->fname, "-"))
	{	/* Output is stdout. */
		dst->fname = NULL;
		fd = STDOUT_FILENO;
	} else if ((fd = open(dst->fname, O_WRONLY, 0666)) >= 0)
	{	/* File exists.  Is that OK? */
		if (!overwrite)
		{	/* We weren't invoked with -O. */
			if (fstat(fd, &sb) < 0)
				goto out;
			if (S_ISREG(sb.st_mode))
			{	/* File exists and we can't $overwrite it. */
				errno = EEXIST;
				goto out;
			}
		}
	} else if ((fd = open(dst->fname,O_CREAT|O_WRONLY|O_EXCL,0666)) >= 0)
		/* We created the file, so it should be deleted on error. */
		deletable = 1;
	else
		goto out;

	/* Get the file type. */
	if (!sb.st_mode && fstat(fd, &sb) < 0)
		goto out;

	/* It's only meaningful to check the free space if the output
	 * is a regular file, otherwise it doesn't occupy space on the
	 * file system. */
	if (check_free_space && S_ISREG(sb.st_mode))
	{
		fsblkcnt_t space;
		struct statvfs fssb;
		off_t required, available;

		/* The manual prefers fstatvfs() over fstatfs(). */
		if (fstatvfs(fd, &fssb) < 0)
		{
			if (dst->fname)
				warn("statfs(%s): %m", dst->fname);
			else
				warn("statfs(stdout): %m");
			goto out0;
		} /* fstatvfst() failed */

		/* Privileged users might have more free $space available,
		 * but unfortunately we have no means to determine which
		 * are those privileged users. */
		space = geteuid() > 0 ? fssb.f_bavail : fssb.f_bfree;
		required = (off_t)src->blocksize * src->nblocks;
		available = (off_t)fssb.f_bsize * space;
		if (required > available)
		{
			warn("Not enough free space is available "
			     "(required: %luB, available: %luB)",
			     required, available);
			goto out0;
		}
	} /* $check_free_space */

	/* Truncate the file to 0 bytes (if we created it then it's empty). */
	if (!deletable && S_ISREG(sb.st_mode) && ftruncate(fd, 0) < 0)
		goto out;

	/* Determine whether $dst->seekable (then it can't be a named pipe).
	 * If it is we'll possibly use pwrite(). */
	dst->seekable = !S_ISFIFO(sb.st_mode) && lseek(fd, 0, SEEK_CUR) == 0;

	/* All's OK. */
	return fd;

out:	/* Print $errno. */
	if (dst->fname)
		warn_errno(dst->fname);
	else
		warn_errno("(stdout)");

out0:	/* close()/unlink() the file and return with failure. */
	if (dst->fname)
	{
		close(fd);
		if (deletable)
			unlink(dst->fname);
	}
	return -1;
} /* open_output */

int remote_to_local(struct input_st *input,
	int overwrite, int check_free_space)
{
	ino_t iscsi_src_ino;
	struct pollfd pfd[2];
	struct endpoint_st *src = input->src;
	struct endpoint_st *dst = input->dst;

	/* Initialize output. */
	if ((pfd[1].fd = open_output(dst, src,
			overwrite, check_free_space)) < 0)
		return 0;

	/* Loop until $input->until is reached. */
	iscsi_src_ino = 0;
	pfd[0].fd = iscsi_get_fd(src->iscsi);
	get_inode(pfd[0].fd, &iscsi_src_ino);
	for (;;)
	{
		int eof, ret;

		/* (Re)create the iSCSI read requests,
		 * but don't send them to $src just yet. */
		if (!restart_requests(input, chunk_read, NULL))
			return 0;
		if (!start_iscsi_read_requests(input, chunk_read))
			return 0;

		/* Anything more to do? */
		eof = !input->nreqs && !input->failed;
		if (eof && !input->output->enqueued)
			break;

		/* Wait until I/O is possible without blocking. */
		pfd[0].events = iscsi_which_events(src->iscsi);
		pfd[1].events = process_output_queue(-1, dst, input->output,
					!eof)
			? POLLOUT : 0;
		if ((ret = xfpoll(pfd, MEMBS_OF(pfd), input)) < 0)
		{
			warn_errno("poll");
			return 0;
		} else if (!ret)
			continue;

		/* Try to (re-)send the iSCSI read requests. */
		if (!run_endpoint(src, pfd[0].revents))
			return 0;

		/* Did we reconnect? */
		if (get_inode(pfd[0].fd, &iscsi_src_ino))
		{
			warn("reconnected to source target");
			reduce_maxreqs(src);
			free_surplus_unused_chunks(input);
		}

		/* Dump $input->output to the local file. */
		if (pfd[1].revents)
		{
			process_output_queue(pfd[1].fd, dst, input->output,
				!eof);
			free_surplus_unused_chunks(input);
		}
	} /* until $eof is reached and everything is written out */

	assert(input->top_block == input->until);
	if (Opt_verbosity > 0)
		info("read %u blocks", input->until);

	/* Close the output file and make sure it's succesful (no pending
	 * write errors). */
	if (close(pfd[1].fd) < 0)
		die("%s: %m", dst->fname ? dst->fname : "(stdout)");

	return 1;
} /* remote_to_local }}} */

/* Copy between remote iSCSI targets. {{{ */
int remote_to_remote(struct input_st *input)
{
	struct pollfd pfd[2];
	ino_t iscsi_src_ino, iscsi_dst_ino;
	struct endpoint_st *src = input->src;
	struct endpoint_st *dst = input->dst;

	/* Loop until $src->until is reached and everything is written out
	 * to $dst. */
	pfd[0].fd = iscsi_get_fd(src->iscsi);
	pfd[1].fd = iscsi_get_fd(dst->iscsi);
	iscsi_src_ino = iscsi_dst_ino = 0;
	get_inode(pfd[0].fd, &iscsi_src_ino);
	get_inode(pfd[1].fd, &iscsi_dst_ino);
	for (;;)
	{
		int ret;

		/* (Re)create iSCSI requests. */
		if (!restart_requests(input, chunk_read, chunk_written))
			return 0;
		if (!start_iscsi_read_requests(input, chunk_read))
			return 0;
		if (!input->nreqs && !input->output->nreqs && !input->failed)
			break;

		/* Wait until I/O is possible without blocking. */
		pfd[0].events = iscsi_which_events(src->iscsi);
		pfd[1].events = iscsi_which_events(dst->iscsi);
		if ((ret = xfpoll(pfd, MEMBS_OF(pfd), input)) < 0)
		{
			warn_errno("poll");
			return 0;
		} else if (!ret)
			continue;

		/* Read */
		if (!run_endpoint(src, pfd[0].revents))
			return 0;
		if (get_inode(pfd[0].fd, &iscsi_src_ino))
		{
			warn("reconnected to source target");
			reduce_maxreqs(src);
			free_surplus_unused_chunks(input);
		}

		/* Write */
		if (!run_endpoint(dst, pfd[1].revents))
			return 0;
		if (get_inode(pfd[1].fd, &iscsi_dst_ino))
		{
			warn("reconnected to destination target");
			reduce_maxreqs(dst);
		}

		free_surplus_unused_chunks(input);
	} /* until $src->until is reached and everything is written out */

	assert(input->top_block == input->until);
	if (Opt_verbosity > 0)
		info("transferred %u blocks", input->until);

	return 1;
} /* remote_to_remote }}} */

/* The main function {{{ */
int main(int argc, char *argv[])
{
	struct
	{
		int is_local;
		union
		{
			char const *url;
			char const *fname;
		};

		size_t fallback_blocksize;
		scsi_block_count_t desired_optimum;

		struct endpoint_st endp;
	} src, dst;
	struct input_st input;
	struct output_st output;
	char const *optstring;
	int isok, optchar, nop, overwrite, check_free_space;

	/* Initialize diagnostic output. */
	Info = stdout;
	setvbuf(stderr, NULL, _IOLBF, 0);
	if ((Basename = strrchr(argv[0], '/')) != NULL)
		Basename++;
	else
		Basename = argv[0];

	/* Prepare our working area.  All data structures are rooted 
	 * from $input: $input.output, $input.src, $input.dst. */
	memset(&src, 0, sizeof(src));
	memset(&dst, 0, sizeof(dst));
	memset(&output, 0, sizeof(output));
	src.endp.which = "source";
	dst.endp.which = "destination";

	/* Parse the command line */
	nop = 0;
	Opt_verbosity = 1;
	overwrite = check_free_space = 0;

	/* These defaults are used in --debug mode. */
	src.url = "iscsi://127.0.0.1/iqn.2014-07.net.nsn-net.timmy:try/0";
	dst.url = "iscsi://127.0.0.1/iqn.2014-07.net.nsn-net.timmy:try/1";
	if (argv[1] && !strcmp(argv[1], "--debug"))
	{
		argc--;
		argv++;
	} else
		src.url = dst.url = NULL;

#ifdef SEXYWRAP
# define SEXYWRAP_CMDLINE			"x:"
#else
# define SEXYWRAP_CMDLINE			/* none */
#endif
	optstring = "hvqp:i:s:S:f:c:m:I:d:D:F:C:M:OVb:B:r:R:N"
		SEXYWRAP_CMDLINE;

	while ((optchar = getopt(argc, argv, optstring)) != EOF)
		switch (optchar)
		{
		case 'v':
			Opt_verbosity++;
			break;
		case 'q':
			Opt_verbosity--;
			break;
		case 'p':
			if (sscanf(optarg, "%ums%n", &Opt_progress,
				&optchar) != 1 || optchar != strlen(optarg))
			{	/* Convert seconds to milliseconds. */
				if (sscanf(optarg, "%u%n", &Opt_progress,
							&optchar) != 1
				    		|| optchar != strlen(optarg))
					die("-p: not an integer");
				else
					Opt_progress *= 1000;
			}
			break;

		/* Source-related options */
		case 'i':
			src.endp.initiator = optarg;
			break;
		case 's':
			src.is_local = 0;
			src.url = optarg;
			break;
		case 'S':
			src.is_local = 1;
			src.fname = optarg;
			break;
		case 'f':
			src.fallback_blocksize = atoi(optarg);
			dst.fallback_blocksize = src.fallback_blocksize;
			break;
		case 'c':
			src.desired_optimum = atoi(optarg);
			dst.desired_optimum = src.desired_optimum;
			break;
		case 'm':
			src.endp.maxreqs = atoi(optarg);
			dst.endp.maxreqs = src.endp.maxreqs;
			break;

		/* Destination-related options */
		case 'I':
			dst.endp.initiator = optarg;
			break;
		case 'd':
			dst.is_local = 0;
			dst.url = optarg;
			break;
		case 'D':
			dst.is_local = 1;
			dst.fname = optarg;
			break;
		case 'M':
			dst.endp.maxreqs = atoi(optarg);
			break;
		case 'F':
			dst.fallback_blocksize = atoi(optarg);
			break;
		case 'C':
			dst.desired_optimum = atoi(optarg);
			break;
		case 'O':
			overwrite = 1;
			break;
		case 'V':
			check_free_space = 1;
			break;

		/* Error recovery */
		case 'r':
			Opt_request_retry_time = atoi(optarg);
			break;
		case 'R':
			Opt_maxreqs_degradation = atoi(optarg);
			if (Opt_maxreqs_degradation > 100)
				die("maximum iSCSI requests "
					"degradation must be under 100%%");
			break;

		/* Output batch controls */
		case 'b':
			Opt_min_output_batch = atoi(optarg);
			break;
		case 'B':
			Opt_max_output_queue = atoi(optarg);
			break;

		/* Mode of operation. */
		case 'N':
			nop = 1;
			break;
#ifdef SEXYWRAP
		case 'x':
		{	/* Execute a program preloaded with us. */
			ssize_t n;
			char *env;
			char path[PATH_MAX];
			char const *preload;

			/* Retrieve our absolute path. */
			n = readlink("/proc/self/exe", path, sizeof(path));
			if (n < 0)
			{
				warn_errno("readlink");
				die(NULL);
			} else if (n >= sizeof(path))
			{
				errno = ENAMETOOLONG;
				warn_errno("readlink");
				die(NULL);
			} else	/* readlink() doesn't terminate the string. */
				path[n] = '\0';

			/* Construct and set a new $LD_PRELOAD. */
			if ((preload = getenv("LD_PRELOAD")) != NULL)
			{
				size_t m;

				m = strlen(preload);
				env = xmalloc(m + 1 + n + 1);
				memcpy(env, preload, m);
				env[m] = ':';
				memcpy(&env[m+1], path, n);
				env[m+1+n] = '\0';
				setenv("LD_PRELOAD", env, 1);
				free(env);
			} else
				setenv("LD_PRELOAD", path, 1);

			/* Set the $initiator for sexywrap. */
			if (src.endp.initiator && !src.endp.initiator[0])
				die("invalid source initiator name");
			if (dst.endp.initiator)
				die("destination initiator name "
					"cannot be specified");
			if (src.endp.initiator)
				setenv("SEXYWRAP_INITIATOR",
					src.endp.initiator, 1);

			/* Execute the program. */
			argv += optind - 1;
			execvp(optarg, argv);
			warn_errno(optarg);
			die(NULL);
		} /* -x */
#endif /* SEXYWRAP */

		case 'h':
			usage();
			exit(0);
		default:
			exit(1);
		}

	if (argc > optind)
		die("too many arguments");

	/* Verify that we're not given two local targets. */
	if (!src.url && !dst.url)
		/* None of -sSdD is specified. */
		usage();
	if (!src.is_local && !src.url)
		/* Input is stdin. */
		src.is_local = 1;
	if (!dst.is_local && !dst.url)
		/* Output is stdout. */
		dst.is_local = 1;
	if (src.is_local && dst.is_local)
		die("at least one iSCSI target must be specified");

	/* Verify that both $src's and $dst's initiators are usable. */
	if (!src.endp.initiator || !src.endp.initiator[0])
		src.endp.initiator = "jaccom";
	if (!dst.endp.initiator)
		dst.endp.initiator = src.endp.initiator;
	else if (!dst.endp.initiator[0])
		dst.endp.initiator = "jaccom";

	/* Both local_to_remote() and remote_to_local() interpret
	 * NULL file names as stdin/stdout. */
	assert(src.is_local || src.url);
	assert(dst.is_local || dst.url);

	/* Make sure we have sane settings.  It's important to leave
	 * local targets' maxreqs zero, because restart_requests()
	 * depends on it. */
	if (!src.is_local && !src.endp.maxreqs)
		src.endp.maxreqs = DFLT_INITIAL_MAX_ISCSI_REQS;
	if (!dst.is_local && !dst.endp.maxreqs)
		dst.endp.maxreqs = DFLT_INITIAL_MAX_ISCSI_REQS;
	if (!Opt_min_output_batch)
		Opt_min_output_batch = 1;
	if (Opt_max_output_queue < Opt_min_output_batch)
		Opt_max_output_queue = Opt_min_output_batch;

	/* Init */
	signal(SIGPIPE, SIG_IGN);
	if (src.is_local)
		/* LOCAL_TO_REMOTE() */
		src.endp.fname = src.fname;
	else if (!init_endpoint(&src.endp, src.url, src.fallback_blocksize))
		die(NULL);
	else if (dst.is_local)
		calibrate_endpoint(&src.endp, src.desired_optimum);
	if (dst.is_local)
	{	/* REMOTE_TO_LOCAL() */
		if (!dst.fname || !strcmp(dst.fname, "-"))
			/* Output is stdout, don't clobber it with info
			 * messages.  $dst.endp.fname can be left NULL. */
			Info = stderr;
		else	/* Output is NOT stdout. */
			dst.endp.fname = dst.fname;

		/* process_output_queue() needs the block size of the source
		 * in order to calculate the output offset. */
		dst.endp.blocksize = src.endp.blocksize;

		/* $output.max, .iov and .tasks will be allocated in
		 * add_output_chunk(). */
	} else if (!init_endpoint(&dst.endp, dst.url, dst.fallback_blocksize))
		die(NULL);
	else if (src.is_local)
		calibrate_endpoint(&dst.endp, dst.desired_optimum);

	if (!nop && !src.is_local && !dst.is_local)
	{	/* REMOTE_TO_REMOTE(). */
		if ((off_t)src.endp.blocksize * src.endp.nblocks
			> (off_t)dst.endp.blocksize * dst.endp.nblocks)
		{	/* $src > $dst */
			src.endp.nblocks =
				(off_t)dst.endp.blocksize * dst.endp.nblocks
				/ src.endp.blocksize;
			warn("only the first %u blocks will be copied",
				src.endp.nblocks);
		} else if ((off_t)src.endp.blocksize * src.endp.nblocks
				% dst.endp.blocksize != 0)
			/* TODO We can't write partial blocks. */
			die("amount to copy is not divisable by the "
				"destination's block size");

		/* Make $to->maximum <= $from->maximum and enforce it. */
		void set_maximum(struct endpoint_st *to,
			struct endpoint_st const *from)
		{
			if (to->maximum && from->maximum
					&& to->maximum > from->maximum)
				to->maximum = from->maximum;

			if (!to->maximum)
				return;
			if (to->optimum > to->maximum)
				to->optimum = to->maximum;
			if (to->granuality > to->maximum)
				to->granuality = to->maximum;
		} /* set_maximum */

		/* $to->optimum <- $from->optimum if $to->blocksize allows. */
		int set_optimum(struct endpoint_st *to,
			struct endpoint_st const *from)
		{
			off_t optimum;

			if (!from->optimum)
				return 0;

			/* Is $from's $optimum dividable by $to->blocksize? */
			optimum = (off_t)from->blocksize * from->optimum;
			if (optimum % to->blocksize != 0)
				return 0;

			to->optimum = optimum / to->blocksize;
			return 1;
		} /* set_optimum */

		/* Set the desired chunk sizes before set_maximum(),
		 * so they can be adjusted if needed. */
		if (src.desired_optimum)
			src.endp.optimum = src.desired_optimum;
		if (dst.desired_optimum)
			dst.endp.optimum = dst.desired_optimum;

		/* Both endpoint's $maximum <- minimum($src, $dst). */
		set_maximum(&src.endp, &dst.endp);
		set_maximum(&dst.endp, &src.endp);

		/*
		 * First try to use the destination's $optimum (because
		 * writing is supposed to be the heavier operation),
		 * otherwise the source's one.  Ask the user to specify
		 * if none works.
		 */
		if (!set_optimum(&src.endp, &dst.endp)
				&& !set_optimum(&dst.endp, &src.endp))
			die("couldn't figure out a good transfer size, "
				"please specify it manually with -cC");

		/* Set up the $granuality of the endpoints. */
		calibrate_endpoint(&src.endp, 0);
		calibrate_endpoint(&dst.endp, 0);

		/* These conditions have to be met for read_chunk_size()
		 * to choose a chunk size appropriate for both targets. */
		assert((off_t)src.endp.blocksize * src.endp.optimum
				% dst.endp.blocksize == 0);
		assert((off_t)src.endp.blocksize * src.endp.nblocks
				% dst.endp.blocksize == 0);
	} /* REMOTE_TO_REMOTE() */

	/* Read/write all blocks of the disk. */
	if (!init_input(&input, &output, &src.endp, &dst.endp))
		die("malloc: %m");
	input.until = LOCAL_TO_REMOTE(&input)
		? dst.endp.nblocks : src.endp.nblocks;
	clock_gettime(CLOCK_MONOTONIC, &Start);

	/* Run */
	if (nop)
	{	/* Just print the capacity of the targets. */
		if (!src.is_local)
			print_endpoint(&src.endp);
		if (!dst.is_local)
			print_endpoint(&dst.endp);
		isok = 1;
	} else if (LOCAL_TO_REMOTE(&input))
		isok = local_to_remote(&input);
	else if (REMOTE_TO_LOCAL(&input))
		isok = remote_to_local(&input, overwrite, check_free_space);
	else
		isok = remote_to_remote(&input);

	/* Done */
	if (isok)
	{	/* If we're not $isok, the libiscsi context may be
		 * in inconsistent state, better not to risk using
		 * it anymore. */
   		   if (src.endp.iscsi)
			iscsi_logout_sync(src.endp.iscsi);
		if (dst.endp.iscsi)
			iscsi_logout_sync(dst.endp.iscsi);
	}

	/* Free resources */
	done_input(&input);
	destroy_endpoint(&src.endp);
	destroy_endpoint(&dst.endp);
	if (output.tasks)
	{
		unsigned i;

		/* These are neither allocated by init_input()
		 * nor freed by done_input(). */
		for (i = 0; i < output.enqueued; i++)
			scsi_free_scsi_task(output.tasks[i]);
		free(output.tasks);
		free(output.iov);
	}

	exit(!isok);
} /* main }}} */
#endif /* SEXYCAT }}} */

/* vim: set foldmarker={{{,}}} foldmethod=marker: */
/* End of sexycat.c */
