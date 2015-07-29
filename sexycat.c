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
 *				argument is an empty string the same hardcoded
 *				default is used as for <src-initiator-name>.
 *				Ignored if the destination is a local file.
 *   -rR			Reserve the entire source/destination target's
 *				LUN when connecting.  Might be useful if you
 *				get RESERVATION CONFLICT errors.  Ignored if
 *				the target is local.  Not available if compiled
 *				with libiscsi 1.4.
 *   -N				Don't do any I/O, just connect to the iSCSI
 *				device(s) and log in and print the capacity
 *				of the iSCSI target(s).
 *   -f				Before starting downloading ensure that the
 *				necessary free disk space is available.
 *   -F				Overwrite the local destination <file-name>.
 *   -v				Be more verbose:
 *				-- at level 2 it's printed when a block is
 *				   being re-read or rewritten due to a fault
 *				The default level is 1.
 *   -q				Be less verbose.  At verbosity level 0 all
 *				informational output is suppressed.
 *   -V				Timestamp error messages.
 *   -p {<secs>|<millissecs>ms}	Report progress (block number being read,
 *				last block that has been read and written)
 *				every so often.  If no progress was made
 *				since the last time it had been reported,
 *				it's suppressed, unles 10 * <seconds> have
 *				passed.
 *   -cC {<chunk-size>[mMkKbB]|<fraction>|<percentage>%}
 *   				Read/write <chunk-size> mega/kilo/bytes or
 *				blocks of data at once if possible.  If not
 *				specified the server is queried for its
 *				preference.  You can instruct the use of
 *				a <fraction> between 0..1 or a <percentage>
 *				of that.  -C only sets the destination's
 *				<chunk-size>, -c sets it for both targets.
 *				If you only want to set it for the source,
 *				specify -C 0 explicitly after -c.
 *   -mM <max-reqs>		The maximum number of parallel requests
 *				to iSCSI targets.  If the connection breaks,
 *				this number is reduced by the factor which
 *				can be specified with -Q.  Ignored when
 *				the endpoint is a local file, otherwise
 *				the default is 32.  -mM behave similarly
 *				as -cC.
 *   -b <min-output-batch>	Collect at least this number of input chunks
 *				before writing them out.  Writing of larger
 *				batches can be more efficient.  Only effective
 *				if the destination is a local file, and then
 *				the default is 32.
 *   -B <max-output-batch>	Write the output batch if this many input
 *				chunks has been collected.  Only effective
 *				if the destination is a local file, and then
 *				the default is 64.
 *   -t <retry-delay>		If reading or writing a chunk is failed
 *				(the server returns an error response)
 *				wait <retry-delay> milliseconds before
 *				retrying.  The default is three seconds.
 *   -T <request-timeout>	Consider a read/write iSCSI request timed out
 *				after this many milliseconds (30s by default).
 *				Then the request retried immedeately.
 *   -H <pause-between-attempts>[x<max-attempts>]
 *				When the connection breaks with a target,
 *				sexycat tries to reconnect, and without
 *				this flag gives up if it's unsuccessful.
 *				Otherwise it makes <max-attempts> altogether,
 *				pausing inbetween <pause-between-attempts>
 *				seconds.  If <max-attempts> is zero, sexycat
 *				persists until connection could be established
 *				and the server allowed to Login.
 *   -Q <degradation-percent>	When the connection breaks with an iSCSI
 *				target it can be because sexycat issued
 *				too many requests in parallel (at least
 *				this is the case with istgt).  This case
 *				the maximimum number of requests (which
 *				can be specified with -mM) can be reduced
 *				to this percent.  The value must be between
 *				0..100.  0/100 mean not to do this reduction
 *				and this is the default.
 *   -zZ <fallback-blocksize>	If the iSCSI target's block size cannot be
 *				determined, suppose the given value instead
 *				of the default 512 bytes.  This is intended
 *				as a very-last-resort measure.  -zZ behave
 *				similarly as -cC.
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
#if !defined(SEXYCAT) && !defined(SEXYWRAP)
# define SEXYCAT
#endif

#if defined(SEXYWRAP) && defined(SEXYCAT) && !defined(__PIE__)
# error "You need to build sexywrap+sexycat with -shared -pie -fPIE"
#endif

/* Include files {{{ */
#include <stdlib.h>
#include <limits.h>
#include <unistd.h>
#include <stdarg.h>
#include <errno.h>
#include <assert.h>

#include <string.h>
#include <stdio.h>
#include <math.h>
#include <time.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <setjmp.h>

#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>
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

#define DFLT_ISCSI_REQUEST_TIMEOUT	(30 * 1000)
#define DFLT_ISCSI_REQUEST_RETRY_PAUSE	( 3 * 1000)
/* }}} */

/* Macros {{{ */
/* Return the number of elements in $ary. */
#define MEMBS_OF(ary)	(sizeof(ary) / sizeof((ary)[0]))

/* Shortcuts */
#ifdef LIBISCSI_API_VERSION
  /* This is necessary for LBA_OF() to work. */
# define SET_TASK_PTR(task, op)	(task)->ptr = scsi_cdb_unmarshall((task), op)

  /* We assume that offsetof(scsi_read10_cdb, lba) == that of write10. */
# define LBA_OF(task)	(((struct scsi_read10_cdb const *)((task)->ptr))->lba)
#else /* libiscsi 1.4 */
# define SET_TASK_PTR(task, op)	/* NOP */
# define LBA_OF(task)		((task)->params.read10.lba)
# define iscsi_scsi_cancel_task	iscsi_scsi_task_cancel
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

			/* reserve6 the LUN? */
			int reserve;
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
	/* The chunk can be in input_st::unused chain ($prev is NULL),
	 * in the ::in_use chain or being transferred from one to the
	 * other (ie. it's "floating"; both $prev and $next are NULL). */
	struct chunk_st *prev, *next;

	/* All chunks link to the same input_st. */
	struct input_st *input;

	/*
	 * The read/write task being carried out or waiting to be carried
	 * out with this chunk.  The operation is encoded in $task->xfer_dir
	 * and the status (in progress or failed, waiting for reply or retry)
	 * in $task->status.  NULL if the chunk is unused.
	 *
	 * It's important that $task->ptr be set to the unmarshalled response
	 * with SET_TASK_PTR() in the callback, otherwise LBA_OF() won't work.
	 */
	struct scsi_task *task;

	/* Time in milliseconds until the request is retried, either because
	 * of no reply or the time after a failure has elapsed.  Zero if the
	 * chunk is unused.  Recalculated by xfpoll(). */
	unsigned time_to_retry;

	/* The size of buffer referred by the pointers below. */
	size_t sbuf;

	/* The payload carried by this chunk.  NULL if the chunk is unused. */
	union
	{
		struct
		{
			/* Used by sexywrap and points to a separately and
			 * possibly user-allocated buffer, so it must not
			 * be free()d. */
			void const *wrpbuf;

			/* Used by remote_to_remote() and points to the
			 * payload read from the source target. */
			void *rtrbuf;
		} s;

		/* Used by local_to_remote() and designates the beginning
		 * of the buffer allocated together with the chunk_st. */
		unsigned char ltrbuf[0];
	};
};

/* Encapsulates all state information needed for writing.  In theory
 * this struct could be a union at the moment, but this may change
 * in the future. */
struct output_st
{
	union
	{
		/* The number of outstanding write requests. */
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
	 * All other chunks are $in_use, except those which are floating
	 * a little before added to the list or returned to the $unused
	 * list because of an error.  Chunks $in_use are either waiting
	 * for reply to a request or are waiting for chunk_st::time_to_retry
	 * to elapse and be retried.  $last_in_use is for enqueue_chunk().
	 */
	unsigned nunused;
	struct chunk_st *unused;
	struct chunk_st *in_use, *last_in_use;

	/* Links to all other structures. */
	struct output_st *output;
	struct endpoint_st *src, *dst;
};
/* }}} */

/* Function prototypes {{{ */
static unsigned timediff(
	struct timespec const *later,
	struct timespec const *earlier);
static char const *timestamp(unsigned ms);

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

static void *__attribute__((malloc)) xmalloc(size_t size);
static void xrealloc(void *ptrp, size_t size);

static int get_inode(int fd, ino_t *inodep);
static void start_timer(unsigned ms);
static void stop_timer(void);
static void report_progress(int unused);

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
static enum scsi_xfer_dir chunk_dir(struct chunk_st const *chunk);
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
static void enqueue_chunk(struct chunk_st *chunk,
	int status, unsigned timeout);
static void retry_chunk(struct chunk_st *chunk);
static void chunk_failed(struct chunk_st *chunk);
static void chunk_started(struct chunk_st *chunk);
static struct chunk_st *get_chunk(struct input_st *input);

static void done_input(struct input_st *input);
static int init_input(struct input_st *input, struct output_st *output,
	struct endpoint_st *src, struct endpoint_st *dst);

static void endpoint_connected(struct iscsi_context *iscsi, int status,
	void *command_data, void *private_data);
static int connect_endpoint(
	struct iscsi_context *iscsi, struct iscsi_url *url, int reserve);
static int reconnect_endpoint(struct endpoint_st *endp);

static struct scsi_task *read_endpoint(struct endpoint_st const *endp,
	scsi_block_addr_t block, size_t chunk_size,
	callback_t read_cb, struct chunk_st *chunk);
static struct scsi_task *write_endpoint(struct endpoint_st const *endp,
	scsi_block_addr_t block, void const *buf, size_t sbuf,
	callback_t write_cb, struct chunk_st *chunk);

static void destroy_endpoint(struct endpoint_st *endp);
static void print_endpoint(struct endpoint_st const *endp);
static void set_endpoint_desired_optimum(struct endpoint_st *endp,
	char const *str);
static void calibrate_endpoint(struct endpoint_st *endp,
	char const *desired_optimum);
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
/* -Vvqp */
/* By default $Opt_verbosity is 1.  $Opt_progress is in milliseconds. */
static int Opt_timestamp, Opt_verbosity, Opt_progress;

/* -bB */
#ifdef SEXYCAT
static unsigned Opt_min_output_batch = DFLT_MIN_OUTPUT_BATCH;
static unsigned Opt_max_output_queue = DFLT_INITIAL_MAX_OUTPUT_QUEUE;
#endif

/* -HtTQ */
static struct
{
	int enabled;
	unsigned pause;
	unsigned ntimes;
} Opt_retry_connection;;
static unsigned Opt_request_timeout	= DFLT_ISCSI_REQUEST_TIMEOUT;
static unsigned Opt_request_retry_time  = DFLT_ISCSI_REQUEST_RETRY_PAUSE;
static unsigned Opt_maxreqs_degradation;
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
 * -- $Now: the current time; used by report_progress() and xfpoll()
 * Both are acquired with clock_gettime().
 */
static struct timespec Start, Now;

/* The latest blocks being or having been read or written. */
static struct progress_st
{
	scsi_block_addr_t reading;	/* Updated by
					 * start_iscsi_read_requests(). */
	scsi_block_addr_t red;		/* Updated by chunk_read(). */
	scsi_block_addr_t writing;	/* Updated by add_output_chunk(),
					 * chunk_read(), local_to_remote(). */
	scsi_block_addr_t written;	/* Updated by  chunk_written()
					 * and process_output_queue(). */
} Last;
/* }}} */

/* Program code */
/* Return $later - $earlier in ms.  It is assumed that $later >= $earlier. */
unsigned timediff(struct timespec const *later,
	struct timespec const *earlier)
{
	const unsigned ms_per_sec = 1000;
	const long ns_per_ms = 1000000;
	unsigned diff;

	/* Verify the precondition. */
	assert(earlier->tv_sec || earlier->tv_nsec);
	if (later->tv_sec != earlier->tv_sec)
		assert(later->tv_sec > earlier->tv_sec);
	else 
		assert(later->tv_nsec >= earlier->tv_nsec);

	diff  = (later->tv_sec  - earlier->tv_sec)  * ms_per_sec;
	diff += (later->tv_nsec - earlier->tv_nsec) / ns_per_ms;

	return diff;
} /* timediff */

char const *timestamp(unsigned ms)
{
#ifdef SEXYCAT
	static char str[32];
	unsigned hours, mins, secs;
	int serrno;

	if (!Start.tv_sec && !Start.tv_nsec)
		/* Called by sexywrap, no timestampts. */
		return "";
	if (!ms && !Opt_timestamp)
		/* -V wasn't specified */
		return "";

	serrno = errno;
	if (!ms)
	{
		struct timespec now;

		clock_gettime(CLOCK_MONOTONIC, &now);
		ms = timediff(&now, &Start);
	}

	ms /= 1000;
	hours = ms / (60*60);
	ms %= 60*60;
	mins = ms / 60;
	secs = ms % 60;

	sprintf(str, "[%.2u:%.2u:%.2u]", hours, mins, secs);

	errno = serrno;
	return str;
#else	/* ! SEXYCAT */
	return "";
#endif
}

void usage(void)
{
	printf("usage: %s [-vq] [-p <progress>] "
		"[-cC <chunk-size>] "
		"[-mM <max-requests> "
		"[-t <retry-pause>] [-T <request-timeout>] "
		"[-H <reconnection-pause>[x<max-attempts>] "
		"[-Q <request-degradation>] [-zZ <fallback-blocksize>] "
		"[-bB <batch-size>] "
		"[-iI <initiator>] [-rR] [-N] "
#ifdef SEXYWRAP
		"[-x <program> [<args>...]] "
#endif
		"[-sS <source>] [-fF] [-dD <destination>]\n",
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

	fprintf(stderr, "%s%s: ", Basename, timestamp(0));
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
	fprintf(stderr, "%s%s: %s: %m\n", Basename, timestamp(0), op);
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
		fprintf(stderr, "%s%s: %s: %s\n",
			Basename, timestamp(0), op,
			iscsi_get_error(iscsi));
	else
		fprintf(stderr, "%s%s: %s\n",
			Basename, timestamp(0),
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

#ifdef SEXYCAT
void start_timer(unsigned ms)
{
	struct itimerval it;

	memset(&it, 0, sizeof(it));
	it.it_value.tv_sec  =  ms / 1000;
	it.it_value.tv_usec = (ms % 1000) * 1000;
	it.it_interval = it.it_value;
	setitimer(ITIMER_REAL, &it, NULL);
}

void stop_timer(void)
{
	struct itimerval it;

	memset(&it, 0, sizeof(it));
	setitimer(ITIMER_REAL, &it, NULL);
}

/* Print $Last if $Opt_progress has passed since the previous report.
 * Invoked by SIGALRM. */
void report_progress(int unused)
{
	static struct timespec last_report;
	static struct progress_st prev;
	unsigned diff;

	clock_gettime(CLOCK_MONOTONIC, &Now);
	diff = timediff(&Now, last_report.tv_sec || last_report.tv_nsec
		? &last_report : &Start);
	if (diff < Opt_progress)
		/* $Opt_progress hasn't passed since $Last_report. */
		return;
	if (diff < 10 * Opt_progress
			&& Last.reading == prev.reading
			&& Last.red     == prev.red
			&& Last.writing == prev.written
			&& Last.written == prev.written)
		/* $Opt_progress has passed, but the values didn't change,
		 * don't report unless 10*$Opt_progress has passed. */
		return;

	/* $diff := $Now - $Start.  Don't recalculate it if we used
	 * $Start earlier. */
	if (last_report.tv_sec || last_report.tv_nsec)
		diff = timediff(&Now, &Start);

	info("%s reading #%u, have read #%u, writing #%u, written #%u",
		timestamp(diff),
		Last.reading, Last.red, Last.writing, Last.written);

	prev = Last;
	last_report = Now;
} /* report_progress */
#endif /* SEXYCAT */

/* On failure $errno is set. */
int xfpoll(struct pollfd *pfd, unsigned npolls, struct input_st *input)
{
	/* poll() as long as it returns EINTR. */
	memset(&Now, 0, sizeof(Now));
	for (;;)
	{
		int ret, serrno;
		struct timespec since;
		unsigned timeout, elapsed;

		/* Sleep at most as much as the oldest $chunk $in_use. */
		if (input)
		{
			struct chunk_st *chunk;

			timeout = 0;
			for (chunk = input->in_use; ; chunk = chunk->next)
			{
				if (!chunk)
					break;
				else if (chunk_dir(chunk) == SCSI_XFER_NONE)
					continue;
				else if (!chunk->time_to_retry)
					return 0;
				else if (!timeout)
					timeout = chunk->time_to_retry;
				else if (timeout > chunk->time_to_retry)
					timeout = chunk->time_to_retry;
				break;
			} /* for all $failed $chunk */
		} else	/* Called by connect_endpoint(), wait for Login. */
			timeout = Opt_request_timeout;

		/* Measure the time [p]poll() takes. */
		if (Now.tv_sec || Now.tv_nsec)
		{	/* We know $Now from the previous iteration. */
			since = Now;
			memset(&Now, 0, sizeof(Now));
		} else
			clock_gettime(CLOCK_MONOTONIC, &since);

		/* Poll $pfd. */
		if (input && Opt_progress)
		{
			sigset_t empty;

			/* Unblock SIGALRM (report_progress()). */
			sigemptyset(&empty);
			if (timeout > 0)
			{
				struct timespec ts;

				memset(&ts, 0, sizeof(ts));
				ts.tv_sec  =  timeout / 1000;
				ts.tv_nsec = (timeout % 1000) * 1000000;
				ret = ppoll(pfd, npolls, &ts,  &empty);
			} else
				ret = ppoll(pfd, npolls, NULL, &empty);
		} else	/* connect_endpoint() || !report_progress() */
			ret = poll(pfd, npolls, timeout ? timeout : -1);
		serrno = errno;

		/* Get the $elapsed time $since.
		 * report_progress() might have set $Now. */
		if (!Now.tv_sec && !Now.tv_nsec)
			clock_gettime(CLOCK_MONOTONIC, &Now);
		elapsed = timediff(&Now, &since);

		/* Subtract the $elapsed time from all chunks $in_use. */
		if (input && elapsed)
		{
			struct chunk_st *chunk;

			for (chunk = input->in_use; chunk;
					chunk = chunk->next)
				if (chunk->time_to_retry > elapsed)
					chunk->time_to_retry -= elapsed;
				else
					chunk->time_to_retry = 0;
		}

		if (ret < 0)
		{
			if (serrno == EINTR)
				continue;
			errno = serrno;
		}
		if (ret != 0 || !input)
			return ret;
	} /* until there's something to (re-)read/write or time runs out */
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

		if (niov > 1)
			ret = seek
				? pwritev(fd, iov, niov, offset)
				:  writev(fd, iov, niov);
		else
			ret = seek
				? pwrite(fd, iov[0].iov_base, iov[0].iov_len,
					offset)
				:  write(fd, iov[0].iov_base, iov[0].iov_len);
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
		warn("%s(#%u): sense key:%d ascq:%04x",
			op, LBA_OF(task),
			task->sense.key, task->sense.ascq);
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
	struct output_st *output;
	scsi_block_addr_t chunk_address;

	/* Make room for $chunk in $output->tasks if it's full. */
	output = chunk->input->output;
	if (output->enqueued >= output->max)
	{
		unsigned n;

		/*
		 * $output->tasks is either unallocated or we've used up
		 * all the free entries.  Allocate it or 25% more.  Do it
		 * together with ->iov so we don't need to keep a separate
		 * account of its size.
		 */
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
	chunk_address = LBA_OF(chunk->task);
	assert(output->enqueued < output->max);
	for (i = output->enqueued; i > 0; i--)
		if (LBA_OF(output->tasks[i-1]) < chunk_address)
			break;

	/* Insert $chunk->task into $output->tasks[$i]. */
	memmove(&output->tasks[i+1], &output->tasks[i],
		sizeof(*output->tasks) * (output->enqueued - i));
	output->tasks[i] = chunk->task;
	chunk->task = NULL;
	output->enqueued++;

	if (Last.writing < chunk_address)
		Last.writing = chunk_address;

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
	unsigned niov, ntasks;
	scsi_block_addr_t block;
	struct scsi_task **tasks, **from, **t;

	/*
	 * $niov	:= the number of buffers in the current batch
	 * $block	:= the next block we expect in the batch
	 * $tasks	:= where to take from the next buffer of the batch
	 * $ntasks	:= how many buffers till the end of $output->tasks
	 * $from	:= the first buffer in the batch
	 */
	niov = 0;
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
			size_t diff;
			struct iovec *prev;

			/* ...but it does sometimes for unknown reason. */
			if (fd < 0)
				continue;
			diff = (size_t)dst->blocksize
				* (block - LBA_OF(tasks[0]));
			prev = &output->iov[niov-1];
			assert(prev->iov_len > diff);

			/* Verify that the buffers really overlap. */
			assert(!memcmp(
				&prev->iov_base + (prev->iov_len-diff),
				tasks[0]->datain.data,
				diff <= tasks[0]->datain.size
					? diff : tasks[0]->datain.size));

			/* Reduce the size of the $prev:ios buffer. */
			if (Opt_verbosity > 0)
				warn("server returned +%zu unexpected data "
					"for block %u",
					diff, LBA_OF(tasks[-1]));
			prev->iov_len -= diff;
			continue;
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

		/* Write the buffers to $fd.  If $dst is $seekable always
		 * use pwrite[v](), because practically we're writing buffers
		 * in arbitrary order. */
		assert(tasks > from);
		if (!xpwritev(fd, output->iov, niov,
			(off_t)dst->blocksize * LBA_OF(from[0]),
			dst->seekable))
		{
			warn("%s: %m", dst->fname ? dst->fname : "(stdout)");
			return 0;
		}

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
	assert(chunk->task == task);

	assert(input->output->nreqs > 0);
	input->output->nreqs--;

	SET_TASK_PTR(task, SCSI_OPCODE_WRITE10);
	if (status == SCSI_STATUS_CANCELLED)
	{
		task->status = status;
		return;
	} else if (is_iscsi_error(iscsi, task, "write10", status))
	{
		chunk_failed(chunk);
		return;
	}

	assert(LBA_OF(task) <= Last.writing);
	assert(Last.written <= Last.writing);
	if (Last.written < LBA_OF(task))
		Last.written = LBA_OF(task);

	scsi_free_scsi_task(task);
	chunk->task = NULL;
	chunk->time_to_retry = 0;
	if (REMOTE_TO_REMOTE(input))
	{
		assert(chunk->s.rtrbuf);
		free(chunk->s.rtrbuf);
		chunk->s.rtrbuf = NULL;
	}
	return_chunk(chunk);
}

void chunk_read(struct iscsi_context *iscsi, int status,
	void *command_data, void *private_data)
{
	scsi_block_addr_t chunk_address;
	struct scsi_task *task = command_data;
	struct chunk_st *chunk = private_data;
	struct endpoint_st *dst = chunk->input->dst;

	assert(chunk != NULL);
	assert(!LOCAL_TO_REMOTE(chunk->input));
	assert(!chunk->s.rtrbuf);

	assert(task != NULL);
	assert(task == chunk->task);

	assert(chunk->input->nreqs > 0);
	chunk->input->nreqs--;

	/* libiscsi won't need this pointer anymore, so we can use it
	 * to store the task's scsi_read10_cdb.  This will be freed by
	 * scsi_free_scsi_task() automagically. */
	SET_TASK_PTR(task, SCSI_OPCODE_READ10);

	if (status == SCSI_STATUS_CANCELLED)
	{	/* restart_requests() cancelled us.  Set the $task->status
		 * so restart_requests() won't cancel us again.  It'll also
		 * influence chunk_dir(). */
		task->status = status;
		return;
	} else if (is_iscsi_error(iscsi, task, "read10", status))
	{
		chunk_failed(chunk);
		return;
	}

	chunk_address = LBA_OF(task);
	assert(chunk_address <= Last.reading);
	assert(Last.red <= Last.reading);
	if (Last.red < chunk_address)
		Last.red = chunk_address;

	if (REMOTE_TO_LOCAL(chunk->input))
	{
		chunk->time_to_retry = 0;
		add_output_chunk(chunk);
		return;
	} else
	{
		assert(REMOTE_TO_REMOTE(chunk->input));
		assert(!chunk->s.rtrbuf);

		chunk->sbuf = task->datain.size;
		chunk->s.rtrbuf = task->datain.data;
		task->datain.data = NULL;
	}

	if (chunk->input->src->blocksize != dst->blocksize)
	{	/* Translate source address to destination address. */
		off_t n;

		n = (off_t)chunk_address * chunk->input->src->blocksize;
		assert(n % dst->blocksize == 0);
		chunk_address = n / dst->blocksize;
	}

	if (!(chunk->input->output->nreqs < chunk->input->dst->maxreqs))
	{	/* Maximum outstanding write requests reached,
		 * write $chunk later. */
		retry_chunk(chunk);
		return;
	}

	/* Don't trash $chunk->task until we have a new one. */
	task = write_endpoint(dst, chunk_address,
		chunk->s.rtrbuf, chunk->sbuf, chunk_written, chunk);
	if (task != NULL)
	{
		if (Last.writing < chunk_address)
			Last.writing = chunk_address;
		scsi_free_scsi_task(chunk->task);
		chunk->task = task;
		chunk_started(chunk);
		chunk->input->output->nreqs++;
	} else
	{
		warn_iscsi("write10", dst->iscsi);
		retry_chunk(chunk);
	}
}
#endif /* SEXYCAT */

enum scsi_xfer_dir chunk_dir(struct chunk_st const *chunk)
{
	struct input_st const *input;

	input = chunk->input;
	assert(input != NULL);
	assert(chunk->task != NULL);

	if (chunk->task->status == SCSI_STATUS_GOOD)
		/* Can be restarted without increasing
		 * the number of outstanding requests. */
		return chunk->task->xfer_dir;
	else if (chunk->task->xfer_dir == SCSI_XFER_READ)
	{	/* Re-read */
		assert(!LOCAL_TO_REMOTE(input) && !chunk->s.rtrbuf);
		assert(input->src && input->src->iscsi);
		if (!(input->nreqs < input->src->maxreqs))
			return SCSI_XFER_NONE;
	} else	/* SCSI_XFER_WRITE */
	{	/* Rewrite */
		assert(!REMOTE_TO_LOCAL(input));
		assert(LOCAL_TO_REMOTE(input) || chunk->s.rtrbuf);
		assert(input->dst && input->dst->iscsi);
		if (!(input->output->nreqs < input->dst->maxreqs))
			return SCSI_XFER_NONE;
	}

	/* New request can be and needs to be started. */
	return chunk->task->xfer_dir;
}

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
	struct chunk_st *chunk, *next;
	struct output_st *output = input->output;
	struct endpoint_st *src = input->src;
	struct endpoint_st *dst = input->dst;

	/* Do we have anything to do? */
	if (!(chunk = input->in_use))
		return 1;

	/* As long as we have requests which have reached $time_to_retry. */
	do
	{
		int timeout;
		struct scsi_task *task;
		scsi_block_addr_t chunk_address;

		/* Since the list is ordered, the first time we meet a $chunk
		 * still not ready to retry, we can stop. */
		if (chunk->time_to_retry)
			break;
		assert(chunk->task != NULL);
		timeout = chunk->task->status == SCSI_STATUS_GOOD;

		/* We might modify the chain. */
		next = chunk->next;

		/* Reissue the failed or timed out request if possible. */
		switch (chunk_dir(chunk))
		{
		case SCSI_XFER_READ:
		{	/* Re-read */
			/* First we need to cancel the task and make the
			 * callback set $task->ptr, otherwise LBA_OF()
			 * won't work. */
			if (timeout)
				assert(!iscsi_scsi_cancel_task(
						input->src->iscsi,
						chunk->task));
			if (!(input->nreqs < src->maxreqs))
				/* This could be cause by reduce_maxreqs(). */
				continue;
			chunk_address = LBA_OF(chunk->task);

			if (Opt_verbosity > 0)
			{
				if (timeout)
					warn("source block #%u timed out, "
						"re-reading", chunk_address);
				else
					warn("re-reading source block %u",
						chunk_address);
			}

			task = read_endpoint(src, chunk_address,
				read_chunk_size(src, dst,
					chunk_address, input->until),
				read_cb, chunk);
			if (task != NULL)
			{
				scsi_free_scsi_task(chunk->task);
				chunk->task = task;
				chunk_started(chunk);
				input->nreqs++;
			} else
			{
				chunk->task->status = SCSI_STATUS_ERROR;
				warn_iscsi("read10", src->iscsi);
				return 0;
			}
			break;
		} case SCSI_XFER_WRITE:
		{	/* Rewrite */
			size_t sbuf;
			unsigned char const *buf;

			if (timeout)
				assert(!iscsi_scsi_cancel_task(
						input->dst->iscsi,
						chunk->task));
			if (!(output->nreqs < dst->maxreqs))
				continue;
			chunk_address = LBA_OF(chunk->task);

			if (Opt_verbosity > 0)
			{
				if (timeout)
					warn("destination block #%u "
						"timed out, re-writing",
						chunk_address);
				else
					warn("rewriting destination block %u",
						chunk_address);
			}

			sbuf = chunk->sbuf;
			if (IS_SEXYWRAP(input))
				buf = chunk->s.wrpbuf;
			else if (REMOTE_TO_REMOTE(input))
				buf = chunk->s.rtrbuf;
			else /* LOCAL_TO_REMOTE() */
				buf = chunk->ltrbuf;

			task = write_endpoint(dst,
				chunk_address, buf, sbuf,
				write_cb, chunk);
			if (task != NULL)
			{
				scsi_free_scsi_task(chunk->task);
				chunk->task = task;
				chunk_started(chunk);
				output->nreqs++;
			} else
			{
				chunk->task->status = SCSI_STATUS_ERROR;
				warn_iscsi("write10", dst->iscsi);
				return 0;
			}
			break;
		} default:
			/* Chunk cannot be re-read or rewritten because
			 * the maximum number of requests has reached. */
			break;
		} /* what to do with $chunk */
	} while ((chunk = next) != NULL);

	return 1;
}

int start_iscsi_read_requests(struct input_st *input, callback_t read_cb)
{
	struct endpoint_st *src = input->src;

	/* Issue new read requests as long as we can. */
	assert(!LOCAL_TO_REMOTE(input));
	while (input->nreqs < src->maxreqs
		&& input->top_block < input->until)
	{
		struct chunk_st *chunk;
		size_t this_chunk_size;

		if (!(chunk = get_chunk(input)))
			break;

		this_chunk_size = read_chunk_size(src, input->dst,
			input->top_block, input->until);
		if (!(chunk->task = read_endpoint(src, input->top_block,
			this_chunk_size, read_cb, chunk)))
		{
			return_chunk(chunk);
			warn_iscsi("read10", src->iscsi);
			return 0;
		} else
		{
			chunk_started(chunk);
			input->nreqs++;
		}

		assert(!Last.reading || Last.reading < input->top_block);
		Last.reading = input->top_block;
		input->top_block += this_chunk_size / src->blocksize;
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
		if (chunk->task)
			scsi_free_scsi_task(chunk->task);
		if (REMOTE_TO_REMOTE(chunk->input))
			free(chunk->s.rtrbuf);
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
		assert(LOCAL_TO_REMOTE(chunk->input) || !chunk->s.rtrbuf);
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

/* Return a $chunk (either floating or being in use) to $input->unused. */
void return_chunk(struct chunk_st *chunk)
{
	struct input_st *input = chunk->input;

	assert(!chunk->task);
	assert(!chunk->time_to_retry);
	if (IS_SEXYWRAP(input) || !LOCAL_TO_REMOTE(input))
		assert(!chunk->s.wrpbuf && !chunk->s.rtrbuf);

	if (chunk == input->last_in_use)
	{	/* $chunk is the last one in the chain */
		assert(!chunk->next);
		input->last_in_use = chunk->prev;
	}

	if (chunk == input->in_use)
	{	/* $chunk is the first and possibly last too */
		assert(!chunk->prev);
		input->in_use = chunk->next;
	} else if (chunk->prev)
		/* $chunk is not the first, but possibly the last */
		chunk->prev->next = chunk->next;

	if (chunk->next)
		chunk->next->prev = chunk->prev;
	chunk->prev = NULL;

	/* Prepend $chunk to the unused chain. */
	chunk->next = input->unused;
	input->unused = chunk;
	input->nunused++;
} /* return_chunk */

/* Verify the integrity of input_st::in_use before and after modification. */
#define VERIFY_LIST

/* Either enqueue a floating chunk (not $in_use) or requeue one
 * with a new $timeout. */
void enqueue_chunk(struct chunk_st *chunk, int status, unsigned timeout)
{
	struct input_st *input = chunk->input;

#ifdef VERIFY_LIST
	/* Verify the integrity of the $in_use chain beforehand. */
	unsigned nchunks = 0;
	if (!input->in_use)
	{	/* Nothing is $in_use => $chunk must be floating. */
		nchunks++;
		assert(!input->last_in_use);
		assert(!chunk->prev && !chunk->next);
	} else
	{
		int find_it;
		struct chunk_st const *ch;

		/* If $chunk is not floating, $find_it. */
		find_it = chunk == input->in_use||chunk->prev||chunk->next;
		if (!find_it)
			/* We'll add a new chunk. */
			nchunks++;

		assert(!input->in_use->prev);
		for (ch = input->in_use; ; ch = ch->next)
		{
			nchunks++;
			if (ch == chunk)
			{
				assert(find_it);
				find_it = 0;
			}
			if (ch->next)
			{	/* Verify that $ch:unks are ordered
				 * by $time_to_retry ascendingly. */
				assert(ch->time_to_retry
					<= ch->next->time_to_retry);
				assert(ch->next->prev == ch);
			} else
				break;
		} /* for all $ch:unks $in_use */
		assert(ch == input->last_in_use);
		assert(!find_it);
	} /* there are chunks $in_use */
#endif /* VERIFY_LIST */

	assert(chunk->task != NULL);
	chunk->task->status = status;

	if (!input->in_use)
	{	/* $chunk will be the first to be in-use,
		 * so it must be floating. */
		assert(!chunk->prev);
		assert(!chunk->next);
		input->in_use = input->last_in_use = chunk;
	} else if (timeout <= input->in_use->time_to_retry)
	{	/* $chunk comes before the first one in the chain. */
		if (chunk == input->in_use)
		{	/* It's in the right place already. */
			goto done;
		} else if (!chunk->prev)
		{	/* $chunk is floating, NOP */
			assert(!chunk->next);
		} else if (chunk == input->last_in_use)
		{	/* $chunk is the last, but not the first $in_use */
			input->last_in_use = chunk->prev;
			input->last_in_use->next = NULL;
		} else
		{	/* $chunk is neither the first nor the last one,
			 * simply unlink it */
			chunk->prev->next = chunk->next;
			chunk->next->prev = chunk->prev;
		}

		/* Prepend $in_use with $chunk. */
		chunk->prev = NULL;
		chunk->next = input->in_use;
		input->in_use->prev = chunk;
		input->in_use = chunk;
	} else if (timeout >= input->last_in_use->time_to_retry)
	{	/* $chunk expires after the last one in the chain. */
		if (chunk == input->last_in_use)
		{	/* It's in the right place already. */
			goto done;
		} else if (!chunk->next)
		{	/* $chunk is floating, NOP */
			assert(!chunk->prev);
		} else if (chunk == input->in_use)
		{	/* $chunk is the first, but not the last $in_use */
			input->in_use = chunk->next;
			input->in_use->prev = NULL;
		} else
		{	/* $chunk is neither the first nor the last one */
			chunk->prev->next = chunk->next;
			chunk->next->prev = chunk->prev;
		}

		/* Append $chunk to $in_use. */
		chunk->next = NULL;
		chunk->prev = input->last_in_use;
		input->last_in_use->next = chunk;
		input->last_in_use = chunk;
	} else if (timeout != chunk->time_to_retry)
	{	/* There must be >= 2 chunks $in_use. */
		struct chunk_st *prec;

		/* $chunk could still be the first or the last $in_use,
		 * or it could be floating. */
		assert(input->in_use != input->last_in_use);
		assert(timeout > input->in_use->time_to_retry);
		assert(timeout < input->last_in_use->time_to_retry);

		/* Where to place $chunk? */
		if (timeout < chunk->time_to_retry)
		{	/*
			 * We'll move $chunk backwards.  This case it can't
			 * be the first $in_use because that situation has
			 * been covered earlier.  Also $chunk cannot be
			 * floating because then $time_to_retry would be 0.
			 */
			assert(chunk != input->in_use);
			prec = chunk;
		} else if (!chunk->next || timeout>chunk->next->time_to_retry)
			/* We'll move $chunk forward, or insert it probably
			 * at the end of the list. */
			prec = input->last_in_use;
		else	/* $time_to_retry < $timeout <= $next->time_to_retry
			 * $timeout is increasing, but the position of $chunk
			 * stays the same. */
			goto done;

		do
		{
			prec = prec->prev;
			assert(prec != NULL);
		} while (prec->time_to_retry > timeout);

		/* Insert $chunk right after $prec. */
		if (prec == chunk->prev || prec == chunk)
		{	/* $chunk is in the right place already. */
			goto done;
		} else if (chunk == input->in_use)
		{
			assert(!chunk->prev);
			assert(chunk->next != NULL);
			input->in_use = chunk->next;
			input->in_use->prev = NULL;
		} else if (chunk == input->last_in_use)
		{
			assert(!chunk->next);
			assert(chunk->prev != NULL);
			input->last_in_use = chunk->prev;
			input->last_in_use->next = NULL;
		} else if (chunk->prev)
		{	/* $chunk is not floating, unlink it */
			chunk->prev->next = chunk->next;
			chunk->next->prev = chunk->prev;
		}

		chunk->prev = prec;
		chunk->next = prec->next;
		prec->next->prev = chunk;
		prec->next = chunk;
	} else	/* $chunk is not floating and its $timeout and consequently
		 * its place doesn't change. */
		assert(chunk->prev || chunk->next);

done:	chunk->time_to_retry = timeout;

#ifdef VERIFY_LIST
	/* Verify the integrity of the $in_use chain after modification. */
	{
		int found_it;
		struct chunk_st const *ch;

		found_it = 0;
		assert(!input->in_use->prev);
		for (ch = input->in_use; ; ch = ch->next)
		{
			assert(nchunks > 0);
			nchunks--;

			if (ch == chunk)
			{
				assert(!found_it);
				found_it = 1;
			}

			if (ch->next)
			{
				assert(ch->time_to_retry
					<= ch->next->time_to_retry);
				assert(ch->next->prev == ch);
			} else
				break;
		} /* for all $ch:unks $in_use */
		assert(ch == input->last_in_use);
		assert(found_it);
		assert(!nchunks);
	}
#endif /* VERIFY_LIST */
} /* enqueue_chunk */

void retry_chunk(struct chunk_st *chunk)
{
	enqueue_chunk(chunk, SCSI_STATUS_GOOD, Opt_request_retry_time);
}

void chunk_failed(struct chunk_st *chunk)
{
	enqueue_chunk(chunk, SCSI_STATUS_ERROR, Opt_request_retry_time);
}

void chunk_started(struct chunk_st *chunk)
{
	enqueue_chunk(chunk, SCSI_STATUS_GOOD, Opt_request_timeout);
}

/* Return a $chunk from $input->unused or allocate a new one. */
struct chunk_st *get_chunk(struct input_st *input)
{
	struct chunk_st *chunk;

	/* In future we might create new chunks if none is unused,
	 * but it didn't seem to improve throughput. */
	if (!input->unused)
		return NULL;

	chunk = input->unused;
	input->unused = chunk->next;
	chunk->next = NULL;
	assert(!chunk->prev);

	assert(input->nunused > 0);
	input->nunused--;

	assert(chunk->input == input);
	assert(!chunk->task);
	assert(!chunk->time_to_retry);
	if (IS_SEXYWRAP(input) || !LOCAL_TO_REMOTE(input))
		assert(!chunk->s.wrpbuf && !chunk->s.rtrbuf);

	return chunk;
} /* get_chunk */

/* Free resources allocated by init_input() or start_iscsi_read_requests().
 * $errno is preserved. */
void done_input(struct input_st *input)
{
	free_chunks(input->unused);
	free_chunks(input->in_use);
	input->unused = input->in_use = NULL;
} /* done_input */

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
	{	/* Discount sizeof(s). */
		max_chunk_size -= sizeof(chunk->s);
		max_chunk_size += (size_t)dst->blocksize * dst->optimum;
	}

	/* Create $input->input chunks.  This is just the initial number
	 * of chunks, get_chunk() could in theory allocate more if all
	 * the available chunks are failed for example. */
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

	/* $Last needs to be reset if sexywrap uses us more than once. */
	if (IS_SEXYWRAP(input))
		memset(&Last, 0, sizeof(Last));

	return 1;
} /* init_input */

void endpoint_connected(struct iscsi_context *iscsi, int status,
	void *command_data, void *private_data)
{
	int *connected = private_data;
	*connected = status == SCSI_STATUS_GOOD;
}

int connect_endpoint(struct iscsi_context *iscsi, struct iscsi_url *url,
	int reserve)
{
	unsigned ntries;

	iscsi_set_targetname(iscsi, url->target);
	iscsi_set_session_type(iscsi, ISCSI_SESSION_NORMAL);

	ntries = 0;
	for (;;)
	{
		struct pollfd pfd;
		int ret, connected;

		connected = -1;
		if (iscsi_full_connect_async(iscsi, url->portal, url->lun,
			endpoint_connected, &connected) != 0)
		{
			warn_iscsi("connect", iscsi);
			return -1;
		}

repoll:		pfd.fd = iscsi_get_fd(iscsi);
		pfd.events = iscsi_which_events(iscsi);
		if ((ret = xfpoll(&pfd, MEMBS_OF(&pfd), NULL)) < 0)
		{
			warn_errno("poll");
			return -1;
		} else if (ret > 0)
		{
			if (!run_iscsi_event_loop(iscsi, pfd.revents))
			{	/* run_iscsi_event_loop() logged the error. */
				if (!is_connection_error(iscsi, NULL,
						pfd.revents))
					return -1;
			} else if (!connected)
			{
				char const *err;

				err = iscsi_get_error(iscsi);
				warn("connect: %s: %s: %s",
					url->portal, url->target, err);

				/*
				 * Consider these fatal errors because they
				 * cannot be correct by reconnection attempts.
				 * Unfortunately we don't have access to the
				 * scsi_task and to the sense key and ascq,
				 * so we've got to check out the error string.
				 */
				if (strstr(err, "LOGICAL_UNIT_NOT_SUPPORTED"))
					return -1;
				if (strstr(err, "Target not found"))
					return -1;
			}
			else if (connected < 0)
				/* callback wasn't called */
				goto repoll;
			else	/* $connected > 0 */
				break;
		} else	/* Cancel timed out task. */
			iscsi_scsi_cancel_all_tasks(iscsi);

		/* Try hard to reconnect? */
		if (!Opt_retry_connection.enabled)
			return 0;
		ntries++;
		if (Opt_retry_connection.ntimes
				&& ntries >= Opt_retry_connection.ntimes)
			/* Maximum number of tries reached. */
			return 0;
		if (Opt_retry_connection.pause)
		{
			if (Opt_verbosity > 0)
				warn("retrying in %u second(s)...",
					Opt_retry_connection.pause);
			sleep(Opt_retry_connection.pause);
		} else if (Opt_verbosity > 0)
			warn("retrying connection");

		iscsi_disconnect(iscsi);
	} /* until $connected */

#ifdef LIBISCSI_API_VERSION
	/* $reserve the LUN if requested.  This might help decrease spurious
	 * RESERVATION CONFLICT errors (observed with EMC VNX 5300).
	 * This function is not available in libiscsi 1.4.  */
	if (reserve)
	{
		struct scsi_task *task;

		if (Opt_verbosity > 0)
			info("reserving LUN %u", url->lun);
		if (!(task = iscsi_reserve6_sync(iscsi, url->lun)))
		{
			warn_iscsi("reserve6", iscsi);
			return -1;
		} else if (is_iscsi_error(iscsi, task, "read6", task->status))
		{
			scsi_free_scsi_task(task);
			return -1;
		} else
			scsi_free_scsi_task(task);
	}
#endif /* ! LIBISCSI_API_VERSION */

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
		return connect_endpoint(endp->iscsi, endp->url,
			endp->reserve) > 0;
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
		iscsi_destroy_url(endp->url);
		iscsi_destroy_context(endp->iscsi);
		endp->iscsi = NULL;
	}
	endp->url = NULL;
}

/* Print the target's capacity and characteristics. */
void print_endpoint(struct endpoint_st const *endp)
{
	printf("%s target: nblocks=%u, blocksize=%u, "
		"granuality=%u, optimum=%u, maximum=%u\n",
		endp->which, endp->nblocks, endp->blocksize,
		endp->granuality, endp->optimum, endp->maximum);
} /* print_endpoint */

void set_endpoint_desired_optimum(struct endpoint_st *endp, char const *str)
{
	char *fend;
	float f, i;

	/* Any preference? */
	if (!str)
		return;

	/* Bail out if $str cannot be parsed or if it's not a number
	 * or it's too large, too close to 0, or is negative. */
	errno = 0;
	f = strtof(str, &fend);
	if (fend == str	|| (f == 0 && errno != 0)
	    		|| f == HUGE_VALF || f == -HUGE_VALF || f == NAN
			|| f < 0)
		goto out;

	/* In what units is $f? */
	if ((fend[0] == 'M' || fend[0] == 'm') && !fend[1])
	{	/* $f is in megabytes */
		f *= 1024.0 * 1024.0;
	} else if ((fend[0] == 'K' || fend[0] == 'k') && !fend[1])
	{	/* $f is in kilobytes */
		f *= 1024.0;
	} else if ((fend[0] == 'B' || fend[0] == 'b') && !fend[1])
	{	/* $f is an exact number of bytes */
		unsigned u;

		/* Refuse non-integers. */
		if (modff(f, &i) != 0.0)
			goto out;
		u = i;

		/* Is it a multiple of the block size? */
		if (u % endp->blocksize)
			die("chunk size %u bytes is not a multiple "
				"of the target's block size", u);
		endp->optimum = u / endp->blocksize;
		goto check_granuality;
	} else if (fend[0] == '%' && !fend[1])
	{	/* $f is a percentage of the target's optimum. */
		if (f > 100.0)
			goto out;
		f *= endp->optimum;
		f /= 100.0;
	} else if (!fend[0])
	{	/* $f is either the desired number of blocks (in which case
		 * we don't have to do anything with it) or a fraction of
		 * the optimum. */
		if (f < 1.0)
			f *= endp->optimum;
	} else
		goto out;

	/* Zero means keep to the optimum in all cases. */
	if (f == 0.0)
		return;

	if (fend[0] == '%' || !fend[0])
	{	/* $f is either a fraction or an exact number of blocks. */
		if (f < 1.0)
			die("%s: chunk size too small", str);
	} else
	{	/* $f is in bytes, convert it to blocks */
		if (f < endp->blocksize)
			die("%s: chunk size too small", str);
		f /= (float)endp->blocksize;
	}

	/* Truncate fractional block numbers. */
	if (modff(f, &i) != 0.0)
	{
		warn("chunk size %s is not a multiply of the block size, "
			"rounding down to %u blocks", str, (unsigned)i);
		f = i;
	} 

	/* Make sure we don't overflow $endp->optimum. */
	if (f >= (float)UINT_MAX)
		die("%s: chunk size too large", str);
	endp->optimum = f;

check_granuality:
	/* Is the determined desired optimum a multiple of the granuality? */
	if (endp->granuality && endp->optimum % endp->granuality)
		warn("chunk size %u is not a multiple "
			"of the target's granuality", endp->optimum);
	return;

out:	die("%s: invalid chunk size", str);
}
#endif /* SEXYCAT */

/* Calculate the optimal transfer size based on the target's preferences.
 * $endp is assumed to be initialized with stat_endpoint(). */
void calibrate_endpoint(struct endpoint_st *endp, char const *desired_optimum)
{
	/* The fallback optimal transfer size in bytes. */
	const size_t dflt_optimum = 1024*1024;

#ifdef SEXYCAT
	/* $desired_optimum comes from the command line. */
	set_endpoint_desired_optimum(endp, desired_optimum);
#else
	assert(!desired_optimum);
#endif

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
	int ret;

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
	}

	if (!(ret = connect_endpoint(endp->iscsi, endp->url, endp->reserve)))
	{
		if (Opt_retry_connection.enabled)
			warn("connection to the %s target timed out",
				endp->which);
		destroy_endpoint(endp);
		return 0;
	} else if (ret < 0 || !stat_endpoint(endp, fallback_blocksize))
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
		struct chunk_st *chunk;

		/* Recreate failed or timed out iSCSI write requests,
		 * but don't send them to $dst just yet. */
		if (!restart_requests(input, NULL, chunk_written))
			return 0;

		/* Done if !pending && (eof || disk full) */
		if (!input->in_use)
		{
			if (eof)
				break;
			if (!(input->top_block < input->until))
				break;
		}

		/* POLLIN <=> !eof && can request && !disk full */
		chunk = NULL;
		pfd[0].events = !eof
			&& (input->output->nreqs < input->dst->maxreqs)
			&& (chunk = get_chunk(input)) != NULL
			&& (input->top_block < input->until)
			? POLLIN : 0;
		pfd[1].events = iscsi_which_events(dst->iscsi);
		if ((ret = xfpoll(pfd, MEMBS_OF(pfd), input)) <= 0)
		{
			if (ret < 0)
				warn_errno("poll");
			if (chunk)
				return_chunk(chunk);
			if (ret < 0)
				return 0;
			continue;
		}

		/* Read $src if we can and create an iSCSI write request. */
		if (pfd[0].revents & POLLIN)
		{	/* We must have been waiting for POLLIN. */
			size_t max_chunk_size;

			/* $chunk <- read($src, $max_chunk_size) */
			assert(pfd[0].events & POLLIN);
			assert(chunk != NULL);
			max_chunk_size = read_chunk_size(NULL, dst,
				input->top_block, input->until);
			assert(max_chunk_size
				<= (size_t)dst->blocksize * dst->optimum);
			if (!xread(pfd[0].fd, chunk->ltrbuf,
				max_chunk_size, &chunk->sbuf))
			{	/* A read() error is serious enough
				   to terminate because of it. */
				warn_errno(src->fname
					? src->fname : "(stdin)");
				return_chunk(chunk);
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
			{	/* Not yet. */
				scsi_block_addr_t chunk_address;

				chunk_address = input->top_block;
				input->top_block +=
					chunk->sbuf / dst->blocksize;

				assert(!Last.writing
					|| Last.writing < chunk_address);

				/* Create the iSCSI write request. */
				chunk->task = write_endpoint(dst,
					chunk_address,
					chunk->ltrbuf, chunk->sbuf,
					chunk_written, chunk);
				if (!chunk->task)
				{	/* Unfortunately we can't re-read()
					 * the buffer, so we can't send the
					 * write request later. */
					warn_iscsi("write10", dst->iscsi);
					return_chunk(chunk);
					return 0;
				} else
				{
					Last.writing = chunk_address;
					chunk_started(chunk);
					input->output->nreqs++;
				}
			} else
			{	/* We didn't read anything. */
				eof = 1;
				return_chunk(chunk);
			}
		} else if (chunk)
			/* Not ready to read from $src after all. */
			return_chunk(chunk);

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
		eof = !input->in_use;
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
		if (!input->in_use)
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
		char const *desired_optimum;

		struct endpoint_st endp;
	} src, dst;
	struct input_st input;
	struct output_st output;
	char const *optstring;
	int isok, optchar, nop, overwrite, check_free_space;
	sigset_t alrm;

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
	optstring = "hVvqp:i:s:S:rc:m:z:I:d:D:RfFC:M:Z:b:B:t:T:H:Q:N"
		SEXYWRAP_CMDLINE;

	while ((optchar = getopt(argc, argv, optstring)) != EOF)
		switch (optchar)
		{
		case 'V':
			Opt_timestamp = 1;
			break;
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
		case 'r':
			src.endp.reserve = 1;
			break;
		case 'c':
			src.desired_optimum = optarg;
			dst.desired_optimum = optarg;
			break;
		case 'm':
			src.endp.maxreqs = atoi(optarg);
			dst.endp.maxreqs = src.endp.maxreqs;
			break;
		case 'z':
			src.fallback_blocksize = atoi(optarg);
			dst.fallback_blocksize = src.fallback_blocksize;
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
		case 'R':
			dst.endp.reserve = 1;
			break;
		case 'f':
			check_free_space = 1;
			break;
		case 'F':
			overwrite = 1;
			break;
		case 'C':
			dst.desired_optimum = optarg;
			break;
		case 'M':
			dst.endp.maxreqs = atoi(optarg);
			break;
		case 'Z':
			dst.fallback_blocksize = atoi(optarg);
			break;

		/* Error recovery */
		case 't':
			Opt_request_retry_time = atoi(optarg);
			break;
		case 'T':
			Opt_request_timeout = atoi(optarg);
			break;
		case 'H':
			Opt_retry_connection.enabled = 1;
			if (sscanf(optarg, "%ux%u",
				&Opt_retry_connection.pause,
				&Opt_retry_connection.ntimes) != 2)
			{
				Opt_retry_connection.pause = atoi(optarg);
				Opt_retry_connection.ntimes = 0;
			}
			break;
		case 'Q':
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
#ifndef LIBISCSI_API_VERSION
	if (src.endp.reserve || dst.endp.reserve)
		die("can't reserve LUNs");
#endif

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
	if (src.is_local)
		src.endp.maxreqs = 0;
	else if (!src.endp.maxreqs)
		src.endp.maxreqs = DFLT_INITIAL_MAX_ISCSI_REQS;
	if (dst.is_local)
		dst.endp.maxreqs = 0;
	else if (!dst.endp.maxreqs)
		dst.endp.maxreqs = DFLT_INITIAL_MAX_ISCSI_REQS;
	if (!Opt_min_output_batch)
		Opt_min_output_batch = 1;
	if (Opt_max_output_queue < Opt_min_output_batch)
		Opt_max_output_queue = Opt_min_output_batch;

	/* Init.  $Start is needed by warn*() quite early on. */
	signal(SIGPIPE, SIG_IGN);
	clock_gettime(CLOCK_MONOTONIC, &Start);
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
		set_endpoint_desired_optimum(&src.endp, src.desired_optimum);
		set_endpoint_desired_optimum(&dst.endp, dst.desired_optimum);

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
		calibrate_endpoint(&src.endp, NULL);
		calibrate_endpoint(&dst.endp, NULL);

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

	/* Allow report_progress() only interrupt xfpoll(). */
	sigemptyset(&alrm);
	sigaddset(&alrm, SIGALRM);
	if (Opt_progress)
	{
		sigprocmask(SIG_BLOCK, &alrm, NULL);
		signal(SIGALRM, report_progress);
		start_timer(Opt_progress);
	}

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
	if (Opt_progress)
		stop_timer();

	if (isok)
	{	/* If we're not $isok, the libiscsi context may be
		 * in inconsistent state, better not to risk using
		 * it anymore.  Otherwise log out. */
		jmp_buf jb;

		/* SIGALRM handler. */
		void nope(int unused)
		{	/* Log the error and throw an exception. */
			if (Opt_verbosity > 0)
				warn("logout timed out");
			longjmp(jb, 1);
		}

		/* Interrupt iscsi_logout_sync() in $Opt_request_timeout ms */
		if (Opt_request_timeout)
		{
			signal(SIGALRM, nope);
			sigprocmask(SIG_UNBLOCK, &alrm, NULL);
			start_timer(Opt_request_timeout);
		}

		if (src.endp.iscsi
		    		&& !setjmp(jb)
				&& iscsi_logout_sync(src.endp.iscsi) != 0)
			warn_iscsi("logout", src.endp.iscsi);
		if (dst.endp.iscsi
		    		&& !setjmp(jb)
		    		&& iscsi_logout_sync(dst.endp.iscsi) != 0)
			warn_iscsi("logout", dst.endp.iscsi);

		/* Stop the timer. */
		if (Opt_request_timeout)
		{
			stop_timer();
			signal(SIGALRM, SIG_IGN);
		}
	} /* $isok */

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
