/*
 * sexywrap.c -- LD_PRELOAD:able library for transparent iSCSI support {{{
 *
 * Provided functions: open(), close(), fstat(), lseek(), read(), write()
 *
 * Sorry, no more documentation yet.
 *
 * To build it as a shared library:
 * cc -shared -pthread -Wall -O2 -s -fPIC -lrt -ldl -liscsi sexywrap.c \
 *	-o libsexywrap.so;
 * Usage: LD_PRELOAD=./libsexywrap.so cat <iscsi-url> > ide
 *
 * To build a combined binary of the wrapper library and the sexycat program:
 * cc -shared -pie -pthread -Wall -O2 -s -fPIE -DSEXYCAT -lrt -ldl -liscsi \
 *	sexywrap.c -o sexywrap;
 * Usage: sexywrap -x cat <iscsi-url> > ide
 * Or you can use the LD_PRELOAD method as well.
 *
 * TODO	make the allocation of $Targets dynamic
 * TODO	support O_CLOEXEC in open() (possibly set it always)
 * TODO	support individual initiator names per target;
 *      maybe it should be encoded in the iscsi:// URL
 * TODO	provide pread(), pwrite() (don't forget *64())
 * TODO	provide stat(), lstat()
 * TODO provide ftruncate()
 * TODO	provide the dup*() functions; don't forget about fcntl(F_DUPFD)
 * }}}
 */

/* Include sexycat.c {{{ */
/* We need types.h for off_t. */
#define _GNU_SOURCE
#include <sys/types.h>

/* For __NR_dup* */
#include <unistd.h>
#include <sys/syscall.h>

/* These functions are not declared in glibc, but they exist and call
 * the real syscalls. */
extern int __open(char const *fname, int flags, ...);
extern int __close(int fd);
extern off_t __lseek(int fd, off_t offset, int whence);
extern ssize_t __read(int fd, void *buf, size_t sbuf);
extern ssize_t __write(int fd, void const *buf, size_t sbuf);

/* Provide sexycat.c with such definitions that point to the real syscalss,
 * because we certainly want it to use them rather than our overrides. */
#define SEXYWRAP
#define open				__open
#define dup(fd)				syscall(__NR_dup, fd)
#define dup2(oldfd, newfd)		syscall(__NR_dup2, oldfd, newfd)
#define dup3(oldfd, newfd, flags)	syscall(__NR_dup3, oldfd, newfd,flags)
#define close				__close
#define lseek				__lseek
#define read				__read
#define write				__write
#include "sexycat.c"
#undef open
#undef dup
#undef dup2
#undef dup3
#undef close
#undef lseek
#undef read
#undef write
/* #include sexycat.c }}} */

/* Include files {{{ */
#include <dlfcn.h>
#include <pthread.h>

#include <sys/stat.h>

#include <linux/major.h>
#include <linux/kdev_t.h>
/* }}} */

/*
 * When write(2)ing, this is the maximum number of blocks we'll request for
 * but won't read, because it's entirely overwritten.  If enabled 2 reads
 * and 3 writes can be reduced to 1/1 in some cases. Of course this is a
 * memory and network traffic overhead (because these dead blocks need to
 * be transmitted and stored).
 */
#define DEAD_READ			1

/* Private functions {{{ */
/* Creating/finding/returning targets. */
static struct target_st *is_target_unused(struct target_st *target);
static struct target_st *find_unused_target(void);
static struct target_st *find_target(int fd);
static struct target_st *new_target(struct iscsi_context *iscsi);
static void release_target(struct target_st *target);
static int cleanup_target(struct target_st *target);

/* The middleware between libiscsi and our read()/write() overrides. */
static int get_rofi(struct input_st *input, struct output_st *output,
	struct endpoint_st *src, off_t position, size_t *sbufp);
static int read_blocks(struct input_st *input, callback_t read_cb);
static int write_blocks(struct input_st *input, scsi_block_addr_t from,
	void const *buf, size_t min, size_t max);

/* Utilities for the syscall overrides. */
static int real_fxstat(int version, int fd, struct stat *sbuf);
/* }}} */

/* Private variables {{{ */
static struct target_st
{
	pthread_mutex_t lock;
	unsigned mode;
	off_t position;
	struct endpoint_st endp;
} Targets[16] =
{
	{ PTHREAD_MUTEX_INITIALIZER },
	{ PTHREAD_MUTEX_INITIALIZER },
	{ PTHREAD_MUTEX_INITIALIZER },
	{ PTHREAD_MUTEX_INITIALIZER },
	{ PTHREAD_MUTEX_INITIALIZER },
	{ PTHREAD_MUTEX_INITIALIZER },
	{ PTHREAD_MUTEX_INITIALIZER },
	{ PTHREAD_MUTEX_INITIALIZER },
	{ PTHREAD_MUTEX_INITIALIZER },
	{ PTHREAD_MUTEX_INITIALIZER },
	{ PTHREAD_MUTEX_INITIALIZER },
	{ PTHREAD_MUTEX_INITIALIZER },
	{ PTHREAD_MUTEX_INITIALIZER },
	{ PTHREAD_MUTEX_INITIALIZER },
	{ PTHREAD_MUTEX_INITIALIZER },
	{ PTHREAD_MUTEX_INITIALIZER },
};
/* }}} */

/* Program code */
/* Targets {{{ */
/* Returns whether $target is opened.  If it's not, lock it and return. */
struct target_st *is_target_unused(struct target_st *target)
{
	/* pthread_mutex_trylock() is guaranteed to fail if we,
	 * the calling thread have locked it. */
	if (pthread_mutex_trylock(&target->lock))
		return NULL;
	if (target->endp.url)
	{	/* $url is not NULL, the $target is in use. */
		pthread_mutex_unlock(&target->lock);
		return NULL;
	}

	assert(!target->endp.iscsi || iscsi_get_fd(target->endp.iscsi) < 0);
	return target;
} /* is_target_unused */

/* Return a target which isn't associated with a file descriptor (not opened).
 * The returned target is locked. */
struct target_st *find_unused_target(void)
{
	unsigned i;

	/* Find an unused target in $Targets. */
	for (i = 0; i < MEMBS_OF(Targets); i++)
		if (is_target_unused(&Targets[i]))
			return &Targets[i];

	return NULL;
} /* find_unused_target */

/*
 * Find an in-use target with $fd, and return NULL if none found.
 * The returned target is locked.
 *
 * Note that if there's a target with $fd but it's currently locked,
 * we won't find it.  This is intentional, since very likely we're
 * called from libiscsi, for which we don't want to proxy the calls
 * to ... libiscsi.  On the other hand this makes it impossible to
 * use the same $fd from different threads concurrently, which can
 * be considered a limitation.
 */
struct target_st *find_target(int fd)
{
	unsigned i;

	/* If we return NULL the call will be proxied to the real syscall,
	 * which will handle this condition then. */
	if (fd < 0)
		return NULL;

	/* Find $fd in $Targets. */
	for (i = 0; i < MEMBS_OF(Targets); i++)
	{
		if (pthread_mutex_trylock(&Targets[i].lock))
			continue;
		if (Targets[i].endp.iscsi
			&& iscsi_get_fd(Targets[i].endp.iscsi) == fd)
		{	/* We've found the corresponding target. */
			assert(Targets[i].endp.url);
			return &Targets[i];
		}
		pthread_mutex_unlock(&Targets[i].lock);
	} /* for all @Targets */

	return NULL;
} /* find_target */

/* Return a possibly newly allocated struct target_st.  If an already
 * existing structure is chosen, its ->iscsi is destroyed and overridden
 * by $iscsi.  The returned $target is locked. */
struct target_st *new_target(struct iscsi_context *iscsi)
{
	struct target_st *target;

	if ((target = find_unused_target()) != NULL)
	{
		if (target->endp.iscsi)
		{	/* Replace $target-iscsi with a brand new one;
			 * it feels safer than reusing the old one. */
			iscsi_destroy_context(target->endp.iscsi);
			target->endp.iscsi = iscsi;
		}
		return target;
	} /* an unused $target is found */

	/* Out of $Targets. */
	errno = EMFILE;
	return NULL;
} /* new_target */

/* Lift the lock from $target, so it can be used by another function.
 * $errno is preserved. */
void release_target(struct target_st *target)
{
	int serrno = errno;
	pthread_mutex_unlock(&target->lock);
	errno = serrno;
} /* release_target */

/*
 * Log out (if logged in) and disconnect (if connected) $target->iscsi.
 * $target is expected to be locked, and will be unlocked at the end.
 * The libiscsi context is not destroyed and can be reused.
 */
int cleanup_target(struct target_st *target)
{
	int ret;
	struct iscsi_context *iscsi;

	/* We can't use destroy_endp() because we want to keep
	 * $iscsi around. */
	assert(target->endp.iscsi != NULL);
	iscsi = target->endp.iscsi;
	if (iscsi_get_fd(iscsi) >= 0)
	{	/* $iscsi is connected. */
		ret = iscsi_is_logged_in(iscsi)
			? iscsi_logout_sync(iscsi) : 0;
		iscsi_disconnect(iscsi);
		if (ret < 0)
			errno = EIO;
	} else /* $iscsi is not connected and consequently not logged in. */
		ret = 0;

	/* We might have a URL even if $iscsi is not connected. */
	if (target->endp.url)
	{	/* $url == NULL indicates that this target_st is unused. */
		iscsi_destroy_url(target->endp.url);
		target->endp.url = NULL;
	}

	release_target(target);
	return ret;
} /* cleanup_target */
/* targets }}} */

/* Middleware between libiscsi and read()/write(). {{{ */
/*
 * Initialize $input with $output and $endp, verify that at least part
 * of the requested region [$position..$position+*$sbufp[ is within the
 * limits of $endp, and figure out the corresponding block numbers (RoI)
 * [$input->top_block..$input->until[ which covers the requested region.
 *
 * If *$sbufp == 0 or $position is off the limits of $endp, *$sbufp is
 * set to/left 0 and 0 is returned.  Otherwise *$sbufp is reduced to > 0
 * as necessary.  On error false is returned and $errno is set.  Otherwise
 * true is returned.
 */
int get_rofi(struct input_st *input, struct output_st *output,
	struct endpoint_st *endp, off_t position, size_t *sbufp)
{
	off_t n;
	size_t sbuf;
	scsi_block_addr_t lba;
	scsi_block_count_t nblocks;

	/* Don't exercise ourselves unnecessarily if the user specified
	 * zero buffer size. */
	if (!*sbufp)
		return 0;
	sbuf = *sbufp;

	/* Check the file position. */
	n = (off_t)endp->blocksize * endp->nblocks;
	if (position < n)
	{	/* OK, we're within bounds.  Let's check the max $sbuf. */;
		n -= position;
		if (sbuf > n)
			/* We can only r/w up to (disk size ($n) - $position)
			 * bytes, so let's reduce $sbuf. */
			sbuf = n;
		assert(sbuf > 0);
	} else	/* End of file reached. */
	{
		*sbufp = 0;
		return 0;
	}

	/* Prepare $input for reading from $endp. */
	memset(output, 0, sizeof(*output));
	if (!init_input(input, output, endp, NULL))
		/* $errno is set */
		return 0;

	/*
	 * Calculate the starting $lba and the $nblocks to r/w.
	 *
	 *                   n0|    n1     |            n2             |
	 *                 +---v----------\+---------------------------.
	 *                 |   |           |               |     m     |
	 * |---blocksize---|---v-----------|---blocksize---|-----------v---|
	 *                 /position                                   |
	 *              lba    |                 sbuf                  |
	 *                     `---------------------------------------/
	 */
	n = position % endp->blocksize;
	lba = (position - n) / endp->blocksize;
	nblocks = 1;
	n = endp->blocksize - n;
	if (sbuf > n)
	{	/* We'll need to r/w more than one blocks. */
		size_t m;

		n = sbuf - n;
		m = n % endp->blocksize;
		nblocks += (n - m) / endp->blocksize;
		if (m > 0)
			/* We'll need to read a last partial block. */
			nblocks++;
	}

	/* Save the results. */
	input->top_block = lba;
	input->until = lba + nblocks;

	/* Return the # of bytes that can effectively be read/written. */
	*sbufp = sbuf;
	return 1;
} /* get_rofi */

/*
 * This function drives libiscsi for our read() override.  Essentially
 * it does the same as remote_to_local() in sexycat.c.  Reads $input->src
 * $input->until is reached, and calls $read_cb() for all received chunks.
 * Returns whether everything has gone well, and sets $errno if necessary.
 */
int read_blocks(struct input_st *input, callback_t read_cb)
{
	struct pollfd pfd;
	ino_t iscsi_src_ino;
	struct endpoint_st *src = input->src;

	/* Loop until we're out of read requests. */
	assert(!input->failed);
	assert(input->unused && input->nunused);
	pfd.fd = iscsi_get_fd(src->iscsi);
	iscsi_src_ino = 0;
	get_inode(pfd.fd, &iscsi_src_ino);
	for (;;)
	{
		int ret;

		/* (Re)create the iSCSI read requests and return
		 * if none needed. */
		if (!restart_requests(input, read_cb, NULL))
			break;
		if (!start_iscsi_read_requests(input, read_cb))
			break;
		if (!input->nreqs && !input->failed)
			return 1;

		/* Wait for input. */
		pfd.events = iscsi_which_events(src->iscsi);
		if ((ret = xfpoll(&pfd, 1, input)) < 0)
			return 0;
		else if (!ret)
			continue;

		/* (Re)send the iSCSI read requests. */
		if (!run_endpoint(src, pfd.revents))
		{
			errno = EIO;
			return 0;
		} else if (get_inode(pfd.fd, &iscsi_src_ino))
		{
			reduce_maxreqs(src);
			free_surplus_unused_chunks(input);
		}
	} /* until $input->until is reached */

	/* We ran into an error. */
	errno = ENOMEM;
	return 0;
} /* read_blocks */

/*
 * Write $buf to $input->dst starting $from block.  $buf is expected
 * to be on block-boundary, and an undefined number of bytes between
 * $min and $max will be written.  The limits aren't required to be
 * a multiple of $input->dst's block size.
 */
int write_blocks(struct input_st *input, scsi_block_addr_t from,
	void const *buf, size_t min, size_t max)
{
	size_t sbuf;
	struct pollfd pfd;
	ino_t iscsi_dst_ino;
	scsi_block_addr_t until;
	struct endpoint_st *dst = input->dst;

	assert(!input->failed);
	assert(input->unused && input->nunused);

	/* $sbuf := round_up($min, $blocksize) */
	sbuf = min;
	min %= dst->blocksize;
	if (min > 0)
		sbuf += dst->blocksize - min;
	assert(sbuf <= max);
	assert(sbuf % dst->blocksize == 0);

	/* $max := round_down($max, $blocksize) */
	max -= max % dst->blocksize;
	if (max < sbuf)
		max = sbuf;
	until = from + max / dst->blocksize;

	/* Loop until $sbuf is entirely consumed. */
	pfd.fd = iscsi_get_fd(dst->iscsi);
	iscsi_dst_ino = 0;
	get_inode(pfd.fd, &iscsi_dst_ino);
	for (;;)
	{
		int ret;

		/*
		 * Called when a chunk is/not written and add it to
		 * the failed list or returns it to the unused list.
		 * This callback is required by restart_requests()
		 * to know what's completed and what's failed.
		 */
		void write_cb(struct iscsi_context *iscsi, int status,
			void *command_data, void *private_data)
		{
			struct scsi_task *task = command_data;
			struct chunk_st *chunk = private_data;

			assert(task != NULL);
			assert(chunk != NULL);

			assert(chunk->input->output->nreqs > 0);
			chunk->input->output->nreqs--;

			if (is_iscsi_error(iscsi, task, "write10", status))
			{
				scsi_free_scsi_task(task);
				chunk_failed(chunk);
			} else
			{
				scsi_free_scsi_task(task);
				return_chunk(chunk);
			}
		} /* write_cb */

		/* Recreate failed iSCSI requests.
		 * Return if the job is done. */
		if (!restart_requests(input, NULL, write_cb))
			break;
		if (!sbuf && !input->output->nreqs && !input->failed)
			return 1;

		/* Add new write request if we can ($input has $unused
		 * chunks). */
		if (sbuf > 0 && input->unused)
		{
			struct chunk_st *chunk;

			chunk = input->unused;
			take_chunk(chunk);

			chunk->sbuf = read_chunk_size(NULL, dst, from, until);
			chunk->u.wbuf = buf;
			if (!write_endpoint(dst, from,
					chunk->u.wbuf, chunk->sbuf,
					write_cb, chunk))
				break;
			input->output->nreqs++;

			buf  += chunk->sbuf;
			if (sbuf > chunk->sbuf)
				sbuf -= chunk->sbuf;
			else	/* $sbuf < we wrote <= $max */
				sbuf = 0;
			from += chunk->sbuf / dst->blocksize;
		} /* request write */

		/* Wait until output is possible without blocking. */
		pfd.events = iscsi_which_events(dst->iscsi);
		if ((ret = xfpoll(&pfd, 1, input)) < 0)
			return 0;
		else if (!ret)
			continue;

		/* (Re)send the iSCSI write requests. */
		if (!run_endpoint(dst, pfd.revents))
		{
			errno = EIO;
			return 0;
		} else if (get_inode(pfd.fd, &iscsi_dst_ino))
			reduce_maxreqs(dst);
		free_surplus_unused_chunks(input);
	} /* until !$sbuf */

	errno = ENOMEM;
	return 0;
} /* write_blocks */
/* libiscsi middleware }}} */

/* libc overrides */
/* open*(2) {{{ */
/* O_ASYNC, O_NOCTTY and O_CREAT|O_EXCL flags are not supported. */
int open(char const *fname, int flags, ...)
{
	char const *initiator;
	struct iscsi_url *url;
	struct target_st *target;
	struct iscsi_context *iscsi;

	/* Clean up $target or deallocate $url and $iscsi. */
	void local_cleanup(int new_errno)
	{
		if (!target)
		{
			if (url)
				iscsi_destroy_url(url);
			iscsi_destroy_context(iscsi);
		} else
			cleanup_target(target);
		if (new_errno)
			errno = new_errno;
	}

	/* Unfortunately we need an $iscsi context before parsing $fname.
	 * Let's try to recycle an old one first. */
	target = find_unused_target();
	if (!target || !target->endp.iscsi)
	{	/* Assume that $SEXYWRAP_INITIATOR persists the same. */
		if (!(initiator = getenv("SEXYWRAP_INITIATOR")))
			initiator = "jaccom";
		if (!(iscsi = iscsi_create_context(initiator)))
			/* $errno is expected to be set. */
			return -1;
		if (target)
			target->endp.iscsi = iscsi;
	} else 
		iscsi = target->endp.iscsi;

	/* Try to parse $fname as an iscsi:// URL.  It might not be. */
	assert(iscsi != NULL);
	url = iscsi_parse_full_url(iscsi, fname);
	if (target)
	{
		assert(target->endp.iscsi == iscsi);
		assert(!target->endp.url);
		target->endp.url = url;
	}

	/* Is $fname an iscsi:// URL? */
	if (!url)
	{	/* No, redirect to open(2). */
		local_cleanup(0);

		if (flags & O_CREAT)
		{	/* Suppose va_end() doesn't alter $errno. */
			int ret;
			va_list args;

			va_start(args, flags);
			ret = __open(fname, flags, va_arg(args, int));
			va_end(args);

			return ret;
		} else	/* Mode is irrelevant. */
			return __open(fname, flags);
	} else if ((flags & (O_ASYNC|O_NOCTTY))
		|| ((flags & (O_CREAT|O_EXCL)) == (O_CREAT|O_EXCL)))
	{
		/*
		 * We can't create, truncate or append to iSCSI targets.
		 * Even though meaningless, O_CREAT/O_EXCL individually,
		 * and O_APPEND and O_TRUNC are tolerated (this is the
		 * same behavior as /dev/loop's).
		 *
		 * Maybe we should whitelist rather than blacklist
		 * unacceptable $flags.
		 */
		local_cleanup(EINVAL);
		return -1;
	} else if (flags & O_DIRECTORY)
	{	/* Definitely we're not a directory. */
		local_cleanup(ENOTDIR);
		return -1;
	}

	/* Get a new $target unless we have one already. */
	if (target)
	{
		assert(target->endp.url == url);
		target->endp.initiator = initiator;
	} else if ((target = new_target(iscsi)) != NULL)
	{
		target->endp.url = url;
		target->endp.initiator = initiator;
	} else
	{	/* Return the $errno set by new_target(). */
		local_cleanup(errno);
		return -1;
	}

	/* Connect to the target iSCSI. */
	if (!connect_endpoint(iscsi, url) || !stat_endpoint(&target->endp, 0))
	{	/* Return some generic error.  The called functions have
		 * already logged the real reason. */
		cleanup_target(target);
		errno = EIO;
		return -1;
	} else
	{	/* Finishing touches. */
		calibrate_endpoint(&target->endp, 0);
		target->endp.maxreqs = DFLT_INITIAL_MAX_ISCSI_REQS;
		target->mode = flags & (O_RDONLY | O_WRONLY | O_RDWR);
	}

	release_target(target);
	return iscsi_get_fd(iscsi);
} /* open */

/* Just redirect to the open() function above.  I hope this works
 * even on 32bit systems (ie. O_LARGEFILE shouldn't have effect). */
int open64(char const *fname, int flags, ...)
{
	if (flags & O_CREAT)
	{
		int ret;
		va_list args;

		/* Retrieve and pass on the permission bits. */
		va_start(args, flags);
		ret = open(fname, flags, va_arg(args, int));
		va_end(args);

		return ret;
	} else
		return open(fname, flags);
} /* open64 */
/* open }}} */

/* dup*(2) TODO neither is implemented {{{ */
int dup(int fd)
{
	struct target_st *target;

	if (!(target = find_target(fd)))
		return syscall(__NR_dup, fd);

	warn("attempt to dup() an iSCSI target");
	cleanup_target(target);

	errno = EINVAL;
	return -1;
}

int dup2(int oldfd, int newfd)
{
	struct target_st *target;

	if (!(target = find_target(oldfd)))
		return syscall(__NR_dup2, oldfd, newfd);

	warn("attempt to dup2() an iSCSI target");
	cleanup_target(target);

	errno = EINVAL;
	return -1;
}

int dup3(int oldfd, int newfd, int flags)
{
	struct target_st *target;

	if (!(target = find_target(oldfd)))
		return syscall(__NR_dup3, oldfd, newfd, flags);

	warn("attempt to dup3() an iSCSI target");
	cleanup_target(target);

	errno = EINVAL;
	return -1;
}
/* dup }}} */

/* cleanup_target() the one associated with $fd. {{{ */
int close(int fd)
{
	struct target_st *target;

	if (!(target = find_target(fd)))
		return __close(fd);
	else
		return cleanup_target(target);
} /* close }}} */

/* fstat(2): report the target as a block device {{{ */
/* glibc doesn't provide a symbol for the real __fxstat(), so we need
 * to find it out with libdl. */
int real_fxstat(int version, int fd, struct stat *sbuf)
{
	static int use_fstat, use_fxstat;
	static int (*libcs_fstat)(int, struct stat *);
	static int (*libcs_fxstat)(int, int, struct stat *);

	/* In theory NULL might be a valid function pointers (but I think,
	 * if it were so, a lot of programs could be broken).  So be nice
	 * and track the functions' availability with a different flag. */
	if (use_fxstat)
		return libcs_fxstat(version, fd, sbuf);
	if (use_fstat)
		return libcs_fstat(fd, sbuf);

	/*
	 * The way dlsym(3) proposes to resolve functions is not particularly
	 * threading-friendly, but we can't help much: even if we protected
	 * ourselves with a mutex, there could be other concurrent users of
	 * libdl.
	 */
	dlerror();

	/* Prefer __fxstat() because we have a $version number to honor. */
	libcs_fxstat = dlsym(RTLD_NEXT, "__fxstat");
	if (libcs_fxstat || !dlerror())
	{
		use_fxstat = 1;
		return libcs_fxstat(version, fd, sbuf);
	}

	/* glibc doesn't even provide this function, but who knows
	 * the mighty future. */
	libcs_fstat = dlsym(RTLD_NEXT, "fstat");
	if (libcs_fstat || !dlerror())
	{
		use_fstat = 1;
		return libcs_fstat(fd, sbuf);
	}

	/* What da fakk.  We could invoke the syscall directly as
	 * the very last resort, but at the moment I don't feel like it. */
	errno = ENOSYS;
	return -1;
} /* real_fxstat */

int __fxstat(int version, int fd, struct stat *sbuf)
{
	struct target_st *target;

	if (!(target = find_target(fd)))
		return real_fxstat(version, fd, sbuf);

	/* Do we understand the caller's struct stat? */
	if (version != _STAT_VER)
	{	/* No, glibc returns EINVAL in this case, so do we. */
		release_target(target);
		errno = EINVAL;
		return -1;
	}

	/* Fill $sbuf as sanely as possible. */
	if (real_fxstat(version, fd, sbuf) < 0)
	{
		release_target(target);
		return -1;
	}

	/* From the outsize we most resemble to a block device. */
	sbuf->st_mode = S_IFBLK | 0666;
	sbuf->st_rdev = MKDEV(SCSI_DISK7_MAJOR, 0);

	/*
	 * Nevertheless it sounds like a good idea to report the size
	 * of the target disk.  Note that st_blocks is not ->nblocks,
	 * but the number of 512-byte blocks.  Since ->blocksize is
	 * assumed to be a multiply of 512, we can divide it.
	 */
	sbuf->st_size     = target->endp.blocksize;
	sbuf->st_size    *= target->endp.nblocks;
	sbuf->st_blksize  = target->endp.blocksize;
	sbuf->st_blocks   = target->endp.blocksize / 512;
	sbuf->st_blocks  *= target->endp.nblocks;

	release_target(target);
	return 0;
} /* __fxstat */
/* stat }}} */

/* lseek(2): adjust $target->position {{{ */
off_t lseek(int fd, off_t offset, int whence)
{
	off_t disksize;
	struct target_st *target;

	if (!(target = find_target(fd)))
		return __lseek(fd, offset, whence);

	/* Calculate the final $offset. */
	disksize  = target->endp.blocksize;
	disksize *= target->endp.nblocks;
	if (whence == SEEK_CUR)
		offset += target->position;
	else if (whence == SEEK_END)
		offset += disksize;
	else if (whence != SEEK_SET)
		goto einval;
	if (offset < 0 || offset > disksize)
		/* $offset is out of range. */
		goto einval;

	/* Since we tell libiscsi the block number when we read/write,
	 * at the moment it's enough to remember the new position. */
	target->position = offset;
	release_target(target);
	return offset;

einval:
	release_target(target);
	errno = EINVAL;
	return -1;
} /* lseek */

#ifdef __LP64__
/* This case this is identical to lseek() so we can redirect to it.
 * Otherwise on 32bit platforms I don't know what to do. */
off_t lseek64(int fd, off_t offset, int whence)
{
	return lseek(fd, offset, whence);
}
#endif /* __LP64__ */
/* seek }}} */

/* read(2) {{{ */
ssize_t read(int fd, void *buf, size_t sbuf)
{
	int fatal;
	off_t nread;
	struct input_st input;
	struct output_st output;
	scsi_block_addr_t first;
	struct target_st *target;

	/* Is it our call? */
	if (!(target = find_target(fd)))
		return __read(fd, buf, sbuf);

	/* Check whether the file is open for reading.  This is probably
	 * dead code because all files are open for reading, but let's
	 * be pedantic. */
	if (O_RDONLY && !(target->mode & (O_RDONLY|O_RDWR)))
	{
		release_target(target);
		errno = EBADF;
		return -1;
	}

	/* Return 0 if nothing should/could be read. */
	if (!get_rofi(&input,&output, &target->endp, target->position,&sbuf))
	{	/* $errno is set by get_rofi(). */
		release_target(target);
		return sbuf > 0 ? -1 : 0;
	} else
	{
		fatal = 0;
		first = input.top_block;
	}

	/* Called when a chunk of data is read by libiscsi.  Its purpose
	 * is to copy the received data to the appropriate place of $buf. */
	void read_cb(struct iscsi_context *iscsi, int status,
		void *command_data, void *private_data)
	{
		size_t offset, n;
		struct scsi_task *task = command_data;
		struct chunk_st *chunk = private_data;

		assert(task != NULL);
		assert(chunk != NULL);

#ifdef LIBISCSI_API_VERSION
		task->ptr = scsi_cdb_unmarshall(task, SCSI_OPCODE_READ10);
#endif
		assert(LBA_OF(task) == chunk->address);

		assert(chunk->address >= first);
		assert(chunk->address < input.until);

		assert(chunk->input->nreqs > 0);
		chunk->input->nreqs--;

		offset = target->position % target->endp.blocksize;
		if (fatal)
			/* Failed @fatal:ly earlier, don't do anything. */;
		else if (is_iscsi_error(iscsi, task, "read10", status))
		{	/* Re-read the chunk. */
			scsi_free_scsi_task(task);
			chunk_failed(chunk);
			return;
		} else if (chunk->address > first)
		{	/* $first < $chunk->address < $first + $nblocks */
			/* This chunk possibly includes the last block. */
			/* $offset := where to copy in @buf */
			offset  = target->endp.blocksize - offset;
			offset += (chunk->address - first - 1)
				* target->endp.blocksize;

			/*
			 *  first     first+1 (=: address)
			 * /     blocksize   \/task->datain.data\
			 * |--------v---------|======v===========|
			 * |        |offset1&2|  n   |      first+2
			 * v      ./+----------------+
			 * offset0  |      sbuf      |
			 *       position
			 */

			/* $n := the number of bytes to copy */
			assert(sbuf > offset);
			n = sbuf > offset + task->datain.size
				? task->datain.size
				: sbuf - offset;
			memcpy(buf+offset, task->datain.data, n);
			nread += n;
		} else if (task->datain.size > offset)
		{	/* First block, we may not need the first $offset
			 * bytes of the returned data. */
			assert(chunk->address == first);

			/* $n := the number of bytes to copy */
			assert(offset < task->datain.size);
			n = offset + sbuf > task->datain.size
				? task->datain.size - offset
				: sbuf;
			memcpy(buf, &task->datain.data[offset], n);
			nread += n;
		} else	/* Less than blocksize data returned.  This is
			 * a serious error and indicates broken server,
			 * so let's consider this a $fatal error. */
			fatal = 1;

		scsi_free_scsi_task(task);
		return_chunk(chunk);
	} /* read_cb */

	nread = 0;
	if (!read_blocks(&input, read_cb))
	{	/* Failure, $errno is set. */;
		sbuf = 0;
	} else if (fatal || nread < sbuf)
	{	/* We've read less than expected, but we have no means
		 * knowing which blocks have been read, so let's report
		 * total failure. */
		sbuf = 0;
		errno = EIO;
	} else	/* Success */
		target->position += sbuf;

	release_target(target);
	done_input(&input);
	return sbuf ? sbuf : -1;
} /* read }}} */

/* write(2) {{{ */
ssize_t write(int fd, void const *buf, size_t sbuf)
{
	struct target_st *target;
	struct input_st input;
	struct output_st output;
	scsi_block_addr_t from;
	scsi_block_count_t nblocks;
	unsigned blocksize, offset;
	struct scsi_task *first, *last;
	size_t n;
	off_t cnt;

	/* Is it our call? */
	if (!(target = find_target(fd)))
		return __write(fd, buf, sbuf);

	/* Check whether the $target is open for writing. */
	if (!(target->mode & (O_WRONLY|O_RDWR)))
	{	/* Yes, this error is returned by write() in this case. */
		release_target(target);
		errno = EBADF;
		return -1;
	} else if (!sbuf)
	{	/* Nothing to write. */
		release_target(target);
		return 0;
	}

	/* Return ENOSPC if nothing could be written. */
	if (!get_rofi(&input,&output, &target->endp, target->position,&sbuf))
	{	/* If $sbuf > 0 $errno is set by get_rofi(). */
		release_target(target);
		if (!sbuf)
			errno = ENOSPC;
		return -1;
	}

	/* First we'll read $first, $second and $last, whichever is needed. */
	from = input.top_block;
	nblocks = input.until - from;
	blocksize = target->endp.blocksize;
	first = last = NULL;

	/* Called when a chunk of data is read.  Store them in $first,
	 * $second or $last as appropriate, depending on their block no. */
	void read_cb(struct iscsi_context *iscsi, int status,
		void *command_data, void *private_data)
	{
		struct scsi_task *task = command_data;
		struct chunk_st *chunk = private_data;

		assert(task != NULL);
		assert(chunk != NULL);

#ifdef LIBISCSI_API_VERSION
		/* See chunk_read() in sexycat.c. */
		task->ptr = scsi_cdb_unmarshall(task, SCSI_OPCODE_READ10);
#endif

		assert(chunk->address == LBA_OF(task));
		assert(chunk->address >= from);
		assert(chunk->address < input.until);
		assert(task->datain.size > 0);
		assert(task->datain.size % blocksize == 0);

		assert(chunk->input->nreqs > 0);
		chunk->input->nreqs--;

		if (is_iscsi_error(iscsi, task, "read10", status))
		{
			scsi_free_scsi_task(task);
			chunk_failed(chunk);
			return;
		}

		/* Is it the $first or $last chunk? */
		if (chunk->address == from)
		{	/* We'll write the head and possibly
			 * the tail of $buf to $first. */
			assert(!first);
			first = task;
		} else if (input.until - chunk->address
			<= task->datain.size / blocksize)
		{	/* $address + $nblocks >= $until.
			 * We'll write the tail of $buf to $last. */
			assert(!last);
			last = task;
		} else	/* Not interested in this chunk. */
			scsi_free_scsi_task(task);

		return_chunk(chunk);
	} /* read_cb */

	/* Deallocate $first, $last and $input, and set $errno as needed. */
	int clean_up(int new_errno)
	{
		if (first)
			scsi_free_scsi_task(first);
		if (last)
			scsi_free_scsi_task(last);
		done_input(&input);
		release_target(target);

		if (new_errno)
			errno = new_errno;

		return -1;
	} /* clean_up */

	/*
	 * These are the possible cases regarding $target->position, {{{
	 * $sbuf and block boundaries.  Since we can only read/write
	 * in blocks, our strategy is to read the $first and $last blocks,
	 * modify their contents and write them back.  If there's a gap
	 * in between (blocks to overwrite completely) we just write them
	 * out ("bulk copy").  This is best illustrated by case 4.
	 *
	 * Not all the cases require $first and/or $last, as indicated below.
	 * Furthermore in some cases we [can] optimize by loading the entire
	 * range of interest (RoI) into $first, overwriting the appropriate
	 * part of it with $buf and writing it back.  back.  This can reduce
	 * the number of read/write operations, which can be more expensive
	 * than transferring some untouched data back and forth.
	 *
	 * What can complicate things is that once we request more than one
	 * block we may get more than one chunks in return.  So for example
	 * in case 4, even if we requested to read 3 blocks we might get two
	 * chunks: one for the first block and another for the remaining two.
	 * We need to handle this situation.
	 *
	 * /////////////////////////// CASE 1 //////////////////////////////
	 *
	 *         offset         sbuf
	 * -----|-----|=============|-------------------|
	 *    block               block               block
	 *
	 * $nblocks == 1
	 * $offset > 0 (head is unaligned)
	 * $sbuf < $blocksize
	 * $offset + $sbuf == $blocksize
	 * $first is used (1 block), $last is unset
	 *
	 * /////////////////////////// CASE 2 //////////////////////////////
	 *
	 *   offset         sbuf
	 * -----|=============|-----|-------------------|
	 *    block               block               block
	 *
	 * $nblocks == 1
	 * $offset == 0 (head is aligned)
	 * $sbuf < $blocksize, $offset + $sbuf < $blocksize
	 * $offset + $sbuf < $blocksize
	 * $first is used (1 block), $last is unset
	 *
	 * /////////////////////////// CASE 3 //////////////////////////////
	 *
	 *         offset                sbuf
	 * -----|-----|=============|======|------------|
	 *    block               block               block
	 *
	 * $nblocks == 2
	 * $offset > 0 (head is unaligned)
	 * $sbuf < $blocksize*2
	 * $blocksize < $offset + $sbuf < $blocksize*2
	 * ($sbuf - ($blocksize-$offset)) % $blocksize > 0 (tail is unaligned)
	 * $first is used (request 2 blocks),
	 * $last is used if sizeof($first) < $nblocks
	 *
	 * /////////////////////////// CASE 4 //////////////////////////////
	 *
	 *         offset                                           sbuf
	 * -----|-----|=============|===================|=============|-----|
	 *    block               block               block               block
	 *
	 * $nblocks > 2
	 * $offset > 0 (head is unaligned)
	 * $sbuf > $blocksize
	 * $blocksize*2 < $offset + $sbuf
	 * ($sbuf - ($blocksize-$offset)) % $blocksize > 0 (tail is unaligned)
	 *   <=> ($offset + $sbuf) % $blocksize > 0
	 * $first is used (request $nblocks if 1+DEAD_READ+1 >= $nblocks,
	 *   otherwise request 1 block),
	 * $last is used if sizeof($first) < $nblocks
	 * bulk copy is used if sizeof($first) < $nblocks-1
	 *
	 * /////////////////////////// CASE 5 //////////////////////////////
	 *
	 *         offset                             sbuf
	 * -----|-----|=============|===================|
	 *    block               block               block
	 *
	 * $nblocks > 1
	 * $offset > 0 (head is unaligned)
	 * $blocksize < $sbuf
	 * $offset + $sbuf >= $blocksize*2
	 * ($sbuf - ($blocksize-$offset)) % $blocksize == 0 (tail is aligned)
	 * $first is used (request $nblocks if 1+DEAD_READ >= $nblocks,
	 *   otherwise request 1 block)
	 * $last can be set, but isn't used
	 * bulk copy is used if sizeof($first) < $nblocks
	 *
	 * /////////////////////////// CASES 6-7 ///////////////////////////
	 *
	 *   offset                      sbuf
	 * -----|===================|======|------------|
	 *    block               block               block
	 *
	 *   offset                                                 sbuf
	 * -----|===================|===================|=============|-----|
	 *    block               block               block               block
	 *
	 * $nblocks > 1
	 * $offset == 0 (head is aligned)
	 * $sbuf > $blocksize
	 * ($sbuf - ($blocksize-$offset)) % $blocksize > 0 (tail is unaligned)
	 *   <=> $sbuf % $blocksize > 0 <=> ($offset + $sbuf) % $blocksize > 0
	 * $first is unset, bulk copy is used, $last is used
	 * possible optimization: like above
	 *
	 * /////////////////////////// CASES 8-9 ///////////////////////////
	 *
	 *   offset               sbuf
	 * -----|===================|-------------------|
	 *    block               block               block
	 *
	 *   offset                                   sbuf
	 * -----|===================|===================|
	 *    block               block               block
	 *
	 * $nblocks >= 1
	 * $offset == 0 (head is aligned)
	 * $sbuf >= $blocksize
	 * ($sbuf - ($blocksize-$offset)) % $blocksize == 0 (tail is aligned)
	 *   <=> $sbuf % $blocksize == 0 <=> ($offset+$sbuf) % $blocksize == 0
	 * $first and $last are unset, bulk copy is used
	 * }}}
	 */

	/* Get $first and/or $last for cases 1-7. */
	assert(nblocks > 0);
	offset = target->position % blocksize;
	if (offset > 0 || sbuf % blocksize)
	{
		/*
		 * We can optimize by reading the entire RoI into $first in
		 * case 4:   if 1+DEAD_READ+1 >= $nblocks
		 * case 5:   if 1+DEAD_READ >= $nblocks
		 * case 6/7: if DEAD_READ+1 >= $nblocks
		 * Otherwise (that is, if the conditions below ARE met)
		 * just read a single block to $first/$last.
		 */
		if (!offset)
		{	/* Cases 2/6/7 */
			if (nblocks > DEAD_READ + 1)
				/* Load the $last block (not in case 2). */
				input.top_block = input.until - 1;
		} else if ((offset + sbuf) % blocksize == 0)
		{	/* Case 1/5 */
			if (nblocks > 1 + DEAD_READ)
				/* Load only the $first block (!case 1). */
				input.until = from + 1;
		} else
		{	/* Case 3/4 */
			if (nblocks > 1 + DEAD_READ + 1)
				/* Likewise (not in case 3) */
				input.until = from + 1;
		} /* for each case 1-7 */

		if (!read_blocks(&input, read_cb))
			return clean_up(errno);

		/* Verify that we have've got $first and/or $last. */
		if (offset + sbuf <= blocksize)
		{	/* Cases 1-2 */
			assert(first && !last);
		} else if (offset > 0 && (offset + sbuf) % blocksize)
		{	/* Cases 3-4 */
			assert(first);
			if (first->datain.size < nblocks*blocksize && !last)
			{	/* We need the $last block. */
				input.top_block = from + nblocks - 1;
				input.until = input.top_block + 1;
				if (!read_blocks(&input, read_cb))
					return clean_up(errno);
				assert(last);
			}
		} else if (offset > 0)
		{	/* Case 5 */
			assert(first);
			if (last)
			{	/* Use bulk copy instead of
				 * writing back $last. */
				scsi_free_scsi_task(last);
				last = NULL;
			}
		} else
		{	/* Cases 6-7 */
			assert(!offset && sbuf % blocksize && nblocks > 1);
			if (first && first->datain.size < nblocks * blocksize)
			{	/* Similarly, use bulk copy rather than
				 * writing back $first.*/
				assert(last);
				scsi_free_scsi_task(first);
				first = NULL;
			} else if (!first)
				assert(last);
		} /* for each case 1-7 */
	} /* get $first and $last */

	/* Done with reading. */
	input.src = NULL;
	input.dst = &target->endp;

	/* Write $first back.  $cnt := the number of bytes written. */
	cnt = 0;
	if (first)
	{
		/* We must not use $first above its last block boundary,
		 * because we couldn't write it back.  Of course such a
		 * chunk shouldn't have been returned in the first place. */
		first->datain.size -= first->datain.size % blocksize;

		/* Copy the head of $buf into $first and write it back.
		 * $offset is index where to write the head of $buf.
		 * $n := the number of bytes to copy. */
		assert(offset < blocksize);
		assert(first->datain.size >= blocksize);
		assert(first->datain.size > offset);
		n = first->datain.size - offset;
		if (n > sbuf)
			n = sbuf;
		memcpy(&first->datain.data[offset], buf, n);
		if (!write_blocks(&input, from, first->datain.data,
				offset+n, first->datain.size))
			return clean_up(errno);
		cnt += n;
		buf += n;
		sbuf -= n;
		from += (offset + n) / blocksize;

		/* Did we manage to write everything out in a single burst? */
		if ((offset + n) % blocksize)
		{	/* Cases 1-2 and possibly 3-7. */
			assert(!sbuf);
			assert(!last);
			assert(++from == input.until);
			goto finito;
		}
	} /* write back $first */
	/* Cases 1-2 are considered done. */

	/* Bulk copy $n..$sbuf bytes. */
	if (!last)
		/* Case 5/8/9 */
		n = sbuf;
	else if (LBA_OF(last) > from)
		/* Cases 6-7 and possibly 4 */
		n = (LBA_OF(last) - from) * blocksize;
	else	/* Cases 3 and possibly 4 */
		n = 0;
	if (n > 0)
	{
		assert(n <= sbuf);
		assert(n % blocksize == 0);
		if (!write_blocks(&input, from, buf, n, sbuf))
			goto finito;
		cnt += n;
		buf += n;
		sbuf -= n;
		from += n / blocksize;
	} /* bulk copy */
	/* Cases 5/8/9 are considered done. */

	/* The remaining cases are 3-4/6-7.  Write back the $last chunk. */
	if (last)
	{
		assert(sbuf > 0);

		/* It's possible, though unlikely that in case 4
		 * $first and $last overlap. */
		if (LBA_OF(last) < from)
		{	/* $n := the offset in $last to write $from */
			assert(first);
			assert(LBA_OF(first) + first->datain.size/blocksize
				== from);
			n = (from - LBA_OF(last)) * blocksize;
		} else
			n = 0;
		assert(last->datain.size >= n + sbuf);

		memcpy(&last->datain.data[n], buf, sbuf);
		if (!write_blocks(&input, from, &last->datain.data[n],
				sbuf, last->datain.size - n))
			return clean_up(errno);
		cnt += sbuf;
	} else	/* We must have consumed the entire $buf. */
		assert(!sbuf);

finito:
	clean_up(0);
	target->position += cnt;
	return cnt;
} /* write }}} */

/* vim: set foldmethod=marker foldmarker={{{,}}}: */
/* End of sexywrap.c */
