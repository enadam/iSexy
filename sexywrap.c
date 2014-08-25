/*
 * sexywrap.c -- LD_PRELOAD:able library for transparent iSCSI support
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
 * TODO	provide pread(), pwrite() (don't forget *64())
 * TODO	provide stat(), lstat()
 * TODO	provide the dup*() functions; don't forget about fcntl(F_DUPFD)
 * TODO	support individual initiator names per target.  Maybe it should be
 *	encoded in the iscsi:// URL.
 */

/* Include sexycat.c */
/* We need types.h for off_t. */
#define _GNU_SOURCE
#include <sys/types.h>

/* For __NR_dup* */
#include <unistd.h>
#include <sys/syscall.h>

/* These functions call the real syscalls, even though they aren't declared
 * in glibc. */
extern int __open(char const *fname, int flags, ...);
extern int __close(int fd);
extern off_t __lseek(int fd, off_t offset, int whence);
extern ssize_t __read(int fd, void *buf, size_t sbuf);
extern ssize_t __write(int fd, void const *buf, size_t sbuf);

/* We override these functions, but certainly we want sexycat to use
 * the native versions. */
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

/* Include files */
#include <dlfcn.h>
#include <pthread.h>

#include <sys/stat.h>

#include <linux/major.h>
#include <linux/kdev_t.h>

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

/* Returns whether $target is opened.  If it's not, return it locked.
 * Note that pthread_mutex_trylock() will guaranteed to fail if _we_
 * (the current thread) have locked it. */
static struct target_st *is_target_unused(struct target_st *target)
{
	if (pthread_mutex_trylock(&target->lock))
		return NULL;
	if (target->endp.url)
	{
		pthread_mutex_unlock(&target->lock);
		return NULL;
	}

	assert(!target->endp.iscsi || iscsi_get_fd(target->endp.iscsi) < 0);
	return target;
}

/* Return a locked target which is not opened. */
static struct target_st *find_unused_target(void)
{
	unsigned i;

	for (i = 0; i < MEMBS_OF(Targets); i++)
		if (is_target_unused(&Targets[i]))
			return &Targets[i];

	return NULL;
}

/*
 * Find an in-use target with $fd, and return NULL if none found.
 * Note that if there's a target with $fd but it's currently locked,
 * we won't find it.  This is intentional, since very likely we're
 * called from libiscsi, for which we don't want to proxy the calls
 * to ... libiscsi.
 */
static struct target_st *find_target(int fd)
{
	unsigned i;

	if (fd < 0)
		return NULL;

	for (i = 0; i < MEMBS_OF(Targets); i++)
	{
		if (pthread_mutex_trylock(&Targets[i].lock))
			continue;
		if (Targets[i].endp.iscsi
				&& iscsi_get_fd(Targets[i].endp.iscsi) == fd)
		{
			assert(Targets[i].endp.url);
			return &Targets[i];
		}
		pthread_mutex_unlock(&Targets[i].lock);
	}

	return NULL;
}

/* Return a possibly newly allocated struct target_st.  If an already
 * existing structure is chosen, its ->iscsi is destroyed and overridden
 * by $iscsi. */
static struct target_st *new_target(struct iscsi_context *iscsi)
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
	}

	errno = EMFILE;
	return NULL;
}

/* Preserve $errno. */
static void release_target(struct target_st *target)
{
	int serrno = errno;
	pthread_mutex_unlock(&target->lock);
	errno = serrno;
}

/*
 * Log out (if logged in) and disconnect (if connected) $target->iscsi.
 * $target is expected to be locked, and will be unlocked at the end.
 * The libiscsi context is not destroyed and can be reused.
 */
static int cleanup_target(struct target_st *target)
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
}

static int write_blocks(struct input_st *input, scsi_block_addr_t from,
	void const *buf, size_t min, size_t max)
{
	size_t sbuf;
	struct pollfd pfd;
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

	pfd.fd = iscsi_get_fd(dst->iscsi);
	for (;;)
	{
		int ret;

		/* Called when a chunk is/not written and places the chunk
		 * in the failed list or returns it to the unused list. */
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

		if (!restart_requests(input, NULL, write_cb))
			goto enomem;
		if (!sbuf && !input->output->nreqs && !input->failed)
			return 1;

		/* Add new write request if we can. */
		if (sbuf > 0 && input->unused)
		{
			struct chunk_st *chunk;

			chunk = input->unused;
			take_chunk(chunk);

			assert(sbuf >= dst->blocksize);
			if (!iscsi_write10_task(
					dst->iscsi, dst->url->lun,
					(void *)buf, dst->blocksize,
					from++, 0, 0, dst->blocksize,
					write_cb, chunk))
				goto enomem;

			input->output->nreqs++;
			buf += dst->blocksize;
			sbuf -= dst->blocksize;
		} /* request write */

		pfd.events = iscsi_which_events(dst->iscsi);
		if ((ret = xfpoll(&pfd, 1, input)) < 0)
			return 0;
		else if (!ret)
			continue;

		if (!is_connection_error(dst->iscsi, NULL, pfd.revents))
		{
			if (!run_iscsi_event_loop(dst->iscsi, pfd.revents))
				return 0;
			free_surplus_unused_chunks(input);
		} else
		{
			if (!reconnect_endpoint(dst))
				return 0;
			reduce_maxreqs(dst, NULL);
			free_surplus_unused_chunks(input);
		}
	}

enomem:	errno = ENOMEM;
	return 0;
}

static int read_blocks(struct input_st *input, callback_t read_cb)
{
	struct pollfd pfd;
	struct endpoint_st *src = input->src;

	assert(!input->failed);
	assert(input->unused && input->nunused);
	pfd.fd = iscsi_get_fd(src->iscsi);
	for (;;)
	{
		int ret;

		if (!restart_requests(input, read_cb, NULL))
			goto enomem;
		if (!start_iscsi_read_requests(input, read_cb))
			goto enomem;
		if (!input->nreqs && !input->failed)
			return 1;

		pfd.events = iscsi_which_events(src->iscsi);
		if ((ret = xfpoll(&pfd, 1, input)) < 0)
			return 0;
		else if (!ret)
			continue;

		if (!is_connection_error(src->iscsi, NULL, pfd.revents))
		{
			if (!run_iscsi_event_loop(src->iscsi, pfd.revents))
				goto eio;
		} else
		{
			if (!reconnect_endpoint(src))
				goto eio;
			reduce_maxreqs(src, NULL);
			free_surplus_unused_chunks(input);
		}
	}

enomem:	errno = ENOMEM;
	return 0;
eio:	errno = EIO;
	return 0;
}

static int prepare_read(struct input_st *input, struct output_st *output,
	struct endpoint_st *src, off_t position, size_t *sbufp)
{
	off_t n;
	size_t sbuf;
	scsi_block_addr_t lba;
	scsi_block_count_t nblocks;

	/* Don't exercise ourselves unnecessarily if the caller didn't
	 * really want to read. */
	if (!*sbufp)
		return 0;
	sbuf = *sbufp;

	/* Check the file position. */
	n = src->blocksize * src->nblocks;
	if (position < n)
	{	/* OK, we're within bounds.  Let's check the max $sbuf. */;
		n -= position;
		if (sbuf > n)
			/* We can't read > disk size - position bytes. */
			sbuf = n;
		assert(sbuf > 0);
	} else	/* End of file reached. */
	{
		*sbufp = 0;
		return 0;
	}

	/* Prepare $input for reading. */
	memset(output, 0, sizeof(*output));
	if (!init_input(input, output, src, NULL))
		/* $errno is set */
		return 0;

	/* Calculate from which $lba to read $nblocks from. */
	n = position % src->blocksize;
	lba = (position - n) / src->blocksize;
	nblocks = 1;
	n = src->blocksize - n;
	if (sbuf > n)
	{	/* We'll need to read more than one blocks. */
		size_t m;

		n = sbuf - n;
		m = n % src->blocksize;
		nblocks += (n - m) / src->blocksize;
		if (m > 0)
			/* We'll need to read a last partial block. */
			nblocks++;
	}

	/* Settings for start_iscsi_read_requests(). */
	input->top_block = lba;
	input->until = lba + nblocks;

	/* Return the number of bytes that can be read. */
	*sbufp = sbuf;
	return 1;
}

/* glibc doesn't provide a symbol for the real __fxstat(), so we need
 * to find it out with libdl. */
static int real_fxstat(int version, int fd, struct stat *sbuf)
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
}

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
	if (!connect_endpoint(iscsi, url)
		|| !stat_endpoint(&target->endp, NULL))
	{	/* Return some generic error.  The called functions have
		 * already logged the real reason. */
		cleanup_target(target);
		errno = EIO;
		return -1;
	} else
	{	/* Finishing touches. */
		target->endp.maxreqs = DFLT_INITIAL_MAX_ISCSI_REQS;
		target->mode = flags & (O_RDONLY | O_WRONLY | O_RDWR);
	}

	release_target(target);
	return iscsi_get_fd(iscsi);
}

int open64(char const *fname, int flags, ...)
{
	/* Just redirect to the open() function above.  I hope this works
	 * even on 32bit systems (ie. O_LARGEFILE shouldn't have effect). */
	if (flags & O_CREAT)
	{
		int ret;
		va_list args;

		va_start(args, flags);
		ret = open(fname, flags, va_arg(args, int));
		va_end(args);

		return ret;
	} else
		return open(fname, flags);
}

/* TODO Not implemented */
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

/* TODO Not implemented */
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

/* TODO Not implemented */
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

int close(int fd)
{
	struct target_st *target;

	if (!(target = find_target(fd)))
		return __close(fd);
	else
		return cleanup_target(target);
}

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
	 * Nevertheless is sounds like a good idea to report the size
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
}

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
	if (offset < 0 || offset >= disksize)
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
}

#ifdef __LP64__
/* This case this is identical to lseek() so we can redirect to it.
 * Otherwise on 32bit platforms I don't know what to do. */
off_t lseek64(int fd, off_t offset, int whence)
{
	return lseek(fd, offset, whence);
}
#endif /* __LP64__ */

ssize_t read(int fd, void *buf, size_t sbuf)
{
	struct target_st *target;
	struct input_st input;
	struct output_st output;
	scsi_block_addr_t first;
	int fatal;

	/* Is it our call? */
	if (!(target = find_target(fd)))
		return __read(fd, buf, sbuf);

	/* Check whether the file is open for reading.  This is probably
	 * unnecessary because all files are open for reading, but let's
	 * be pedantic. */
	if (O_RDONLY && !(target->mode & (O_RDONLY|O_RDWR)))
	{
		release_target(target);
		errno = EBADF;
		return -1;
	}

	/* Return 0 if nothing should/could be read. */
	if (!prepare_read(&input, &output, &target->endp,
		target->position, &sbuf))
	{	/* $errno is set by prepare_read() */
		release_target(target);
		return sbuf > 0 ? -1 : 0;
	} else
	{
		fatal = 0;
		first = input.top_block;
	}

	/* Called when a chunk of data is read by libiscsi.
	 * It's purpose is to copy the received data to the
	 * appropriate place of $buf. */
	void read_cb(struct iscsi_context *iscsi, int status,
		void *command_data, void *private_data)
	{
		size_t offset, n;
		struct scsi_task *task = command_data;
		struct chunk_st *chunk = private_data;

		assert(task != NULL);
		assert(chunk != NULL);
		assert(LBA_OF(task) == chunk->srcblock);
		assert(chunk->srcblock >= first);
		assert(chunk->srcblock < input.until);

		assert(chunk->input->nreqs > 0);
		chunk->input->nreqs--;

		offset = target->position % target->endp.blocksize;
		if (fatal)
			/* Don't do anything. */;
		else if (is_iscsi_error(iscsi, task, "read10", status))
		{	/* Re-read the chunk. */
			scsi_free_scsi_task(task);
			chunk_failed(chunk);
			return;
		} else if (chunk->srcblock > first)
		{	/* $first < $chunk->srcblock < $first + $nblocks */
			/* This chunk possibly includes the last block. */
			/* $offset := where to copy */
			offset  = target->endp.blocksize - offset;
			offset += (chunk->srcblock - first - 1)
				* target->endp.blocksize;
			assert(offset < sbuf);

			/* $n := the number of bytes to copy */
			n = sbuf - offset;
			if (n > task->datain.size)
				n = task->datain.size;
			memcpy(buf+offset, task->datain.data, n);
			input.nread += n;
		} else if (task->datain.size > offset)
		{	/* First block, we may not need the first $offset
			 * bytes of the returned data. */
			assert(chunk->srcblock == first);

			/* $n := the number of bytes to copy */
			n = sbuf;
			if (offset + n > task->datain.size)
				n = task->datain.size - offset;
			memcpy(buf, &task->datain.data[offset], n);
			input.nread += n;
		} else
			/*
			 * Less than blocksize data returned.
			 * This is a serious error and indicates
			 * broken server, so let's consider this
			 * a $fatal error.
			 */
			fatal = 1;

		scsi_free_scsi_task(task);
		return_chunk(chunk);
	} /* read_cb */

	if (!read_blocks(&input, read_cb))
	{	/* Failure, $errno is set. */;
		sbuf = 0;
	} else if (fatal || input.nread < sbuf)
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
}

ssize_t write(int fd, void const *buf, size_t sbuf)
{
	struct target_st *target;
	struct input_st input;
	struct output_st output;
	scsi_block_addr_t from;
	scsi_block_count_t nblocks;
	unsigned blocksize, offset;
	struct scsi_task *first, *second, *last;
	size_t n;
	off_t cnt;

	/* Is it our call? */
	if (!(target = find_target(fd)))
		return __write(fd, buf, sbuf);

	/* Check whether the $target is open for writing. */
	if (!(target->mode & (O_WRONLY|O_RDWR)))
	{	/* Yes, this error is returned by write() in this case. */
		errno = EBADF;
		return -1;
	} else if (!sbuf)
		/* Nothing to write. */
		return 0;

	/* Return ENOSPC if nothing could be written. */
	if (!prepare_read(&input, &output, &target->endp,
		target->position, &sbuf))
	{
		if (!sbuf)
			errno = ENOSPC;
		return -1;
	}

	from = input.top_block;
	nblocks = input.until - from;
	blocksize = target->endp.blocksize;
	first = second = last = NULL;

	/* Called when a chunk of data is read.  Store them in $first,
	 * $second or $last as appropriate, depending on their block no. */
	void read_cb(struct iscsi_context *iscsi, int status,
		void *command_data, void *private_data)
	{
		struct scsi_task *task = command_data;
		struct chunk_st *chunk = private_data;

		assert(task != NULL);
		assert(chunk != NULL);
		assert(LBA_OF(task) == chunk->srcblock);
		assert(chunk->srcblock >= from);
		assert(chunk->srcblock < input.until);

		assert(chunk->input->nreqs > 0);
		chunk->input->nreqs--;

		if (is_iscsi_error(iscsi, task, "read10", status))
		{
			scsi_free_scsi_task(task);
			chunk_failed(chunk);
			return;
		}

		/* Determine which block has been read.  When checking
		 * the LBAs take care not to commit integer overflow. */
		if (chunk->srcblock == from)
		{
			assert(!first);
			first = task;
		} else if (chunk->srcblock - from == 1)
		{
			assert(!second);
			second = task;
		} else
		{
			assert(input.until - chunk->srcblock == 1);
			assert(!last);
			last = task;
		}

		return_chunk(chunk);
	} /* read_cb */

	/* Deallocate $first, $second, $last and $input,
	 * and set $errno if necessary. */
	int clean_up(int new_errno)
	{
		if (first)
			scsi_free_scsi_task(first);
		if (second)
			scsi_free_scsi_task(second);
		if (last)
			scsi_free_scsi_task(last);
		done_input(&input);
		release_target(target);

		if (new_errno)
			errno = new_errno;

		return -1;
	} /* clean_up */

	// We have the following cases regarding $target->position, $sbuf
	// and block boundaries:
	//
	////////////////////////////// CASE 1 ///////////////////////////////
	//
	//         position       sbuf
	// -----|-----|=============|-------------------|
	//    block               block               block
	//
	// $nblocks == 1
	// $offset > 0 (head is unaligned)
	// $sbuf < $blocksize
	// $offset + $sbuf == $blocksize
	// $first is used (request 1 block), $second and $last are unset
	//
	////////////////////////////// CASE 2 ///////////////////////////////
	//
	//   position       sbuf
	// -----|=============|-----|-------------------|
	//    block               block               block
	//
	// $nblocks == 1
	// $offset == 0 (head is aligned)
	// $sbuf < $blocksize, $offset + $sbuf < $blocksize
	// $offset + $sbuf < $blocksize
	// $first is used (request 1 block), $second and $last are unset
	//
	////////////////////////////// CASE 3 ///////////////////////////////
	//
	//         position              sbuf
	// -----|-----|=============|======|------------|
	//    block               block               block
	//
	// $nblocks == 2
	// $offset > 0 (head is unaligned)
	// $sbuf < $blocksize*2
	// $blocksize < $offset + $sbuf < $blocksize*2
	// ($sbuf - ($blocksize-$offset)) % $blocksize > 0 (tail is unaligned)
	// $first is used (request 2 blocks),
	// $second is used if sizeof($first) < $blocksize*2,
	// $last is unset
	//
	////////////////////////////// CASE 4 ///////////////////////////////
	//
	//         position                           sbuf
	// -----|-----|=============|===================|
	//    block               block               block
	//
	// $nblocks == 2
	// $offset > 0 (head is unaligned)
	// $blocksize < $sbuf < $blocksize*2
	// $offset + $sbuf == $blocksize*2
	// ($sbuf - ($blocksize-$offset)) % $blocksize == 0 (tail is aligned)
	// $first is used (request 1 block), $second and last are unset
	// if sizeof($first) < $blocksize*2, bulk copy is used
	// possible optimization: request $blocksize*2 for the $first chunk
	// (at the moment $n blocks == $n requests)
	//
	////////////////////////////// CASE 5 ///////////////////////////////
	//
	//         position                                         sbuf
	// -----|-----|=============|===================|=============|-----|
	//    block               block               block               block
	//
	// $nblocks > 2
	// $offset > 0 (head is unaligned)
	// $sbuf > $blocksize
	// $blocksize*2 < $offset + $sbuf < $blocksize*3
	// ($sbuf - ($blocksize-$offset)) % $blocksize > 0 (tail is unaligned)
	//   <=> ($offset + $sbuf) % $blocksize > 0
	// $first is used (request 1 block), $second is unset, bulk copy is
	// used, $last is used
	// possible optimization: if $sbuf is not too large, read and write
	// all the blocks with the $first chunk
	//
	////////////////////////////// CASES 6-7 ////////////////////////////
	//
	//   position                    sbuf
	// -----|===================|======|------------|
	//    block               block               block
	//
	//   position                                               sbuf
	// -----|===================|===================|=============|-----|
	//    block               block               block               block
	//
	// $nblocks > 1
	// $offset == 0 (head is aligned)
	// $sbuf > $blocksize
	// ($sbuf - ($blocksize-$offset)) % $blocksize > 0 (tail is unaligned)
	//   <=> $sbuf % $blocksize > 0 <=> ($offset + $sbuf) % $blocksize > 0
	// $first and second are unset, bulk copy is used, $last is used
	// possible optimization: like above
	//
	////////////////////////////// CASES 8-9 ////////////////////////////
	//
	//   position             sbuf
	// -----|===================|-------------------|
	//    block               block               block
	//
	//   position                                 sbuf
	// -----|===================|===================|
	//    block               block               block
	//
	// $nblocks can be anything
	// $offset == 0 (head is aligned)
	// $sbuf >= $blocksize
	// ($sbuf - ($blocksize-$offset)) % $blocksize == 0 (tail is aligned)
	//   <=> $sbuf % $blocksize == 0 <=> ($offset+$sbuf) % $blocksize == 0
	// $first, $second and $last are unset, bulk copy is used

	/* Get $first and possibly $second for cases 1-5. */
	assert(nblocks > 0);
	offset = target->position % blocksize;
	if (offset > 0 || sbuf < blocksize)
	{	/* Write < than a block or the head of $buf is unaligned. */
		if (offset + sbuf >= blocksize*2)
			/* Cases 4-5: adjust $input.until to request a single
			 * block for $first; for cases 1-3 $input.until is
			 * already correct (one or two blocks). */
			input.until = from + 1;
		if (!read_blocks(&input, read_cb))
			return clean_up(errno);

		/* Verify that we have usable $first and $second. */
		assert(first && !last);
		if (first->datain.size < blocksize)
			return clean_up(EIO);
		else if (blocksize < offset + sbuf
			&& offset + sbuf < blocksize*2
			&& first->datain.size < blocksize*2)
		{	/* Case 3 && sizeof($first) < 2 blocks */
			assert(second);
			if (second->datain.size < blocksize)
				return clean_up(EIO);
		} else	/* All other cases. */
			assert(!second);
	} /* get $first and $second */

	/* Get $last for cases 5-7. */
	if ((nblocks > 2 || (nblocks == 2 && !offset))
		&& (offset + sbuf) % blocksize > 0)
	{	/* We'll need to write back a partial $last block. */
		input.until = from + nblocks;
		input.top_block = input.until - 1;
		if (!read_blocks(&input, read_cb))
			return clean_up(errno);

		if (nblocks == 2)
		{	/* read_cb() mistook $second for $last. */
			assert(second && !last);
			last = second;
			second = NULL;
		} else
			assert(last != NULL);

		if (last->datain.size < blocksize)
			return clean_up(EIO);
	} /* get $last */

	/* Done with reading. */
	input.src = NULL;
	input.dst = &target->endp;

	/* Start writing.  $cnt := the number of byte written. */
	cnt = 0;
	if (offset > 0 || sbuf < blocksize)
	{	/* Cases 1-5: write back the $first chunk. */
		assert(first != NULL);

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
		from += (offset+n) / blocksize;
		if ((offset+n) % blocksize)
			from++;

		/* Case 3 special: write back the $second chunk. */
		if (blocksize < offset + sbuf+n
			&& offset + sbuf+n < blocksize*2
			&& first->datain.size < blocksize*2)
		{	/* $second should be large enough for the remains
			   of $buf.  Copy the remaining $buf to the head
			   of $second. */
			assert(second);
			assert(0 < sbuf && sbuf < blocksize);
			assert(sbuf < second->datain.size);
			memcpy(second->datain.data, buf, sbuf);
			if (write_blocks(&input, from, second->datain.data,
					sbuf, second->datain.size))
				cnt += sbuf;

			/* Worst case we had limited success with $first. */
			goto success;
		} else
			assert(!second);
	} else	/* Cases 6-9 */
		assert(!first && !second);

	/* Cases 4-9: bulk copy. */
	if (sbuf >= blocksize)
	{	/* $n := the number of bytes to write from $buf. */
		n = sbuf - sbuf % blocksize;
		assert(n % blocksize == 0);
		if (!write_blocks(&input, from, buf, n, sbuf))
			goto success;
		cnt += n;
		buf += n;
		sbuf -= n;
		from += n / blocksize;
	}

	/* Cases 5-7: write back the $last block */
	if (sbuf > 0)
	{	/* The remains of $buf must fit in $last. */
		assert(last);
		assert(sbuf < blocksize);
		memcpy(last->datain.data, buf, sbuf);
		if (write_blocks(&input, from, last->datain.data,
				sbuf, last->datain.size))
			cnt += sbuf;
	} else
		assert(!last);

success:
	clean_up(0);
	target->position += cnt;
	return cnt;
}

/* End of sexywrap.c */
