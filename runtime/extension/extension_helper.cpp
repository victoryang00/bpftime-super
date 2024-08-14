#include "bpftime_helper_group.hpp"
#include <cerrno>
#include <sched.h>
#ifdef ENABLE_BPFTIME_VERIFIER
#include "bpftime-verifier.hpp"
#endif
#include "spdlog/spdlog.h"
#include <map>
#include <stdio.h>
#include <stdarg.h>
#include <cstring>
#include <time.h>
#include <unistd.h>
#include <ctime>
#include <filesystem>
#include "bpftime.hpp"
#include "bpftime_shm.hpp"
#include "bpftime_internal.h"
#include <spdlog/spdlog.h>
#include <vector>

#if defined (BPFTIME_ENABLE_IOURING_EXT) && __linux__
#include "liburing.h"
#endif

using namespace std;

#if BPFTIME_ENABLE_FS_HELPER
uint64_t bpftime_get_abs_path(const char *filename, const char *buffer,
			      uint64_t size)
{
	auto path = std::filesystem::absolute(filename);
	return (uint64_t)(uintptr_t)strncpy((char *)(uintptr_t)buffer,
					    path.c_str(), size);
}

uint64_t bpftime_path_join(const char *filename1, const char *filename2,
			   const char *buffer, uint64_t size)
{
	auto path = std::filesystem::path(filename1) /
		    std::filesystem::path(filename2);
	return (uint64_t)(uintptr_t)strncpy((char *)(uintptr_t)buffer,
					    path.c_str(), size);
}
#endif

namespace bpftime
{
/*
io_uring are only available in linux atm 
so adding linux guards to the following code
*/

#if defined (BPFTIME_ENABLE_IOURING_EXT) && __linux__
static int submit_io_uring_write(struct io_uring *ring, int fd, char *buf,
				 size_t size)
{
	struct io_uring_sqe *sqe;

	sqe = io_uring_get_sqe(ring);
	if (!sqe) {
		return 1;
	}
	io_uring_prep_write(sqe, fd, buf, size, -1);
	sqe->user_data = 1;

	return 0;
}

static int submit_io_uring_read(struct io_uring *ring, int fd, char *buf,
				size_t size, off_t offset)
{
	struct io_uring_sqe *sqe;

	sqe = io_uring_get_sqe(ring);
	if (!sqe) {
		return 1;
	}

	io_uring_prep_read(sqe, fd, buf, size, offset);
	sqe->user_data = 2;

	return 0;
}

static int submit_io_uring_send(struct io_uring *ring, int fd, char *buf,
				size_t size, int flags)
{
	struct io_uring_sqe *sqe;

	sqe = io_uring_get_sqe(ring);
	if (!sqe) {
		return 1;
	}

	io_uring_prep_send(sqe, fd, buf, size, flags);
	sqe->user_data = 3;

	return 0;
}

static int submit_io_uring_recv(struct io_uring *ring, int fd, char *buf,
				size_t size, int flags)
{
	struct io_uring_sqe *sqe;

	sqe = io_uring_get_sqe(ring);
	if (!sqe) {
		return 1;
	}

	io_uring_prep_recv(sqe, fd, buf, size, flags);
	sqe->user_data = 4;

	return 0;
}

static int submit_io_uring_fsync(struct io_uring *ring, int fd)
{
	struct io_uring_sqe *sqe;

	sqe = io_uring_get_sqe(ring);
	if (!sqe) {
		return 1;
	}

	io_uring_prep_fsync(sqe, fd, IORING_FSYNC_DATASYNC);
	sqe->user_data = 5;

	return 0;
}

static int io_uring_init(struct io_uring *ring)
{
	int ret = io_uring_queue_init(1024, ring, IORING_SETUP_SINGLE_ISSUER);
	
	if (ret) {
		return 1;
	}
	return 0;
}

static int io_uring_get_sqe_ptr(struct io_uring *ring)
{
	return io_uring_get_sqe(ring);
}

static int io_uring_submit_and_wait_and_seen(struct io_uring *ring, int count)
{
	int ret = io_uring_submit_and_wait(ring, count);
	if (ret < 0) {
		return ret;
	}
	return 0;
}

static int io_uring_wait_and_seen(struct io_uring *ring,
				  struct io_uring_cqe *cqe)
{
	int ret = io_uring_wait_cqe(ring, &cqe);
	if (ret < 0) {
		return ret;
	}
	io_uring_cqe_seen(ring, cqe);
	return 0;
}

static int io_uring_set_linkflag(struct io_uring_sqe *sqe)
{
    if (!sqe) {
        return -1;  
    }
    sqe->flags |= IOSQE_IO_LINK; 
    return 0;  
}

static struct io_uring ring;

uint64_t io_uring_init_global(void)
{
	return io_uring_init(&ring);
}

uint64_t bpftime_io_uring_submit_write(int fd, char *buf, size_t size)
{
	return submit_io_uring_write(&ring, fd, buf, size);
}
uint64_t bpftime_io_uring_submit_read(int fd, char *buf, size_t size,
				      off_t offset)
{
	return submit_io_uring_read(&ring, fd, buf, size, offset);
}
uint64_t bpftime_io_uring_submit_send(int fd, char *buf, size_t size, int flags)
{
	return submit_io_uring_send(&ring, fd, buf, size, flags);
}
uint64_t bpftime_io_uring_submit_recv(int fd, char *buf, size_t size, int flags)
{
	return submit_io_uring_recv(&ring, fd, buf, size, flags);
}
uint64_t bpftime_io_uring_submit_fsync(int fd)
{
	return submit_io_uring_fsync(&ring, fd);
}

uint64_t bpftime_io_uring_wait_and_seen(void)
{
	struct io_uring_cqe *cqe = nullptr;
	return io_uring_wait_and_seen(&ring, cqe);
}

uint64_t bpftime_io_uring_submit(void)
{
	return io_uring_submit(&ring);
}

uint64_t bpftime_io_uring_setlink(*sqe)
{
	return io_uring_set_linkflag(sqe);
}

uint64_t bpftime_io_uring_submit_and_wait(int count)
{
	return io_uring_submit_and_wait_and_seen(&ring, count);
}

uint64 bpftime_io_uring_get_sqe(void)
{
	return io_uring_get_sqe_ptr(&ring);
}
#endif

extern const bpftime_helper_group extesion_group = { {
	{ UFUNC_HELPER_ID_FIND_ID,
	  bpftime_helper_info{
		  .index = UFUNC_HELPER_ID_FIND_ID,
		  .name = "__ebpf_call_find_ufunc_id",
		  .fn = (void *)__ebpf_call_find_ufunc_id,
	  } },
	{ UFUNC_HELPER_ID_DISPATCHER,
	  bpftime_helper_info{
		  .index = UFUNC_HELPER_ID_DISPATCHER,
		  .name = "__ebpf_call_ufunc_dispatcher",
		  .fn = (void *)__ebpf_call_ufunc_dispatcher,
	  } },
#if BPFTIME_ENABLE_FS_HELPER
	{ EXTENDED_HELPER_GET_ABS_PATH_ID,
	  bpftime_helper_info{
		  .index = EXTENDED_HELPER_GET_ABS_PATH_ID,
		  .name = "bpftime_get_abs_path",
		  .fn = (void *)bpftime_get_abs_path,
	  } },
	{ EXTENDED_HELPER_PATH_JOIN_ID,
	  bpftime_helper_info{
		  .index = EXTENDED_HELPER_PATH_JOIN_ID,
		  .name = "bpftime_path_join",
		  .fn = (void *)bpftime_path_join,
	  } },
#endif
#if defined (BPFTIME_ENABLE_IOURING_EXT) && __linux__
	{ EXTENDED_HELPER_IOURING_INIT,
	  bpftime_helper_info{
		  .index = EXTENDED_HELPER_IOURING_INIT,
		  .name = "io_uring_init",
		  .fn = (void *)io_uring_init_global,
	  } },
	{ EXTENDED_HELPER_IOURING_SUBMIT_WRITE,
	  bpftime_helper_info{
		  .index = EXTENDED_HELPER_IOURING_SUBMIT_WRITE,
		  .name = "io_uring_submit_write",
		  .fn = (void *)bpftime_io_uring_submit_write,
	  } },
	{ EXTENDED_HELPER_IOURING_SUBMIT_READ,
	  bpftime_helper_info{
		  .index = EXTENDED_HELPER_IOURING_SUBMIT_READ,
		  .name = "io_uring_submit_read",
		  .fn = (void *)bpftime_io_uring_submit_read,
	  } },
	{ EXTENDED_HELPER_IOURING_SUBMIT_SEND,
	  bpftime_helper_info{
		  .index = EXTENDED_HELPER_IOURING_SUBMIT_SEND,
		  .name = "io_uring_submit_send",
		  .fn = (void *)bpftime_io_uring_submit_send,
	  } },
	{ EXTENDED_HELPER_IOURING_SUBMIT_RECV,
	  bpftime_helper_info{
		  .index = EXTENDED_HELPER_IOURING_SUBMIT_RECV,
		  .name = "io_uring_submit_recv",
		  .fn = (void *)bpftime_io_uring_submit_recv,
	  } },
	{ EXTENDED_HELPER_IOURING_SUBMIT_FSYNC,
	  bpftime_helper_info{
		  .index = EXTENDED_HELPER_IOURING_SUBMIT_FSYNC,
		  .name = "io_uring_submit_fsync",
		  .fn = (void *)bpftime_io_uring_submit_fsync,
	  } },
	{ EXTENDED_HELPER_IOURING_WAIT_AND_SEEN,
	  bpftime_helper_info{
		  .index = EXTENDED_HELPER_IOURING_WAIT_AND_SEEN,
		  .name = "io_uring_wait_and_seen",
		  .fn = (void *)bpftime_io_uring_wait_and_seen,
	  } },
	{ EXTENDED_HELPER_IOURING_SUBMIT,
	  bpftime_helper_info{
		  .index = EXTENDED_HELPER_IOURING_SUBMIT,
		  .name = "io_uring_submit",
		  .fn = (void *)bpftime_io_uring_submit,
	  } },
	  	{ EXTENDED_HELPER_IOURING_SET_LINK,
	  bpftime_helper_info{
		  .index = EXTENDED_HELPER_IOURING_SET_LINK,
		  .name = "io_uring_set_link",
		  .fn = (void *)bpftime_io_uring_setlink,
	  } },
	{ EXTENDED_HELPER_IOURING_SUBMIT_AND_WAIT,
	  bpftime_helper_info{
		  .index = EXTENDED_HELPER_IOURING_SUBMIT_AND_WAIT,
		  .name = "io_uring_submit_and_wait",
		  .fn = (void *)bpftime_io_uring_submit_and_wait,
	  } },
	{ EXTENDED_HELPER_IOURING_GET_SQE,
	  bpftime_helper_info{
		  .index = EXTENDED_HELPER_IOURING_GET_SQE,
		  .name = "io_uring_get_sqe",
		  .fn = (void *)bpftime_io_uring_get_sqe,
	  } },
#endif
} };

} // namespace bpftime
