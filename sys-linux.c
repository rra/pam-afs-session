/*
 * sys-linux.c
 *
 * kafs replacement for Linux systems.
 *
 * This is a simple implementation of the k_hasafs, k_setpag, and k_unlog
 * functions for Linux systems only (and new enough implementations of OpenAFS
 * on Linux that /proc/fs/openafs/afs_ioctl exists).  It is for use on systems
 * that don't have libkafs or libkopenafs, or where a dependency on those
 * libraries is not desirable for some reason.
 *
 * A more robust implementation of the full kafs interface would have a
 * separate header file with the various system call constants and would
 * support more operations and the k_pioctl interface.  Since this is a
 * stripped-down implementation with only the few functions that the AFS PAM
 * module requires, various interface constants and system call numbers are
 * hard-coded here.
 */

#include "config.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* 
 * The struct passed to ioctl to do an AFS system call.  Definition taken from
 * the afs/afs_args.h OpenAFS header.
 */
struct afsprocdata {
    long param4;
    long param3;
    long param2;
    long param1;
    long syscall;
};

/*
 * The struct passed to unlog as an argument.  All the values are NULL or 0,
 * but we need the struct to be the right size.
 */
struct ViceIoctl {
    void *in, *out;
    short in_size;
    short out_size;
}

/*
 * The workhorse function that does the actual system call.  All the values
 * are passed as longs to match the internal OpenAFS interface, which means
 * that there's all sorts of ugly type conversion happening here.
 *
 * The first path we attempt is the OpenAFS path; the second is the one used
 * by Arla (at least some versions).
 */
static int
afs_syscall(long syscall, long param1, long param2, long param3, long param4,
            int *rval)
{
    struct afsprocdata syscall_data;
    int fd;

    fd = open("/proc/fs/openafs/afs_ioctl", O_RDWR);
    if (fd < 0)
        fd = open("/proc/fs/nnpfs/afs_ioctl", O_RDWR);
    if (fd < 0)
        return -1;

    syscall_data.syscall = syscall;
    syscall_data.param1 = param1;
    syscall_data.param2 = param2;
    syscall_data.param3 = param3;
    syscall_data.param4 = param4;
    *rval = ioctl(fd, _IOW('C', 1, void *), &syscall_data);

    close(fd);
    return 0;
}

/*
 * The other system calls are implemented in terms of k_pioctl.  This is a
 * standard part of the kafs interface, but we don't export it here since the
 * AFS PAM module never needs to call it directly and therefore doesn't need
 * to know the constants that it uses.
 */
static int
k_pioctl(const char *path, int cmd, const void *cmarg, int follow)
{
    int err, rval;

    rval = afs_syscall(20, (long) path, cmd, (long) cmarg, follow, &err);
    if (rval != 0)
        err = rval;
    return err;
}

/*
 * Probe to see if AFS is available and we can make system calls
 * successfully.  This just attempts the set token system call with an empty
 * token structure, which will be a no-op in the kernel.
 */
int
k_hasafs(void)
{
    struct ViceIoctl iob;
    int result;

    iob.in = NULL;
    iob.in_size = 0;
    iob.out = NULL;
    iob.out_size = 0;
    result = k_pioctl(NULL, _IOW('V', 3, struct ViceIoctl), &iob, 0);
    return (result == 0);
}

/*
 * The setpag system call.  This is special in that it's not a pioctl;
 * instead, it's a separate system call done directly through the afs_syscall
 * function.
 */
int
k_setpag(void)
{
    int err, rval;

    rval = afs_syscall(21, 0, 0, 0, 0, &err);
    if (rval != 0)
        err = rval;
    return err;
}

/*
 * The unlog system call.  This destroys any tokens in the current PAG.
 */
int
k_unlog(void)
{
    struct ViceIoctl iob;

    iob.in = NULL;
    iob.in_size = 0;
    iob.out = NULL;
    iob.out_size = 0;
    return k_pioctl(NULL, _IOW('V', 9, struct ViceIoctl), &iob, 0);
}
