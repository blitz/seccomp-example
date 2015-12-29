#include <libowfat/io.h>
#include <libowfat/errmsg.h>

#include <sys/prctl.h>
#include <sys/wait.h>
#include <linux/audit.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <sys/syscall.h> 

#include <unistd.h>

#include <cstddef>
#include <cstdio>
#include <cstdint>
#include <cstdlib>


#define BPF_SYS_WHITELIST(nr)                                       \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 1),                  \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)

namespace {
    static const constexpr bool RESTRICT_ENABLE = true;

    
    static sock_filter sys_filter[] = {
        // Check architecture.
        BPF_STMT(BPF_LD  | BPF_W   | BPF_ABS, (offsetof(struct seccomp_data, arch))),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,   AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K,             SECCOMP_RET_KILL),

        // Load syscall number.
        BPF_STMT(BPF_LD  | BPF_W   | BPF_ABS, (offsetof(struct seccomp_data, nr))),

        // Now whitelist system calls
        BPF_SYS_WHITELIST(SYS_exit),
        BPF_SYS_WHITELIST(SYS_exit_group),


        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),

    };

    static const sock_fprog sys_filter_prog = {
        .len    = sizeof(sys_filter)/sizeof(sys_filter[0]),
        .filter = sys_filter,
    };

    void child_process(int socket)
    {
        // We need to do this, otherwise PR_SET_SECCOMP will fail with EACCES.
        if (RESTRICT_ENABLE and (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)) {
            die(EXIT_FAILURE, "PR_SET_NO_NEW_PRIVS");
        }
        if (RESTRICT_ENABLE and (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &sys_filter_prog, 0) != 0)) {
            die(EXIT_FAILURE, "PR_SET_SECCOMP");
        }


    }


    void parent_process(int socket)
    {
        int status = 0;
        wait(&status);
    }
};

int main()
{
    int64_t sockets[2];

    if (io_socketpair(sockets) == 0) {
        die(EXIT_FAILURE, "io_socketpair");
    }

    pid_t fork_ret = fork();

    if (fork_ret < 0) {
        die(EXIT_FAILURE, "fork");
    }

    if (fork_ret == 0) {
        child_process(sockets[0]);
    } else {
        parent_process(sockets[1]);
    }

    return 0;
}
