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
#include <cassert>
#include <functional>
#include <vector>
#include <initializer_list>
#include <utility>


#define BPF_SYS_WHITELIST(nr)                                       \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 1),                  \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)

namespace {

    [[noreturn]] void die_errno(const char *msg)
    {
        perror(msg);
        exit(EXIT_FAILURE);
    }

    class ForkedChild {

        pid_t child_ = 0;

        enum {
            NOT_STARTED,
            STARTED,
            FINISHED,
        } state = NOT_STARTED;

        int child_main(std::function<int()> const &fn)
        {
            prepare_child();
            return fn();
        }

    protected:

        virtual void prepare_child()
        {
            // Default does nothing.
        }

    public:

        void run(std::function<int()> const &fn)
        {
            state = STARTED;
            child_ = fork();

            if (child_ < 0) {
                die_errno("fork");
            }

            if (child_ == 0) {
                _exit(child_main(fn));
            }
        }

        /// Wait for the child to finish. Can only be called when the child was actually started with
        /// run(). Will be automatically called by the destructor, if it hasn't been called before.
        int wait_for_child()
        {
            assert(state == STARTED);
            state = FINISHED;

            int status = 0;
            waitpid(child_, &status, 0);
            return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        }

        ForkedChild() = default;

        ForkedChild(ForkedChild const &) = delete;
        ForkedChild &operator=(ForkedChild const &) = delete;

        virtual ~ForkedChild()
        {
            switch (state) {
            case STARTED:
                wait_for_child();
                break;
            default:
                // Nothing to do.
                break;
            }
        }
    };


    class SeccompChild final : public ForkedChild {

        std::vector<sock_filter> seccomp_filter {
            // Check architecture.
            BPF_STMT(BPF_LD  | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, arch))),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,   AUDIT_ARCH_X86_64, 1, 0),
            BPF_STMT(BPF_RET | BPF_K,             SECCOMP_RET_KILL),
        };

        void extend_all() {}

        template <typename FIRST, typename... REST>
        void extend_all(FIRST first, REST... rest)
        {
            first.push_into(seccomp_filter);
            extend_all(rest...);
        }


    protected:

        void prepare_child() override
        {

            unsigned short len = seccomp_filter.size();
            assert(len == seccomp_filter.size());

            const sock_fprog prog = {
                .len = len,
                .filter = seccomp_filter.data(),
            };

            // We need to do this, otherwise PR_SET_SECCOMP will fail with EACCES.
            if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
                die_errno("PR_SET_NO_NEW_PRIVS");
            }

            if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0) != 0) {
                die_errno("PR_SET_SECCOMP");
            }

        }

    public:

        template <typename... TYPES>
        explicit SeccompChild(const TYPES &... entries)
        {
            // Load syscall number.
            seccomp_filter.push_back(BPF_STMT(BPF_LD  | BPF_W   | BPF_ABS, (offsetof(struct seccomp_data, nr))));

            extend_all(entries...);


            // for (unsigned sysnr : sys_whitelist) {
            //     extend_filter(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, sysnr, 0, 1));
            //     extend_filter(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
            // }

            // for (auto t : sys_errno) {
            //     extend_filter(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, t.first, 0, 1));
            //     extend_filter(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (t.second & SECCOMP_RET_DATA)));
            // }

            // Finalize filter.
            seccomp_filter.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL));
        }
    };

    class SeccompWhitelist {
        unsigned sysnr_;

    public:
        explicit SeccompWhitelist(unsigned sysnr)
            : sysnr_(sysnr)
        {}

        template <typename VECTOR>
        void push_into(VECTOR &v) const
        {
            v.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, nr))));
            v.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, sysnr_, 0, 1));
            v.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
        }
    };

    class SeccompWhitelistWithArg {
        unsigned sysnr_;
        uint64_t arg0_;

    public:
        explicit SeccompWhitelistWithArg(unsigned sysnr, uint64_t arg0)
            : sysnr_(sysnr), arg0_(arg0)
        {}

        template <typename VECTOR>
        void push_into(VECTOR &v) const
        {
            v.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, nr))));
            v.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, sysnr_, 0, 6));

            // First half of arg
            v.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, args))));
            v.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, static_cast<uint32_t>(arg0_), 0, 3));

            // Second half of arg
            v.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, sizeof(uint32_t) + (offsetof(struct seccomp_data, args))));
            v.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, static_cast<uint32_t>(arg0_ >> 32), 0, 1));

            v.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
            v.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL));
        }
    };

}

int main()
{

    SeccompChild s {
        SeccompWhitelist(SYS_exit_group),
        SeccompWhitelist(SYS_exit),

        // Only allow write to stdout.
        SeccompWhitelistWithArg(SYS_write, STDOUT_FILENO),

        // Seems to be used for isatty().
        SeccompWhitelistWithArg(SYS_fstat, STDOUT_FILENO),

        // To allocate memory.
        SeccompWhitelistWithArg(SYS_mmap, 0),
    };

    // Fork a child and sandbox it.
    s.run([] { printf("Hello from sandbox!\n"); return 0; });

    return EXIT_SUCCESS;
}

// EOF
