/*
 * sandbox-init: PID 1 of every sandbox.
 *
 * Its only job is to reap orphaned zombies, because whatever runs as PID 1 in a
 * PID namespace inherits every orphan in it. It is static C (not Python) for one
 * reason: it is exec'd from a sealed memfd, so /proc/1/exe inside the sandbox
 * points at an anonymous, immutable file, not at any host binary that sandboxed
 * root could try to open for writing (the CVE-2019-5736 class of bug).
 *
 * It installs no signal handlers. The kernel drops signals sent to a PID-namespace
 * init from inside that namespace unless the init handles them, so sandboxed root
 * cannot kill it. The control plane kills it from outside via cgroup.kill.
 *
 * Build: gcc -static -Os -o sandbox-init init.c
 */
#define _GNU_SOURCE
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void)
{
    sigset_t chld;
    sigemptyset(&chld);
    sigaddset(&chld, SIGCHLD);
    sigprocmask(SIG_BLOCK, &chld, NULL);
    for (;;) {
        siginfo_t si;
        if (sigwaitinfo(&chld, &si) < 0)
            continue;
        while (waitpid(-1, NULL, WNOHANG) > 0)
            ;
    }
}
