#include "hookeye_internal.h"

#include <errno.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

enum hookeye_status hookeye_ptrace_attach(struct hookeye_target *target) {
    if (target == NULL || target->pid <= 0) {
        return HOOKEYE_ERR_ARGUMENT;
    }
    if (target->pid == getpid()) {
        return HOOKEYE_OK;
    }

    if (ptrace(PTRACE_ATTACH, target->pid, NULL, NULL) < 0) {
        return HOOKEYE_ERR_PTRACE;
    }

    int wait_status = 0;
    if (waitpid(target->pid, &wait_status, 0) < 0) {
        (void)ptrace(PTRACE_DETACH, target->pid, NULL, NULL);
        return HOOKEYE_ERR_PTRACE;
    }

    if (!WIFSTOPPED(wait_status)) {
        (void)ptrace(PTRACE_DETACH, target->pid, NULL, NULL);
        return HOOKEYE_ERR_PTRACE;
    }

    target->attached = true;
    return HOOKEYE_OK;
}

void hookeye_ptrace_detach(struct hookeye_target *target) {
    if (target == NULL || !target->attached) {
        return;
    }

    (void)ptrace(PTRACE_DETACH, target->pid, NULL, NULL);
    target->attached = false;
}

static enum hookeye_status hookeye_remote_read_ptrace(
    const struct hookeye_target *target,
    uintptr_t remote_address,
    void *buffer,
    size_t size) {
    unsigned char *out = buffer;
    size_t offset = 0;

    while (offset < size) {
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, target->pid, (void *)(remote_address + offset), NULL);
        if (word == -1L && errno != 0) {
            return HOOKEYE_ERR_PTRACE;
        }

        size_t chunk = sizeof(word);
        if (chunk > size - offset) {
            chunk = size - offset;
        }
        memcpy(out + offset, &word, chunk);
        offset += chunk;
    }

    return HOOKEYE_OK;
}

enum hookeye_status hookeye_remote_read(
    const struct hookeye_target *target,
    uintptr_t remote_address,
    void *buffer,
    size_t size) {
    if (target == NULL || buffer == NULL) {
        return HOOKEYE_ERR_ARGUMENT;
    }
    if (size == 0U) {
        return HOOKEYE_OK;
    }
    if (target->pid == getpid()) {
        memcpy(buffer, (const void *)remote_address, size);
        return HOOKEYE_OK;
    }

    struct iovec local = {
        .iov_base = buffer,
        .iov_len = size,
    };
    struct iovec remote = {
        .iov_base = (void *)remote_address,
        .iov_len = size,
    };

    ssize_t copied = process_vm_readv(target->pid, &local, 1, &remote, 1, 0);
    if (copied == (ssize_t)size) {
        return HOOKEYE_OK;
    }

    return hookeye_remote_read_ptrace(target, remote_address, buffer, size);
}
