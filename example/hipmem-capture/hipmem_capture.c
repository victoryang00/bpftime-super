/* SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2022, eunomia-bpf org
 * All rights reserved.
 */
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <stdint.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <stdlib.h>
#include "hipmem_capture.skel.h"
#include <inttypes.h>
#include "attach_override.h"

#define warn(...) fprintf(stderr, __VA_ARGS__)

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
               va_list args)
{
    return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

int main(int argc, char **argv)
{
    struct hipmem_capture_bpf *skel;
    int err;
    const char *hip_binary = "./victim_hip";  // HIP victim binary
    const char *hip_library = "/opt/rocm/lib/libamdhip64.so";  // HIP runtime library

    /* Set up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);

    /* Cleaner handling of Ctrl-C */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* Load and verify BPF application */
    skel = hipmem_capture_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    /* Load & verify BPF programs */
    err = hipmem_capture_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    printf("Attaching BPF probes to HIP functions...\n");

    /* Attach to HIP kernel launch function */
    err = bpf_prog_attach_uprobe_with_override(
        bpf_program__fd(skel->progs.do_hipmem_capture), hip_binary,
        "infinite_kernel");  // HIP kernel function
    if (err) {
        warn("Failed to attach to HIP kernel function: %d\n", err);
        // Continue anyway, this might not be critical
    }

    /* Try to attach to HIP runtime library functions */
    
    // Attach to hipMalloc
    err = bpf_prog_attach_uprobe_with_override(
        bpf_program__fd(skel->progs.trace_hip_malloc), hip_library,
        "hipMalloc");
    if (err) {
        warn("Failed to attach to hipMalloc: %d\n", err);
    }

    // Attach to hipFree  
    err = bpf_prog_attach_uprobe_with_override(
        bpf_program__fd(skel->progs.trace_hip_free), hip_library,
        "hipFree");
    if (err) {
        warn("Failed to attach to hipFree: %d\n", err);
    }

    // Attach to hipLaunchKernel
    err = bpf_prog_attach_uprobe_with_override(
        bpf_program__fd(skel->progs.trace_hip_kernel_launch), hip_library,
        "hipLaunchKernel");
    if (err) {
        warn("Failed to attach to hipLaunchKernel: %d\n", err);
    }

    printf("HIP memory capture is running. Press Ctrl+C to exit.\n");
    printf("Run your HIP application now to see memory operations.\n");

    /* Main loop */
    while (!exiting) {
        sleep(1);
    }

cleanup:
    printf("\nShutting down HIP memory capture...\n");
    /* Clean up */
    hipmem_capture_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}