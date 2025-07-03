/* SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2022, eunomia-bpf org
 * All rights reserved.
 */
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <hip/hip_runtime.h>
#include <stdio.h>

// Global variable to control the loop
extern "C" {
__device__ volatile int should_exit = 0;

__global__ void infinite_kernel()
{
    // Only let one thread print information
    if (threadIdx.x == 0 && blockIdx.x == 0) {
        printf("HIP Kernel started\n");
    }

    // Counter for periodic printing
    int counter = 0;

    while (true) {
        // Each thread does some simple computation to avoid completely empty loop
        float x = threadIdx.x + blockIdx.x;
        for (int i = 0; i < 1000; i++) {
            x = sinf(x) * x;
        }

        // Periodic status printing (only one thread)
        if (threadIdx.x == 0 && blockIdx.x == 0) {
            if (++counter % 1000000 == 0) {
                printf("HIP kernel still running... counter=%d\n", counter);
            }
        }

        // Prevent compiler from optimizing away the computation
        if (x == 0.0f) {
            should_exit = 1; // Never happens
        }

        // Yield some time to other threads
    }

    if (threadIdx.x == 0 && blockIdx.x == 0) {
        printf("HIP Kernel exiting\n");
    }
}
}

int main()
{
    printf("HIP Memory Capture Victim (Working Version)\n");
    printf("This version demonstrates HIP runtime functionality without kernel launch issues.\n");
    
    // Set device
    hipError_t err = hipSetDevice(0);
    if (err != hipSuccess) {
        printf("Failed to set HIP device: %s\n", hipGetErrorString(err));
        return 1;
    }
    
    // Get device properties
    hipDeviceProp_t prop;
    err = hipGetDeviceProperties(&prop, 0);
    if (err == hipSuccess) {
        printf("Using device: %s\n", prop.name);
    }

    // Simulate GPU memory operations for eBPF capture
    printf("Performing HIP memory operations for capture...\n");
    
    void* gpu_ptr = nullptr;
    size_t mem_size = 128 * 1024 * 1024; // 128 MB
    
    // Allocate GPU memory
    err = hipMalloc(&gpu_ptr, mem_size);
    if (err != hipSuccess) {
        printf("hipMalloc failed: %s\n", hipGetErrorString(err));
        return 1;
    }
    printf("Allocated %zu MB on GPU\n", mem_size / (1024*1024));
    
    // Allocate host memory  
    void* host_ptr = malloc(mem_size);
    if (!host_ptr) {
        printf("Host malloc failed\n");
        hipFree(gpu_ptr);
        return 1;
    }
    
    // Initialize host data
    memset(host_ptr, 0x42, mem_size);
    
    // Copy to device (this should be captured by eBPF)
    err = hipMemcpy(gpu_ptr, host_ptr, mem_size, hipMemcpyHostToDevice);
    if (err != hipSuccess) {
        printf("hipMemcpy H2D failed: %s\n", hipGetErrorString(err));
        free(host_ptr);
        hipFree(gpu_ptr);
        return 1;
    }
    printf("Copied data to GPU\n");
    
    // Create a stream
    hipStream_t stream;
    err = hipStreamCreate(&stream);
    if (err == hipSuccess) {
        printf("Created HIP stream\n");
        
        // Perform async memory copy
        err = hipMemcpyAsync(host_ptr, gpu_ptr, mem_size, hipMemcpyDeviceToHost, stream);
        if (err == hipSuccess) {
            printf("Performed async copy\n");
        }
        
        // Synchronize stream
        hipStreamSynchronize(stream);
        hipStreamDestroy(stream);
    }
    
    // Launch infinite kernel for eBPF capture testing
    printf("Launching infinite HIP kernel...\n");
    infinite_kernel<<<1, 32>>>();
    
    err = hipGetLastError();
    if (err != hipSuccess) {
        printf("Infinite kernel launch failed: %s\n", hipGetErrorString(err));
        printf("Continuing with memory operations only...\n");
    } else {
        printf("Infinite kernel launched successfully!\n");
        printf("Note: Kernel will run indefinitely until program exits.\n");
    }

    printf("Memory operations completed. Press Enter to exit and cleanup...\n");
    getchar();
    
    // Signal the infinite kernel to exit
    printf("Signaling infinite kernel to exit...\n");
    int exit_val = 1;
    err = hipMemcpyToSymbol(should_exit, &exit_val, sizeof(int));
    if (err != hipSuccess) {
        printf("Warning: Failed to signal kernel exit: %s\n", hipGetErrorString(err));
    }
    
    // Wait a bit for kernel to exit gracefully, then sync
    printf("Waiting for kernel to exit...\n");
    sleep(1);
    
    err = hipDeviceSynchronize();
    if (err != hipSuccess) {
        printf("Warning: Device synchronization failed: %s\n", hipGetErrorString(err));
    } else {
        printf("Kernel stopped successfully.\n");
    }
    
    // Cleanup
    free(host_ptr);
    err = hipFree(gpu_ptr);
    if (err != hipSuccess) {
        printf("hipFree failed: %s\n", hipGetErrorString(err));
        return 1;
    }
    
    printf("HIP memory operations completed successfully!\n");
    printf("Check eBPF capture logs for traced operations.\n");
    return 0;
}