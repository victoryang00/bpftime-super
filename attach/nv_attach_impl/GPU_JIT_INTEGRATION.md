# GPU JIT Code Replacement Integration in bpftime

## Overview

This document describes how the GPU self-modifying code (JIT) functionality has been integrated into bpftime's CUDA attachment mechanism.

## Architecture

The integration adds GPU checkpoint/restore and self-modifying code capabilities directly into bpftime's CUDA attachment logic:

```
┌─────────────────────────────────────────┐
│         User Application/Script          │
│              ↓                          │
│         GPUJITApi::getInstance()        │
│              ↓                          │
├─────────────────────────────────────────┤
│         nv_attach_impl                  │
│   ┌─────────────────────────────┐      │
│   │ gpu_checkpoint_restore      │      │
│   │ self_modifying_manager      │      │
│   └─────────────────────────────┘      │
│              ↓                          │
│    Frida Interceptor Hooks              │
│   - __cudaRegisterFatBinary             │
│   - cudaLaunchKernel                    │
├─────────────────────────────────────────┤
│         CUDA Runtime                    │
└─────────────────────────────────────────┘
```

## Key Components

### 1. GPU JIT API (`gpu_jit_api.hpp/cpp`)
- Singleton interface for external code to schedule replacements
- Thread-safe API for runtime kernel modification
- Automatically connects to the active nv_attach_impl instance

### 2. Integration Points

#### During FatBin Registration
- PTX code is parsed and analyzed
- Kernels marked for JIT support are identified
- Self-modifying code infrastructure is injected

#### During Kernel Launch (cudaLaunchKernel)
- Checks if code replacement is scheduled
- Creates checkpoint if needed
- Replaces kernel function pointer with new implementation
- Tracks kernel execution metrics

### 3. Modified Files
- `nv_attach_impl.hpp`: Added GPU checkpoint/restore members
- `nv_attach_impl.cpp`: Added scheduleCodeReplacement implementation
- `nv_attach_impl_frida_setup.cpp`: Added kernel launch interception
- `CMakeLists.txt`: Added new source files

## Usage

### From External Code

```cpp
#include "gpu_jit_api.hpp"

// Schedule immediate replacement
GPUJITApi::getInstance().scheduleCodeReplacement(
    "myKernel",           // Kernel name
    new_ptx_code,         // New PTX code
    -1                    // Immediate replacement
);

// Schedule replacement after 1000 iterations
GPUJITApi::getInstance().scheduleCodeReplacement(
    "myKernel", 
    optimized_ptx_code, 
    1000
);

// Enable checkpointing
GPUJITApi::getInstance().enableCheckpointing(
    "criticalKernel",
    5.0  // Every 5 seconds
);
```

### From bpftime Attach Script

When using bpftime to attach to a CUDA program:

```bash
# Attach bpftime to CUDA process
bpftime attach <pid>

# The GPU JIT API is automatically available
# Use it from your attach scripts or plugins
```

## Features

### 1. Live Code Replacement
- Replace kernel code without stopping execution
- Preserve kernel state across replacements
- Support for iteration-based triggers

### 2. Checkpoint/Restore
- Automatic checkpointing based on time or iteration
- Full GPU state capture (memory, registers, etc.)
- File-based persistence with compression

### 3. Self-Modifying Kernels
- Kernels can modify their own code
- Data-dependent optimization
- Adaptive computation patterns

## Implementation Details

### PTX Injection

When a kernel is marked for self-modifying support, the following PTX functions are injected:

```ptx
.extern .func (.param .b32 retval) gpu_create_checkpoint(
    .param .b64 kernel_name,
    .param .b32 iteration
);

.extern .func (.param .b32 retval) gpu_schedule_code_replacement(
    .param .b64 kernel_name,
    .param .b64 new_ptx_code,
    .param .b32 trigger_iteration
);
```

### Kernel Launch Interception

The cudaLaunchKernel hook:
1. Checks if replacement is scheduled
2. Creates checkpoint if needed
3. Compiles new PTX using NVRTC
4. Replaces function pointer
5. Updates execution metrics

## Limitations

1. Requires CUDA Driver API support
2. PTX must be compatible with target GPU architecture
3. Checkpoint size depends on kernel memory usage
4. Currently single-GPU only

## Future Enhancements

1. Multi-GPU support
2. Incremental checkpointing
3. Network-based checkpoint storage
4. Automatic performance profiling
5. Machine learning-based optimization

## Example

See `examples/gpu_jit_usage_example.cpp` for a complete example of using the GPU JIT API.

## Building

The GPU JIT functionality is automatically built with bpftime when CUDA support is enabled:

```bash
cmake .. -DENABLE_CUDA=ON
make
```

## Testing

Run the GPU JIT tests:

```bash
cd attach/nv_attach_impl/test
./test_gpu_jit
```