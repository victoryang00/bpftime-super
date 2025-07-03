# HIP Memory Capture Example

This example demonstrates how to use eBPF to capture and monitor HIP (ROCm) memory operations and kernel launches.

## Overview

The HIP memory capture tool consists of:

1. **eBPF kernel program** (`hipmem_capture.bpf.c`) - Monitors HIP runtime functions
2. **Userspace capture tool** (`hipmem_capture.c`) - Loads and manages the eBPF program
3. **HIP victim application** (`victim_hip.cu`) - A test HIP application to monitor
4. **HIP runtime test** (`runptx_hip.cpp`) - Alternative HIP application using module loading

## Prerequisites

### ROCm Installation

You need ROCm installed on your system:

```bash
# For Ubuntu/Debian
wget https://repo.radeon.com/amdgpu-install/latest/ubuntu/focal/amdgpu-install_*_all.deb
sudo dpkg -i amdgpu-install_*_all.deb
sudo amdgpu-install --usecase=rocm

# For other distributions, see: https://docs.amd.com/bundle/ROCm-Installation-Guide-v5.3/page/How_to_Install_ROCm.html
```

### Dependencies

- libbpf development headers
- BPF-enabled kernel (>= 4.15)
- ROCm/HIP runtime
- Clang/LLVM for BPF compilation

## Building

### Check ROCm Installation

```bash
make -f Makefile_hip check-rocm
```

### Build All Targets

```bash
make -f Makefile_hip all
```

This will build:
- `hipmem_capture` - The eBPF memory capture tool
- `victim_hip` - The HIP test application

### Build Individual Targets

```bash
# Build just the capture tool
make -f Makefile_hip hipmem_capture

# Build just the HIP victim
make -f Makefile_hip victim_hip

# Build HIP code object for module loading
make -f Makefile_hip victim_hip.hsaco

# Build the HIP runtime test
make -f Makefile_hip runptx_hip
```

## Usage

### Basic Memory Capture

1. **Start the memory capture tool** (requires root for eBPF):
   ```bash
   sudo ./hipmem_capture
   ```

2. **In another terminal, run the HIP victim application**:
   ```bash
   ./victim_hip
   ```

3. **Monitor the output**:
   - The capture tool will show attached probes
   - Check kernel logs for captured operations:
     ```bash
     sudo dmesg | tail -f
     ```

### Advanced Usage

#### Monitor Specific HIP Functions

The eBPF program can be modified to monitor specific HIP functions:

- `hipMalloc` - Device memory allocation
- `hipFree` - Device memory deallocation  
- `hipMemcpy` - Memory transfers
- `hipLaunchKernel` - Kernel launches
- `hipModuleLaunchKernel` - Module-based kernel launches

#### Custom Kernel Monitoring

To monitor your own HIP kernels:

1. Modify `hipmem_capture.bpf.c` to add probes for your kernel functions
2. Update `hipmem_capture.c` to attach to your application binary
3. Rebuild and run

## Architecture

### HIP vs CUDA Differences

| CUDA | HIP | Notes |
|------|-----|-------|
| `cudaMalloc` | `hipMalloc` | Device memory allocation |
| `cudaFree` | `hipFree` | Device memory deallocation |
| `cudaLaunchKernel` | `hipLaunchKernel` | Kernel launch |
| `cuModuleLoad` | `hipModuleLoad` | Module loading |
| PTX | GCN/RDNA ISA | Different GPU assembly |
| CUDA Runtime | HIP Runtime | Different runtime libraries |

### Memory Capture Flow

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   HIP App       │───▶│   HIP Runtime   │───▶│   ROCm Driver   │
│                 │    │                 │    │                 │
│ victim_hip.cu   │    │ libamdhip64.so  │    │ amdgpu.ko       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   eBPF Probe    │    │   eBPF Probe    │    │   eBPF Probe    │
│                 │    │                 │    │                 │
│ uprobe/kernel   │    │ uprobe/hipMalloc│    │ kprobe/amdgpu   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                                 ▼
                    ┌─────────────────┐
                    │ hipmem_capture  │
                    │                 │
                    │ (userspace)     │
                    └─────────────────┘
```

## Monitoring Output

### Successful Capture Example

```
$ sudo ./hipmem_capture
Attaching BPF probes to HIP functions...
HIP memory capture is running. Press Ctrl+C to exit.
Run your HIP application now to see memory operations.

# In kernel logs (dmesg):
[12345.678] HIP memory operation detected: PID=1234, TID=1234
[12345.679] HIP kernel launch detected: PID=1234
[12345.680] HIP malloc detected: PID=1234
[12345.681] bpf: HIP memory operation continues normally
```

### Troubleshooting

#### ROCm Not Found
```
Error: hipcc not found. Please install ROCm.
```
**Solution**: Install ROCm using the official installation guide.

#### Permission Denied
```
Failed to load and verify BPF skeleton
```
**Solution**: Run with `sudo` or ensure your user has BPF capabilities.

#### HIP Application Fails
```
Failed to set HIP device: No HIP-capable device found
```
**Solution**: Ensure you have an AMD GPU and proper ROCm drivers installed.

## Development

### Adding New Probes

1. **Add eBPF function in `hipmem_capture.bpf.c`**:
   ```c
   SEC("uprobe/hipMemcpy")
   int trace_hip_memcpy(struct pt_regs *ctx) {
       // Your capture logic
       return 0;
   }
   ```

2. **Attach probe in `hipmem_capture.c`**:
   ```c
   err = bpf_prog_attach_uprobe_with_override(
       bpf_program__fd(skel->progs.trace_hip_memcpy),
       hip_library, "hipMemcpy");
   ```

### Testing

```bash
# Run basic test
make -f Makefile_hip test-hip

# Check if everything builds
make -f Makefile_hip clean && make -f Makefile_hip all
```

## Files

- `victim_hip.cu` - HIP test application with infinite kernel
- `runptx_hip.cpp` - HIP application using module loading
- `hipmem_capture.bpf.c` - eBPF kernel program for memory capture
- `hipmem_capture.c` - Userspace capture application
- `Makefile_hip` - Build configuration for HIP/ROCm
- `README_hip.md` - This documentation

## Related Documentation

- [ROCm Documentation](https://docs.amd.com/bundle/ROCm-Installation-Guide-v5.3/page/Introduction_to_AMD_ROCm_Installation_Guide_for_Linux.html)
- [HIP Programming Guide](https://docs.amd.com/bundle/HIP-Programming-Guide-v5.3/page/Introduction_to_HIP_Programming_Guide.html)
- [eBPF Documentation](https://ebpf.io/what-is-ebpf/)
- [libbpf Documentation](https://libbpf.readthedocs.io/)