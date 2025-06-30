# GPU Checkpoint/Restore + JIT Demo

This example demonstrates how to implement GPU self-modifying code using checkpoint/restore mechanisms and JIT compilation.

## Features

1. **GPU State Checkpoint/Restore**: Capture and restore complete GPU kernel execution state
2. **JIT Compilation**: Dynamic generation and compilation of optimized PTX code
3. **Live Kernel Migration**: Replace running kernel code without losing state
4. **Self-Modifying Code**: Kernels that adapt their behavior based on runtime conditions

## Architecture

The implementation consists of several key components:

### 1. GPU Checkpoint/Restore (`gpu_checkpoint_restore.hpp/cpp`)
- Captures GPU kernel state including:
  - Thread and block configuration
  - Memory snapshots (global, shared, constant)
  - Register states per thread
  - Kernel function information
- Supports state serialization and restoration

### 2. PTX JIT Compiler (`ptx_jit_compiler.hpp/cpp`)
- Runtime PTX code generation
- Dynamic kernel optimization
- Template-based code generation
- Memory access optimization

### 3. GPU State Manager (`gpu_state_manager.hpp/cpp`)
- Orchestrates checkpoint/restore operations
- Manages kernel execution monitoring
- Handles live kernel migration
- Provides continuous checkpointing

## Building

```bash
cd example/gpu-checkpoint-jit
mkdir build && cd build
cmake ..
make
```

## Running

```bash
./gpu_checkpoint_jit_demo
```

## Example Output

```
=== GPU Checkpoint/Restore + JIT Demo ===

1. Loading original kernel...
Kernel loaded successfully

2. Running kernel with execution monitoring...
Kernel execution time: 1234 microseconds

3. Creating checkpoint during execution...
Creating checkpoint: execution_checkpoint_1
Checkpoint created successfully

4. JIT compiling optimized kernel...
Generating optimized kernel...
Kernel replacement scheduled successfully

5. Performing live kernel migration...
Preparing for migration...
Migrating to optimized kernel...
Migration completed successfully

6. Verifying results...
Verifying results (first 10 elements):
  [0] Result: 0 (Original expected: 0, Optimized expected: 0)
  [1] Result: 1.1 (Original expected: 0.8, Optimized expected: 1.1)
  ...

7. Demonstrating checkpoint restore...
Restoring from checkpoint...
Checkpoint restored successfully
```

## How It Works

### 1. Checkpoint Creation

When a checkpoint is requested, the system:
- Pauses GPU execution
- Captures all thread states
- Saves memory contents
- Records kernel parameters
- Stores execution context

### 2. JIT Optimization

The JIT compiler can:
- Generate specialized kernels based on runtime data
- Optimize memory access patterns
- Unroll loops dynamically
- Apply architecture-specific optimizations

### 3. Live Migration

During live kernel migration:
- Current state is checkpointed
- New kernel is loaded
- State is mapped to new kernel layout
- Execution resumes with new code

### 4. Self-Modifying Code

Kernels can modify themselves by:
- Monitoring execution metrics
- Triggering JIT recompilation
- Replacing their own code
- Continuing execution seamlessly

## Use Cases

1. **Adaptive Algorithms**: Kernels that optimize themselves based on input data patterns
2. **Performance Tuning**: Runtime optimization without restarting applications
3. **Fault Tolerance**: Checkpoint/restore for long-running GPU computations
4. **Dynamic Specialization**: Generate specialized kernels for specific data sizes/types

## Advanced Features

### Continuous Checkpointing
```cpp
stateManager->enableContinuousCheckpointing(1.0); // Checkpoint every second
```

### Custom JIT Templates
```cpp
jitCompiler->registerTemplate("matmul", matmulTemplate);
auto specialized = jitCompiler->instantiateTemplate("matmul", {{"TILE_SIZE", "16"}});
```

### Checkpoint Compression
```cpp
CheckpointFileManager fileManager("/tmp/checkpoints");
fileManager.enableCompression(true);
fileManager.saveCheckpoint("checkpoint1", state);
```

## Limitations

1. Requires driver-level support for full register state capture
2. Memory overhead for state storage
3. Performance impact during checkpoint/restore operations
4. Limited to architectures with PTX support

## Future Enhancements

1. Support for multi-GPU checkpointing
2. Distributed checkpoint storage
3. Incremental checkpointing
4. Hardware-accelerated state capture