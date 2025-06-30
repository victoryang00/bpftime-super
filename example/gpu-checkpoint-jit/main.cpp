#include <iostream>
#include <cuda_runtime.h>
#include <cuda.h>
#include <vector>
#include <chrono>
#include <thread>

#include "../../attach/nv_attach_impl/gpu_state_manager.hpp"
#include "../../attach/nv_attach_impl/ptx_jit_compiler.hpp"

using namespace bpftime::attach;

// Original kernel PTX code template
const char* ORIGINAL_KERNEL_PTX = R"(
.version 7.0
.target sm_70
.address_size 64

.visible .entry vector_add(
    .param .u64 param_a,
    .param .u64 param_b,
    .param .u64 param_c,
    .param .u32 param_n
)
{
    .reg .u32 %tid;
    .reg .u64 %addr_a, %addr_b, %addr_c;
    .reg .f32 %val_a, %val_b, %val_c;
    .reg .pred %p1;
    
    // Get thread ID
    mov.u32 %tid, %tid.x;
    
    // Check bounds
    ld.param.u32 %r1, [param_n];
    setp.lt.u32 %p1, %tid, %r1;
    @!%p1 ret;
    
    // Load addresses
    ld.param.u64 %addr_a, [param_a];
    ld.param.u64 %addr_b, [param_b];
    ld.param.u64 %addr_c, [param_c];
    
    // Calculate offsets
    mul.wide.u32 %r2, %tid, 4;
    add.u64 %addr_a, %addr_a, %r2;
    add.u64 %addr_b, %addr_b, %r2;
    add.u64 %addr_c, %addr_c, %r2;
    
    // Load values
    ld.global.f32 %val_a, [%addr_a];
    ld.global.f32 %val_b, [%addr_b];
    
    // Perform addition
    add.f32 %val_c, %val_a, %val_b;
    
    // Store result
    st.global.f32 [%addr_c], %val_c;
    
    ret;
}
)";

// Optimized kernel with FMA operation
const char* OPTIMIZED_KERNEL_PTX = R"(
.version 7.0
.target sm_70
.address_size 64

.visible .entry vector_add(
    .param .u64 param_a,
    .param .u64 param_b,
    .param .u64 param_c,
    .param .u32 param_n
)
{
    .reg .u32 %tid;
    .reg .u64 %addr_a, %addr_b, %addr_c;
    .reg .f32 %val_a, %val_b, %val_c;
    .reg .pred %p1;
    .reg .f32 %scale;
    
    // Get thread ID
    mov.u32 %tid, %tid.x;
    
    // Check bounds
    ld.param.u32 %r1, [param_n];
    setp.lt.u32 %p1, %tid, %r1;
    @!%p1 ret;
    
    // Load addresses
    ld.param.u64 %addr_a, [param_a];
    ld.param.u64 %addr_b, [param_b];
    ld.param.u64 %addr_c, [param_c];
    
    // Calculate offsets
    mul.wide.u32 %r2, %tid, 4;
    add.u64 %addr_a, %addr_a, %r2;
    add.u64 %addr_b, %addr_b, %r2;
    add.u64 %addr_c, %addr_c, %r2;
    
    // Load values
    ld.global.f32 %val_a, [%addr_a];
    ld.global.f32 %val_b, [%addr_b];
    
    // Perform FMA operation (a + b * 2.0)
    mov.f32 %scale, 0f40000000; // 2.0 in hex
    fma.rn.f32 %val_c, %val_b, %scale, %val_a;
    
    // Store result
    st.global.f32 [%addr_c], %val_c;
    
    ret;
}
)";

class GPUCheckpointJITDemo {
public:
    GPUCheckpointJITDemo() : N(1024 * 1024) {
        // Initialize CUDA
        cudaSetDevice(0);
        cuInit(0);
        cuCtxCreate(&context, 0, 0);
        
        // Initialize managers
        stateManager = std::make_unique<GPUStateManager>();
        jitCompiler = std::make_unique<PTXJITCompiler>();
        
        stateManager->initialize(context);
        stateManager->enableJIT(jitCompiler.get());
        
        // Allocate device memory
        size_t size = N * sizeof(float);
        cudaMalloc(&d_a, size);
        cudaMalloc(&d_b, size);
        cudaMalloc(&d_c, size);
        
        // Initialize data
        initializeData();
    }
    
    ~GPUCheckpointJITDemo() {
        cudaFree(d_a);
        cudaFree(d_b);
        cudaFree(d_c);
        cuCtxDestroy(context);
    }
    
    void runDemo() {
        std::cout << "=== GPU Checkpoint/Restore + JIT Demo ===" << std::endl;
        
        // Step 1: Load and run original kernel
        std::cout << "\n1. Loading original kernel..." << std::endl;
        loadKernel(ORIGINAL_KERNEL_PTX, "vector_add");
        
        // Step 2: Run kernel with monitoring
        std::cout << "\n2. Running kernel with execution monitoring..." << std::endl;
        runKernelWithMonitoring();
        
        // Step 3: Create checkpoint
        std::cout << "\n3. Creating checkpoint during execution..." << std::endl;
        createCheckpointDuringExecution();
        
        // Step 4: JIT compile and load optimized kernel
        std::cout << "\n4. JIT compiling optimized kernel..." << std::endl;
        performJITOptimization();
        
        // Step 5: Live migration to new kernel
        std::cout << "\n5. Performing live kernel migration..." << std::endl;
        performLiveKernelMigration();
        
        // Step 6: Verify results
        std::cout << "\n6. Verifying results..." << std::endl;
        verifyResults();
        
        // Step 7: Demonstrate restore functionality
        std::cout << "\n7. Demonstrating checkpoint restore..." << std::endl;
        demonstrateRestore();
    }
    
private:
    CUcontext context;
    CUmodule module;
    CUfunction kernel;
    
    std::unique_ptr<GPUStateManager> stateManager;
    std::unique_ptr<PTXJITCompiler> jitCompiler;
    
    float *d_a, *d_b, *d_c;
    std::vector<float> h_a, h_b, h_c;
    int N;
    
    void initializeData() {
        h_a.resize(N);
        h_b.resize(N);
        h_c.resize(N);
        
        // Initialize with test data
        for (int i = 0; i < N; i++) {
            h_a[i] = i * 0.5f;
            h_b[i] = i * 0.3f;
            h_c[i] = 0.0f;
        }
        
        // Copy to device
        cudaMemcpy(d_a, h_a.data(), N * sizeof(float), cudaMemcpyHostToDevice);
        cudaMemcpy(d_b, h_b.data(), N * sizeof(float), cudaMemcpyHostToDevice);
    }
    
    void loadKernel(const char* ptxCode, const std::string& kernelName) {
        CUresult res = cuModuleLoadData(&module, ptxCode);
        if (res != CUDA_SUCCESS) {
            std::cerr << "Failed to load PTX module" << std::endl;
            return;
        }
        
        res = cuModuleGetFunction(&kernel, module, kernelName.c_str());
        if (res != CUDA_SUCCESS) {
            std::cerr << "Failed to get kernel function" << std::endl;
            return;
        }
        
        std::cout << "Kernel loaded successfully" << std::endl;
    }
    
    void runKernelWithMonitoring() {
        // Set up kernel parameters
        void* kernelParams[] = { &d_a, &d_b, &d_c, &N };
        
        // Launch kernel
        int blockSize = 256;
        int gridSize = (N + blockSize - 1) / blockSize;
        
        auto start = std::chrono::high_resolution_clock::now();
        
        CUresult res = cuLaunchKernel(kernel,
                                     gridSize, 1, 1,    // grid dimensions
                                     blockSize, 1, 1,   // block dimensions
                                     0, 0,              // shared mem, stream
                                     kernelParams, nullptr);
        
        if (res != CUDA_SUCCESS) {
            std::cerr << "Failed to launch kernel" << std::endl;
            return;
        }
        
        cuCtxSynchronize();
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        
        std::cout << "Kernel execution time: " << duration.count() << " microseconds" << std::endl;
    }
    
    void createCheckpointDuringExecution() {
        // Create a checkpoint
        std::string checkpointId = "execution_checkpoint_1";
        
        std::cout << "Creating checkpoint: " << checkpointId << std::endl;
        bool success = stateManager->createCheckpoint(checkpointId);
        
        if (success) {
            std::cout << "Checkpoint created successfully" << std::endl;
        } else {
            std::cerr << "Failed to create checkpoint" << std::endl;
        }
        
        // Set up checkpoint callback
        stateManager->onCheckpointCreated([](const std::string& id) {
            std::cout << "Checkpoint callback: " << id << " created" << std::endl;
        });
    }
    
    void performJITOptimization() {
        // Generate optimized kernel using JIT
        std::cout << "Generating optimized kernel..." << std::endl;
        
        // Create self-modifying kernel
        auto selfModKernel = std::make_unique<SelfModifyingKernel>(ORIGINAL_KERNEL_PTX);
        
        // Set up modification trigger
        selfModKernel->onIterationCount(5, [](const std::string& ptx) {
            std::cout << "Triggering kernel optimization after 5 iterations" << std::endl;
            return std::string(OPTIMIZED_KERNEL_PTX);
        });
        
        // Schedule kernel replacement
        bool success = stateManager->scheduleKernelReplacement("vector_add", 
                                                              OPTIMIZED_KERNEL_PTX);
        
        if (success) {
            std::cout << "Kernel replacement scheduled successfully" << std::endl;
        } else {
            std::cerr << "Failed to schedule kernel replacement" << std::endl;
        }
    }
    
    void performLiveKernelMigration() {
        // Create migration handler
        auto migration = std::make_unique<LiveKernelMigration>(stateManager.get());
        
        std::cout << "Preparing for migration..." << std::endl;
        migration->prepareForMigration(kernel);
        
        // Load new optimized kernel
        CUmodule newModule;
        CUfunction newKernel;
        
        CUresult res = cuModuleLoadData(&newModule, OPTIMIZED_KERNEL_PTX);
        if (res == CUDA_SUCCESS) {
            res = cuModuleGetFunction(&newKernel, newModule, "vector_add");
            
            if (res == CUDA_SUCCESS) {
                std::cout << "Migrating to optimized kernel..." << std::endl;
                migration->migrateToNewKernel(newKernel);
                migration->completeMigration();
                
                // Update kernel reference
                kernel = newKernel;
                module = newModule;
                
                std::cout << "Migration completed successfully" << std::endl;
            }
        }
    }
    
    void verifyResults() {
        // Copy results back
        cudaMemcpy(h_c.data(), d_c, N * sizeof(float), cudaMemcpyDeviceToHost);
        
        // Verify first few results
        std::cout << "Verifying results (first 10 elements):" << std::endl;
        for (int i = 0; i < 10 && i < N; i++) {
            float expected_original = h_a[i] + h_b[i];
            float expected_optimized = h_a[i] + h_b[i] * 2.0f;
            
            std::cout << "  [" << i << "] Result: " << h_c[i];
            std::cout << " (Original expected: " << expected_original;
            std::cout << ", Optimized expected: " << expected_optimized << ")" << std::endl;
        }
    }
    
    void demonstrateRestore() {
        std::cout << "Restoring from checkpoint..." << std::endl;
        
        // Corrupt some data
        float corrupt_value = -999.0f;
        cudaMemset(d_c, 0, N * sizeof(float));
        
        // Restore checkpoint
        bool success = stateManager->restoreCheckpoint("execution_checkpoint_1");
        
        if (success) {
            std::cout << "Checkpoint restored successfully" << std::endl;
            
            // Re-run kernel to verify
            runKernelWithMonitoring();
            verifyResults();
        } else {
            std::cerr << "Failed to restore checkpoint" << std::endl;
        }
    }
};

int main() {
    try {
        GPUCheckpointJITDemo demo;
        demo.runDemo();
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}