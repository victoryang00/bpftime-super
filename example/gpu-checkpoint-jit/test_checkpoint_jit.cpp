#include <gtest/gtest.h>
#include <cuda_runtime.h>
#include <cuda.h>
#include <memory>
#include <vector>

#include "../../attach/nv_attach_impl/gpu_checkpoint_restore.hpp"
#include "../../attach/nv_attach_impl/ptx_jit_compiler.hpp"
#include "../../attach/nv_attach_impl/gpu_state_manager.hpp"

using namespace bpftime::attach;

class GPUCheckpointTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize CUDA
        cuInit(0);
        cuCtxCreate(&context, 0, 0);
        
        // Create managers
        checkpointRestore = std::make_unique<GPUCheckpointRestore>();
        jitCompiler = std::make_unique<PTXJITCompiler>();
        stateManager = std::make_unique<GPUStateManager>();
        
        stateManager->initialize(context);
    }
    
    void TearDown() override {
        cuCtxDestroy(context);
    }
    
    CUcontext context;
    std::unique_ptr<GPUCheckpointRestore> checkpointRestore;
    std::unique_ptr<PTXJITCompiler> jitCompiler;
    std::unique_ptr<GPUStateManager> stateManager;
};

// Test basic checkpoint creation and restoration
TEST_F(GPUCheckpointTest, BasicCheckpointRestore) {
    // Create a checkpoint
    std::string checkpointId = "test_checkpoint_1";
    ASSERT_TRUE(checkpointRestore->createCheckpoint(checkpointId, context));
    
    // Create kernel state
    GPUKernelState state;
    state.gridDim = dim3(256, 1, 1);
    state.blockDim = dim3(256, 1, 1);
    
    // Capture state (simplified)
    ASSERT_TRUE(checkpointRestore->captureKernelState(state, nullptr));
    
    // Restore checkpoint
    ASSERT_TRUE(checkpointRestore->restoreCheckpoint(checkpointId));
}

// Test PTX JIT compilation
TEST_F(GPUCheckpointTest, PTXJITCompilation) {
    const char* simplePTX = R"(
        .version 7.0
        .target sm_70
        .address_size 64
        
        .visible .entry simple_kernel()
        {
            ret;
        }
    )";
    
    CUmodule module;
    ASSERT_TRUE(jitCompiler->compilePTX(simplePTX, module));
    
    // Verify module loaded
    CUfunction function;
    CUresult res = cuModuleGetFunction(&function, module, "simple_kernel");
    ASSERT_EQ(res, CUDA_SUCCESS);
    
    cuModuleUnload(module);
}

// Test PTX instruction generation
TEST_F(GPUCheckpointTest, PTXInstructionGeneration) {
    // Test MOV instruction
    PTXInstruction movInst(PTXInstructionType::MOV);
    movInst.withDestination("%r1")
           .withSource("%r2")
           .withModifier("u32");
    
    std::string generated = movInst.generate();
    EXPECT_EQ(generated, "mov.u32 %r1, %r2;");
    
    // Test predicated instruction
    PTXInstruction predInst(PTXInstructionType::ADD);
    predInst.withPredicate("%p1")
            .withDestination("%r3")
            .withSources({"%r4", "%r5"})
            .withModifier("s32");
    
    generated = predInst.generate();
    EXPECT_EQ(generated, "@%p1 add.s32 %r3, %r4, %r5;");
}

// Test kernel code replacement
TEST_F(GPUCheckpointTest, KernelCodeReplacement) {
    std::string checkpointId = "replacement_test";
    ASSERT_TRUE(checkpointRestore->createCheckpoint(checkpointId, context));
    
    const char* newPTX = R"(
        .version 7.0
        .target sm_70
        .visible .entry new_kernel() { ret; }
    )";
    
    ASSERT_TRUE(checkpointRestore->replaceKernelCode(checkpointId, newPTX));
}

// Test state manager checkpoint operations
TEST_F(GPUCheckpointTest, StateManagerCheckpoint) {
    // Enable JIT
    stateManager->enableJIT(jitCompiler.get());
    
    // Create checkpoint
    std::string checkpointId = "state_manager_test";
    ASSERT_TRUE(stateManager->createCheckpoint(checkpointId));
    
    // Test pause/resume
    ASSERT_TRUE(stateManager->pauseExecution());
    ASSERT_TRUE(stateManager->isExecutionPaused());
    ASSERT_TRUE(stateManager->resumeExecution());
    ASSERT_FALSE(stateManager->isExecutionPaused());
}

// Test checkpoint callbacks
TEST_F(GPUCheckpointTest, CheckpointCallbacks) {
    bool callbackCalled = false;
    std::string callbackCheckpointId;
    
    stateManager->onCheckpointCreated([&](const std::string& id) {
        callbackCalled = true;
        callbackCheckpointId = id;
    });
    
    std::string testId = "callback_test";
    stateManager->createCheckpoint(testId);
    
    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ(callbackCheckpointId, testId);
}

// Test memory modification
TEST_F(GPUCheckpointTest, MemoryModification) {
    // Allocate device memory
    CUdeviceptr deviceMem;
    size_t size = 1024 * sizeof(float);
    CUresult res = cuMemAlloc(&deviceMem, size);
    ASSERT_EQ(res, CUDA_SUCCESS);
    
    // Modify memory through state manager
    float testData[] = {1.0f, 2.0f, 3.0f, 4.0f};
    ASSERT_TRUE(stateManager->modifyMemory(deviceMem, 0, testData, sizeof(testData)));
    
    // Verify modification
    float readBack[4];
    res = cuMemcpyDtoH(readBack, deviceMem, sizeof(readBack));
    ASSERT_EQ(res, CUDA_SUCCESS);
    
    for (int i = 0; i < 4; i++) {
        EXPECT_FLOAT_EQ(readBack[i], testData[i]);
    }
    
    cuMemFree(deviceMem);
}

// Test checkpoint file operations
TEST_F(GPUCheckpointTest, CheckpointFileOperations) {
    CheckpointFileManager fileManager("/tmp/gpu_checkpoints_test");
    
    // Create a test state
    GPUKernelState state;
    state.gridDim = dim3(128, 1, 1);
    state.blockDim = dim3(256, 1, 1);
    state.memory.globalMemory = {1, 2, 3, 4, 5, 6, 7, 8};
    
    // Save checkpoint
    std::string checkpointId = "file_test_1";
    ASSERT_TRUE(fileManager.saveCheckpoint(checkpointId, state));
    
    // Load checkpoint
    GPUKernelState loadedState;
    ASSERT_TRUE(fileManager.loadCheckpoint(checkpointId, loadedState));
    
    // Verify loaded state
    EXPECT_EQ(loadedState.gridDim.x, state.gridDim.x);
    EXPECT_EQ(loadedState.blockDim.x, state.blockDim.x);
    EXPECT_EQ(loadedState.memory.globalMemory.size(), state.memory.globalMemory.size());
    
    // List checkpoints
    auto checkpoints = fileManager.listCheckpoints();
    EXPECT_GE(checkpoints.size(), 1);
    
    // Delete checkpoint
    ASSERT_TRUE(fileManager.deleteCheckpoint(checkpointId));
}

// Test kernel specialization
TEST_F(GPUCheckpointTest, KernelSpecialization) {
    KernelSpecializer specializer(jitCompiler.get());
    
    const char* genericKernel = R"(
        .reg .u32 %tid;
        BLOCK_SIZE 256
        // kernel code
    )";
    
    // Test data size specialization
    std::string specialized = specializer.specializeForDataSize(genericKernel, 512);
    EXPECT_NE(specialized.find("BLOCK_SIZE 64"), std::string::npos);
    
    // Test device capability specialization
    specialized = specializer.specializeForDeviceCapability(genericKernel, 8, 0);
    // Should have Ampere optimizations
}

// Test self-modifying kernel
TEST_F(GPUCheckpointTest, SelfModifyingKernel) {
    const char* basePTX = R"(
        .version 7.0
        .target sm_70
        .visible .entry base_kernel() { ret; }
    )";
    
    SelfModifyingKernel kernel(basePTX);
    
    // Add iteration count trigger
    bool modificationTriggered = false;
    kernel.onIterationCount(3, [&](const std::string& ptx) {
        modificationTriggered = true;
        return ptx + "\n// Modified";
    });
    
    // Simulate iterations
    for (int i = 0; i < 5; i++) {
        kernel.shouldModify(nullptr);
    }
    
    EXPECT_TRUE(modificationTriggered);
    
    std::string modifiedPTX = kernel.getModifiedPTX();
    EXPECT_NE(modifiedPTX.find("// Modified"), std::string::npos);
}

// Test continuous checkpointing
TEST_F(GPUCheckpointTest, ContinuousCheckpointing) {
    // Enable continuous checkpointing with 0.1 second interval
    ASSERT_TRUE(stateManager->enableContinuousCheckpointing(0.1));
    
    // Wait for a checkpoint to be created
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    // Pause to stop continuous checkpointing
    stateManager->pauseExecution();
}

// Test live kernel migration
TEST_F(GPUCheckpointTest, LiveKernelMigration) {
    LiveKernelMigration migration(stateManager.get());
    
    // Create dummy kernels
    const char* kernel1PTX = R"(
        .version 7.0
        .target sm_70
        .visible .entry kernel1() { ret; }
    )";
    
    const char* kernel2PTX = R"(
        .version 7.0
        .target sm_70
        .visible .entry kernel2() { ret; }
    )";
    
    CUmodule module1, module2;
    CUfunction func1, func2;
    
    ASSERT_TRUE(jitCompiler->compilePTX(kernel1PTX, module1));
    ASSERT_TRUE(jitCompiler->compilePTX(kernel2PTX, module2));
    
    cuModuleGetFunction(&func1, module1, "kernel1");
    cuModuleGetFunction(&func2, module2, "kernel2");
    
    // Prepare migration
    ASSERT_TRUE(migration.prepareForMigration(func1));
    
    // Migrate to new kernel
    ASSERT_TRUE(migration.migrateToNewKernel(func2));
    
    // Complete migration
    ASSERT_TRUE(migration.completeMigration());
    
    cuModuleUnload(module1);
    cuModuleUnload(module2);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}