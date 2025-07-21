#ifndef _GPU_CHECKPOINT_RESTORE_HPP
#define _GPU_CHECKPOINT_RESTORE_HPP

#include <cuda.h>
#include <cuda_runtime.h>
#include <vector>
#include <memory>
#include <string>
#include <unordered_map>

namespace bpftime {
namespace attach {

// GPU kernel state structure
struct GPUKernelState {
    // Thread and block information
    dim3 gridDim;
    dim3 blockDim;
    dim3 blockIdx;
    dim3 threadIdx;
    
    // Memory state
    struct MemorySnapshot {
        std::vector<uint8_t> globalMemory;
        std::vector<uint8_t> sharedMemory;
        std::vector<uint8_t> constantMemory;
        size_t globalMemSize;
        size_t sharedMemSize;
        size_t constantMemSize;
        CUdeviceptr globalMemBase;
    };
    MemorySnapshot memory;
    
    // Register state per thread
    struct ThreadRegisterState {
        std::vector<uint32_t> registers;
        uint32_t programCounter;
        uint32_t stackPointer;
    };
    std::vector<ThreadRegisterState> threadStates;
    
    // Kernel function information
    std::string kernelName;
    CUfunction kernelFunc;
    std::vector<void*> kernelParams;
    
    // PTX code
    std::string originalPTX;
    std::string currentPTX;
    
    // Loaded module handle
    CUmodule loadedModule = nullptr;
};

// GPU checkpoint/restore manager
class GPUCheckpointRestore {
public:
    GPUCheckpointRestore();
    ~GPUCheckpointRestore();
    
    // Checkpoint operations
    bool createCheckpoint(const std::string& checkpointId, CUcontext ctx);
    bool captureKernelState(GPUKernelState& state, CUfunction kernel);
    
    // JIT operations
    bool compileAndLoadPTX(const std::string& ptxCode, CUmodule& module, 
                          const std::string& kernelName, CUfunction& function);
    bool replaceKernelCode(const std::string& checkpointId, 
                          const std::string& newPTX);
    
    // Restore operations
    bool restoreCheckpoint(const std::string& checkpointId);
    bool restoreKernelState(const GPUKernelState& state);
    
    // Utility functions
    bool injectCheckpointCode(std::string& ptxCode, const std::string& funcName);
    std::string generateJITCode(const std::string& originalPTX, 
                               const std::string& modifications);
    
private:
    std::unordered_map<std::string, std::unique_ptr<GPUKernelState>> checkpoints;
    CUcontext currentContext;
    
    // Helper functions
    bool captureGlobalMemory(GPUKernelState::MemorySnapshot& snapshot);
    bool captureSharedMemory(GPUKernelState::MemorySnapshot& snapshot);
    bool captureThreadRegisters(std::vector<GPUKernelState::ThreadRegisterState>& states);
    
    bool restoreGlobalMemory(const GPUKernelState::MemorySnapshot& snapshot);
    bool restoreSharedMemory(const GPUKernelState::MemorySnapshot& snapshot);
    bool restoreThreadRegisters(const std::vector<GPUKernelState::ThreadRegisterState>& states);
    
    // PTX manipulation
    std::string insertCheckpointInstructions(const std::string& ptx);
    std::string insertRestoreInstructions(const std::string& ptx);
};

// Checkpoint trigger mechanism
class CheckpointTrigger {
public:
    enum TriggerType {
        INSTRUCTION_COUNT,
        MEMORY_ACCESS,
        FUNCTION_CALL,
        MANUAL
    };
    
    CheckpointTrigger() : type(MANUAL), threshold(0), lastCheckpoint(0) {}
    CheckpointTrigger(TriggerType type, uint64_t threshold = 0);
    bool shouldCheckpoint(uint64_t currentValue);
    
private:
    TriggerType type;
    uint64_t threshold;
    uint64_t lastCheckpoint;
};

// Self-modifying code manager
class SelfModifyingCodeManager {
public:
    SelfModifyingCodeManager(GPUCheckpointRestore* checkpointRestore);
    
    // JIT compilation and replacement
    bool scheduleCodeReplacement(const std::string& kernelName, 
                                const std::string& newCode,
                                CheckpointTrigger::TriggerType trigger);
    bool executeReplacement(const std::string& kernelName);
    
    // Code generation helpers
    std::string optimizeForCurrentData(const std::string& originalPTX,
                                      const GPUKernelState& currentState);
    std::string generateSpecializedKernel(const std::string& templatePTX,
                                         const std::unordered_map<std::string, int>& params);
    
private:
    GPUCheckpointRestore* checkpointRestore;
    std::unordered_map<std::string, std::string> pendingReplacements;
    std::unordered_map<std::string, CheckpointTrigger> triggers;
};

} // namespace attach
} // namespace bpftime

#endif // _GPU_CHECKPOINT_RESTORE_HPP