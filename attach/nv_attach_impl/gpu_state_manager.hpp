#ifndef _GPU_STATE_MANAGER_HPP
#define _GPU_STATE_MANAGER_HPP

#include <cuda.h>
#include <cuda_runtime.h>
#include <memory>
#include <atomic>
#include <thread>
#include <functional>
#include "gpu_checkpoint_restore.hpp"
#include "ptx_jit_compiler.hpp"

namespace bpftime {
namespace attach {

// Forward declarations
class GPUStateManager;

// GPU execution context
struct GPUExecutionContext {
    CUcontext cudaContext;
    CUstream stream;
    CUevent checkpointEvent;
    CUevent restoreEvent;
    
    // Current kernel info
    CUfunction currentFunction;
    void** kernelParams;
    dim3 gridDim;
    dim3 blockDim;
    
    // Checkpoint control
    std::atomic<bool> checkpointRequested;
    std::atomic<bool> restoreRequested;
    std::string activeCheckpointId;
};

// Kernel execution monitor
class KernelExecutionMonitor {
public:
    KernelExecutionMonitor(GPUStateManager* manager);
    
    // Monitoring methods
    void startMonitoring(CUfunction kernel);
    void stopMonitoring();
    
    // Metrics collection
    struct ExecutionMetrics {
        uint64_t instructionCount;
        uint64_t memoryAccessCount;
        double executionTime;
        size_t memoryBandwidth;
    };
    
    ExecutionMetrics getMetrics() const;
    
    // Checkpoint triggers
    void setInstructionCountTrigger(uint64_t threshold);
    void setTimeTrigger(double seconds);
    void setMemoryAccessTrigger(uint64_t threshold);
    
private:
    GPUStateManager* stateManager;
    std::thread monitorThread;
    std::atomic<bool> monitoring;
    ExecutionMetrics currentMetrics;
    
    void monitorLoop();
    bool checkTriggers();
};

// State restoration controller
class StateRestorationController {
public:
    StateRestorationController();
    
    // Restoration strategies
    enum class RestorationStrategy {
        IMMEDIATE,      // Restore immediately
        LAZY,          // Restore on next kernel launch
        SELECTIVE,     // Restore only modified state
        INCREMENTAL    // Restore in chunks
    };
    
    void setStrategy(RestorationStrategy strategy);
    
    // Restoration methods
    bool prepareRestoration(const GPUKernelState& state);
    bool executeRestoration(GPUExecutionContext& context);
    bool validateRestoration();
    
    // Partial restoration
    bool restoreMemoryRegion(CUdeviceptr ptr, size_t size, const void* data);
    bool restoreRegistersForBlock(int blockId, const std::vector<uint32_t>& registers);
    
private:
    RestorationStrategy currentStrategy;
    std::unique_ptr<GPUKernelState> pendingState;
    
    bool immediateRestore(GPUExecutionContext& context);
    bool lazyRestore(GPUExecutionContext& context);
    bool selectiveRestore(GPUExecutionContext& context);
    bool incrementalRestore(GPUExecutionContext& context);
};

// Main GPU state manager
class GPUStateManager {
public:
    GPUStateManager();
    ~GPUStateManager();
    
    // Initialization
    bool initialize(CUcontext context);
    
    // Checkpoint/Restore operations
    bool createCheckpoint(const std::string& checkpointId);
    bool restoreCheckpoint(const std::string& checkpointId);
    
    // JIT integration
    bool enableJIT(PTXJITCompiler* compiler);
    bool scheduleKernelReplacement(const std::string& kernelName, 
                                  const std::string& newPTX);
    
    // Execution control
    bool pauseExecution();
    bool resumeExecution();
    bool isExecutionPaused() const;
    
    // State manipulation
    bool modifyMemory(CUdeviceptr ptr, size_t offset, const void* data, size_t size);
    bool modifyRegisters(int threadId, const std::vector<uint32_t>& registers);
    
    // Event callbacks
    using CheckpointCallback = std::function<void(const std::string&)>;
    using RestoreCallback = std::function<void(const std::string&)>;
    
    void onCheckpointCreated(CheckpointCallback callback);
    void onCheckpointRestored(RestoreCallback callback);
    
    // Advanced features
    bool enableContinuousCheckpointing(double intervalSeconds);
    bool enableAdaptiveCheckpointing(bool enable);
    
    // Debugging support
    void dumpCurrentState(const std::string& filename);
    void compareStates(const std::string& checkpoint1, const std::string& checkpoint2);
    
private:
    std::unique_ptr<GPUCheckpointRestore> checkpointRestore;
    std::unique_ptr<KernelExecutionMonitor> executionMonitor;
    std::unique_ptr<StateRestorationController> restorationController;
    std::unique_ptr<GPUExecutionContext> executionContext;
    
    PTXJITCompiler* jitCompiler;
    
    // State management
    std::atomic<bool> executionPaused;
    std::thread continuousCheckpointThread;
    
    // Callbacks
    std::vector<CheckpointCallback> checkpointCallbacks;
    std::vector<RestoreCallback> restoreCallbacks;
    
    // Helper methods
    bool captureCurrentState(GPUKernelState& state);
    bool applyStateModifications(GPUKernelState& state);
    void continuousCheckpointLoop(double interval);
};

// Checkpoint file manager
class CheckpointFileManager {
public:
    CheckpointFileManager(const std::string& baseDir);
    
    // File operations
    bool saveCheckpoint(const std::string& checkpointId, const GPUKernelState& state);
    bool loadCheckpoint(const std::string& checkpointId, GPUKernelState& state);
    bool deleteCheckpoint(const std::string& checkpointId);
    
    // Checkpoint management
    std::vector<std::string> listCheckpoints();
    size_t getCheckpointSize(const std::string& checkpointId);
    
    // Compression support
    void enableCompression(bool enable);
    
private:
    std::string baseDirectory;
    bool compressionEnabled;
    
    std::string getCheckpointPath(const std::string& checkpointId);
    bool compressData(const std::vector<uint8_t>& input, std::vector<uint8_t>& output);
    bool decompressData(const std::vector<uint8_t>& input, std::vector<uint8_t>& output);
};

// Live kernel migration
class LiveKernelMigration {
public:
    LiveKernelMigration(GPUStateManager* stateManager);
    
    // Migration operations
    bool prepareForMigration(CUfunction currentKernel);
    bool migrateToNewKernel(CUfunction newKernel);
    bool completeMigration();
    
    // State mapping
    bool mapOldStateToNew(const GPUKernelState& oldState, GPUKernelState& newState);
    bool validateStateMapping();
    
private:
    GPUStateManager* stateManager;
    std::unique_ptr<GPUKernelState> migrationState;
    
    CUfunction sourceKernel;
    CUfunction targetKernel;
    
    // Helper methods
    bool analyzeKernelDifferences();
    bool generateStateTransformation();
};

} // namespace attach
} // namespace bpftime

#endif // _GPU_STATE_MANAGER_HPP