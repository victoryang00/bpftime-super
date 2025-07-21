#include "gpu_state_manager.hpp"
#include <spdlog/spdlog.h>
#include <chrono>
#include <fstream>
#include <filesystem>

namespace bpftime {
namespace attach {

// KernelExecutionMonitor implementation
KernelExecutionMonitor::KernelExecutionMonitor(GPUStateManager* manager)
    : stateManager(manager), monitoring(false) {
    currentMetrics = {0, 0, 0.0, 0};
}

void KernelExecutionMonitor::startMonitoring(CUfunction kernel) {
    if (monitoring.load()) {
        spdlog::warn("Monitoring already active");
        return;
    }
    
    monitoring = true;
    monitorThread = std::thread(&KernelExecutionMonitor::monitorLoop, this);
    
    spdlog::info("Started monitoring kernel execution");
}

void KernelExecutionMonitor::stopMonitoring() {
    monitoring = false;
    if (monitorThread.joinable()) {
        monitorThread.join();
    }
    
    spdlog::info("Stopped monitoring kernel execution");
}

KernelExecutionMonitor::ExecutionMetrics KernelExecutionMonitor::getMetrics() const {
    return currentMetrics;
}

void KernelExecutionMonitor::monitorLoop() {
    auto startTime = std::chrono::high_resolution_clock::now();
    
    while (monitoring.load()) {
        // Update execution time
        auto currentTime = std::chrono::high_resolution_clock::now();
        currentMetrics.executionTime = std::chrono::duration<double>(
            currentTime - startTime).count();
        
        // Check triggers
        if (checkTriggers()) {
            spdlog::info("Checkpoint trigger activated");
            stateManager->createCheckpoint("auto_checkpoint_" + 
                std::to_string(std::chrono::system_clock::now().time_since_epoch().count()));
        }
        
        // Sleep briefly to avoid busy waiting
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

bool KernelExecutionMonitor::checkTriggers() {
    // Placeholder for trigger checking logic
    // In real implementation, would check against configured thresholds
    return false;
}

// StateRestorationController implementation
StateRestorationController::StateRestorationController() 
    : currentStrategy(RestorationStrategy::IMMEDIATE) {}

void StateRestorationController::setStrategy(RestorationStrategy strategy) {
    currentStrategy = strategy;
    spdlog::info("Set restoration strategy to {}", static_cast<int>(strategy));
}

bool StateRestorationController::prepareRestoration(const GPUKernelState& state) {
    pendingState = std::make_unique<GPUKernelState>(state);
    return true;
}

bool StateRestorationController::executeRestoration(GPUExecutionContext& context) {
    if (!pendingState) {
        spdlog::error("No pending state for restoration");
        return false;
    }
    
    switch (currentStrategy) {
        case RestorationStrategy::IMMEDIATE:
            return immediateRestore(context);
        case RestorationStrategy::LAZY:
            return lazyRestore(context);
        case RestorationStrategy::SELECTIVE:
            return selectiveRestore(context);
        case RestorationStrategy::INCREMENTAL:
            return incrementalRestore(context);
        default:
            return false;
    }
}

bool StateRestorationController::immediateRestore(GPUExecutionContext& context) {
    // Synchronize stream
    CUresult res = cuStreamSynchronize(context.stream);
    if (res != CUDA_SUCCESS) {
        spdlog::error("Failed to synchronize stream for restoration");
        return false;
    }
    
    // Restore memory
    if (!pendingState->memory.globalMemory.empty()) {
        res = cuMemcpyHtoD(pendingState->memory.globalMemBase,
                          pendingState->memory.globalMemory.data(),
                          pendingState->memory.globalMemory.size());
        if (res != CUDA_SUCCESS) {
            spdlog::error("Failed to restore global memory");
            return false;
        }
    }
    
    // Signal restoration complete
    res = cuEventRecord(context.restoreEvent, context.stream);
    
    spdlog::info("Immediate restoration completed");
    return res == CUDA_SUCCESS;
}

bool StateRestorationController::lazyRestore(GPUExecutionContext& context) {
    // Mark for restoration on next kernel launch
    context.restoreRequested = true;
    spdlog::info("Lazy restoration scheduled");
    return true;
}

bool StateRestorationController::selectiveRestore(GPUExecutionContext& context) {
    // Only restore modified regions
    // This requires tracking of modifications
    spdlog::info("Selective restoration not fully implemented");
    return immediateRestore(context);
}

bool StateRestorationController::incrementalRestore(GPUExecutionContext& context) {
    // Restore in chunks to minimize disruption
    const size_t chunkSize = 1024 * 1024; // 1MB chunks
    
    size_t totalSize = pendingState->memory.globalMemory.size();
    size_t restored = 0;
    
    while (restored < totalSize) {
        size_t currentChunk = std::min(chunkSize, totalSize - restored);
        
        CUresult res = cuMemcpyHtoD(
            pendingState->memory.globalMemBase + restored,
            pendingState->memory.globalMemory.data() + restored,
            currentChunk);
            
        if (res != CUDA_SUCCESS) {
            spdlog::error("Failed to restore chunk at offset {}", restored);
            return false;
        }
        
        restored += currentChunk;
        
        // Brief pause between chunks
        std::this_thread::sleep_for(std::chrono::microseconds(100));
    }
    
    spdlog::info("Incremental restoration completed");
    return true;
}

// GPUStateManager implementation
GPUStateManager::GPUStateManager() 
    : executionPaused(false), jitCompiler(nullptr) {
    checkpointRestore = std::make_unique<GPUCheckpointRestore>();
    executionMonitor = std::make_unique<KernelExecutionMonitor>(this);
    restorationController = std::make_unique<StateRestorationController>();
    executionContext = std::make_unique<GPUExecutionContext>();
}

GPUStateManager::~GPUStateManager() {
    if (continuousCheckpointThread.joinable()) {
        continuousCheckpointThread.join();
    }
}

bool GPUStateManager::initialize(CUcontext context) {
    executionContext->cudaContext = context;
    
    // Create stream for async operations
    CUresult res = cuStreamCreate(&executionContext->stream, CU_STREAM_NON_BLOCKING);
    if (res != CUDA_SUCCESS) {
        spdlog::error("Failed to create CUDA stream");
        return false;
    }
    
    // Create events for synchronization
    res = cuEventCreate(&executionContext->checkpointEvent, CU_EVENT_DEFAULT);
    if (res != CUDA_SUCCESS) {
        spdlog::error("Failed to create checkpoint event");
        return false;
    }
    
    res = cuEventCreate(&executionContext->restoreEvent, CU_EVENT_DEFAULT);
    if (res != CUDA_SUCCESS) {
        spdlog::error("Failed to create restore event");
        return false;
    }
    
    spdlog::info("GPU State Manager initialized successfully");
    return true;
}

bool GPUStateManager::createCheckpoint(const std::string& checkpointId) {
    if (!executionContext->cudaContext) {
        spdlog::error("GPU State Manager not initialized");
        return false;
    }
    
    // Pause execution if needed
    bool wasPaused = executionPaused.load();
    if (!wasPaused) {
        pauseExecution();
    }
    
    // Create checkpoint
    bool success = checkpointRestore->createCheckpoint(checkpointId, 
                                                      executionContext->cudaContext);
    
    if (success) {
        // Capture current state
        GPUKernelState state;
        captureCurrentState(state); // Try to capture, but don't fail if no kernel
        
        // Store the state
        executionContext->activeCheckpointId = checkpointId;
        
        // Notify callbacks
        for (const auto& callback : checkpointCallbacks) {
            callback(checkpointId);
        }
    }
    
    // Resume execution if it wasn't paused before
    if (!wasPaused) {
        resumeExecution();
    }
    
    return success;
}

bool GPUStateManager::restoreCheckpoint(const std::string& checkpointId) {
    if (!executionContext->cudaContext) {
        spdlog::error("GPU State Manager not initialized");
        return false;
    }
    
    // Pause execution
    pauseExecution();
    
    // Prepare restoration
    bool success = checkpointRestore->restoreCheckpoint(checkpointId);
    
    if (success) {
        // Execute restoration
        success = restorationController->executeRestoration(*executionContext);
        
        if (success) {
            executionContext->activeCheckpointId = checkpointId;
            
            // Notify callbacks
            for (const auto& callback : restoreCallbacks) {
                callback(checkpointId);
            }
        }
    }
    
    // Resume execution
    resumeExecution();
    
    return success;
}

bool GPUStateManager::enableJIT(PTXJITCompiler* compiler) {
    if (!compiler) {
        spdlog::error("Invalid JIT compiler provided");
        return false;
    }
    
    jitCompiler = compiler;
    spdlog::info("JIT compiler enabled for GPU State Manager");
    return true;
}

bool GPUStateManager::scheduleKernelReplacement(const std::string& kernelName,
                                              const std::string& newPTX) {
    if (!jitCompiler) {
        spdlog::error("JIT compiler not enabled");
        return false;
    }
    
    // Create a checkpoint before replacement
    std::string checkpointId = kernelName + "_pre_replacement";
    if (!createCheckpoint(checkpointId)) {
        spdlog::error("Failed to create pre-replacement checkpoint");
        return false;
    }
    
    // Schedule the replacement
    return checkpointRestore->replaceKernelCode(checkpointId, newPTX);
}

bool GPUStateManager::pauseExecution() {
    if (executionPaused.load()) {
        return true;
    }
    
    // Synchronize all streams
    CUresult res = cuCtxSynchronize();
    if (res != CUDA_SUCCESS) {
        spdlog::error("Failed to synchronize context");
        return false;
    }
    
    executionPaused = true;
    spdlog::info("GPU execution paused");
    return true;
}

bool GPUStateManager::resumeExecution() {
    if (!executionPaused.load()) {
        return true;
    }
    
    executionPaused = false;
    spdlog::info("GPU execution resumed");
    return true;
}

bool GPUStateManager::isExecutionPaused() const {
    return executionPaused.load();
}

bool GPUStateManager::captureCurrentState(GPUKernelState& state) {
    if (!executionContext->currentFunction) {
        spdlog::warn("No active kernel to capture state from");
        return false;
    }
    
    return checkpointRestore->captureKernelState(state, 
                                                executionContext->currentFunction);
}

bool GPUStateManager::enableContinuousCheckpointing(double intervalSeconds) {
    if (continuousCheckpointThread.joinable()) {
        spdlog::warn("Continuous checkpointing already enabled");
        return false;
    }
    
    continuousCheckpointThread = std::thread(
        &GPUStateManager::continuousCheckpointLoop, this, intervalSeconds);
    
    spdlog::info("Enabled continuous checkpointing with {} second interval", 
                intervalSeconds);
    return true;
}

void GPUStateManager::continuousCheckpointLoop(double interval) {
    while (!executionPaused.load()) {
        std::this_thread::sleep_for(
            std::chrono::milliseconds(static_cast<int>(interval * 1000)));
        
        std::string checkpointId = "continuous_" + 
            std::to_string(std::chrono::system_clock::now().time_since_epoch().count());
        
        createCheckpoint(checkpointId);
    }
}

void GPUStateManager::onCheckpointCreated(CheckpointCallback callback) {
    checkpointCallbacks.push_back(callback);
}

void GPUStateManager::onCheckpointRestored(RestoreCallback callback) {
    restoreCallbacks.push_back(callback);
}

// CheckpointFileManager implementation
CheckpointFileManager::CheckpointFileManager(const std::string& baseDir)
    : baseDirectory(baseDir), compressionEnabled(false) {
    // Create directory if it doesn't exist
    std::filesystem::create_directories(baseDirectory);
}

bool CheckpointFileManager::saveCheckpoint(const std::string& checkpointId,
                                         const GPUKernelState& state) {
    std::string filepath = getCheckpointPath(checkpointId);
    std::ofstream file(filepath, std::ios::binary);
    
    if (!file.is_open()) {
        spdlog::error("Failed to open checkpoint file: {}", filepath);
        return false;
    }
    
    // Write checkpoint header with version and magic number
    const uint32_t magic = 0x43504B47; // "CPKG" - CheckPoint Kernel Gpu
    const uint32_t version = 1;
    file.write(reinterpret_cast<const char*>(&magic), sizeof(uint32_t));
    file.write(reinterpret_cast<const char*>(&version), sizeof(uint32_t));
    
    // Write checkpoint metadata
    const uint64_t timestamp = std::chrono::system_clock::now().time_since_epoch().count();
    file.write(reinterpret_cast<const char*>(&timestamp), sizeof(uint64_t));
    
    // Write kernel dimensions
    file.write(reinterpret_cast<const char*>(&state.gridDim), sizeof(dim3));
    file.write(reinterpret_cast<const char*>(&state.blockDim), sizeof(dim3));
    
    // Write kernel metadata
    uint32_t kernelNameLen = state.kernelName.length();
    file.write(reinterpret_cast<const char*>(&kernelNameLen), sizeof(uint32_t));
    file.write(state.kernelName.c_str(), kernelNameLen);
    
    // Write memory sections with proper headers
    // 1. Global memory
    uint32_t sectionType = 1; // Global memory section
    file.write(reinterpret_cast<const char*>(&sectionType), sizeof(uint32_t));
    uint64_t globalMemSize = state.memory.globalMemory.size();
    file.write(reinterpret_cast<const char*>(&globalMemSize), sizeof(uint64_t));
    file.write(reinterpret_cast<const char*>(&state.memory.globalMemBase), sizeof(CUdeviceptr));
    
    if (globalMemSize > 0) {
        if (compressionEnabled) {
            std::vector<uint8_t> compressed;
            if (compressData(state.memory.globalMemory, compressed)) {
                uint64_t compressedSize = compressed.size();
                file.write(reinterpret_cast<const char*>(&compressedSize), sizeof(uint64_t));
                file.write(reinterpret_cast<const char*>(compressed.data()), compressedSize);
            } else {
                // Compression failed, write uncompressed
                uint64_t uncompressedSize = globalMemSize;
                file.write(reinterpret_cast<const char*>(&uncompressedSize), sizeof(uint64_t));
                file.write(reinterpret_cast<const char*>(state.memory.globalMemory.data()), globalMemSize);
            }
        } else {
            file.write(reinterpret_cast<const char*>(state.memory.globalMemory.data()), globalMemSize);
        }
    }
    
    // 2. Shared memory
    sectionType = 2;
    file.write(reinterpret_cast<const char*>(&sectionType), sizeof(uint32_t));
    uint64_t sharedMemSize = state.memory.sharedMemory.size();
    file.write(reinterpret_cast<const char*>(&sharedMemSize), sizeof(uint64_t));
    if (sharedMemSize > 0) {
        file.write(reinterpret_cast<const char*>(state.memory.sharedMemory.data()), sharedMemSize);
    }
    
    // 3. PTX code sections
    sectionType = 3; // Original PTX
    file.write(reinterpret_cast<const char*>(&sectionType), sizeof(uint32_t));
    uint64_t ptxLen = state.originalPTX.length();
    file.write(reinterpret_cast<const char*>(&ptxLen), sizeof(uint64_t));
    file.write(state.originalPTX.c_str(), ptxLen);
    
    sectionType = 4; // Current PTX
    file.write(reinterpret_cast<const char*>(&sectionType), sizeof(uint32_t));
    ptxLen = state.currentPTX.length();
    file.write(reinterpret_cast<const char*>(&ptxLen), sizeof(uint64_t));
    file.write(state.currentPTX.c_str(), ptxLen);
    
    // 4. Thread states
    sectionType = 5;
    file.write(reinterpret_cast<const char*>(&sectionType), sizeof(uint32_t));
    uint64_t numThreads = state.threadStates.size();
    file.write(reinterpret_cast<const char*>(&numThreads), sizeof(uint64_t));
    
    for (const auto& threadState : state.threadStates) {
        uint32_t numRegisters = threadState.registers.size();
        file.write(reinterpret_cast<const char*>(&numRegisters), sizeof(uint32_t));
        file.write(reinterpret_cast<const char*>(threadState.registers.data()), 
                  numRegisters * sizeof(uint32_t));
        file.write(reinterpret_cast<const char*>(&threadState.programCounter), sizeof(uint32_t));
        file.write(reinterpret_cast<const char*>(&threadState.stackPointer), sizeof(uint32_t));
    }
    
    // End marker
    sectionType = 0xFFFFFFFF;
    file.write(reinterpret_cast<const char*>(&sectionType), sizeof(uint32_t));
    
    file.close();
    spdlog::info("Saved checkpoint {} to {} ({}MB)", checkpointId, filepath, 
                file.tellp() / (1024.0 * 1024.0));
    return true;
}

bool CheckpointFileManager::loadCheckpoint(const std::string& checkpointId,
                                         GPUKernelState& state) {
    std::string filepath = getCheckpointPath(checkpointId);
    std::ifstream file(filepath, std::ios::binary);
    
    if (!file.is_open()) {
        spdlog::error("Failed to open checkpoint file: {}", filepath);
        return false;
    }
    
    // Read and verify header
    uint32_t magic, version;
    file.read(reinterpret_cast<char*>(&magic), sizeof(uint32_t));
    file.read(reinterpret_cast<char*>(&version), sizeof(uint32_t));
    
    if (magic != 0x43504B47) {
        spdlog::error("Invalid checkpoint file magic number: 0x{:x}", magic);
        return false;
    }
    
    if (version != 1) {
        spdlog::error("Unsupported checkpoint version: {}", version);
        return false;
    }
    
    // Read metadata
    uint64_t timestamp;
    file.read(reinterpret_cast<char*>(&timestamp), sizeof(uint64_t));
    
    // Read kernel dimensions
    file.read(reinterpret_cast<char*>(&state.gridDim), sizeof(dim3));
    file.read(reinterpret_cast<char*>(&state.blockDim), sizeof(dim3));
    
    // Read kernel name
    uint32_t kernelNameLen;
    file.read(reinterpret_cast<char*>(&kernelNameLen), sizeof(uint32_t));
    state.kernelName.resize(kernelNameLen);
    file.read(&state.kernelName[0], kernelNameLen);
    
    // Read sections
    while (file.good()) {
        uint32_t sectionType;
        file.read(reinterpret_cast<char*>(&sectionType), sizeof(uint32_t));
        
        if (sectionType == 0xFFFFFFFF) {
            // End marker
            break;
        }
        
        switch (sectionType) {
            case 1: { // Global memory
                uint64_t globalMemSize;
                file.read(reinterpret_cast<char*>(&globalMemSize), sizeof(uint64_t));
                file.read(reinterpret_cast<char*>(&state.memory.globalMemBase), sizeof(CUdeviceptr));
                
                state.memory.globalMemory.resize(globalMemSize);
                state.memory.globalMemSize = globalMemSize;
                
                if (globalMemSize > 0) {
                    if (compressionEnabled) {
                        uint64_t compressedSize;
                        file.read(reinterpret_cast<char*>(&compressedSize), sizeof(uint64_t));
                        std::vector<uint8_t> compressed(compressedSize);
                        file.read(reinterpret_cast<char*>(compressed.data()), compressedSize);
                        decompressData(compressed, state.memory.globalMemory);
                    } else {
                        file.read(reinterpret_cast<char*>(state.memory.globalMemory.data()), globalMemSize);
                    }
                }
                break;
            }
            
            case 2: { // Shared memory
                uint64_t sharedMemSize;
                file.read(reinterpret_cast<char*>(&sharedMemSize), sizeof(uint64_t));
                state.memory.sharedMemory.resize(sharedMemSize);
                state.memory.sharedMemSize = sharedMemSize;
                if (sharedMemSize > 0) {
                    file.read(reinterpret_cast<char*>(state.memory.sharedMemory.data()), sharedMemSize);
                }
                break;
            }
            
            case 3: { // Original PTX
                uint64_t ptxLen;
                file.read(reinterpret_cast<char*>(&ptxLen), sizeof(uint64_t));
                state.originalPTX.resize(ptxLen);
                file.read(&state.originalPTX[0], ptxLen);
                break;
            }
            
            case 4: { // Current PTX
                uint64_t ptxLen;
                file.read(reinterpret_cast<char*>(&ptxLen), sizeof(uint64_t));
                state.currentPTX.resize(ptxLen);
                file.read(&state.currentPTX[0], ptxLen);
                break;
            }
            
            case 5: { // Thread states
                uint64_t numThreads;
                file.read(reinterpret_cast<char*>(&numThreads), sizeof(uint64_t));
                state.threadStates.resize(numThreads);
                
                for (auto& threadState : state.threadStates) {
                    uint32_t numRegisters;
                    file.read(reinterpret_cast<char*>(&numRegisters), sizeof(uint32_t));
                    threadState.registers.resize(numRegisters);
                    file.read(reinterpret_cast<char*>(threadState.registers.data()), 
                            numRegisters * sizeof(uint32_t));
                    file.read(reinterpret_cast<char*>(&threadState.programCounter), sizeof(uint32_t));
                    file.read(reinterpret_cast<char*>(&threadState.stackPointer), sizeof(uint32_t));
                }
                break;
            }
            
            default:
                spdlog::warn("Unknown checkpoint section type: {}", sectionType);
                return false;
        }
    }
    
    file.close();
    
    auto fileTime = std::chrono::system_clock::time_point(std::chrono::nanoseconds(timestamp));
    auto timeSinceCheckpoint = std::chrono::system_clock::now() - fileTime;
    auto hours = std::chrono::duration_cast<std::chrono::hours>(timeSinceCheckpoint).count();
    
    spdlog::info("Loaded checkpoint {} from {} (created {} hours ago)", 
                checkpointId, filepath, hours);
    return true;
}

std::string CheckpointFileManager::getCheckpointPath(const std::string& checkpointId) {
    return baseDirectory + "/" + checkpointId + ".ckpt";
}

bool CheckpointFileManager::compressData(const std::vector<uint8_t>& input,
                                       std::vector<uint8_t>& output) {
    // Placeholder for compression implementation
    // Would use zlib or similar in real implementation
    output = input;
    return true;
}

bool CheckpointFileManager::decompressData(const std::vector<uint8_t>& input,
                                         std::vector<uint8_t>& output) {
    // Placeholder for decompression implementation
    output = input;
    return true;
}

// LiveKernelMigration implementation
LiveKernelMigration::LiveKernelMigration(GPUStateManager* stateManager)
    : stateManager(stateManager), sourceKernel(nullptr), targetKernel(nullptr) {}

bool LiveKernelMigration::prepareForMigration(CUfunction currentKernel) {
    sourceKernel = currentKernel;
    
    // Create checkpoint of current state
    migrationState = std::make_unique<GPUKernelState>();
    
    // Pause execution
    stateManager->pauseExecution();
    
    spdlog::info("Prepared for kernel migration");
    return true;
}

bool LiveKernelMigration::migrateToNewKernel(CUfunction newKernel) {
    if (!sourceKernel || !migrationState) {
        spdlog::error("Migration not prepared");
        return false;
    }
    
    targetKernel = newKernel;
    
    // Analyze differences between kernels
    if (!analyzeKernelDifferences()) {
        spdlog::error("Failed to analyze kernel differences");
        return false;
    }
    
    // Generate state transformation
    if (!generateStateTransformation()) {
        spdlog::error("Failed to generate state transformation");
        return false;
    }
    
    // Map old state to new state
    GPUKernelState newState;
    if (!mapOldStateToNew(*migrationState, newState)) {
        spdlog::error("Failed to map states");
        return false;
    }
    
    // Update kernel function
    migrationState->kernelFunc = targetKernel;
    
    spdlog::info("Migrated to new kernel");
    return true;
}

bool LiveKernelMigration::completeMigration() {
    if (!migrationState || !targetKernel) {
        spdlog::error("Migration not ready to complete");
        return false;
    }
    
    // Resume execution with new kernel
    stateManager->resumeExecution();
    
    spdlog::info("Kernel migration completed");
    return true;
}

bool LiveKernelMigration::analyzeKernelDifferences() {
    // Analyze PTX differences, register usage, memory layout
    // This is a placeholder for complex analysis
    return true;
}

bool LiveKernelMigration::generateStateTransformation() {
    // Generate transformation rules for state mapping
    // This is a placeholder for transformation generation
    return true;
}

bool LiveKernelMigration::mapOldStateToNew(const GPUKernelState& oldState,
                                          GPUKernelState& newState) {
    // Map registers, memory, and other state components
    newState = oldState; // Simple copy for now
    return true;
}

// GPUStateManager::modifyMemory implementation
bool GPUStateManager::modifyMemory(CUdeviceptr ptr, size_t offset, const void* data, size_t size) {
    if (!data || size == 0) {
        spdlog::error("Invalid parameters for memory modification");
        return false;
    }
    
    // Directly modify device memory
    CUresult res = cuMemcpyHtoD(ptr + offset, data, size);
    if (res != CUDA_SUCCESS) {
        const char* errorStr;
        cuGetErrorString(res, &errorStr);
        spdlog::error("Failed to modify memory: {}", errorStr);
        return false;
    }
    
    spdlog::debug("Modified {} bytes at device memory 0x{:x}", size, ptr + offset);
    return true;
}

// CheckpointFileManager missing implementations
std::vector<std::string> CheckpointFileManager::listCheckpoints() {
    std::vector<std::string> checkpoints;
    std::string path = baseDirectory;
    
    // Use filesystem to list checkpoint files
    try {
        if (std::filesystem::exists(path) && std::filesystem::is_directory(path)) {
            for (const auto& entry : std::filesystem::directory_iterator(path)) {
                if (entry.is_regular_file() && entry.path().extension() == ".ckpt") {
                    std::string filename = entry.path().stem().string();
                    checkpoints.push_back(filename);
                }
            }
        }
    } catch (const std::exception& e) {
        spdlog::error("Failed to list checkpoints: {}", e.what());
    }
    
    return checkpoints;
}

bool CheckpointFileManager::deleteCheckpoint(const std::string& checkpointId) {
    std::string filepath = getCheckpointPath(checkpointId);
    
    try {
        if (std::filesystem::exists(filepath)) {
            std::filesystem::remove(filepath);
            spdlog::info("Deleted checkpoint: {}", checkpointId);
            return true;
        } else {
            spdlog::warn("Checkpoint not found: {}", checkpointId);
            return false;
        }
    } catch (const std::exception& e) {
        spdlog::error("Failed to delete checkpoint {}: {}", checkpointId, e.what());
        return false;
    }
}

size_t CheckpointFileManager::getCheckpointSize(const std::string& checkpointId) {
    std::string filepath = getCheckpointPath(checkpointId);
    
    try {
        if (std::filesystem::exists(filepath)) {
            return std::filesystem::file_size(filepath);
        }
    } catch (const std::exception& e) {
        spdlog::error("Failed to get checkpoint size: {}", e.what());
    }
    
    return 0;
}

} // namespace attach
} // namespace bpftime