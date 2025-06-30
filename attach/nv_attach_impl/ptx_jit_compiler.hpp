#ifndef _PTX_JIT_COMPILER_HPP
#define _PTX_JIT_COMPILER_HPP

#include <string>
#include <vector>
#include <memory>
#include <unordered_map>
#include <cuda.h>
#include <nvrtc.h>
#include <functional>

namespace bpftime {
namespace attach {

// PTX instruction types for dynamic generation
enum class PTXInstructionType {
    MOV,
    ADD,
    MUL,
    LD,
    ST,
    SETP,
    BRA,
    CALL,
    RET,
    BAR_SYNC
};

// PTX register types
enum class PTXRegisterType {
    U32,
    U64,
    F32,
    F64,
    PRED
};

// PTX instruction builder
class PTXInstruction {
public:
    PTXInstruction(PTXInstructionType type);
    
    PTXInstruction& withDestination(const std::string& dest);
    PTXInstruction& withSource(const std::string& src);
    PTXInstruction& withSources(const std::vector<std::string>& srcs);
    PTXInstruction& withPredicate(const std::string& pred);
    PTXInstruction& withModifier(const std::string& mod);
    
    std::string generate() const;
    
private:
    PTXInstructionType type;
    std::string destination;
    std::vector<std::string> sources;
    std::string predicate;
    std::string modifier;
};

// PTX code block for structured generation
class PTXCodeBlock {
public:
    PTXCodeBlock(const std::string& label = "");
    
    void addInstruction(const PTXInstruction& inst);
    void addRawInstruction(const std::string& inst);
    void addComment(const std::string& comment);
    void addLabel(const std::string& label);
    
    std::string generate() const;
    
private:
    std::string blockLabel;
    std::vector<std::string> instructions;
};

// PTX function builder
class PTXFunction {
public:
    PTXFunction(const std::string& name);
    
    // Function signature
    PTXFunction& withParameter(const std::string& type, const std::string& name);
    PTXFunction& withSharedMemory(size_t size);
    PTXFunction& withRegister(PTXRegisterType type, const std::string& name, int count = 1);
    
    // Function body
    void addCodeBlock(const PTXCodeBlock& block);
    void addEntryBlock(const PTXCodeBlock& block);
    void addExitBlock(const PTXCodeBlock& block);
    
    std::string generate() const;
    
private:
    std::string functionName;
    std::vector<std::pair<std::string, std::string>> parameters;
    std::unordered_map<std::string, std::pair<PTXRegisterType, int>> registers;
    size_t sharedMemorySize;
    std::vector<PTXCodeBlock> codeBlocks;
    PTXCodeBlock entryBlock;
    PTXCodeBlock exitBlock;
};

// JIT compiler for PTX
class PTXJITCompiler {
public:
    PTXJITCompiler();
    ~PTXJITCompiler();
    
    // Compilation methods
    bool compileCUDA(const std::string& cudaCode, std::string& ptxOutput);
    bool compilePTX(const std::string& ptxCode, CUmodule& module);
    
    // Code generation helpers
    std::string generateOptimizedLoop(int unrollFactor, const std::string& loopBody);
    std::string generateVectorizedMemAccess(int vectorSize, const std::string& baseAddr);
    std::string generateConditionalExecution(const std::string& condition, 
                                           const std::string& trueBranch,
                                           const std::string& falseBranch = "");
    
    // Optimization passes
    std::string optimizeMemoryAccess(const std::string& ptx);
    std::string optimizeRegisterUsage(const std::string& ptx);
    std::string optimizeBranchPrediction(const std::string& ptx);
    
    // Dynamic kernel generation
    std::string generateMatrixMultiplyKernel(int tileSize, bool useShared);
    std::string generateReductionKernel(const std::string& operation, int blockSize);
    std::string generateStencilKernel(int stencilSize, const std::vector<float>& weights);
    
    // Template-based generation
    void registerTemplate(const std::string& name, const std::string& templateCode);
    std::string instantiateTemplate(const std::string& templateName,
                                  const std::unordered_map<std::string, std::string>& params);
    
private:
    std::unordered_map<std::string, std::string> templates;
    nvrtcProgram currentProgram;
    
    // Helper methods
    std::string addCheckpointHooks(const std::string& ptx);
    std::string injectProfilingCode(const std::string& ptx);
    bool parseAndValidatePTX(const std::string& ptx);
};

// Runtime kernel specialization
class KernelSpecializer {
public:
    KernelSpecializer(PTXJITCompiler* compiler);
    
    // Specialization based on runtime parameters
    std::string specializeForDataSize(const std::string& genericKernel, size_t dataSize);
    std::string specializeForDeviceCapability(const std::string& kernel, int major, int minor);
    std::string specializeForMemoryPattern(const std::string& kernel, 
                                         const std::string& accessPattern);
    
    // Auto-tuning support
    struct TuningParameters {
        int blockSize;
        int tileSize;
        int unrollFactor;
        bool useSharedMemory;
        bool useTexture;
    };
    
    std::string generateTunedKernel(const std::string& baseKernel,
                                  const TuningParameters& params);
    TuningParameters autoTune(const std::string& kernel, 
                             const std::vector<void*>& sampleInputs);
    
private:
    PTXJITCompiler* compiler;
    
    // Performance model
    double predictPerformance(const std::string& kernel, const TuningParameters& params);
    std::vector<TuningParameters> generateSearchSpace();
};

// Self-modifying kernel wrapper
class SelfModifyingKernel {
public:
    SelfModifyingKernel(const std::string& basePTX);
    
    // Modification triggers
    void onMemoryPattern(std::function<std::string(const std::string&)> modifier);
    void onIterationCount(int threshold, std::function<std::string(const std::string&)> modifier);
    void onDataValue(std::function<bool(void*)> condition, 
                     std::function<std::string(const std::string&)> modifier);
    
    // Execution
    bool shouldModify(const void* kernelArgs);
    std::string getModifiedPTX();
    
private:
    std::string basePTX;
    std::string currentPTX;
    std::vector<std::pair<std::function<bool(void*)>, 
                         std::function<std::string(const std::string&)>>> modifiers;
    int iterationCount;
};

} // namespace attach
} // namespace bpftime

#endif // _PTX_JIT_COMPILER_HPP