#include "ptx_jit_compiler.hpp"
#include <spdlog/spdlog.h>
#include <sstream>
#include <regex>
#include <algorithm>

namespace bpftime {
namespace attach {

// PTXInstruction implementation
PTXInstruction::PTXInstruction(PTXInstructionType type) : type(type) {}

PTXInstruction& PTXInstruction::withDestination(const std::string& dest) {
    destination = dest;
    return *this;
}

PTXInstruction& PTXInstruction::withSource(const std::string& src) {
    sources.push_back(src);
    return *this;
}

PTXInstruction& PTXInstruction::withSources(const std::vector<std::string>& srcs) {
    sources = srcs;
    return *this;
}

PTXInstruction& PTXInstruction::withPredicate(const std::string& pred) {
    predicate = pred;
    return *this;
}

PTXInstruction& PTXInstruction::withModifier(const std::string& mod) {
    modifier = mod;
    return *this;
}

std::string PTXInstruction::generate() const {
    std::stringstream ss;
    
    // Add predicate if present
    if (!predicate.empty()) {
        ss << "@" << predicate << " ";
    }
    
    // Instruction opcode
    switch (type) {
        case PTXInstructionType::MOV:
            ss << "mov";
            break;
        case PTXInstructionType::ADD:
            ss << "add";
            break;
        case PTXInstructionType::MUL:
            ss << "mul";
            break;
        case PTXInstructionType::LD:
            ss << "ld";
            break;
        case PTXInstructionType::ST:
            ss << "st";
            break;
        case PTXInstructionType::SETP:
            ss << "setp";
            break;
        case PTXInstructionType::BRA:
            ss << "bra";
            break;
        case PTXInstructionType::CALL:
            ss << "call";
            break;
        case PTXInstructionType::RET:
            ss << "ret";
            break;
        case PTXInstructionType::BAR_SYNC:
            ss << "bar.sync";
            break;
    }
    
    // Add modifier
    if (!modifier.empty()) {
        ss << "." << modifier;
    }
    
    // Add destination
    if (!destination.empty()) {
        ss << " " << destination;
    }
    
    // Add sources
    if (!sources.empty()) {
        ss << ", ";
        for (size_t i = 0; i < sources.size(); ++i) {
            if (i > 0) ss << ", ";
            ss << sources[i];
        }
    }
    
    ss << ";";
    return ss.str();
}

// PTXCodeBlock implementation
PTXCodeBlock::PTXCodeBlock(const std::string& label) : blockLabel(label) {}

void PTXCodeBlock::addInstruction(const PTXInstruction& inst) {
    instructions.push_back(inst.generate());
}

void PTXCodeBlock::addRawInstruction(const std::string& inst) {
    instructions.push_back(inst);
}

void PTXCodeBlock::addComment(const std::string& comment) {
    instructions.push_back("// " + comment);
}

void PTXCodeBlock::addLabel(const std::string& label) {
    instructions.push_back(label + ":");
}

std::string PTXCodeBlock::generate() const {
    std::stringstream ss;
    
    if (!blockLabel.empty()) {
        ss << blockLabel << ":\n";
    }
    
    for (const auto& inst : instructions) {
        ss << "    " << inst << "\n";
    }
    
    return ss.str();
}

// PTXFunction implementation
PTXFunction::PTXFunction(const std::string& name) 
    : functionName(name), sharedMemorySize(0) {}

PTXFunction& PTXFunction::withParameter(const std::string& type, const std::string& name) {
    parameters.push_back({type, name});
    return *this;
}

PTXFunction& PTXFunction::withSharedMemory(size_t size) {
    sharedMemorySize = size;
    return *this;
}

PTXFunction& PTXFunction::withRegister(PTXRegisterType type, const std::string& name, int count) {
    registers[name] = {type, count};
    return *this;
}

void PTXFunction::addCodeBlock(const PTXCodeBlock& block) {
    codeBlocks.push_back(block);
}

void PTXFunction::addEntryBlock(const PTXCodeBlock& block) {
    entryBlock = block;
}

void PTXFunction::addExitBlock(const PTXCodeBlock& block) {
    exitBlock = block;
}

std::string PTXFunction::generate() const {
    std::stringstream ss;
    
    // Function declaration
    ss << ".visible .entry " << functionName << "(\n";
    for (size_t i = 0; i < parameters.size(); ++i) {
        if (i > 0) ss << ",\n";
        ss << "    .param ." << parameters[i].first << " " << parameters[i].second;
    }
    ss << "\n)\n{\n";
    
    // Register declarations
    for (const auto& [name, info] : registers) {
        ss << "    .reg ";
        switch (info.first) {
            case PTXRegisterType::U32:
                ss << ".u32";
                break;
            case PTXRegisterType::U64:
                ss << ".u64";
                break;
            case PTXRegisterType::F32:
                ss << ".f32";
                break;
            case PTXRegisterType::F64:
                ss << ".f64";
                break;
            case PTXRegisterType::PRED:
                ss << ".pred";
                break;
        }
        ss << " " << name;
        if (info.second > 1) {
            ss << "<" << info.second << ">";
        }
        ss << ";\n";
    }
    
    // Shared memory
    if (sharedMemorySize > 0) {
        ss << "    .shared .align 8 .b8 shared_mem[" << sharedMemorySize << "];\n";
    }
    
    ss << "\n";
    
    // Entry block
    ss << entryBlock.generate();
    
    // Code blocks
    for (const auto& block : codeBlocks) {
        ss << block.generate();
    }
    
    // Exit block
    ss << exitBlock.generate();
    
    ss << "}\n";
    
    return ss.str();
}

// PTXJITCompiler implementation
PTXJITCompiler::PTXJITCompiler() : currentProgram(nullptr) {}

PTXJITCompiler::~PTXJITCompiler() {
    if (currentProgram) {
        nvrtcDestroyProgram(&currentProgram);
    }
}

bool PTXJITCompiler::compileCUDA(const std::string& cudaCode, std::string& ptxOutput) {
    // Create NVRTC program
    nvrtcResult result = nvrtcCreateProgram(&currentProgram, cudaCode.c_str(),
                                           "jit_kernel.cu", 0, nullptr, nullptr);
    
    if (result != NVRTC_SUCCESS) {
        spdlog::error("Failed to create NVRTC program: {}", nvrtcGetErrorString(result));
        return false;
    }
    
    // Compile to PTX
    const char* opts[] = {
        "--gpu-architecture=compute_70",
        "--fmad=true",
        "--restrict"
    };
    
    result = nvrtcCompileProgram(currentProgram, 3, opts);
    
    if (result != NVRTC_SUCCESS) {
        size_t logSize;
        nvrtcGetProgramLogSize(currentProgram, &logSize);
        std::vector<char> log(logSize);
        nvrtcGetProgramLog(currentProgram, log.data());
        spdlog::error("NVRTC compilation failed: {}", log.data());
        return false;
    }
    
    // Get PTX
    size_t ptxSize;
    nvrtcGetPTXSize(currentProgram, &ptxSize);
    ptxOutput.resize(ptxSize);
    nvrtcGetPTX(currentProgram, ptxOutput.data());
    
    return true;
}

bool PTXJITCompiler::compilePTX(const std::string& ptxCode, CUmodule& module) {
    CUresult res = cuModuleLoadData(&module, ptxCode.c_str());
    
    if (res != CUDA_SUCCESS) {
        const char* error_str;
        cuGetErrorString(res, &error_str);
        spdlog::error("Failed to load PTX module: {}", error_str);
        return false;
    }
    
    return true;
}

std::string PTXJITCompiler::generateOptimizedLoop(int unrollFactor, const std::string& loopBody) {
    std::stringstream ss;
    
    ss << "// Unrolled loop with factor " << unrollFactor << "\n";
    
    // Generate unrolled iterations
    for (int i = 0; i < unrollFactor; ++i) {
        std::string unrolledBody = loopBody;
        // Replace loop index with unrolled index
        std::regex indexRegex("\\%tid");
        unrolledBody = std::regex_replace(unrolledBody, indexRegex, 
                                         "%tid_" + std::to_string(i));
        ss << unrolledBody << "\n";
    }
    
    return ss.str();
}

std::string PTXJITCompiler::generateVectorizedMemAccess(int vectorSize, const std::string& baseAddr) {
    std::stringstream ss;
    
    std::string vectorType;
    switch (vectorSize) {
        case 2:
            vectorType = "v2";
            break;
        case 4:
            vectorType = "v4";
            break;
        default:
            vectorType = "";
    }
    
    ss << "ld.global." << vectorType << ".f32 ";
    ss << "%vec_reg, [" << baseAddr << "];";
    
    return ss.str();
}

std::string PTXJITCompiler::generateConditionalExecution(const std::string& condition,
                                                       const std::string& trueBranch,
                                                       const std::string& falseBranch) {
    std::stringstream ss;
    
    ss << "    setp.ne.u32 %p_cond, " << condition << ", 0;\n";
    ss << "    @%p_cond bra TRUE_BRANCH;\n";
    
    if (!falseBranch.empty()) {
        ss << falseBranch << "\n";
        ss << "    bra END_COND;\n";
    }
    
    ss << "TRUE_BRANCH:\n";
    ss << trueBranch << "\n";
    ss << "END_COND:\n";
    
    return ss.str();
}

std::string PTXJITCompiler::optimizeMemoryAccess(const std::string& ptx) {
    std::string optimized = ptx;
    
    // Coalesce memory accesses
    std::regex consecutiveLoads("ld\\.global\\.f32\\s+%r(\\d+),\\s*\\[(.+)\\];\\s*\n\\s*ld\\.global\\.f32\\s+%r(\\d+),\\s*\\[\\2\\+4\\];");
    optimized = std::regex_replace(optimized, consecutiveLoads, 
                                 "ld.global.v2.f32 {%r$1, %r$3}, [$2];");
    
    return optimized;
}

std::string PTXJITCompiler::optimizeRegisterUsage(const std::string& ptx) {
    // Simple register renaming to reduce dependencies
    std::string optimized = ptx;
    
    // This is a placeholder - real implementation would do data flow analysis
    return optimized;
}

std::string PTXJITCompiler::optimizeBranchPrediction(const std::string& ptx) {
    std::string optimized = ptx;
    
    // Add branch hints
    std::regex unconditionalBranch("bra\\s+([^;]+);");
    optimized = std::regex_replace(optimized, unconditionalBranch, 
                                 "bra.uni $1;");
    
    return optimized;
}

std::string PTXJITCompiler::generateMatrixMultiplyKernel(int tileSize, bool useShared) {
    PTXFunction matmul("matmul_kernel");
    
    matmul.withParameter("u64", "param_A")
          .withParameter("u64", "param_B")
          .withParameter("u64", "param_C")
          .withParameter("u32", "param_N");
    
    if (useShared) {
        matmul.withSharedMemory(tileSize * tileSize * sizeof(float) * 2);
    }
    
    matmul.withRegister(PTXRegisterType::U32, "%tid_x")
          .withRegister(PTXRegisterType::U32, "%tid_y")
          .withRegister(PTXRegisterType::F32, "%sum")
          .withRegister(PTXRegisterType::U64, "%addr");
    
    PTXCodeBlock init;
    init.addRawInstruction("mov.u32 %tid_x, %tid.x;");
    init.addRawInstruction("mov.u32 %tid_y, %tid.y;");
    init.addRawInstruction("mov.f32 %sum, 0.0;");
    
    matmul.addEntryBlock(init);
    
    // Add main computation blocks...
    
    return matmul.generate();
}

std::string PTXJITCompiler::generateReductionKernel(const std::string& operation, int blockSize) {
    std::stringstream ss;
    
    ss << ".visible .entry reduction_kernel(\n";
    ss << "    .param .u64 param_data,\n";
    ss << "    .param .u64 param_result,\n";
    ss << "    .param .u32 param_n\n";
    ss << ")\n{\n";
    ss << "    .shared .align 4 .f32 shared_data[" << blockSize << "];\n";
    ss << "    .reg .u32 %tid, %bid, %idx;\n";
    ss << "    .reg .f32 %val, %sum;\n";
    
    // Thread index calculation
    ss << "    mov.u32 %tid, %tid.x;\n";
    ss << "    mov.u32 %bid, %ctaid.x;\n";
    
    // Reduction logic based on operation
    if (operation == "sum") {
        ss << "    add.f32 %sum, %sum, %val;\n";
    } else if (operation == "max") {
        ss << "    max.f32 %sum, %sum, %val;\n";
    }
    
    ss << "    ret;\n";
    ss << "}\n";
    
    return ss.str();
}

void PTXJITCompiler::registerTemplate(const std::string& name, const std::string& templateCode) {
    templates[name] = templateCode;
}

std::string PTXJITCompiler::instantiateTemplate(const std::string& templateName,
                                              const std::unordered_map<std::string, std::string>& params) {
    auto it = templates.find(templateName);
    if (it == templates.end()) {
        spdlog::error("Template {} not found", templateName);
        return "";
    }
    
    std::string instantiated = it->second;
    
    // Replace template parameters
    for (const auto& [param, value] : params) {
        std::regex paramRegex("\\$\\{" + param + "\\}");
        instantiated = std::regex_replace(instantiated, paramRegex, value);
    }
    
    return instantiated;
}

// KernelSpecializer implementation
KernelSpecializer::KernelSpecializer(PTXJITCompiler* compiler) : compiler(compiler) {}

std::string KernelSpecializer::specializeForDataSize(const std::string& genericKernel, size_t dataSize) {
    std::string specialized = genericKernel;
    
    // Adjust block size based on data size
    int optimalBlockSize = 256;
    if (dataSize < 1024) {
        optimalBlockSize = 64;
    } else if (dataSize < 65536) {
        optimalBlockSize = 128;
    }
    
    // Replace generic block size
    std::regex blockSizeRegex("BLOCK_SIZE\\s+(\\d+)");
    specialized = std::regex_replace(specialized, blockSizeRegex, 
                                   "BLOCK_SIZE " + std::to_string(optimalBlockSize));
    
    return specialized;
}

std::string KernelSpecializer::specializeForDeviceCapability(const std::string& kernel, 
                                                           int major, int minor) {
    std::string specialized = kernel;
    
    // Enable features based on compute capability
    if (major >= 7) {
        // Enable tensor cores for Volta+
        specialized = std::regex_replace(specialized, 
                                       std::regex("// TENSOR_CORE_PLACEHOLDER"),
                                       "wmma.mma.sync.m16n16k16.f32.f16");
    }
    
    if (major >= 8) {
        // Enable async copy for Ampere+
        specialized = std::regex_replace(specialized,
                                       std::regex("ld\\.global"),
                                       "cp.async.ca.shared.global");
    }
    
    return specialized;
}

std::string KernelSpecializer::generateTunedKernel(const std::string& baseKernel,
                                                 const TuningParameters& params) {
    std::string tuned = baseKernel;
    
    // Apply tuning parameters
    tuned = std::regex_replace(tuned, std::regex("BLOCK_SIZE\\s+\\d+"),
                             "BLOCK_SIZE " + std::to_string(params.blockSize));
    
    tuned = std::regex_replace(tuned, std::regex("TILE_SIZE\\s+\\d+"),
                             "TILE_SIZE " + std::to_string(params.tileSize));
    
    if (params.unrollFactor > 1) {
        tuned = std::regex_replace(tuned, std::regex("#pragma unroll\\s*\\n"),
                                 "#pragma unroll " + std::to_string(params.unrollFactor) + "\n");
    }
    
    return tuned;
}

// SelfModifyingKernel implementation
SelfModifyingKernel::SelfModifyingKernel(const std::string& basePTX) 
    : basePTX(basePTX), currentPTX(basePTX), iterationCount(0) {}

void SelfModifyingKernel::onIterationCount(int threshold, 
                                          std::function<std::string(const std::string&)> modifier) {
    modifiers.push_back({
        [this, threshold](void*) { return iterationCount >= threshold; },
        modifier
    });
}

bool SelfModifyingKernel::shouldModify(const void* kernelArgs) {
    iterationCount++;
    
    for (const auto& [condition, modifier] : modifiers) {
        if (condition(const_cast<void*>(kernelArgs))) {
            // Apply the modification when condition is met
            currentPTX = modifier(currentPTX);
            return true;
        }
    }
    
    return false;
}

std::string SelfModifyingKernel::getModifiedPTX() {
    // Apply modifications based on current state
    bool modified = false;
    for (const auto& [condition, modifier] : modifiers) {
        if (condition(nullptr)) {
            currentPTX = modifier(currentPTX);
            modified = true;
        }
    }
    
    // If nothing was modified, return the current PTX as is
    return currentPTX;
}

} // namespace attach
} // namespace bpftime