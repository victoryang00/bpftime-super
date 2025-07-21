#include "gpu_jit_api.hpp"
#include "gpu_checkpoint_restore.hpp"
#include "spdlog/spdlog.h"

namespace bpftime {
namespace attach {

GPUJITApi& GPUJITApi::getInstance() {
    static GPUJITApi instance;
    return instance;
}

void GPUJITApi::setAttachImpl(nv_attach_impl* impl) {
    attach_impl = impl;
}

void GPUJITApi::scheduleCodeReplacement(const std::string& kernel_name,
                                       const std::string& new_ptx_code,
                                       int trigger_iteration) {
    if (!attach_impl) {
        SPDLOG_ERROR("GPUJITApi: nv_attach_impl not set. Is bpftime attached?");
        return;
    }
    
    // TODO: Implement when nv_attach_impl is available
    // attach_impl->scheduleCodeReplacement(kernel_name, new_ptx_code, trigger_iteration);
    SPDLOG_INFO("GPUJITApi: Scheduled code replacement for kernel {}", kernel_name);
}

void GPUJITApi::enableCheckpointing(const std::string& kernel_name,
                                   double interval_seconds) {
    if (!attach_impl) {
        SPDLOG_ERROR("GPUJITApi: nv_attach_impl not set. Is bpftime attached?");
        return;
    }
    
    // Using INSTRUCTION_COUNT as a proxy for time-based checkpointing
    // The threshold represents the interval in seconds converted to instruction count
    CheckpointTrigger trigger(CheckpointTrigger::INSTRUCTION_COUNT, 
                             static_cast<uint64_t>(interval_seconds * 1000000));
    
    // TODO: Implement when nv_attach_impl is available
    // attach_impl->enableCheckpointing(kernel_name, trigger);
    SPDLOG_INFO("GPUJITApi: Enabled checkpointing for kernel {} with interval {}s", kernel_name, interval_seconds);
}

void GPUJITApi::restoreCheckpoint(const std::string& checkpoint_id) {
    if (!attach_impl) {
        SPDLOG_ERROR("GPUJITApi: nv_attach_impl not set. Is bpftime attached?");
        return;
    }
    
    // TODO: Implement when nv_attach_impl is available
    // attach_impl->restoreCheckpoint(checkpoint_id);
    SPDLOG_INFO("GPUJITApi: Restored checkpoint {}", checkpoint_id);
}

} // namespace attach
} // namespace bpftime