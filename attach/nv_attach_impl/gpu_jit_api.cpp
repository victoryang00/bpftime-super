#include "gpu_jit_api.hpp"
#include "nv_attach_impl.hpp"
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
    
    attach_impl->scheduleCodeReplacement(kernel_name, new_ptx_code, trigger_iteration);
}

void GPUJITApi::enableCheckpointing(const std::string& kernel_name,
                                   double interval_seconds) {
    if (!attach_impl) {
        SPDLOG_ERROR("GPUJITApi: nv_attach_impl not set. Is bpftime attached?");
        return;
    }
    
    CheckpointTrigger trigger;
    trigger.type = CheckpointTrigger::TIME_BASED;
    trigger.threshold = interval_seconds;
    
    attach_impl->enableCheckpointing(kernel_name, trigger);
}

void GPUJITApi::restoreCheckpoint(const std::string& checkpoint_id) {
    if (!attach_impl) {
        SPDLOG_ERROR("GPUJITApi: nv_attach_impl not set. Is bpftime attached?");
        return;
    }
    
    attach_impl->restoreCheckpoint(checkpoint_id);
}

} // namespace attach
} // namespace bpftime