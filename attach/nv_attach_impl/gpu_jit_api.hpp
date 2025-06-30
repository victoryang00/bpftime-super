#ifndef _BPFTIME_GPU_JIT_API_HPP
#define _BPFTIME_GPU_JIT_API_HPP

#include <string>
#include <memory>

namespace bpftime {
namespace attach {

class nv_attach_impl;

/**
 * @brief API for GPU self-modifying code functionality in bpftime
 * 
 * This API allows users to schedule code replacement for GPU kernels
 * when bpftime attaches to a CUDA program.
 */
class GPUJITApi {
public:
    /**
     * @brief Get the singleton instance of GPUJITApi
     */
    static GPUJITApi& getInstance();
    
    /**
     * @brief Schedule code replacement for a GPU kernel
     * 
     * @param kernel_name The name of the kernel to replace
     * @param new_ptx_code The new PTX code to inject
     * @param trigger_iteration The iteration count to trigger replacement (-1 for immediate)
     */
    void scheduleCodeReplacement(const std::string& kernel_name,
                                const std::string& new_ptx_code,
                                int trigger_iteration = -1);
    
    /**
     * @brief Enable checkpointing for a kernel
     * 
     * @param kernel_name The name of the kernel
     * @param interval_seconds Checkpoint interval in seconds
     */
    void enableCheckpointing(const std::string& kernel_name,
                           double interval_seconds);
    
    /**
     * @brief Restore from a checkpoint
     * 
     * @param checkpoint_id The ID of the checkpoint to restore
     */
    void restoreCheckpoint(const std::string& checkpoint_id);
    
    /**
     * @brief Set the nv_attach_impl instance (called internally by bpftime)
     */
    void setAttachImpl(nv_attach_impl* impl);

private:
    GPUJITApi() = default;
    ~GPUJITApi() = default;
    GPUJITApi(const GPUJITApi&) = delete;
    GPUJITApi& operator=(const GPUJITApi&) = delete;
    
    nv_attach_impl* attach_impl = nullptr;
};

} // namespace attach
} // namespace bpftime

#endif // _BPFTIME_GPU_JIT_API_HPP