cmake_minimum_required(VERSION 3.10)
project(gpu-checkpoint-jit CUDA CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CUDA_STANDARD 14)

# Find CUDA
find_package(CUDA REQUIRED)
find_package(Threads REQUIRED)

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/../../attach/nv_attach_impl
    ${CMAKE_CURRENT_SOURCE_DIR}/../../runtime/pos/include
    ${CUDA_INCLUDE_DIRS}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../third_party/spdlog/include
)

# Source files
set(SOURCES
    main.cpp
    ../../attach/nv_attach_impl/gpu_checkpoint_restore.cpp
    ../../attach/nv_attach_impl/ptx_jit_compiler.cpp
    ../../attach/nv_attach_impl/gpu_state_manager.cpp
)

# Create executable
add_executable(gpu_checkpoint_jit_demo ${SOURCES})

# Link libraries
target_link_libraries(gpu_checkpoint_jit_demo
    ${CUDA_LIBRARIES}
    ${CUDA_CUDA_LIBRARY}
    ${CUDA_nvrtc_LIBRARY}
    Threads::Threads
    cuda
    nvrtc
)

# Set CUDA flags
set(CMAKE_CUDA_FLAGS "${CMAKE_CUDA_FLAGS} -arch=sm_70")

# Add custom target to run the demo
add_custom_target(run_demo
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/gpu_checkpoint_jit_demo
    DEPENDS gpu_checkpoint_jit_demo
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)