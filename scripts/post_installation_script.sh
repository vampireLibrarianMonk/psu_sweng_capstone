#!/bin/bash
# Post-installation script for llama-cpp-python
echo "Installing llama-cpp-python with custom CMake arguments..."

CMAKE_ARGS="-D MAKEFLAGS=-j$(($(nproc) - 2)) \
-D GGML_HIPBLAS=on \
-D CMAKE_C_COMPILER=/opt/rocm/llvm/bin/clang \
-D CMAKE_CXX_COMPILER=/opt/rocm/llvm/bin/clang++ \
-D CMAKE_PREFIX_PATH=/opt/rocm \
-D AMDGPU_TARGETS=gfx1100"

FORCE_CMAKE=1 pip install llama-cpp-python==0.3.1 --upgrade --force-reinstall --no-cache-dir

pip install numpy==1.26.4