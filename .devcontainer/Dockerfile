FROM mcr.microsoft.com/devcontainers/cpp:1-ubuntu-22.04

#ARG REINSTALL_CMAKE_VERSION_FROM_SOURCE="3.22.2"

# Optionally install the cmake for vcpkg
#COPY ./reinstall-cmake.sh /tmp/

#RUN if [ "${REINSTALL_CMAKE_VERSION_FROM_SOURCE}" != "none" ]; then \
#        chmod +x /tmp/reinstall-cmake.sh && /tmp/reinstall-cmake.sh ${REINSTALL_CMAKE_VERSION_FROM_SOURCE}; \
#    fi \
#    && rm -f /tmp/reinstall-cmake.sh

# [Optional] Uncomment this section to install additional vcpkg ports.
# RUN su vscode -c "${VCPKG_ROOT}/vcpkg install <your-port-name-here>"

# [Optional] Uncomment this section to install additional packages.
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends cmake clang llvm lcov
RUN --mount=type=secret,id=CIFUZZ_CREDENTIALS,required sh -c "$(curl -fsSL http://downloads.code-intelligence.com/assets/install-cifuzz.sh)" $(cat /run/secrets/CIFUZZ_CREDENTIALS) latest

# # Set random bits to less then 32 to avoid a LLVM bug that will cause segmentation faults during fuzzing execution.
# RUN sysctl vm.mmap_rnd_bits=30
RUN cifuzz completion bash > /etc/bash_completion.d/cifuzz
