# Building pkcs11test for Windows

This document describes process of building both 32-bit and 64-bit versions of pkcs11test on 64-bit Windows machine.

## Required software

- [Visual Studio](https://visualstudio.microsoft.com/vs/community/) (Community)
- [C/C++ dependency manager from Microsoft](https://vcpkg.io/) 
- [CMake](https://cmake.org/)

## Prepare working directories

    set P11TEST_HOME=C:\Projects\pkcs11test
    set VCPKG_HOME=C:\Projects\vcpkg 

## Build GTest
 
    cd %VCPKG_HOME%
    bootstrap-vcpkg.bat
    vcpkg install gtest:x86-windows
    vcpkg install gtest:x64-windows
    vcpkg integrate install

## Build pkcs11test 
    git clone https://github.com/google/pkcs11test.git %P11TEST_HOME%
## x86
    mkdir %P11TEST_HOME%\tmp
    cd %P11TEST_HOME%\tmp
    cmake .. -A Win32 -DCMAKE_TOOLCHAIN_FILE=%VCPKG_HOME%/scripts/buildsystems/vcpkg.cmake
    cmake --build . --config RelWithDebInfo
    cmake -DCMAKE_INSTALL_PREFIX=%P11TEST_HOME%\out32 -DCMAKE_INSTALL_CONFIG_NAME=RelWithDebInfo -P cmake_install.cmake

## x64
    mkdir %P11TEST_HOME%\tmp
    cd %P11TEST_HOME%\tmp
    cmake .. -A x64 -DVCPKG_TARGET_TRIPLET=x64-windows -DCMAKE_TOOLCHAIN_FILE=%VCPKG_HOME%/scripts/buildsystems/vcpkg.cmake
    cmake --build . --config RelWithDebInfo
    cmake -DCMAKE_INSTALL_PREFIX=%P11TEST_HOME%\out64 -DCMAKE_INSTALL_CONFIG_NAME=RelWithDebInfo -P cmake_install.cmake
