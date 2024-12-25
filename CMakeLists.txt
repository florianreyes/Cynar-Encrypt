# Minimum required CMake version
cmake_minimum_required(VERSION 3.10)

# Project name
project(Encryptor)

# Find OpenSSL package 
find_package(OpenSSL REQUIRED)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)

# Include directories 
include_directories(${PROJECT_SOURCE_DIR}/include)

# Add source files (add all your source files here)
set(SOURCES
    src/Encrypter.cpp
)

# Define the executable
add_executable(encryptor ${SOURCES})

# Link OpenSSL libraries
target_link_libraries(encryptor OpenSSL::SSL OpenSSL::Crypto)
