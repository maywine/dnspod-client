cmake_minimum_required (VERSION 3.16)
project(dnspod_client VERSION 1.0  LANGUAGES CXX)

if(NOT CMAKE_C_STANDARD)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF) 
endif()

if(NOT CMAKE_CXX_EXTENSIONS)
set(CMAKE_CXX_EXTENSIONS 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF) 
endif()

# default release
# Set a default build type if none was specified
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
set(CMAKE_BUILD_TYPE Release CACHE STRING 
        "Choose the type of build options are: None Debug Release MinSizeRel RelWithDebInfo." 
    FORCE)
endif()

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# find pthread
find_package(Threads REQUIRED)
set(THREADS_PREFER_PTHREAD_FLAG ON)

find_package(OpenSSL REQUIRED COMPONENTS SSL Crypto)
if(NOT OPENSSL_FOUND)
    message(FATAL_ERROR "Fatal error: OpenSSL (version >= 1.1.1) required.\n")
elseif(OPENSSL_VERSION VERSION_LESS "1.1.1")
    message(FATAL_ERROR "Fatal error: OpenSSL (version >= 1.1.1) required.\n")
endif(NOT OPENSSL_FOUND)

add_executable(dnspod)

target_sources(dnspod 
    PRIVATE 
        "src/dnspod.cpp")

target_include_directories(dnspod
    PRIVATE
        ${PROJECT_SOURCE_DIR}/3rd
        ${PROJECT_SOURCE_DIR}/3rd/json/single_include
)

target_compile_options(dnspod
    PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -Werror)

target_link_libraries(dnspod PRIVATE OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(dnspod PRIVATE Threads::Threads rt)

# Install
install (TARGETS dnspod
    DESTINATION bin)