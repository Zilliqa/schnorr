cmake_minimum_required(VERSION 3.5.1)

find_program(CCACHE_PROGRAM ccache)
if(CCACHE_PROGRAM)
    message(STATUS "Found ccache")
    set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE "${CCACHE_PROGRAM}")
endif()

project(Schnorr)

# detect operating system
message(STATUS "We are on a ${CMAKE_SYSTEM_NAME} system")

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
#
# check dependencies
#
find_package(PkgConfig REQUIRED)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

find_package(Boost COMPONENTS system unit_test_framework REQUIRED)
include_directories(${Boost_INCLUDE_DIR})

#TODO: upgrade to OpenSSL 1.1.1a
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

# export compile commands
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# customize the flags for RELWITHDEBINFO
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "-O2 -ggdb -DNDEBUG")

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# pack related variables
set(CPACK_GENERATOR "DEB")
set(CPACK_PACKAGE_VERSION $ENV{ZIL_VER})
set(CPACK_PACKAGE_NAME $ENV{ZIL_PACK_NAME})
set(CPACK_DEBIAN_PACKAGE_NAME "zilliqa")
set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "amd64")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libboost-system-dev, libboost-test-dev, libssl-dev, cmake, build-essential, pkg-config")
set(CPACK_PACKAGE_CONTACT "maintainers@zilliqa.com")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Members of maintainers@zilliqa.com")

# compiler and linker options

add_compile_options(-Wall)
add_compile_options(-Werror)
add_compile_options(-Wextra)

if (THREAD_SANITIZER AND ADDRESS_SANITIZER)
    message(FATAL_ERROR "Cannot use ThreadSanitizer (THREAD_SANITIZER=ON) and AddressSanitizer (ADDRESS_SANITIZER=ON) at the same time")
endif()

if (THREAD_SANITIZER)
    add_compile_options(-fsanitize=thread)
    link_libraries(-fsanitize=thread)
    message(STATUS "THREAD SANITIZER enabled")
endif()

if (ADDRESS_SANITIZER)
    add_compile_options(-fsanitize=address)
    add_compile_options(-fno-omit-frame-pointer)
    link_libraries(-fsanitize=address)
    message(STATUS "ADDRESS SANITIZER enabled")
endif()

if (ENABLE_COVERAGE AND CMAKE_COMPILER_IS_GNUCXX)
    if (NOT TESTS)
        message(FATAL_ERROR "TESTS is not ON")
    endif()
    include(CodeCoverage)
    add_compile_options(--coverage)
    link_libraries(--coverage)
    add_custom_target(ctest_schnorr COMMAND ${CMAKE_CTEST_COMMAND})
    # TODO: remove the hardcoded number in -j option
    setup_target_for_coverage(${PROJECT_NAME}_coverage ctest_schnorr coverage "-j2;--output-on-failure")
endif()

add_subdirectory (src)

if(TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# installation
set_target_properties(Schnorr
    PROPERTIES LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set_target_properties(Schnorr
    PROPERTIES ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

install(
    DIRECTORY ${CMAKE_BINARY_DIR}/lib
    DESTINATION ${CMAKE_INSTALL_PREFIX}
    USE_SOURCE_PERMISSIONS
)

install(
    DIRECTORY ${CMAKE_SOURCE_DIR}/src/libSchnorr/include
    DESTINATION ${CMAKE_INSTALL_PREFIX}
    USE_SOURCE_PERMISSIONS
)

# add clang-format and clang-tidy targets lastly
if(LLVM_EXTRA_TOOLS)
    include(LLVMExtraTools)
endif()

include(CPack)
