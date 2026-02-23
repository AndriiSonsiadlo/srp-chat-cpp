cmake_minimum_required(VERSION 4.0.0)
project(CPPTerminalChat VERSION 0.1.0)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# required for Boost.Asio
if(WIN32)
    add_definitions(-D_WIN32_WINNT=0x0601)  # Windows 7
    add_definitions(-DWIN32_LEAN_AND_MEAN)
    add_definitions(-DNOMINMAX)
endif()

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(
        -Wall
        -Wextra
        -Wpedantic
    )

    if(CMAKE_BUILD_TYPE MATCHES "Debug")
        add_compile_options(-g -O0)
    else()
        add_compile_options(-O2)
    endif()
elseif(MSVC)
    add_compile_options(/W4)
    # Disable specific warnings
    add_compile_options(/wd4996)  # Deprecated functions
endif()

find_package(Boost REQUIRED COMPONENTS system)
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

include_directories(${PROJECT_SOURCE_DIR}/include)

# Common library
add_library(chat_common STATIC
        src/common/buffer.cpp
        src/common/protocol.cpp
)
target_link_libraries(chat_common
        PUBLIC
        Boost::system
)
target_include_directories(chat_common PUBLIC ${PROJECT_SOURCE_DIR}/include)

# Auth library
add_library(chat_auth STATIC
        src/auth/srp_utils.cpp
        src/auth/srp_client.cpp
        src/auth/srp_server.cpp
)
target_link_libraries(chat_auth
        PUBLIC
        OpenSSL::SSL
        OpenSSL::Crypto
)
target_include_directories(chat_auth PUBLIC ${PROJECT_SOURCE_DIR}/include)

# server
add_executable(chat_server
        src/server/main.cpp
        src/server/server.cpp
        src/server/connection_manager.cpp
)
target_link_libraries(chat_server
        PRIVATE
        chat_common
        chat_auth
        Boost::system
        Threads::Threads
)

# client
add_executable(chat_client
        src/client/main.cpp
        src/client/client.cpp
)
target_link_libraries(chat_client
        PRIVATE
        chat_common
        chat_auth
        Boost::system
        Threads::Threads
)

# GTest
option(BUILD_TESTS "Build tests" ON)
if(BUILD_TESTS)
    find_package(GTest REQUIRED)
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)

    enable_testing()

    # test executables
    add_executable(protocol_tests
            tests/protocol_tests.cpp
    )
    target_link_libraries(protocol_tests
            PRIVATE
            chat_common
            GTest::gtest_main
    )

    add_executable(types_tests
            tests/types_tests.cpp
    )
    target_link_libraries(types_tests
            PRIVATE
            chat_common
            GTest::gtest_main
    )

    add_executable(connection_manager_tests
            tests/connection_manager_tests.cpp
            src/server/connection_manager.cpp
    )
    target_link_libraries(connection_manager_tests
            PRIVATE
            chat_common
            Boost::system
            Threads::Threads
            GTest::gtest_main
    )

    include(GoogleTest)
    gtest_discover_tests(protocol_tests)
    gtest_discover_tests(types_tests)
    gtest_discover_tests(connection_manager_tests)
endif()

install(TARGETS chat_server chat_client
    RUNTIME DESTINATION bin
)
