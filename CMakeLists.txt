cmake_minimum_required(VERSION 3.25)
project(SRPChat VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(BUILD_TESTS "Build tests" ON)
option(CHAT_WERROR "Treat warnings as errors" OFF)

# required for Boost.Asio
if(WIN32)
    add_definitions(-D_WIN32_WINNT=0x0601)  # Windows 7
    add_definitions(-DWIN32_LEAN_AND_MEAN)
    add_definitions(-DNOMINMAX)
endif()

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra -Wpedantic -Wshadow)
    if(CHAT_WERROR)
        add_compile_options(-Werror)
    endif()
elseif(MSVC)
    add_compile_options(/W4 /wd4996)
    if(CHAT_WERROR)
        add_compile_options(/WX)
    endif()
endif()

find_package(Boost REQUIRED COMPONENTS system)
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

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

# Crypto library
add_library(chat_crypto STATIC
        src/crypto/aes_engine.cpp
)
target_link_libraries(chat_crypto
        PUBLIC
        OpenSSL::SSL
        OpenSSL::Crypto
)
target_include_directories(chat_crypto PUBLIC ${PROJECT_SOURCE_DIR}/include)

# Auth library
add_library(chat_auth STATIC
        src/auth/srp_utils.cpp
        src/auth/srp_client.cpp
        src/auth/srp_server.cpp
        src/auth/user_store.cpp
)
target_link_libraries(chat_auth
        PUBLIC
        OpenSSL::SSL
        OpenSSL::Crypto
        chat_crypto
)
target_include_directories(chat_auth PUBLIC ${PROJECT_SOURCE_DIR}/include)

# Server executable
add_executable(chat_server
        src/server/main.cpp
        src/server/server.cpp
        src/server/connection_manager.cpp
        src/server/room.cpp
)
target_link_libraries(chat_server
        PRIVATE
        chat_common
        chat_auth
        chat_crypto
        Boost::system
        Threads::Threads
)

# Client executable
add_executable(chat_client
        src/client/main.cpp
        src/client/client.cpp
)
target_link_libraries(chat_client
        PRIVATE
        chat_common
        chat_auth
        chat_crypto
        Boost::system
        Threads::Threads
)

# GTest
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

    add_executable(room_tests
            tests/room_tests.cpp
            src/server/room.cpp
    )
    target_link_libraries(room_tests
            PRIVATE
            chat_common
            chat_auth
            chat_crypto
            Boost::system
            Threads::Threads
            GTest::gtest_main
    )

    add_executable(aes_tests
            tests/aes_tests.cpp
    )
    target_link_libraries(aes_tests
            PRIVATE
            chat_crypto
            chat_auth
            GTest::gtest_main
    )

    add_executable(wire_tests
            tests/wire_tests.cpp
    )
    target_link_libraries(wire_tests
            PRIVATE
            chat_common
            GTest::gtest_main
    )

    add_executable(srp_tests
            tests/srp_tests.cpp
    )
    target_link_libraries(srp_tests
            PRIVATE
            chat_auth
            chat_crypto
            GTest::gtest_main
    )

    add_executable(user_store_tests
            tests/user_store_tests.cpp
    )
    target_link_libraries(user_store_tests
            PRIVATE
            chat_auth
            GTest::gtest_main
    )

    include(GoogleTest)
    gtest_discover_tests(aes_tests)
    gtest_discover_tests(protocol_tests)
    gtest_discover_tests(room_tests)
    gtest_discover_tests(srp_tests)
    gtest_discover_tests(types_tests)
    gtest_discover_tests(user_store_tests)
    gtest_discover_tests(wire_tests)
endif()

install(TARGETS chat_server chat_client
    RUNTIME DESTINATION bin
)
