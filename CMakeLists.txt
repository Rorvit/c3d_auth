cmake_minimum_required(VERSION 3.24)
project(c3d_auth VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Указываем CMake искать библиотеки в папке, которую создаст Conan
list(PREPEND CMAKE_PREFIX_PATH "${CMAKE_BINARY_DIR}/generators")

# Находим библиотеки (Conan подставит пути к ним)
find_package(OpenSSL REQUIRED)
find_package(GTest REQUIRED)

add_library(c3d_auth_lib STATIC src/c3d_auth.cpp)
target_include_directories(c3d_auth_lib PUBLIC include)
target_link_libraries(c3d_auth_lib PRIVATE OpenSSL::SSL OpenSSL::Crypto)

add_executable(c3d_auth src/main.cpp)
target_link_libraries(c3d_auth PRIVATE c3d_auth_lib)

enable_testing()
add_executable(c3d_auth_tests tests/test_auth.cpp)
target_link_libraries(c3d_auth_tests PRIVATE c3d_auth_lib GTest::gtest GTest::gtest_main)
add_test(NAME AuthTests COMMAND c3d_auth_tests)