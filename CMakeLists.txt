cmake_minimum_required(VERSION 3.7.2)
project(aes_implementation VERSION 1.0.0)

enable_language(CXX ASM)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_CLANG_TIDY
  clang-tidy;
  -header-filter=.;)

set(CMAKE_CXX_FLAGS "-mrdseed")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/bin)
set(CMAKE_BUILD_TYPE Debug)

add_subdirectory(src)
