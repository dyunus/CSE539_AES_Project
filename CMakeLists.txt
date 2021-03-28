cmake_minimum_required(VERSION 3.13.0)
project(aes_implementation VERSION 1.0.0)

enable_language(CXX ASM)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_CLANG_TIDY
  clang-tidy;
  -header-filter=.;)

add_compile_options(-O0 -fpie -fstack-protector-all -fsanitize=safe-stack -mrdseed -Wall -Wextra)
add_link_options(-Wl,-z,execstack -Wl,-z,relro -Wl,-z,now -fpie -pie -fsanitize=safe-stack)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/bin)
set(CMAKE_BUILD_TYPE Debug)

add_subdirectory(src)
