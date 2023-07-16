cmake_minimum_required(VERSION 3.25)
project(gen_rand_things C)

set(CMAKE_C_STANDARD 11)
include_directories(/usr/include/)
include_directories(/usr/local/include/)
add_executable(gen_rand_things rand_things.c /usr/local/include/sodium.h rand_things.h)
target_link_libraries(gen_rand_things sodium)