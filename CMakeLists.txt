cmake_minimum_required(VERSION 3.16)
project(revproxy C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Debug or Release" FORCE)
endif()

add_executable(revproxy
    src/main.c
    src/server.c
    src/load_balancer.c
    src/health_check.c
    src/buffer_pool.c
    src/config.c
)

target_include_directories(revproxy PRIVATE include)
target_compile_definitions(revproxy PRIVATE _GNU_SOURCE)
target_compile_options(revproxy PRIVATE
    -Wall -Wextra -Werror -pedantic -pthread
    $<$<CONFIG:Debug>:-O0 -g -fsanitize=address,undefined>
    $<$<CONFIG:Release>:-O3 -DNDEBUG>
)
target_link_options(revproxy PRIVATE
    -pthread
    $<$<CONFIG:Debug>:-fsanitize=address,undefined>
)
