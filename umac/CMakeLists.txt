cmake_minimum_required(VERSION 3.25)
project(python_ssh_protocol C)

set(CMAKE_C_STANDARD 11)

include_directories(.)
include_directories(
        ~/.pyenv/versions/3.7.16/include/python3.7m)
link_directories(
        ~/.pyenv/versions/3.7.16/lib
)

add_executable(python_ssh_protocol
        _umacmodule.c
        rijndael.c
        rijndael.h
        umac.c
        umac.h
        umac128.c)
