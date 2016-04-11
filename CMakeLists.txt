cmake_minimum_required(VERSION 3.3)
project(concurrent_server)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(SOURCE_FILES
    echoClient.c
    server.c
    test.c testserver.c.cpp testclient.c.cpp)

add_executable(concurrent_server ${SOURCE_FILES})