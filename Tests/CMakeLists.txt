cmake_minimum_required(VERSION 3.15.5)

project(project VERSION 1.0)

add_executable(test test.cpp)

find_package(SEAL 3.6.0 REQUIRED)

target_link_libraries(test SEAL::seal)  
