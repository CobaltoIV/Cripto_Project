cmake_minimum_required(VERSION 3.15.5)

project(project VERSION 1.0)

add_subdirectory(CompFunc)
add_subdirectory(HelpFunc)


add_executable(test test.cpp)
add_executable(hello hello.cpp)

find_package(SEAL 3.6.0 REQUIRED)

target_link_libraries(test SEAL::seal CompFunc HelpFunc )  
target_link_libraries(hello SEAL::seal CompFunc HelpFunc )  


target_include_directories(test PUBLIC 
                          "${PROJECT_BINARY_DIR}"
                          "${PROJECT_SOURCE_DIR}/CompFunc"
                          "${PROJECT_SOURCE_DIR}/HelpFunc"
                          )
target_include_directories(hello PUBLIC 
                          "${PROJECT_BINARY_DIR}"
                          "${PROJECT_SOURCE_DIR}/CompFunc"
                          "${PROJECT_SOURCE_DIR}/HelpFunc"
                          )

