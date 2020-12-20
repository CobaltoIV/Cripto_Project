cmake_minimum_required(VERSION 3.15.5)

project(project VERSION 1.0)


add_subdirectory(CompFunc)
add_subdirectory(HelpFunc)

add_executable(CA CA.cpp)
add_executable(App ClientApp.cpp)
add_executable(serverapi serverapi.cpp)

find_package(SEAL 3.6.0 REQUIRED)

target_link_libraries(CA SEAL::seal)
target_link_libraries(App SEAL::seal CompFunc HelpFunc)
target_link_libraries(serverapi SEAL::seal CompFunc HelpFunc)

target_include_directories(App PUBLIC 
                          "${PROJECT_BINARY_DIR}"
                          "${PROJECT_SOURCE_DIR}/CompFunc"
                          "${PROJECT_SOURCE_DIR}/HelpFunc"
                          )
target_include_directories(serverapi PUBLIC 
                          "${PROJECT_BINARY_DIR}"
                          "${PROJECT_SOURCE_DIR}/CompFunc"
                          "${PROJECT_SOURCE_DIR}/HelpFunc"
                          )