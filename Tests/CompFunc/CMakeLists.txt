add_library(CompFunc comparator.cpp)
find_package(SEAL 3.6.0 REQUIRED)
target_link_libraries(CompFunc SEAL::seal)