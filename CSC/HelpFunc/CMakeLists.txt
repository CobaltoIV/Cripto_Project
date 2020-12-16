add_library(HelpFunc enc_dec_func.cpp)
find_package(SEAL 3.6.0 REQUIRED)
target_link_libraries(HelpFunc SEAL::seal)