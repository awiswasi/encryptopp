cmake_minimum_required(VERSION 3.1)

project(video_encryption)

# Set the C++ standard to C++11
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Set the path to the Crypto++ library
set(CRYPTOPP_INCLUDE_DIR "/usr/include/cryptopp")
set(CRYPTOPP_LIBRARY "/usr/lib/x86_64-linux-gnu/libcryptopp.a")

# Add the executable target
add_executable(video_encryption main.cpp)

# Include the Crypto++ header files
target_include_directories(video_encryption PRIVATE ${CRYPTOPP_INCLUDE_DIR})

# Link the Crypto++ library to the target
target_link_libraries(video_encryption PRIVATE ${CRYPTOPP_LIBRARY})

# Set the output directory for the executable and generated files
set_target_properties(video_encryption PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bin"
        LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/lib"
        ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/lib")

# Set the input and output file paths as compile definitions
target_compile_definitions(video_encryption PRIVATE
        INPUT_FILE_PATH="${CMAKE_CURRENT_SOURCE_DIR}/test.mp4"
        OUTPUT_FILE_PATH="${CMAKE_CURRENT_SOURCE_DIR}/encrypted_test.mp4")
