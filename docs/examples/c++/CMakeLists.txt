cmake_minimum_required(VERSION 3.10)
project(ThemisExamples)

# Set the C++ standard
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Include directories
include_directories(
    /workspaces/themis/src/wrappers/themis
)

# Link libraries
set(THEMIS_LIBS themispp themis soter pthread boost_system boost_thread ssl crypto)

# Add executables and link libraries
add_executable(secure_cell_file_encrypter secure_cell_file_encrypter.cpp )
target_link_libraries(secure_cell_file_encrypter ${THEMIS_LIBS})

add_executable(secure_message_client secure_message_client.cpp )
target_link_libraries(secure_message_client ${THEMIS_LIBS})

add_executable(secure_message_server secure_message_server.cpp )
target_link_libraries(secure_message_server ${THEMIS_LIBS})

add_executable(secure_session_client secure_session_client.cpp )
target_link_libraries(secure_session_client ${THEMIS_LIBS})

add_executable(secure_session_server secure_session_server.cpp )
target_link_libraries(secure_session_server ${THEMIS_LIBS})

find_package(cxxopts CONFIG REQUIRED)
add_executable(lic_gen lic_gen.cpp)
target_link_libraries(lic_gen ${THEMIS_LIBS} cxxopts::cxxopts)