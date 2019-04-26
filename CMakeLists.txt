cmake_minimum_required(VERSION 3.7)

project(SteganRtp)

include(FindPCAP.cmake)

# Create a sources variable with a link to all cpp files to compile
set(SOURCES
    src/Main.c
    src/usage.c
)

add_executable(${PROJECT_NAME} ${SOURCES})

target_link_libraries(${PROJECT_NAME} ${PCAP_LIBRARY})
target_include_directories(${PROJECT_NAME}
    PRIVATE
        ${PROJECT_SOURCE_DIR}/include
)