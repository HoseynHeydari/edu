cmake_minimum_required(VERSION 3.7)

project(SteganRtp)

# Create a sources variable with a link to all cpp files to compile
set(SOURCES
    src/main.c
    src/usage.c
    src/exit.c
    src/iptables.c
    src/curses.c
    src/fileinfo.c
    src/sha1.c
)

add_executable(${PROJECT_NAME} ${SOURCES})

target_link_libraries(${PROJECT_NAME} findrtp nfnetlink netfilter_queue pcap curses)
target_include_directories(${PROJECT_NAME}
    PRIVATE
        ${PROJECT_SOURCE_DIR}/include
)