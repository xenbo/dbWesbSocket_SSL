cmake_minimum_required(VERSION 3.8)
project(websocket)

set(CMAKE_CXX_STANDARD 11)

add_definitions(-Wall)
set(CMAKE_CXX_COMPILER "/home/dongbo01/gcc63_contos68/bin/g++63")

set(LINKERFLAGS "-static-libstdc++ -static-libgcc -Wl,-gc-sections -Wl,-rpath=./ ")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS}  ${LINKERFLAGS}")

add_definitions(-Wall)
add_definitions(-g)


include_directories(.)
AUX_SOURCE_DIRECTORY(. SRC)

add_executable(websocket ${SRC})
target_link_libraries(websocket ssl crypto)
