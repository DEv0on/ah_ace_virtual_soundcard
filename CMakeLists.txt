cmake_minimum_required(VERSION 3.28)
project(ilive_udp_stream)

set(CMAKE_CXX_STANDARD 23)

include_directories(C:/Users/dev0on_/Desktop/iliveAudio/WpdPack/Include)
link_libraries(C:/Users/dev0on_/Desktop/iliveAudio/WpdPack/Lib/x64/Packet.lib)
link_libraries(C:/Users/dev0on_/Desktop/iliveAudio/WpdPack/Lib/x64/wpcap.lib)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static")

add_executable(ilive_udp_stream main.cpp)
