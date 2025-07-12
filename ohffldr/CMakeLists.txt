cmake_minimum_required(VERSION 3.30)
project(ohffldr VERSION 1.0.0)

add_executable(${PROJECT_NAME} main.cpp arguments-packer.hpp custom-ohffldr.hpp beacon.h ../ohffldr.hpp)

set_target_properties(${PROJECT_NAME} PROPERTIES OUTPUT_NAME "${PROJECT_NAME}-${PROJECT_VERSION}")