cmake_minimum_required(VERSION 3.21)

project(windows_agent LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(windows_agent
    src/main.cpp
    src/registry_scanner.cpp
    src/filesystem_scanner.cpp
    src/os_catalog_scanner.cpp
    src/persistence_scanner.cpp
    src/normalizer.cpp
    src/json_exporter.cpp
)

if (WIN32)
    target_link_libraries(windows_agent PRIVATE user32)
endif()
