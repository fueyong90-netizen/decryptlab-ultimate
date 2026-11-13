cmake_minimum_required(VERSION 3.16)
project(DecryptLabUltimate VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

add_compile_options(-Wall -Wextra -Wpedantic)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# SQLite3 (for the signature database). Prefer pkg-config, fall back to the lib.
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
  pkg_check_modules(SQLITE3 sqlite3)
endif()
if(NOT SQLITE3_FOUND)
  find_library(SQLITE3_LIBRARIES NAMES sqlite3)
endif()

# ---- core library ----
file(GLOB_RECURSE DLU_CORE_SRC
  ${CMAKE_SOURCE_DIR}/src/core/*.cpp
  ${CMAKE_SOURCE_DIR}/src/util/*.cpp
  ${CMAKE_SOURCE_DIR}/src/vpn/*.cpp
  ${CMAKE_SOURCE_DIR}/src/engines/*.cpp
  ${CMAKE_SOURCE_DIR}/src/net/*.cpp
)

add_library(dlucore STATIC ${DLU_CORE_SRC})
target_include_directories(dlucore PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(dlucore PUBLIC OpenSSL::Crypto Threads::Threads ${SQLITE3_LIBRARIES})
if(SQLITE3_INCLUDE_DIRS)
  target_include_directories(dlucore PUBLIC ${SQLITE3_INCLUDE_DIRS})
endif()

# ---- CLI app ----
add_executable(decryptlab ${CMAKE_SOURCE_DIR}/apps/cli/main.cpp)
target_link_libraries(decryptlab PRIVATE dlucore)

# ---- API + web server ----
add_executable(decryptlab-api ${CMAKE_SOURCE_DIR}/apps/api/main.cpp)
target_link_libraries(decryptlab-api PRIVATE dlucore)

# ---- tests ----
enable_testing()
add_subdirectory(tests)

install(TARGETS decryptlab decryptlab-api RUNTIME DESTINATION bin)
