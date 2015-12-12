cmake_minimum_required(VERSION 3.1.2)
project(evmc CXX)

if(POLICY CMP0054)
    cmake_policy(SET CMP0054 NEW)
endif()

# Default to Release build if non provided
if(CMAKE_BUILD_TYPE STREQUAL "")
    set(CMAKE_BUILD_TYPE "Release")
endif()

if(WIN32)
    add_definitions("-DNOMINMAX")
    add_definitions("-D_WIN32_WINNT=0x0601")
endif()

if(MSVC)
    if(CMAKE_CXX_FLAGS MATCHES "/W[0-4]")
        string(REGEX REPLACE "/W[0-4]" "/W4" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
    else()
        add_compile_options("/W4")
    endif()

    add_definitions("-D_SCL_SECURE_NO_WARNINGS")
    add_definitions("-D_CRT_SECURE_NO_WARNINGS")

    add_compile_options("/wd4996") # Deprecated stuff

    if(CMAKE_CL_64)
        # Visual Studio bails out on debug builds in 64bit mode unless this flag is set...
        set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /bigobj")
        set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO} /bigobj")
    endif()
elseif(("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang") OR
       ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU"))
    # Generate JSON Compilation Database
    set(CMAKE_EXPORT_COMPILE_COMMANDS TRUE)
    # Turn on standard set of warnings
    add_compile_options("-Wall")
    add_compile_options("-pedantic")
    add_compile_options("-Wextra")

    # Activate C++14 or bail-out
    include(CheckCXXCompilerFlag)
    CHECK_CXX_COMPILER_FLAG("-std=c++14" COMPILER_SUPPORTS_CXX14)
    CHECK_CXX_COMPILER_FLAG("-std=c++1y" COMPILER_SUPPORTS_CXX1Y)
    if(COMPILER_SUPPORTS_CXX14)
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14")
    elseif(COMPILER_SUPPORTS_CXX1Y)
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++1y")
    else()
        message(STATUS "The compiler ${CMAKE_CXX_COMPILER} has no C++14 support.\
                        Please use a different C++ compiler.")
    endif()

    if(CMAKE_BUILD_TYPE STREQUAL DEBUG)
        add_definitions("-D_GLIBCXX_DEBUG")
    else()
        # Default symbol visibility (smaller binaries)
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fvisibility=hidden")
    endif()
endif()


set(EVMC_SOURCE_FILES 
    src/bytecode_interpreter.cpp
    src/bytecode_reader.cpp
    src/codegen.cpp
    src/data_symbols.cpp
    src/import_symbols.cpp
    src/main.cpp
    src/pe_writer.cpp
    src/utils.cpp
)

set(EVMC_HEADER_FILES 
    src/bytecode_interpreter.h
    src/bytecode_reader.h
    src/codegen.h
    src/data_symbols.h
    src/import_symbols.h
    src/pe_writer.h
    src/prerequisites.h
)
                 
add_executable(evmc 
    ${EVMC_SOURCE_FILES}
    ${EVMC_HEADER_FILES}
)
