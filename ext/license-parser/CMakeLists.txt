if (NOT SYNERGY_ENTERPRISE)
    if (CMAKE_BUILD_TYPE STREQUAL "Debug")
        set(CARGO_CMD cargo build --verbose)
        set(TARGET_DIR "debug")
    else ()
        set(CARGO_CMD cargo build --release --verbose)
        set(TARGET_DIR "release")
    endif ()

    if (WIN32)
        set(LICENSE_PARSER_LIB "${CMAKE_CURRENT_BINARY_DIR}/${TARGET_DIR}/license_parser.lib")
    else()
        set(LICENSE_PARSER_LIB "${CMAKE_CURRENT_BINARY_DIR}/${TARGET_DIR}/license_parser.a")
    endif()

    set(LICENSE_PARSER_CXX "${CMAKE_CURRENT_BINARY_DIR}/license_parser.cpp")
    set(LICENSE_PARSER_H "${CMAKE_CURRENT_BINARY_DIR}/license_parser.cpp")
    add_library(license_parser STATIC ${LICENSE_PARSER_CXX})
    add_custom_command(
        OUTPUT ${LICENSE_PARSER_CXX}
        COMMAND CARGO_TARGET_DIR=${CMAKE_CURRENT_BINARY_DIR} RUSTFLAGS="${RUST_FLAGS}" ${CARGO_CMD}
        COMMAND cp ${CMAKE_CURRENT_BINARY_DIR}/cxxbridge/license-parser/src/lib.rs.cc ${LICENSE_PARSER_CXX}
        COMMAND cp ${CMAKE_CURRENT_BINARY_DIR}/cxxbridge/license-parser/src/lib.rs.h ${CMAKE_CURRENT_BINARY_DIR}/license_parser.h
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )

    target_link_libraries(license_parser pthread dl ${LICENSE_PARSER_LIB})

    add_test(NAME license_parser_test 
        COMMAND cargo test
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
endif()