if (APPLE)
    set(OS-AGNOSTIC-LOOKUP mac_lookup.s)
endif(APPLE)

if (UNIX AND NOT APPLE)
    set(OS-AGNOSTIC-LOOKUP lookup.s)
endif (UNIX AND NOT APPLE)

set(SOURCES
    ${SOURCES}
    ${OS-AGNOSTIC-LOOKUP}
    main.cpp
    ciphermodes.cpp
    aes.cpp    
    yandom.cpp
    testbench.cpp
)

include_directories(${PROJECT_SOURCE_DIR}/include)
add_executable(aes_exec ${SOURCES})
