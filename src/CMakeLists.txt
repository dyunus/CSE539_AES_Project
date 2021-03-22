set(SOURCES
    ${SOURCES}
    lookup.s
    main.cpp
    ciphermodes.cpp
    aes.cpp    
    yandom.cpp
)

include_directories(${PROJECT_SOURCE_DIR}/include)
add_executable(aes_exec ${SOURCES})
