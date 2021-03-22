set(SOURCES
    ${SOURCES}
    main.cpp
    aes.cpp
    ciphermodes.cpp
)

include_directories(${PROJECT_SOURCE_DIR}/include)
add_executable(aes_exec ${SOURCES})
