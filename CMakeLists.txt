cmake_minimum_required(VERSION 3.10)
project(Fido2YubiKey)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find libfido2 and libcbor
find_package(PkgConfig REQUIRED)
pkg_check_modules(FIDO2 REQUIRED libfido2)
pkg_check_modules(CBOR REQUIRED libcbor)

# Include directories
include_directories(
    ${FIDO2_INCLUDE_DIRS}
    ${CBOR_INCLUDE_DIRS}
)

# Link directories
link_directories(
    ${FIDO2_LIBRARY_DIRS}
    ${CBOR_LIBRARY_DIRS}
)

# Source files
add_executable(fido_main 
    main.cpp 
    Fido2Authenticator.cpp
    HumanVerificationQueue.cpp
)

# Link libraries
target_link_libraries(fido_main
    ${FIDO2_LIBRARIES}
    ${CBOR_LIBRARIES}
)

# Optional: install rules
install(TARGETS fido_main DESTINATION bin)
