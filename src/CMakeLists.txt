cmake_minimum_required(VERSION 2.8)

project(zcash-minimal)

execute_process(COMMAND make all WORKING_DIRECTORY ${ZCASH_MINIMAL_SOURCE}/3rd)

add_subdirectory(zcash)

set(ZCASH_MINIMAL_SOURCE ${CMAKE_CURRENT_SOURCE_DIR})

include_directories(${ZCASH_MINIMAL_SOURCE}
                    ${ZCASH_MINIMAL_SOURCE}/3rd/libsodium-1.0.12/build/include
                    ${ZCASH_MINIMAL_SOURCE}/3rd/snark/build/include
                    
                    )

set(ZCASH_DEPEND_LIBS ${ZCASH_MINIMAL_SOURCE}/3rd/snark/build/lib/libsnark.a 
                      ${ZCASH_MINIMAL_SOURCE}/3rd/libsodium-1.0.12/build/lib/libsodium.a)


set(ZCASH_MINIMAL_DEPEND_SRC ${ZCASH_MINIMAL_SOURCE}/crypto/sha256.cpp
                             ${ZCASH_MINIMAL_SOURCE}/support/cleanse.cpp
                             ${ZCASH_MINIMAL_SOURCE}/utils/uint256.cpp
                             ${ZCASH_MINIMAL_SOURCE}/utils/utilstrencodings.cpp
                             )