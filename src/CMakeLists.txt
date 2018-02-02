cmake_minimum_required(VERSION 2.8)

project(zcash-minimal)

add_subdirectory(zcash)

set(ZCASH_MINIMAL_SOURCE ${CMAKE_CURRENT_SOURCE_DIR})

include_directories(${ZCASH_MINIMAL_SOURCE} 
                    ${ZCASH_MINIMAL_SOURCE}/3rd/libsodium-1.0.12/build/include
                    ${ZCASH_MINIMAL_SOURCE}/3rd/snark/build/include
                    
                    )