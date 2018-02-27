
set(APP_ZCASH-MINIMAL zcash-minimal)

aux_source_directory(${ZCASH_MINIMAL_SOURCE}/zcash APP_SRC)
list(REMOVE_ITEM APP_SRC ${ZCASH_MINIMAL_SOURCE}/zcash/CreateJoinSplit.cpp)

aux_source_directory(${ZCASH_MINIMAL_SOURCE}/zcash/circuit APP_SRC)

set(APP_ZCASH-MINIMAL_SRC ${APP_SRC} ${ZCASH-MINIMAL_DEPEND_SRC})
MESSAGE(STATUS "APP_SRC" ${APP_SRC})

add_executable(${APP_ZCASH-MINIMAL} ${APP_ZCASH-MINIMAL_SRC})

target_link_libraries(${APP_ZCASH-MINIMAL} ${ZCASH_DEPEND_LIBS})
