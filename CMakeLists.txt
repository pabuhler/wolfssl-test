list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

find_package(wolfSSL REQUIRED)

add_executable(wolfssl-test main.c)

target_include_directories(wolfssl-test PRIVATE ${WOLFSSL_INCLUDE_DIR})
target_link_libraries(wolfssl-test ${WOLFSSL_LIBRARY})
