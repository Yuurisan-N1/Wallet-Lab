cmake_minimum_required(VERSION 3.18)
project(ufsecp_jni C)

find_package(JNI REQUIRED)

add_library(ufsecp_jni SHARED jni/ufsecp_jni.c)
target_include_directories(ufsecp_jni PRIVATE
    ${JNI_INCLUDE_DIRS}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../include/ufsecp
    ${CMAKE_CURRENT_SOURCE_DIR}/jni
)

if(TARGET ufsecp_shared)
    target_link_libraries(ufsecp_jni PRIVATE ufsecp_shared)
elseif(TARGET ufsecp::ufsecp)
    target_link_libraries(ufsecp_jni PRIVATE ufsecp::ufsecp)
else()
    message(FATAL_ERROR "ufsecp_jni requires the ufsecp C ABI target")
endif()

if(APPLE)
    set_target_properties(ufsecp_jni PROPERTIES
        INSTALL_RPATH "@loader_path")
elseif(UNIX)
    set_target_properties(ufsecp_jni PROPERTIES
        INSTALL_RPATH "$ORIGIN")
endif()

install(TARGETS ufsecp_jni
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin)
