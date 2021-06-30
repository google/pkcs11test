cmake_minimum_required(VERSION 3.16)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
project(p11test)

set(VERSION "0.0.0")
set(VERSION_MAJOR 0)
set(VERSION_MINOR 0)
set(VERSION_PATCH 0)

set(SOURCES cipher.cc
	describe.cc
	digest.cc
	dual.cc
	globals.cc
	hmac.cc
	init.cc
	key.cc
	keypair.cc
	login.cc
	object.cc
	pkcs11-describe.cc
	pkcs11test.cc
	rng.cc
	session.cc
	sign.cc
	slot.cc
	tookan.cc
)

if(MSVC)
	list(APPEND INCLUDE_DIRS 
                ${CMAKE_CURRENT_SOURCE_DIR}/third_party/win32)
                
	list(APPEND SOURCES 
                ${CMAKE_CURRENT_SOURCE_DIR}/third_party/win32/getopt.cpp)

endif()

list(APPEND INCLUDE_DIRS 
			${CMAKE_CURRENT_SOURCE_DIR}/third_party/pkcs11)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DSTRICT_P11")
find_package(GTest CONFIG REQUIRED COMPONENTS CXX_LIB)
add_executable(${PROJECT_NAME} ${SOURCES})
target_link_libraries(${PROJECT_NAME} PRIVATE GTest::gtest GTest::gtest_main GTest::gmock GTest::gmock_main)
target_include_directories(${PROJECT_NAME} PUBLIC ${INCLUDE_DIRS} )

if(${VCPKG_TARGET_TRIPLET} MATCHES  ".*windows-static$")
	message(FATAL_ERROR "GTest library doesn't support static linking for now") 
	# switch to MultiThreaded runtime library (MT) vs MultiThreaded DLL (MD)
	set_property(TARGET ${PROJECT_NAME} PROPERTY
				 MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()



#install(TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})
#install(FILES $<TARGET_PDB_FILE:${PROJECT_NAME}> DESTINATION bin OPTIONAL)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/RelWithDebInfo/p11test.exe DESTINATION bin)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/RelWithDebInfo/p11test.pdb DESTINATION bin OPTIONAL)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/RelWithDebInfo/gmock.dll DESTINATION bin)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/RelWithDebInfo/gtest.dll DESTINATION bin)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/RelWithDebInfo/gtest_main.dll DESTINATION bin)

# Packaging
set(CPACK_PACKAGE_NAME ${PACKAGE_NAME})
set(CPACK_PACKAGE_VENDOR "plcs11test")
set(CPACK_PACKAGE_VERSION_MAJOR ${VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH ${VERSION_PATCH})
set(CPACK_GENERATOR "ZIP")
set(CPACK_SOURCE_GENERATOR "ZIP")
set(CPACK_SOURCE_IGNORE_FILES "build/*;\.git/*")

include(CPack)

##debug
#get_cmake_property(_variableNames VARIABLES)
#list (SORT _variableNames)
#foreach (_variableName ${_variableNames})
#    message(STATUS "${_variableName}=${${_variableName}}")
#endforeach() 
