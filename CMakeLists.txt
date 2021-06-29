cmake_minimum_required(VERSION 3.20)
#set(CMAKE_CXX_STANDARD 11)
#set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
project(p11test)


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



find_package(GTest CONFIG REQUIRED COMPONENTS CXX_LIB)
add_executable(${PROJECT_NAME} ${SOURCES})
target_link_libraries(${PROJECT_NAME} PRIVATE GTest::gtest GTest::gtest_main GTest::gmock GTest::gmock_main)
target_include_directories(${PROJECT_NAME} PUBLIC ${INCLUDE_DIRS} )

install(TARGETS ${PROJECT_NAME}
        DESTINATION ${CMAKE_INSTALL_BINDIR}
        )
		
install(FILES $<TARGET_PDB_FILE:${PROJECT_NAME}> DESTINATION bin OPTIONAL)
#install(FILES $<TARGET_FILE_DIR:${PROJECT_NAME}>/gmock.dll DESTINATION bin OPTIONAL)
message("$<TARGET_FILE_DIR:${PROJECT_NAME}>")
install(FILES "C:/Projects/pkcs11test/tmp/Debug/gmockd.dll" DESTINATION bin OPTIONAL)

get_cmake_property(_variableNames VARIABLES)
list (SORT _variableNames)
foreach (_variableName ${_variableNames})
    #message(STATUS "${_variableName}=${${_variableName}}")
endforeach() 
