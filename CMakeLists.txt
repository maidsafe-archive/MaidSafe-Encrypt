cmake_minimum_required(VERSION 2.6)
#this needs to be at the top of the file
MESSAGE ("================================================================================")
IF(NOT CMAKE_GEN)
  MESSAGE("")
  IF(UNIX)
    MESSAGE("No generator previously specified.  Use e.g. -G\"CodeBlocks - Unix Makefiles\"")
  ELSE(UNIX)
    MESSAGE("No generator previously specified.  Use e.g. -G\"CodeBlocks - MinGW Makefiles\"")
  ENDIF(UNIX)
  MESSAGE("")
ENDIF(NOT CMAKE_GEN)
SET(CMAKE_GEN ${CMAKE_GENERATOR} CACHE INTERNAL "" FORCE)

IF(NOT CMAKE_BUILD_TYPE)
   SET(CMAKE_BUILD_TYPE "Release" CACHE INTERNAL "Choose the type of build, options are: Debug Release RelWithDebInfo MinSizeRel." FORCE)
ENDIF(NOT CMAKE_BUILD_TYPE)
project (PD)
IF(NOT MAIDSAFE_TEST_TYPE)
   SET(MAIDSAFE_TEST_TYPE "BEH" CACHE INTERNAL "Choose the type of TEST, options are: _ BEH FUNC" FORCE)
ENDIF(NOT MAIDSAFE_TEST_TYPE)

IF(UNIX)
	EXEC_PROGRAM(date ARGS +%a%d%m%y OUTPUT_VARIABLE pddate)
ELSE(UNIX)
	EXEC_PROGRAM("c:\\msys\\1.0\\bin\\date.exe" ARGS +%a%d%m%y OUTPUT_VARIABLE pddate)
ENDIF(UNIX)

IF(CMAKE_BUILD_TYPE MATCHES "Release")
  MESSAGE ("")
  MESSAGE("Building a package which is OK to release.")
  MESSAGE("------------------------------------------")
  SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/Release/bin/)
  SET(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/Release/lib)
ELSE()
  SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/Debug/bin/)
  SET(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/Debug/lib)
  MESSAGE ("")
  MESSAGE("Building a package which is NOT OK to release.")
  MESSAGE("----------------------------------------------")
 	SET(pddate "DEVELOPER_${pddate}")
ENDIF()

IF(NOT BOOST_VERSION)
   SET(BOOST_VERSION "1_40" CACHE INTERNAL "Set boost version i.e. 1_40 (use an underscore)" FORCE)
ENDIF(NOT BOOST_VERSION)
MESSAGE ("================================================================================")
MESSAGE ("")
IF(${BOOST_VERSION} MATCHES "none")
  MESSAGE ("Boost version is not set.")
  SET(BOOST_VERSION "")
ELSE(${BOOST_VERSION} MATCHES "none")
  MESSAGE ("Boost version is set to \"${BOOST_VERSION}\"")
  SET(BOOST_VERSION "-${BOOST_VERSION}")
ENDIF(${BOOST_VERSION} MATCHES "none")
MESSAGE ("")
MESSAGE ("    To alter this (e.g. for Boost 1.40.x),      cmake ../.. -DBOOST_VERSION=1_40")
MESSAGE ("    To have no Boost version set,               cmake ../.. -DBOOST_VERSION=none")

IF(NOT BOOST_INCLUDES)
	IF(WIN32)
    SET(BOOST_INCLUDES "c:\\usr\\include\\boost${BOOST_VERSION}" CACHE INTERNAL "Set location of BOOST headers eg c:\\usr\\include\\boost${BOOST_VERSION}" FORCE)
	ELSE()
    SET(BOOST_INCLUDES "/usr/include/boost/" CACHE INTERNAL "Set location of BOOST headers eg /usr/include/boost/" FORCE)
	ENDIF()
ENDIF(NOT BOOST_INCLUDES)
MESSAGE ("================================================================================")
MESSAGE ("")
MESSAGE ("Boost include is set to \"${BOOST_INCLUDES}\"")
MESSAGE ("")
IF(UNIX)
  MESSAGE ("    To alter this, e.g.   cmake ../.. -DBOOST_INCLUDES=/usr/include/boost-1_40")
ELSE(UNIX)
  MESSAGE ("    To alter this, e.g.   cmake ../.. -DBOOST_INCLUDES=c:\\usr\\include\\boost-1_40")
ENDIF(UNIX)
MESSAGE ("================================================================================")
MESSAGE ("")
IF(CMAKE_COMPILER_IS_GNUCC)
  IF(NOT GCC_VERSION)
    SET(GCC_VERSION "gcc43" CACHE INTERNAL "Set GCC version e.g. gcc44 (for GCC version 4.4.x)" FORCE)
  ENDIF(NOT GCC_VERSION)
  IF(${GCC_VERSION} MATCHES "none")
    MESSAGE ("GCC version is not set.")
    SET(GCC_VERSION "")
  ELSE(${GCC_VERSION} MATCHES "none")
    MESSAGE ("GCC version is set to \"${GCC_VERSION}\"")
    SET(GCC_VERSION "-${GCC_VERSION}")
  ENDIF(${GCC_VERSION} MATCHES "none")
  MESSAGE ("")
  MESSAGE ("    To alter this (e.g. for GCC 4.4.x),          cmake ../.. -DGCC_VERSION=gcc44") 
  MESSAGE ("    To have no GCC version set,                   cmake ../.. -DGCC_VERSION=none")
  MESSAGE ("================================================================================")
 #MESSAGE ("")
  IF(${CMAKE_GENERATOR} MATCHES "MinGW Makefiles")
    STRING(REPLACE "gcc" "mgw" GCC_VERSION "${GCC_VERSION}")
  ENDIF(${CMAKE_GENERATOR} MATCHES "MinGW Makefiles")
ENDIF(CMAKE_COMPILER_IS_GNUCC)

set(CPACK_PACKAGE_VERSION_PATCH ${pddate})

set(CPACK_PACKAGE_VERSION "0.1.${pddate}")
set(CPACK_PACKAGE_VERSION_MAJOR "0")
set(CPACK_PACKAGE_VERSION_MINOR "1")
#CMake Options
#SET(CMAKE_VERBOSE_MAKEFILE TRUE)
set(SOURCE_DIR ${PD_SOURCE_DIR}/src)
set(Boost_USE_STATIC_LIBS ON)
set(BUILD_SHARED_LIBS OFF)
#set(CMAKE_EXE_LINKER_FLAGS "-static")
IF(WIN32)
SET(CMAKE_EXE_LINKER_FLAGS "-Wl,--enable-auto-import")
ENDIF(WIN32)



###################################################################################
#Set up extra includes and libs for windows - it puts them everywhere #############
###################################################################################
IF (WIN32)
	IF(MSVC)
	set(INCLUDE_DIR c:/include/ )
	set(LIB_DIR c:/lib/ )
	ELSE(MSVC)
	set(INCLUDE_DIR c:/usr/include/)
	link_directories(c:/MinGW/lib/ c:/MinGW/mingw32/lib/ c:/usr/lib/ C:/Qt/4.5.0/lib)
	ENDIF(MSVC)
ELSE(WIN32)
	set(INCLUDE_DIR  /opt/local/var/macports/software/macfuse/1.7_0/opt/local/include/ )
ENDIF(WIN32)
INCLUDE_DIRECTORIES(${SOURCE_DIR} ${INCLUDE_DIR} ${BOOST_INCLUDES})
link_directories (${PD_BINARY_DIR})

##################################################################################
#SET UP ALL FILES AS GLOBS #######################################################
##################################################################################
FILE(GLOB M_QT_C "${SOURCE_DIR}/qt/*.c*")                                        #
FILE(GLOB M_QT_H "${SOURCE_DIR}/qt/*.h*")                                        #
FILE(GLOB M_QT_WIDGETS_C "${SOURCE_DIR}/qt/widgets/*.c*")                        #
FILE(GLOB M_QT_WIDGETS_H "${SOURCE_DIR}/qt/widgets/*.h*")                        #
FILE(GLOB M_QT_CLIENT_C "${SOURCE_DIR}/qt/client/*.c*")                          #
FILE(GLOB M_QT_CLIENT_H "${SOURCE_DIR}/qt/client/*.h*")                          #
FILE(GLOB M_QT_UI "${SOURCE_DIR}/qt/ui/*.ui")                                    #
FILE(GLOB M_QT_QRC "${SOURCE_DIR}/qt/resources/*.qrc")                           #
LIST(APPEND M_QT_C ${M_QT_WIDGETS_C} ${M_QT_CLIENT_C})                           #
LIST(APPEND M_QT_H ${M_QT_WIDGETS_H} ${M_QT_CLIENT_H})                           #
LIST(APPEND M_QT_DIR ${M_QT_C} ${M_QT_H})                                        #
FILE(GLOB M_PROTOBUF_C "${SOURCE_DIR}/protobuf/*.c*")                            #
FILE(GLOB M_PROTOBUF_H "${SOURCE_DIR}/protobuf/*.h*")                            #
LIST(APPEND M_PROTOBUF_DIR ${M_PROTOBUF_C} ${M_PROTOBUF_H})                      #
FILE(GLOB M_MAIDSAFE_C "${SOURCE_DIR}/maidsafe/*.c*")                            #
FILE(GLOB M_MAIDSAFE_H "${SOURCE_DIR}/maidsafe/*.h*")                            #
LIST(APPEND M_MAIDSAFE_DIR ${M_MAIDSAFE_C} ${M_MAIDSAFE_H})                      #
LIST(APPEND STYLE_MAIDSAFE ${M_MAIDSAFE_C} ${M_MAIDSAFE_H})                      #
FILE(GLOB M_MSCLIENT_C "${SOURCE_DIR}/maidsafe/client/*.c*")                     #
FILE(GLOB M_MSCLIENT_H "${SOURCE_DIR}/maidsafe/client/*.h*")                     #
LIST(APPEND M_MSCLIENT_DIR ${M_MSCLIENT_C} ${M_MSCLIENT_H})                      #
LIST(APPEND STYLE_MSCLIENT ${M_MSCLIENT_C} ${M_MSCLIENT_H})                      #
FILE(GLOB M_MSVAULT_C "${SOURCE_DIR}/maidsafe/vault/*.c*")                       #
FILE(GLOB M_MSVAULT_H "${SOURCE_DIR}/maidsafe/vault/*.h*")                       #
LIST(APPEND M_MSVAULT_DIR ${M_MSVAULT_C} ${M_MSVAULT_H})                         #
LIST(REMOVE_ITEM M_MSVAULT_DIR "${SOURCE_DIR}/maidsafe/vault/main.cc") 
LIST(REMOVE_ITEM M_MSVAULT_DIR "${SOURCE_DIR}/maidsafe/vault/win_service.cc") 
LIST(REMOVE_ITEM M_MSVAULT_DIR "${SOURCE_DIR}/maidsafe/vault/unix_deamon.cc") 
LIST(APPEND STYLE_MSVAULT ${M_MSVAULT_C} ${M_MSVAULT_H})                         #
FILE(GLOB T_MAIDSAFE_C "${SOURCE_DIR}/tests/maidsafe/*.c*")                      #
FILE(GLOB T_MAIDSAFE_H "${SOURCE_DIR}/tests/maidsafe/*.h*")                      #
LIST(APPEND T_MAIDSAFE_DIR ${T_MAIDSAFE_C} ${T_MAIDSAFE_H})                      #
LIST(REMOVE_ITEM T_MAIDSAFE_DIR "${SOURCE_DIR}/tests/maidsafe/testfuse.cc")
LIST(REMOVE_ITEM T_MAIDSAFE_DIR "${SOURCE_DIR}/tests/maidsafe/functionaltestclientcontroller.cc")
LIST(REMOVE_ITEM T_MAIDSAFE_DIR "${SOURCE_DIR}/tests/maidsafe/testpdvault.cc")
FILE(GLOB T_MAIN  "${SOURCE_DIR}/tests/main.cc")                                 #
FILE(GLOB T_FS  "${SOURCE_DIR}/tests/fs/*.c*")                                   #
##################################################################################
# Qt setup code                                                                  #
##################################################################################
 	##bloody stupid windows
       IF(WIN32)
       	SET(ENV{QTDIR} "C:/Qt/4.5.0")
	SET(QT_STATIC 1)
       ENDIF(WIN32)	
	SET(QT_STATIC 0)
       FIND_PACKAGE( Qt4 )
  INCLUDE( ${QT_USE_FILE} )
  QT4_ADD_RESOURCES(  M_QT_C ${M_QT_QRC} )
  QT4_WRAP_UI( M_QT_UI ${M_QT_UI} )
  QT4_WRAP_CPP( M_QT_C ${M_QT_H} )
  LIST(APPEND M_QT_C ${M_QT_H} ${M_QT_UI} ${M_QT_QRC})
  INCLUDE_DIRECTORIES( ${CMAKE_BINARY_DIR} )

IF (APPLE)
	SET(FS_SOURCE_FILE ${SOURCE_DIR}/fs/l_fuse/fslinux.cc ${SOURCE_DIR}/fs/l_fuse/fusecpp.h)
ELSEIF (UNIX AND NOT APPLE)
  	SET(FS_SOURCE_FILE ${SOURCE_DIR}/fs/l_fuse/fslinux.cc ${SOURCE_DIR}/fs/l_fuse/fusecpp.h)
ELSEIF (WIN32)
  	SET(FS_SOURCE_FILE ${SOURCE_DIR}/fs/w_fuse/fswin.cc ${SOURCE_DIR}/fs/w_fuse/dokan/fileinfo.h )
ENDIF(APPLE)
#######################################################################################
#All Platforms:  Add Test Exes and Create all PD libs                                 #
#######################################################################################
#add_executable(TESTfuse "${SOURCE_DIR}/tests/maidsafe/testfuse.cc" )
#add_executable(TESTclientcontroller "${SOURCE_DIR}/tests/maidsafe/functionaltestclientcontroller.cc")
add_executable(TESTpdvault "${SOURCE_DIR}/tests/maidsafe/testpdvault.cc")
add_executable(TESTmaidsafe ${T_MAIDSAFE_DIR})
add_executable(TESTfs ${T_MAIN} ${T_FS})
add_executable(testvault  "${SOURCE_DIR}/maidsafe/vault/main.cc")
IF (WIN32)
add_executable(vault  "${SOURCE_DIR}/maidsafe/vault/win_service.cc")
ELSE()
add_executable(vault  "${SOURCE_DIR}/maidsafe/vault/unix_deamon.cc")
ENDIF()
#######################################################################################
#Statically compile the pdlibs - then link applications to it                         #
#######################################################################################
add_library(PDmaidsafelib STATIC ${M_MAIDSAFE_DIR} )
add_library(PDmsclientlib STATIC ${M_MSCLIENT_DIR})
add_library(PDmsvaultlib STATIC ${M_MSVAULT_DIR})
add_library(PDTESTmsclientlib STATIC ${M_MSCLIENT_DIR})
add_library(PDfslib STATIC ${SOURCE_DIR}/fs/filesystem.cc ${FS_SOURCE_FILE})
add_library(PDpbmsgslib STATIC  ${M_PROTOBUF_DIR})
##########################################################################################
#Set up some extra compiler and linker flags for the tests mainly                        #
##########################################################################################
SET_TARGET_PROPERTIES(PDTESTmsclientlib  PROPERTIES COMPILE_FLAGS -DLOCAL_PDVAULT)        
#########################################################################################
#BUILDS
IF (APPLE)
###############################
# Apple Builds
###############################
add_executable(perpetualdata MACOSX_BUNDLE ${M_QT_C})
add_executable(pdlocal  MACOSX_BUNDLE  ${M_QT_C} )
SET(SYS_LIB
protobuf
sqlite3
boost_system-xgcc40-mt${BOOST_VERSION}.a
boost_filesystem-xgcc40-mt${BOOST_VERSION}.a
boost_regex-xgcc40-mt${BOOST_VERSION}.a
boost_thread-xgcc40-mt${BOOST_VERSION}.a
boost_date_time-xgcc40-mt${BOOST_VERSION}.a
maidsafe-dht)

ELSEIF (UNIX AND NOT APPLE)
###########################
# LINUX BUILDS
##########################
add_executable(perpetualdata ${M_QT_C} )
add_executable(pdlocal ${M_QT_C} )

SET(SYS_LIB
        maidsafe-dht
	/usr/lib/libboost_thread${GCC_VERSION}-mt${BOOST_VERSION}.a
	sqlite3
	/usr/lib/libprotobuf.a
	/usr/lib/libboost_system${GCC_VERSION}-mt${BOOST_VERSION}.a
	/usr/lib/libboost_filesystem${GCC_VERSION}-mt${BOOST_VERSION}.a
	/usr/lib/libboost_regex${GCC_VERSION}-mt${BOOST_VERSION}.a
	/usr/lib/libboost_date_time${GCC_VERSION}-mt${BOOST_VERSION}.a
	-lrt
	-lc
)

ELSEIF (WIN32)
########################
# Windows Builds
########################
add_executable(perpetualdata WIN32 ${M_QT_C})
add_executable(pdlocal WIN32 ${M_QT_C} )

SET(SYS_LIB
  -lmaidsafe-dht
 -ladvapi32 
 -lkernel32 
 -mi386pe
-lstdc++
-lws2_32
c:/usr/lib/libboost_system${GCC_VERSION}-mt${BOOST_VERSION}.lib
c:/usr/lib/libboost_filesystem${GCC_VERSION}-mt${BOOST_VERSION}.lib
c:/usr/lib/libboost_regex${GCC_VERSION}-mt${BOOST_VERSION}.lib
c:/usr/lib/libboost_thread${GCC_VERSION}-mt${BOOST_VERSION}.lib
c:/usr/lib/libboost_date_time${GCC_VERSION}-mt${BOOST_VERSION}.lib
c:/usr/lib/dokan.lib
c:/usr/lib/libprotobuf.a c:/usr/lib/libsqlite3.a -liphlpapi
)

ENDIF(APPLE)
IF(UNIX)
	SET(FUSE  "fuse")
ENDIF()
TARGET_LINK_LIBRARIES(perpetualdata PDmsclientlib PDmaidsafelib PDmsvaultlib PDfslib PDpbmsgslib ${FUSE} ${QT_LIBRARIES} ${SYS_LIB})
TARGET_LINK_LIBRARIES(pdlocal PDTESTmsclientlib PDmaidsafelib PDmsvaultlib PDfslib PDpbmsgslib ${FUSE} ${QT_LIBRARIES}  ${SYS_LIB})
TARGET_LINK_LIBRARIES(TESTmaidsafe PDmsclientlib PDmaidsafelib PDmsvaultlib PDfslib PDpbmsgslib ${FUSE} gtest gmock ${SYS_LIB})
TARGET_LINK_LIBRARIES(TESTpdvault PDmsclientlib PDmaidsafelib PDmsvaultlib PDfslib PDpbmsgslib ${FUSE} gtest ${SYS_LIB})
#TARGET_LINK_LIBRARIES(TESTclientcontroller PDmsclientlib PDmaidsafelib PDmsvaultlib PDfslib PDpbmsgslib ${FUSE} gtest ${SYS_LIB})
#TARGET_LINK_LIBRARIES(TESTfuse PDmsclientlib PDmaidsafelib PDmsvaultlib PDfslib PDpbmsgslib ${FUSE} gtest ${SYS_LIB})
TARGET_LINK_LIBRARIES(TESTfs PDmaidsafelib PDfslib ${FUSE} gtest ${SYS_LIB})
TARGET_LINK_LIBRARIES(testvault PDmsvaultlib PDmaidsafelib PDpbmsgslib ${SYS_LIB})
TARGET_LINK_LIBRARIES(vault PDmsvaultlib PDmaidsafelib PDpbmsgslib ${SYS_LIB})


IF(WIN32)
SET(TARGET_PROPERTIES vault testvault TESTmaidsafe  COMPILE_FLAGS  ${CMAKE_CXX_FLAGS} --Wl,-subsystem,console)
ENDIF(WIN32)

##################################################################################
# COMPILER FLAGS  - here after all targets declared                              #
##################################################################################
#MESSAGE("qt stuff " ${QT_LIBRARIES})
IF (APPLE)
  SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DMAIDSAFE_APPLE -D_FORTIFY_SOURCE=2 -DOSX -DBSD -D__FreeBSD__=10  -D_FILE_OFFSET_BITS=64" )
  SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -DDEBUG -pg -fprofile-arcs -ftest-coverage" )
  SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O2 -Wuninitialized")

ELSEIF (UNIX AND NOT APPLE)
  SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -DDEBUG -pg -fprofile-arcs -ftest-coverage" )
  SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O2 -Wuninitialized")
  SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DMAIDSAFE_POSIX -Wextra -Wall -Weffc++ -Wextra -Wfloat-equal -Wlong-long  -Wredundant-decls -Wstrict-overflow=5   -Wredundant-decls -Wunused-function  -Wunused-label  -Wunused-parameter -Wunused-value -Wunused-variable -std=c++98 -Wall -ansi -D_FORTIFY_SOURCE=2 -fno-stack-protector -D_FILE_OFFSET_BITS=64 ")
  ##put libs in here that will have no chance of passing tests - 3rd party ONLY !!
  SET_TARGET_PROPERTIES(pdlocal perpetualdata PROPERTIES COMPILE_FLAGS -w )

ELSEIF (WIN32)
IF(MSVC)
  SET(FS_SOURCE_FILE ${SOURCE_DIR}/fs/w_fuse/fswin.cc)
  SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /DUNICODE /D_UNICODE /D_WIN32_WINDOWS /D_CONSOLE /D__MSVC__")
  SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS} /DUNICODE /D_WIN32_WINDOWS /DDEBUG /D_CONSOLE")
ELSE(MSVC)
  SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wfloat-equal -Wlong-long  -Wstrict-overflow=5 -D_FORTIFY_SOURCE=2 -fno-stack-protector  -D_FILE_OFFSET_BITS=64")
  SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -DDEBUG") # -fprofile-arcs -ftest-coverage")
  SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O2 -Wuninitialized")
  SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -I c:/usr/include -DMAIDSAFE_WIN32 -D_FORTIFY_SOURCE=2   -DWIN32_LEAN_AND_MEAN  -D__MINGW__  -L c:/MinGW/lib/ -L c:/MinGW/mingw32/lib/ -static   -mthreads -D_GLIBCXX_USE_WCHAR_T -DUNICODE -D_UNICODE -DWIN32  -D_WIN32_WINNT=0x0501  -mthreads ")
  SET_TARGET_PROPERTIES( pdlocal perpetualdata  PROPERTIES COMPILE_FLAGS -w )
ENDIF(MSVC)
ENDIF(APPLE)

################################################################
# TESTS                                                        #
################################################################
INCLUDE(CTest)
SET(CTEST_CUSTOM_MAXIMUM_PASSED_TEST_OUTPUT_SIZE 50000) 
SET (CTEST_CONTINUOUS_DURATION 600)
SET (CTEST_CONTINUOUS_MINIMUM_INTERVAL 60)
set(CTEST_START_WITH_EMPTY_BINARY_DIRECTORY true)
#ADD_TEST(TestIdentifier ExecutableName [Arguments])
#ADD_TEST(Testclientcontroller ${EXECUTABLE_OUTPUT_PATH}/TESTclientcontroller)
ADD_TEST(Testpdvault ${EXECUTABLE_OUTPUT_PATH}/TESTpdvault)
IF(UNIX)
ADD_TEST(CHK_MS_ ${SOURCE_DIR}/cpplint.py ${STYLE_MAIDSAFE})
#ADD_TEST(CHK_KAD_ ${SOURCE_DIR}/cpplint.py ${STYLE_KADEMLIA})
#ADD_TEST(CHK_TRAN_ ${SOURCE_DIR}/cpplint.py ${M_TRANSPORT_DIR})
#ADD_TEST(CHK_BASE_ ${SOURCE_DIR}/cpplint.py ${M_BASE_DIR})
#ADD_TEST(CHK_RPC_COMPONENT ${SOURCE_DIR}/cpplint.py ${M_RPCPROTO_DIR})
ENDIF(UNIX)
IF(UNIX)
	FOREACH(TESTTYPE TESTmaidsafe )
ELSE(UNIX)
	FOREACH(TESTTYPE TESTmaidsafe.exe )
ENDIF(UNIX)
	EXEC_PROGRAM(${EXECUTABLE_OUTPUT_PATH}/${TESTTYPE} ARGS --gtest_list_tests OUTPUT_VARIABLE maid_tests)
	if(WIN32)
	STRING(REPLACE "\n" ";" maid_tests "${maid_tests}")
	STRING(REPLACE " " "" maid_tests "${maid_tests}")
	#STRING(REPLACE " " ";" TESTTYPE "${TESTTYPE}")
	ELSE(WIN32)
	STRING(REPLACE "\n" ";" maid_tests "${maid_tests}")
	STRING(REPLACE " " "" maid_tests "${maid_tests}")
	STRING(REPLACE " " ";" TESTTYPE "${TESTTYPE}")
	ENDIF(WIN32)

	FOREACH(tst ${maid_tests})
			IF(NOT "${tst}" MATCHES "(profiling).+")
			IF(NOT "${tst}" MATCHES "(\\.$)")
			IF("${tst}" MATCHES "(${MAIDSAFE_TEST_TYPE}).+")
		    ADD_TEST(${tst}    ${EXECUTABLE_OUTPUT_PATH}/${TESTTYPE}   --gtest_filter=*${tst}*)
		    #		    MESSAGE("${tst}   ${TESTTYPE}    --gtest_filter=*${tst}*")
	    		ENDIF()
	    		ENDIF()
			ENDIF()
	ENDFOREACH()
ENDFOREACH()
#ADD_TEST(Testfuse ${EXECUTABLE_OUTPUT_PATH}/TESTfuse)


SET(DART_TESTING_TIMEOUT 3500)
IF(UNIX)
SET(MEMORYCHECK_COMMAND "/usr/bin/valgrind --show-reachable=no")
ENDIF(UNIX)

#Adding the install targets
################################################################
MESSAGE ("")
MESSAGE ("Package version is set to \"${pddate}\"")
MESSAGE ("================================================================================")
MESSAGE ("")
MESSAGE ("Tests included: \"${MAIDSAFE_TEST_TYPE}\"")
MESSAGE ("")
MESSAGE ("    To include all tests,                     cmake ../.. -DMAIDSAFE_TEST_TYPE=_")
MESSAGE ("    To include behavioural tests,           cmake ../.. -DMAIDSAFE_TEST_TYPE=BEH")
MESSAGE ("    To include functional tests,           cmake ../.. -DMAIDSAFE_TEST_TYPE=FUNC")
MESSAGE ("================================================================================")
MESSAGE ("")
MESSAGE ("Build type is set to \"${CMAKE_BUILD_TYPE}\"")
MESSAGE ("")
MESSAGE ("    To alter this (e.g. to Debug),          cmake ../.. -DCMAKE_BUILD_TYPE=Debug")
MESSAGE ("    Options are Release, Debug, RelWithDebInfo, MinSizeRel")
MESSAGE ("================================================================================")
MESSAGE ("")

IF(APPLE)

install(TARGETS pdlocal
  RUNTIME
  BUNDLE DESTINATION "Perpetual Data")
install(TARGETS perpetualdata
  RUNTIME
  BUNDLE DESTINATION "Perpetual Data")
  #COMPONENT client)
ELSE(APPLE)
install(TARGETS pdlocal
  RUNTIME
  DESTINATION bin)
install(TARGETS perpetualdata
  RUNTIME
  DESTINATION bin)
install(TARGETS vault
  RUNTIME
  DESTINATION bin)
ENDIF(APPLE)

 #Adding Dokan for windows
 IF(WIN32)
   install(FILES dokan.dll
   DESTINATION bin)
   #COMPONENT client)

   install(PROGRAMS dokanctl.exe
   DESTINATION bin)
   #COMPONENT client)

   install(PROGRAMS mounter.exe
   DESTINATION bin)
   #COMPONENT client)

   install(FILES dokan.sys
   DESTINATION bin)
   #COMPONENT client)
IF(MSVC)
	#install(FILES libconfig++.dll
	#DESTINATION bin)
   #COMPONENT client)

   install(FILES vcredist_x86.exe
   DESTINATION bin)
   #COMPONENT client)
ELSE(MSVC)
	 install(FILES QtCore4.dll QtGui4.dll mingwm10.dll
	 DESTINATION bin)
   #COMPONENT client)

ENDIF(MSVC)
 ENDIF(WIN32)

set(CPACK_PACKAGE_NAME "PerpetualData")
set(CPACK_PACKAGE_CONTACT "info@maidsafe.net")
set(CPACK_PACKAGE_VENDOR "Maidsafe.net")
 set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Perpetual Data - Client and Vault applications")
 set(CPACK_PACKAGE_INSTALL_DIRECTORY "Maidsafe")
 set(CPACK_PACKAGE_DESCRIPTION_FILE "${PROJECT_SOURCE_DIR}/build/install_files/description.txt")
 set(CPACK_RESOURCE_FILE_LICENSE "${PROJECT_SOURCE_DIR}/build/install_files/LICENSE.txt")
 set(CPACK_RESOURCE_FILE_README "${PROJECT_SOURCE_DIR}/build/install_files/readme.txt")
 set(CPACK_RESOURCE_FILE_WELCOME "${PROJECT_SOURCE_DIR}/build/install_files/welcome.txt")

SET(CPACK_PACKAGE_EXECUTABLES "perpetualdata" "PerpetualData" "pdlocal" "PerpetualDataLocal" "vault" "vault")
 #Setting all the components
 #set(CPACK_COMPONENTS_ALL client)
 #set(CPACK_COMPONENT_CLIENT_DISPLAY_NAME "Perpetual Data Client")
 #set(CPACK_COMPONENT_CLIENT_DESCRIPTION
 #  "The Perpetual Data Client allows you to upload, retrieve and share your files through the Maidsafe Distributed Network")

 #set(CPACK_ALL_INSTALL_TYPES Full Client)
 #set(CPACK_INSTALL_TYPE_FULL_DISPLAY_NAME "Client and Vault")
 #set(CPACK_COMPONENT_CLIENT_INSTALL_TYPES Full Client)

MESSAGE ("Install directory is set to \"${CPACK_PACKAGE_INSTALL_DIRECTORY}\"")
MESSAGE ("================================================================================")
MESSAGE ("")

IF(APPLE)

 option(CPACK_BINARY_PACKAGEMAKER "Enable to build PackageMaker packages" ON)
 #option(CPACK_BINARY_OSXX11       "Enable to build OSX X11 packages"      OFF)
 SET(CMAKE_OSX_ARCHITECTURES i386) #can add ppc;i386
 SET(MACOSX_BUNDLE_ICON_FILE "${PROJECT_SOURCE_DIR}/build/install_files/maidsafe_logo_tick_ok.icns")
 SET(MACOSX_BUNDLE_GUI_IDENTIFIER "Maidsafe")
 SET(MACOSX_BUNDLE_LONG_VERSION_STRING "0.1 ALPHA")
 SET(MACOSX_BUNDLE_SHORT_VERSION_STRING "0.1")
 SET(MACOSX_BUNDLE_BUNDLE_NAME "Perpetual Data")
 SET(MACOSX_BUNDLE_BUNDLE_VERSION "0.1")
 SET(MACOSX_BUNDLE_COPYRIGHT "Maidsafe.Net Ltd.")
 SET(GUI_TYPE MACOSX_BUNDLE)

 SET_SOURCE_FILES_PROPERTIES(
   perpetualdata
   PROPERTIES
   MACOSX_PACKAGE_LOCATION MACOS)

 #Copy all required icons to Resources folder
 SET_SOURCE_FILES_PROPERTIES(
   ${PROJECT_SOURCE_DIR}/build/install_files/maidsafe_logo_tick_ok.icns
   ${PROJECT_SOURCE_DIR}/build/install_files/maidsafe_logo_cross_not_ok.icns
PROPERTIES
MACOSX_PACKAGE_LOCATION Resources)

#MESSAGE("-------MAC OSX Package Information------------")
#MESSAGE("MACOSX_BUNDLE_ICON_FILE (must be an .icns file) is: ${MACOSX_BUNDLE_ICON_FILE}")

#MESSAGE("----------------------------------------------")

ELSEIF(WIN32)
set(CPACK_GENERATOR NSIS)

SET(CPACK_NSIS_MODIFY_PATH OFF)
SET(CPACK_PACKAGE_RELOCATABLE "false")



SET(CPACK_NSIS_MUI_ICON "${PROJECT_SOURCE_DIR}\\\\build\\\\install_files\\\\maidsafe_logo1.ico")

#Location of the .ico icon file for the un installer in start menu
SET(CPACK_NSIS_MUI_UNIICON "${PROJECT_SOURCE_DIR}\\\\build\\\\install_files\\\\maidsafe_logo_cross_not_ok.ico")

#Branding image inside the installer
SET(CPACK_PACKAGE_ICON "${PROJECT_SOURCE_DIR}\\\\build\\\\install_files\\\\pd.png")

#setting the executable


#Setting shortcuts to maidsafe website in Programs Menu
#Can also be added links to documentation, etc
set(CPACK_NSIS_MENU_LINKS
    "http://www.maidsafe.net" "Maidsafe web site"
    "http://bug.maidsafe.net" "Maidsafe support site"
    )

SET(CPACK_RESOURCE_FILE_LICENSE "${PROJECT_SOURCE_DIR}\\\\build\\\\install_files\\\\EULA_001.txt")


SET(CPACK_CREATE_DESKTOP_LINKS "perpetualdata")
SET(CPACK_NSIS_SECTION_SELECTED_VARS ${CPACK_NSIS_SECTION_SELECTED_VARS} "
Function .onInstSuccess
  ExecWait '\\\"sc.exe\\\" create PDVault start= auto binPath= \\\"$INSTDIR\\\\bin\\\\vault.exe\\\"'
  MessageBox MB_YESNO \\\"Installation successful.  Start vault service?\\\" IDNO NoAction
     ExecWait '\\\"sc.exe\\\" start PDVault'
  NoAction:
FunctionEnd
")
SET(CPACK_NSIS_EXTRA_INSTALL_COMMANDS ${CPACK_NSIS_EXTRA_INSTALL_COMMANDS} "
      File ${PD_SOURCE_DIR}\\\\.kadconfig
      SetShellVarContext all

      IfFileExists \\\"$SYSDIR\\\\dokan.dll\\\"  upgrade 0
			CopyFiles \\\"$INSTDIR\\\\bin\\\\dokanctl.exe\\\" \\\"$SYSDIR\\\"
			CopyFiles \\\"$INSTDIR\\\\bin\\\\QtCore4.dll\\\" \\\"$SYSDIR\\\"
			CopyFiles \\\"$INSTDIR\\\\bin\\\\QtGui4.dll\\\" \\\"$SYSDIR\\\"
			CopyFiles \\\"$INSTDIR\\\\bin\\\\mingwm10.dll\\\" \\\"$SYSDIR\\\"
			CopyFiles \\\"$INSTDIR\\\\bin\\\\mounter.exe\\\" \\\"$SYSDIR\\\"
			CopyFiles \\\"$INSTDIR\\\\bin\\\\dokan.dll\\\" \\\"$SYSDIR\\\"
			CopyFiles \\\"$INSTDIR\\\\bin\\\\dokan.sys\\\" \\\"$SYSDIR\\\\drivers\\\"
			Delete \\\"$INSTDIR\\\\bin\\\\dokanctl.exe\\\"
			Delete \\\"$INSTDIR\\\\bin\\\\mounter.exe\\\"
			Delete \\\"$INSTDIR\\\\bin\\\\dokan.dll\\\"
			Delete \\\"$INSTDIR\\\\bin\\\\dokan.sys\\\"
			ExecWait \\\"$SYSDIR\\\\dokanctl.exe /i a\\\"
      CreateDirectory  \\\"$APPDATA\\\\maidsafe\\\"
      CreateDirectory  \\\"$APPDATA\\\\maidsafe\\\\vault\\\"
      CopyFiles \\\"$INSTDIR\\\\.kadconfig\\\" \\\"$APPDATA\\\\maidsafe\\\"
      CopyFiles \\\"$INSTDIR\\\\.kadconfig\\\" \\\"$APPDATA\\\\maidsafe\\\\vault\\\"
			CopyFiles \\\"$INSTDIR\\\\.kadconfig\\\" \\\"$INSTDIR\\\\bin\\\"
			Delete \\\"$INSTDIR\\\\.kadconfig\\\"

			Goto finish

			upgrade:
			!include Library.nsh

;                       !insertmacro InstallLib DLL 1 REBOOT_NOTPROTECTED  \\\"..\\\\..\\\\..\\\\..\\\\install_files\\\\dokan.dll\\\" \\\"$SYSDIR\\\\dokan.dll\\\" \\\"$SYSDIR\\\"
;                        !insertmacro InstallLib DLL 1 REBOOT_NOTPROTECTED  \\\"..\\\\..\\\\..\\\\..\\\\install_files\\\\dokan.sys\\\"   \\\"$SYSDIR\\\\drivers\\\\dokan.sys\\\" \\\"$SYSDIR\\\"
			SetRebootFlag true
		        ExecWait \\\"$SYSDIR\\\\dokanctl.exe /r a\\\"
			CopyFiles \\\"$INSTDIR\\\\bin\\\\dokan.dll\\\" \\\"$SYSDIR\\\"
			CopyFiles \\\"$INSTDIR\\\\bin\\\\dokan.sys\\\" \\\"$SYSDIR\\\\drivers\\\"
			CopyFiles \\\"$INSTDIR\\\\bin\\\\dokanctl.exe\\\" \\\"$SYSDIR\\\"
			CopyFiles \\\"$INSTDIR\\\\bin\\\\QtCore4.dll\\\" \\\"$SYSDIR\\\"
			CopyFiles \\\"$INSTDIR\\\\bin\\\\QtGui4.dll\\\" \\\"$SYSDIR\\\"
			CopyFiles \\\"$INSTDIR\\\\bin\\\\mingwm10.dll\\\" \\\"$SYSDIR\\\"
			CopyFiles \\\"$INSTDIR\\\\bin\\\\mounter.exe\\\" \\\"$SYSDIR\\\"
			Delete \\\"$INSTDIR\\\\bin\\\\dokanctl.exe\\\"
			Delete \\\"$INSTDIR\\\\bin\\\\mounter.exe\\\"
			Delete \\\"$INSTDIR\\\\bin\\\\dokan.dll\\\"
			Delete \\\"$INSTDIR\\\\bin\\\\dokan.sys\\\"
			CreateDirectory  \\\"$APPDATA\\\\maidsafe\\\"
			CreateDirectory  \\\"$APPDATA\\\\maidsafe\\\\vault\\\"
      CopyFiles \\\"$INSTDIR\\\\.kadconfig\\\" \\\"$APPDATA\\\\maidsafe\\\"
      CopyFiles \\\"$INSTDIR\\\\.kadconfig\\\" \\\"$APPDATA\\\\maidsafe\\\\vault\\\"
			CopyFiles \\\"$INSTDIR\\\\.kadconfig\\\" \\\"$INSTDIR\\\\bin\\\"
			Delete \\\"$INSTDIR\\\\.kadconfig\\\"
		 WriteRegStr HKEY_LOCAL_MACHINE \\\"Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce\\\" \\\"maidsafe\\\" \\\"$SYSDIR\\\\dokanctl.exe /i a \\\"
		 	finish:
			")
		IF(MSVC)
		SET(CPACK_NSIS_EXTRA_INSTALL_COMMANDS ${CPACK_NSIS_EXTRA_INSTALL_COMMANDS} "
		ExecWait \\\"$INSTDIR\\\\bin\\\\vcredist_x86.exe\\\ /r a\\\"
		")
		ELSE(MSVC)
			SET(CPACK_NSIS_EXTRA_INSTALL_COMMANDS ${CPACK_NSIS_EXTRA_INSTALL_COMMANDS} "
		")
		SET(CPACK_STRIP_FILES perpetualdata.exe pdlocal.exe vault.exe)
  		SET(CPACK_STRIP_FILES "True")
		ENDIF(MSVC)

SET(CPACK_NSIS_EXTRA_UNINSTALL_COMMANDS ${CPACK_NSIS_EXTRA_UNINSTALL_COMMANDS} "
    ExecWait '\\\"sc.exe\\\" stop PDVault'
    ExecWait '\\\"sc.exe\\\" delete PDVault'
    Delete \\\"$INSTDIR\\\\bin\\\\.kadconfig\\\"
    Delete \\\"$APPDATA\\\\maidsafe\\\\.kadconfig\\\"
		RMDir /r \\\"$APPDATA\\\\maidsafe\\\"
		IfFileExists \\\"$SYSDIR\\\\dokanctl.exe\\\" next1 0
		next1:
		ExecWait \\\"$SYSDIR\\\\dokanctl.exe\\\ /r a\\\"
		  Delete \\\"$SYSDIR\\\\dokan.dll\\\"
		  Delete \\\"$SYSDIR\\\\mounter.exe\\\"
		  Delete \\\"$SYSDIR\\\\dokanctl.exe\\\"
		  IfFileExists \\\"$SYSDIR\\\\drivers\\\\dokan.sys\\\" next 0
		  next:
	   	  Delete \\\"$SYSDIR\\\\drivers\\\\dokan.sys\\\"
	")


#NSIS installer info
SET(CPACK_NSIS_HELP_LINK "http:\\\\\\\\www.maidsafe.net")
SET(CPACK_NSIS_URL_INFO_ABOUT "http:\\\\\\\\www.maidsafe.net")
SET(CPACK_NSIS_CONTACT "contact@maidsafe.net")

ELSEIF(UNIX AND NOT APPLE)
	SET(CMAKE_INSTALL_PREFIX "/usr")
   SET(CPACK_DEBIAN_PACKAGE_DEPENDS "libqtcore4, libqtgui4,, sqlite3") 
	SET(CPACK_SET_DESTDIR on)
 SET(CPACK_STRIP_FILES "perpetualdata pdlocal vault")
  SET(CPACK_RPM_SPEC_INSTALL_POST "if  grep -v maidsafe /etc/passwd ; then /usr/sbin/adduser --system --shell /bin/false --no-create-home maidsafe; fi ;  if [ -e /var/cache/maidsafe/ ];then   mkdir -p /var/cache/maidsafe ;  /bin/chown maidsafe.maidsafe /var/cache/maidsafe;fi; /bin/chmod 755 /etc/init.d/perpetualvault")
   install(FILES ${PD_SOURCE_DIR}/build/install_files/maidsafe_logo.xpm
   DESTINATION share/usr/pixmaps)
   install(FILES ${PD_SOURCE_DIR}/build/install_files/perpetualdata
   DESTINATION share/menu/)
   install(FILES ${PD_SOURCE_DIR}/build/install_files/perpetualdata.desktop
   DESTINATION share/applications/)
   install(FILES ${PD_SOURCE_DIR}/build/install_files/pdlocal.desktop
   DESTINATION share/applications/)
   install(FILES ${PD_SOURCE_DIR}/build/install_files/perpetualdatavault.desktop
   DESTINATION share/applications/)
   install(FILES ${PD_SOURCE_DIR}/.kadconfig
   DESTINATION /var/cache/maidsafe/)
   install(PROGRAMS perpetualvault
   DESTINATION /etc/init.d)

  SET(CPACK_GENERATOR DEB;RPM;TGZ)
ENDIF(APPLE)

INCLUDE(CPack)
