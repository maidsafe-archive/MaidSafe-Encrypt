cmake_minimum_required(VERSION 2.6)
#this needs to be at the top of the file
message ("#############################################")
IF(NOT CMAKE_BUILD_TYPE)
   SET(CMAKE_BUILD_TYPE "Release" CACHE STRING "Choose the type of build, options are: Debug Release RelWithDebInfo MinSizeRel." FORCE)
ENDIF(NOT CMAKE_BUILD_TYPE)
project (PD)
IF(NOT MAIDSAFE_TEST_TYPE)
   SET(MAIDSAFE_TEST_TYPE "BEH" CACHE STRING "Choose the type of TEST, options are: _ BEH FUNC" FORCE)
ENDIF(NOT MAIDSAFE_TEST_TYPE)

if(UNIX)
	EXEC_PROGRAM(date ARGS +%a%d%m%y OUTPUT_VARIABLE pddate)
ELSE(UNIX)
	EXEC_PROGRAM("c:\\msys\\1.0\\bin\\date.exe" ARGS +%a%d%m%y OUTPUT_VARIABLE pddate)
ENDIF(UNIX)

IF(CMAKE_BUILD_TYPE MATCHES "Release")
message("building an ok to release package")
SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/Release/bin/)
SET(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/Release/lib)
ELSE()
SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/Debug/bin/)
SET(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/Debug/lib)
message("building a not for release package")
	SET(pddate "DEVELOPER_${pddate}")
ENDIF()


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
#message ("---------------------------------------------------")


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
INCLUDE_DIRECTORIES(${SOURCE_DIR} ${INCLUDE_DIR} )
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
######################################################################################
#All Platforms:  Add Test Exes and Create all PD libs                                 #
#######################################################################################
add_executable(TESTfuse "${SOURCE_DIR}/tests/maidsafe/testfuse.cc" )
add_executable(TESTclientcontroller "${SOURCE_DIR}/tests/maidsafe/functionaltestclientcontroller.cc")
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
cryptopp
sqlite3
boost_system-xgcc40-mt-1_37
boost_filesystem-xgcc40-mt-1_37
boost_regex-xgcc40-mt-1_37
boost_thread-xgcc40-mt-1_37
boost_date_time-xgcc40-mt-1_37
maidsafe-dht)

ELSEIF (UNIX AND NOT APPLE)
###########################
# LINUX BUILDS
##########################
add_executable(perpetualdata ${M_QT_C} )
add_executable(pdlocal ${M_QT_C} )

SET(SYS_LIB
	/usr/lib/libboost_thread-gcc43-mt.a
	sqlite3
	/usr/lib/libprotobuf.a
	/usr/lib/libboost_system-gcc43-mt.a
	/usr/lib/libboost_filesystem-gcc43-mt.a
	/usr/lib/libcryptopp.a
	/usr/lib/libboost_regex-gcc43-mt.a
	/usr/lib/libboost_date_time-gcc43-mt.a
	-lrt
	-lc
  maidsafe-dht
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
c:/usr/lib/libboost_system-mgw43-mt-1_37.lib
c:/usr/lib/libboost_filesystem-mgw43-mt-1_37.lib
c:/usr/lib/libboost_regex-mgw43-mt-1_37.lib
c:/usr/lib/libboost_thread-mgw43-mt-1_37.lib
c:/usr/lib/libboost_date_time-mgw43-mt-1_37.lib
c:/usr/lib/dokan.lib
c:/usr/lib/libcryptopp.a
c:/usr/lib/libprotobuf.a c:/usr/lib/libsqlite3.a -liphlpapi
)
ENDIF(APPLE)
IF(UNIX)
	SET(FUSE  "fuse")
	ENDIF()
TARGET_LINK_LIBRARIES(perpetualdata PDmsclientlib PDmaidsafelib PDmsvaultlib PDfslib PDpbmsgslib ${FUSE} ${QT_LIBRARIES} ${SYS_LIB})
TARGET_LINK_LIBRARIES(pdlocal PDTESTmsclientlib PDmaidsafelib PDmsvaultlib PDfslib PDpbmsgslib ${FUSE} ${QT_LIBRARIES}  ${SYS_LIB})
TARGET_LINK_LIBRARIES(TESTmaidsafe PDmsclientlib PDmaidsafelib PDmsvaultlib PDfslib PDpbmsgslib ${FUSE} gtest ${SYS_LIB})
TARGET_LINK_LIBRARIES(TESTpdvault PDmsclientlib PDmaidsafelib PDmsvaultlib PDfslib PDpbmsgslib ${FUSE} gtest ${SYS_LIB})
TARGET_LINK_LIBRARIES(TESTclientcontroller PDmsclientlib PDmaidsafelib PDmsvaultlib PDfslib PDpbmsgslib ${FUSE} gtest ${SYS_LIB})
TARGET_LINK_LIBRARIES(TESTfuse PDmsclientlib PDmaidsafelib PDmsvaultlib PDfslib PDpbmsgslib ${FUSE} gtest ${SYS_LIB})
TARGET_LINK_LIBRARIES(TESTfs PDmaidsafelib PDfslib ${FUSE} gtest ${SYS_LIB})
TARGET_LINK_LIBRARIES(testvault PDmsclientlib PDmaidsafelib PDmsvaultlib PDpbmsgslib ${SYS_LIB})
TARGET_LINK_LIBRARIES(vault PDmsvaultlib PDmaidsafelib PDpbmsgslib ${SYS_LIB})


IF(WIN32)
SET(TARGET_PROPERTIES vault testvault TESTmaidsafe  COMPILE_FLAGS  ${CMAKE_CXX_FLAGS} --Wl,-subsystem,console)
ENDIF(WIN32)

##################################################################################
# COMPILER FLAGS  - here after all targets declared                                                                #
##################################################################################
message("qt stuff " ${QT_LIBRARIES})
IF (APPLE)
  SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DMAIDSAFE_APPLE -D_FORTIFY_SOURCE=2 -DOSX -DBSD -D__FreeBSD__=10  -D_FILE_OFFSET_BITS=64" )
  SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -DDEBUG -fprofile-arcs -ftest-coverage" )
  SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O2 -Wuninitialized")
ELSEIF (UNIX AND NOT APPLE)
  SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -DDEBUG -fprofile-arcs -ftest-coverage" )
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
ADD_TEST(Testclientcontroller ${EXECUTABLE_OUTPUT_PATH}/TESTclientcontroller)
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
		    #		    message("${tst}   ${TESTTYPE}    --gtest_filter=*${tst}*")
	    		ENDIF()
	    		ENDIF()
			ENDIF()
	ENDFOREACH()
ENDFOREACH()
ADD_TEST(Testfuse ${EXECUTABLE_OUTPUT_PATH}/TESTfuse)


SET(DART_TESTING_TIMEOUT 3500)
IF(UNIX)
SET(MEMORYCHECK_COMMAND "/usr/bin/valgrind --show-reachable=no")
ENDIF(UNIX)

#Adding the install targets
################################################################
message ("#############################################")
message("package version = " ${pddate})
message ("#############################################")
message("tests included ${MAIDSAFE_TEST_TYPE}")
message ("#############################################")
message (" you can set the test included with cmake -DMAIDSAFE_TEST_TYPE=")
message ("_ ( underscore = all) BEH (behavioural)  FUNC (functional)")
message ("#############################################")
message("Build type set to ${CMAKE_BUILD_TYPE}")
message ("#############################################")
message("You can set the build type by: cmake ../../ -DCMAKE_BUILD_TYPE=")
message("Release (default) Debug RelWithDebInfo MinSizeRel")
message ("#############################################")

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

message("install dir ${CPACK_PACKAGE_INSTALL_DIRECTORY}")

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

#message("-------MAC OSX Package Information------------")
#message("MACOSX_BUNDLE_ICON_FILE (must be an .icns file) is: ${MACOSX_BUNDLE_ICON_FILE}")

#message("----------------------------------------------")

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
SET(CPACK_NSIS_EXTRA_INSTALL_COMMANDS ${CPACK_NSIS_EXTRA_INSTALL_COMMANDS} "
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
			CopyFiles \\\"$INSTDIR\\\\bin\\\\.kadconfig\\\" \\\"$APPDATA\\\\maidsafe\\\"

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
		 WriteRegStr HKEY_LOCAL_MACHINE \\\"Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce\\\" \\\"maidsafe\\\" \\\"$SYSDIR\\\\dokanctl.exe /i a \\\"
		 	finish:



#			Call FindWindow
#			IfFileExists \\\"$SYSDIR\\\\perpetualdata.exe\\\"  upgrade 0
##
##		ExecWait \\\"$SYSDIR\\\\dokanctl.exe\\\ /r a\\\"
##			CopyFiles \\\"$INSTDIR\\\\bin\\\\dokanctl.exe\\\" \\\"$SYSDIR\\\"
##			CopyFiles \\\"$INSTDIR\\\\bin\\\\mounter.exe\\\" \\\"$SYSDIR\\\"
##			CopyFiles \\\"$INSTDIR\\\\bin\\\\dokan.dll\\\" \\\"$SYSDIR\\\"
##			CopyFiles \\\"$INSTDIR\\\\bin\\\\dokan.sys\\\" \\\"$SYSDIR\\\\drivers\\\"
##			Delete \\\"$INSTDIR\\\\bin\\\\dokanctl.exe\\\"
##			Delete \\\"$INSTDIR\\\\bin\\\\mounter.exe\\\"
##			Delete \\\"$INSTDIR\\\\bin\\\\dokan.dll\\\"
##			Delete \\\"$INSTDIR\\\\bin\\\\dokan.sys\\\"
##			ExecWait \\\"$SYSDIR\\\\dokanctl.exe\\\ /i a\\\"
##			Goto finish
##
##			upgrade:
##                        !insertmacro InstallLib DLL 1 REBOOT_NOTPROTECTED dokan.dll \\\"$SYSDIR\\\\dokan.dll\\\" \\\"$SYSDIR\\\"
##                        !insertmacro InstallLib DLL 1 REBOOT_NOTPROTECTED dokan.sys  \\\"$SYSDIR\\\\drivers\\\\dokan.dll\\\" \\\"$SYSDIR\\\"
##			Messagebox MB_OK \\\"IMPORTANT: Rebooting the system is advised in order to finalize maidsafe perpetualdata [tm] installation/upgrade (this is an informational message only, pressing OK will not reboot).\\\"
##			SetRebootFlag true
##			CopyFiles \\\"$INSTDIR\\\\bin\\\\dokanctl.exe\\\" \\\"$SYSDIR\\\"
##			Delete \\\"$INSTDIR\\\\bin\\\\dokanctl.exe\\\"
##			CopyFiles \\\"$INSTDIR\\\\bin\\\\mounter.exe\\\" \\\"$SYSDIR\\\"
##			Delete \\\"$INSTDIR\\\\bin\\\\mounter.exe\\\"
##		 WriteRegStr HKEY_LOCAL_MACHINE \\\"Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce\\\" \\\"maidsafe\\\" \\\"$SYSDIR\\\\dokanctl.exe /i a \\\"
##		 	finish:
#Function FindWindow
#      FindWindow \\\"$R1\\\" \\\"${WNDCLASS}\\\" \\\"Perpetual Data\\\"
#      \\\"${Unless}\\\" \\\"$R1\\\" = 0
#         MessageBox MB_ICONSTOP|MB_OK
#         "Perpetual Data  is running. Please close it and try again."
#         Abort
#      \\\"${EndUnless}\\\"
#FunctionEnd
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
#This example detects if the application you are uninstalling is running at the start of the uninstallation process.
#The easiest way to find the "WindowClassOfYourApplication" and "WindowTitleOfYourApplication" is to use Microsoft Spy++. Spy++ is a tool that comes with Visual Studio. You can also use the freeware tool SysTree++ to find the WindowClass.
#[edit] The Example Script

#/* Replace the values of the two defines below to your application's window class and window title, respectivelly. */
#!define WNDCLASS "WindowClassOfYourApplication"
#!define WNDTITLE "WindowTitleOfYourApplication"
# We can use this to chekc if application is running during install as well !!! // TODO  
#Function un.onInit
#FindWindow $0 "${WNDCLASS}" "${WNDTITLE}"
  #StrCmp $0 0 continueInstall
  #MessageBox MB_ICONSTOP|MB_OK "The application you are trying to remove is running. Close it and try again."
    #Abort
    # continueInstall:
  #FunctionEnd
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
