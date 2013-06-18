#==================================================================================================#
#                                                                                                  #
#  Copyright (c) 2012 MaidSafe.net limited                                                         #
#                                                                                                  #
#  The following source code is property of MaidSafe.net limited and is not meant for external     #
#  use.  The use of this code is governed by the license file licence.txt found in the root        #
#  directory of this project and also on www.maidsafe.net.                                         #
#                                                                                                  #
#  You are not free to copy, amend or otherwise use this source code without the explicit written  #
#  permission of the board of directors of MaidSafe.net.                                           #
#                                                                                                  #
#==================================================================================================#


set(CMAKE_DISABLE_SOURCE_CHANGES ON)
set(CMAKE_DISABLE_IN_SOURCE_BUILD ON)

cmake_minimum_required(VERSION 2.8.10 FATAL_ERROR)
project(encrypt)

include(../../cmake_modules/standard_setup.cmake)

include_directories(${common_SOURCE_DIR}/include)
include_directories(${private_SOURCE_DIR}/include)
include_directories(${passport_SOURCE_DIR}/include)
include_directories(${rudp_SOURCE_DIR}/include)
include_directories(${routing_SOURCE_DIR}/include)
include_directories(${nfs_SOURCE_DIR}/include)


#==================================================================================================#
# Set up all files as GLOBs                                                                        #
#==================================================================================================#
####    CODE    ####
file(GLOB SOURCE_FILES_ENCRYPT_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/encrypt/*.cc")
file(GLOB HEADER_FILES_ENCRYPT_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/encrypt/*.h")
file(GLOB API_FILES_ENCRYPT_DIR "${PROJECT_SOURCE_DIR}/include/maidsafe/encrypt/*.h")
set(ALL_FILES_ENCRYPT_DIR ${SOURCE_FILES_ENCRYPT_DIR} ${HEADER_FILES_ENCRYPT_DIR} ${API_FILES_ENCRYPT_DIR})
source_group("Encrypt Source Files" FILES ${SOURCE_FILES_ENCRYPT_DIR})
source_group("Encrypt Header Files" FILES ${HEADER_FILES_ENCRYPT_DIR})
source_group("Encrypt API Files" FILES ${API_FILES_ENCRYPT_DIR})

####    TESTS    ####
file(GLOB SOURCE_FILES_ENCRYPT_TESTS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/encrypt/tests/*.cc")
file(GLOB HEADER_FILES_ENCRYPT_TESTS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/encrypt/tests/*.h")
set(ALL_FILES_ENCRYPT_TESTS_DIR ${SOURCE_FILES_ENCRYPT_TESTS_DIR} ${HEADER_FILES_ENCRYPT_TESTS_DIR})
source_group("Tests Source Files" FILES ${SOURCE_FILES_ENCRYPT_TESTS_DIR})
source_group("Tests Header Files" FILES ${HEADER_FILES_ENCRYPT_TESTS_DIR})


#==================================================================================================#
# Define MaidSafe libraries and executables                                                        #
#==================================================================================================#
ms_add_static_library(encrypt ${ALL_FILES_ENCRYPT_DIR})
target_link_libraries(maidsafe_encrypt maidsafe_private)

if(MaidsafeTesting)
  ms_add_executable(TESTencrypt "Tests/Encrypt" ${ALL_FILES_ENCRYPT_TESTS_DIR})
  target_link_libraries(TESTencrypt maidsafe_encrypt maidsafe_routing maidsafe_nfs)
endif()

rename_outdated_built_exes()


#==================================================================================================#
# Set compiler and linker flags                                                                    #
#==================================================================================================#
include(standard_flags)

if(UNIX AND NOT APPLE)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-stack-protector")
endif()


#==================================================================================================#
# Tests                                                                                            #
#==================================================================================================#
if(MaidsafeTesting)
  add_style_test()
  add_gtests(TESTencrypt)

  label_as_critical_tests(FileSmallerThanMinFileSize/BasicOffsetTest.BEH_EncryptDecrypt/0
                          FileSmallerThanMinFileSize/BasicOffsetTest.BEH_EncryptDecrypt/1
                          FileSmallerThanMinFileSize/BasicOffsetTest.BEH_EncryptDecrypt/2
                          FileSmallerThanMinFileSize/BasicOffsetTest.BEH_EncryptDecrypt/3
                          FileSmallerThanMinFileSize/BasicOffsetTest.BEH_EncryptDecrypt/4
                          FileSmallerThanOneChunk/BasicOffsetTest.BEH_EncryptDecrypt/0
                          FileSmallerThanOneChunk/BasicOffsetTest.BEH_EncryptDecrypt/1
                          FileSmallerThanOneChunk/BasicOffsetTest.BEH_EncryptDecrypt/2
                          FileSmallerThanOneChunk/BasicOffsetTest.BEH_EncryptDecrypt/3
                          FileSmallerThanOneChunk/BasicOffsetTest.BEH_EncryptDecrypt/4
                          FileSmallerThanThreeNormalChunks/BasicOffsetTest.BEH_EncryptDecrypt/0
                          FileSmallerThanThreeNormalChunks/BasicOffsetTest.BEH_EncryptDecrypt/1
                          FileSmallerThanThreeNormalChunks/BasicOffsetTest.BEH_EncryptDecrypt/2
                          FileSmallerThanThreeNormalChunks/BasicOffsetTest.BEH_EncryptDecrypt/3
                          FileSmallerThanThreeNormalChunks/BasicOffsetTest.BEH_EncryptDecrypt/4
                          FileSmallerThanThreeNormalChunks/BasicOffsetTest.BEH_EncryptDecrypt/5
                          FileSmallerThanThreeNormalChunks/BasicOffsetTest.BEH_EncryptDecrypt/6
                          FileSmallerThanThreeNormalChunks/BasicOffsetTest.BEH_EncryptDecrypt/7
                          FileSmallerThanThreeNormalChunks/BasicOffsetTest.BEH_EncryptDecrypt/8
                          FileSmallerThanThreeNormalChunks/BasicOffsetTest.BEH_EncryptDecrypt/9
                          FileSmallerThanThreeNormalChunks/BasicOffsetTest.BEH_EncryptDecrypt/10
                          FileSmallerThanThreeNormalChunks/BasicOffsetTest.BEH_EncryptDecrypt/11
                          FileSmallerThanThreeNormalChunks/BasicOffsetTest.BEH_EncryptDecrypt/12
                          FileSmallerThanThreeNormalChunks/BasicOffsetTest.BEH_EncryptDecrypt/13
                          FileGreaterThanThreeNormalChunks/BasicOffsetTest.BEH_EncryptDecrypt/0
                          FileGreaterThanThreeNormalChunks/BasicOffsetTest.BEH_EncryptDecrypt/1
                          FileGreaterThanThreeNormalChunks/BasicOffsetTest.BEH_EncryptDecrypt/2
                          FileGreaterThanThreeNormalChunks/BasicOffsetTest.BEH_EncryptDecrypt/3
                          FileGreaterThanThreeNormalChunks/BasicOffsetTest.BEH_EncryptDecrypt/4
                          FileGreaterThanThreeNormalChunks/BasicOffsetTest.BEH_EncryptDecrypt/5
                          FileGreaterThanThreeNormalChunks/BasicOffsetTest.BEH_EncryptDecrypt/6
                          FileGreaterThanThreeNormalChunks/BasicOffsetTest.BEH_EncryptDecrypt/7
                          FileGreaterThanThreeNormalChunks/BasicOffsetTest.BEH_EncryptDecrypt/8
                          FileGreaterThanThreeNormalChunks/BasicOffsetTest.BEH_EncryptDecrypt/9
                          FileGreaterThanThreeNormalChunks/BasicOffsetTest.BEH_EncryptDecrypt/10
                          FileGreaterThanThreeNormalChunks/BasicOffsetTest.BEH_EncryptDecrypt/11
                          FileGreaterThanThreeNormalChunks/BasicOffsetTest.BEH_EncryptDecrypt/12
                          FileGreaterThanThreeNormalChunks/BasicOffsetTest.BEH_EncryptDecrypt/13
                          FileGreaterThanThreeNormalChunks/BasicOffsetTest.BEH_EncryptDecrypt/14
                          FileGreaterThanThreeNormalChunks/BasicOffsetTest.BEH_EncryptDecrypt/15
                          FileGreaterThanThreeNormalChunks/BasicOffsetTest.BEH_EncryptDecrypt/16
                          FileGreaterThanThreeNormalChunks/BasicOffsetTest.BEH_EncryptDecrypt/17
                          FileGreaterThanThreeNormalChunks/BasicOffsetTest.BEH_EncryptDecrypt/18
                          FileGreaterThanThreeNormalChunks/BasicOffsetTest.BEH_EncryptDecrypt/19
                          FileGreaterThanThreeNormalChunks/BasicOffsetTest.BEH_EncryptDecrypt/20
                          FileGreaterThanThreeNormalChunks/BasicOffsetTest.BEH_EncryptDecrypt/21
                          FileGreaterThanThreeNormalChunks/BasicOffsetTest.BEH_EncryptDecrypt/22
                          FileGreaterThanThreeNormalChunks/BasicOffsetTest.BEH_EncryptDecrypt/23
                          FileGreaterThanThreeNormalChunks/BasicOffsetTest.BEH_EncryptDecrypt/24
                          FileGreaterThanThreeNormalChunks/BasicOffsetTest.BEH_EncryptDecrypt/25
                          FileGreaterThanThreeNormalChunks/BasicOffsetTest.BEH_EncryptDecrypt/26
                          FileGreaterThanThreeNormalChunks/BasicOffsetTest.BEH_EncryptDecrypt/27
                          FileGreaterThanThreeNormalChunks/BasicOffsetTest.BEH_EncryptDecrypt/28
                          FileGreaterThanThreeNormalChunks/BasicOffsetTest.BEH_EncryptDecrypt/29
                          FileGreaterThanThreeNormalChunks/BasicOffsetTest.BEH_EncryptDecrypt/30
                          FileGreaterThanThreeNormalChunks/BasicOffsetTest.BEH_EncryptDecrypt/31
                          FileGreaterThanThreeNormalChunks/BasicOffsetTest.BEH_EncryptDecrypt/32
                          FileGreaterThanThreeNormalChunks/BasicOffsetTest.BEH_EncryptDecrypt/33
                          FileGreaterThanThreeNormalChunks/BasicOffsetTest.BEH_EncryptDecrypt/34
                          FileGreaterThanThreeNormalChunks/BasicOffsetTest.BEH_EncryptDecrypt/35
                          FileGreaterThanThreeNormalChunks/BasicOffsetTest.BEH_EncryptDecrypt/36
                          FileGreaterThanThreeNormalChunks/BasicOffsetTest.BEH_EncryptDecrypt/37
                          FileGreaterThanThreeNormalChunks/BasicOffsetTest.BEH_EncryptDecrypt/38
                          FileGreaterThanThreeNormalChunks/BasicOffsetTest.BEH_EncryptDecrypt/39
                          FileGreaterThanThreeNormalChunks/BasicOffsetTest.BEH_EncryptDecrypt/40
                          FileGreaterThanThreeNormalChunks/BasicOffsetTest.BEH_EncryptDecrypt/41
                          FileGreaterThanThreeNormalChunks/BasicOffsetTest.BEH_EncryptDecrypt/42
                          FileGreaterThanTenNormalChunks/BasicOffsetTest.BEH_EncryptDecrypt/0
                          FileGreaterThanTenNormalChunks/BasicOffsetTest.BEH_EncryptDecrypt/1
                          FileGreaterThanTenNormalChunks/BasicOffsetTest.BEH_EncryptDecrypt/2
                          FileGreaterThanTenNormalChunks/BasicOffsetTest.BEH_EncryptDecrypt/3
                          FileGreaterThanTenNormalChunks/BasicOffsetTest.BEH_EncryptDecrypt/4
                          FileGreaterThanTenNormalChunks/BasicOffsetTest.BEH_EncryptDecrypt/5
                          FileGreaterThanTenNormalChunks/BasicOffsetTest.BEH_EncryptDecrypt/6
                          FileGreaterThanTenNormalChunks/BasicOffsetTest.BEH_EncryptDecrypt/7
                          FileGreaterThanTenNormalChunks/BasicOffsetTest.BEH_EncryptDecrypt/8
                          FileGreaterThanTenNormalChunks/BasicOffsetTest.BEH_EncryptDecrypt/9
                          FileGreaterThanTenNormalChunks/BasicOffsetTest.BEH_EncryptDecrypt/10
                          FileGreaterThanTenNormalChunks/BasicOffsetTest.BEH_EncryptDecrypt/11
                          FileGreaterThanTenNormalChunks/BasicOffsetTest.BEH_EncryptDecrypt/12
                          FileGreaterThanTenNormalChunks/BasicOffsetTest.BEH_EncryptDecrypt/13
                          LargeFile/BasicOffsetTest.BEH_EncryptDecrypt/0
                          LargeFile/BasicOffsetTest.BEH_EncryptDecrypt/1
                          LargeFile/BasicOffsetTest.BEH_EncryptDecrypt/2
                          Writing/SingleBytesTest.BEH_WriteInOrder/0
                          Writing/SingleBytesTest.BEH_WriteInOrder/1
                          Writing/SingleBytesTest.BEH_WriteInOrder/2
                          Writing/SingleBytesTest.BEH_WriteInOrder/3
                          Writing/SingleBytesTest.BEH_WriteInOrder/4
                          Writing/SingleBytesTest.BEH_WriteInOrder/5
                          Writing/SingleBytesTest.BEH_WriteInOrder/6
                          Writing/SingleBytesTest.BEH_WriteInOrder/7
                          Writing/SingleBytesTest.BEH_WriteInOrder/8
                          Writing/SingleBytesTest.BEH_WriteInOrder/9
                          Writing/SingleBytesTest.BEH_WriteInOrder/10
                          Writing/SingleBytesTest.BEH_WriteInOrder/11
                          Writing/SingleBytesTest.BEH_WriteInOrder/12
                          Writing/SingleBytesTest.BEH_WriteInOrder/13
                          Writing/SingleBytesTest.BEH_WriteInOrder/14
                          Writing/SingleBytesTest.BEH_WriteInOrder/15
                          Writing/SingleBytesTest.BEH_WriteInOrder/16
                          Writing/SingleBytesTest.BEH_WriteInOrder/17
                          Writing/SingleBytesTest.BEH_WriteAlternatingBytes/0
                          Writing/SingleBytesTest.BEH_WriteAlternatingBytes/1
                          Writing/SingleBytesTest.BEH_WriteAlternatingBytes/2
                          Writing/SingleBytesTest.BEH_WriteAlternatingBytes/3
                          Writing/SingleBytesTest.BEH_WriteAlternatingBytes/4
                          Writing/SingleBytesTest.BEH_WriteAlternatingBytes/5
                          Writing/SingleBytesTest.BEH_WriteAlternatingBytes/6
                          Writing/SingleBytesTest.BEH_WriteAlternatingBytes/7
                          Writing/SingleBytesTest.BEH_WriteAlternatingBytes/8
                          Writing/SingleBytesTest.BEH_WriteAlternatingBytes/9
                          Writing/SingleBytesTest.BEH_WriteAlternatingBytes/10
                          Writing/SingleBytesTest.BEH_WriteAlternatingBytes/11
                          Writing/SingleBytesTest.BEH_WriteAlternatingBytes/12
                          Writing/SingleBytesTest.BEH_WriteAlternatingBytes/13
                          Writing/SingleBytesTest.BEH_WriteAlternatingBytes/14
                          Writing/SingleBytesTest.BEH_WriteAlternatingBytes/15
                          Writing/SingleBytesTest.BEH_WriteAlternatingBytes/16
                          Writing/SingleBytesTest.BEH_WriteAlternatingBytes/17
                          Writing/SmallSingleBytesTest.BEH_WriteRandomOrder/0
                          Writing/SmallSingleBytesTest.BEH_WriteRandomOrder/1
                          Writing/SmallSingleBytesTest.BEH_WriteRandomOrder/2
                          Writing/SmallSingleBytesTest.BEH_WriteRandomOrder/3
                          Writing/SmallSingleBytesTest.BEH_WriteRandomOrder/4
                          Writing/SmallSingleBytesTest.BEH_WriteRandomOrder/5
                          Writing/SmallSingleBytesTest.BEH_WriteRandomOrder/6
                          Writing/SmallSingleBytesTest.BEH_WriteRandomOrder/7
                          Writing/SmallSingleBytesTest.BEH_WriteRandomOrder/8
                          Writing/SmallSingleBytesTest.BEH_WriteRandomOrder/9
                          Reading/InProcessTest.BEH_ReadInOrder/0
                          Reading/InProcessTest.BEH_ReadInOrder/1
                          Reading/InProcessTest.BEH_ReadInOrder/2
                          Reading/InProcessTest.BEH_ReadInOrder/3
                          Reading/InProcessTest.BEH_ReadInOrder/4
                          Reading/InProcessTest.BEH_ReadInOrder/5
                          Reading/InProcessTest.BEH_ReadInOrder/6
                          Reading/InProcessTest.BEH_ReadInOrder/7
                          Reading/InProcessTest.BEH_ReadInOrder/8
                          Reading/InProcessTest.BEH_ReadInOrder/9
                          Reading/InProcessTest.BEH_ReadInOrder/10
                          Reading/InProcessTest.BEH_ReadInOrder/11
                          Reading/InProcessTest.BEH_ReadInOrder/12
                          Reading/InProcessTest.BEH_ReadInOrder/13
                          Reading/InProcessTest.BEH_ReadInOrder/14
                          Reading/InProcessTest.BEH_ReadInOrder/15
                          Reading/InProcessTest.BEH_ReadInOrder/16
                          Reading/InProcessTest.BEH_ReadInOrder/17
                          BasicTest.BEH_ReadArbitaryPosition
                          BasicTest.BEH_NewRead
                          BasicTest.BEH_WriteRandomSizeRandomPosition
                          BasicTest.FUNC_RandomSizedOutOfSequenceWritesWithGapsAndOverlaps
                          BasicTest.BEH_WriteLongAndShort65536SegmentsReadThenRewrite
                          BasicTest.BEH_4096ByteOutOfSequenceWritesReadsAndRewrites
                          BasicTest.BEH_WriteSmallThenAdd
                          BasicTest.BEH_3SmallChunkRewrite
                          BasicTest.BEH_nKFile
                          BasicTest.BEH_nKFileAppend
                          BasicTest.BEH_ManualCheckWrite
                          BasicTest.BEH_TruncateIncreaseScenario1
                          BasicTest.BEH_TruncateIncreaseScenario2
                          BasicTest.BEH_TruncateDecrease
                          BasicTest.FUNC_MassiveWrite
                          BasicTest.FUNC_RandomAccess
                          BasicTest.BEH_EncryptDecryptDataMap
                          BasicTest.BEH_DifferentDataMapSameChunk
                          )

  add_project_experimental()
  test_summary_output()
endif()
