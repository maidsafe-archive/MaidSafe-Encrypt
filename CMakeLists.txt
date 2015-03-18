#==================================================================================================#
#                                                                                                  #
#  Copyright 2012 MaidSafe.net limited                                                             #
#                                                                                                  #
#  This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,        #
#  version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which    #
#  licence you accepted on initial access to the Software (the "Licences").                        #
#                                                                                                  #
#  By contributing code to the MaidSafe Software, or to this project generally, you agree to be    #
#  bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root        #
#  directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also available   #
#  at: http://www.maidsafe.net/licenses                                                            #
#                                                                                                  #
#  Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed    #
#  under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF   #
#  ANY KIND, either express or implied.                                                            #
#                                                                                                  #
#  See the Licences for the specific language governing permissions and limitations relating to    #
#  use of the MaidSafe Software.                                                                   #
#                                                                                                  #
#==================================================================================================#


set(CMAKE_DISABLE_SOURCE_CHANGES ON)
set(CMAKE_DISABLE_IN_SOURCE_BUILD ON)

if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../../cmake_modules/standard_setup.cmake")
  cmake_minimum_required(VERSION 2.8)  # To suppress warning cluttering error message
  set(Msg "\nThis project can currently only be build as part of the MaidSafe super-project.  For")
  set(Msg "${Msg} full details, see https://github.com/maidsafe/MaidSafe/wiki/Build-Instructions\n")
  message(FATAL_ERROR "${Msg}")
endif()

project(encrypt)

include(../../cmake_modules/standard_setup.cmake)


#==================================================================================================#
# Set up all files as GLOBs                                                                        #
#==================================================================================================#
ms_glob_dir(Encrypt ${PROJECT_SOURCE_DIR}/src/maidsafe/encrypt Encrypt)
ms_glob_dir(EncryptTests ${PROJECT_SOURCE_DIR}/src/maidsafe/encrypt/tests Tests)
list(REMOVE_ITEM EncryptTestsAllFiles "${PROJECT_SOURCE_DIR}/src/maidsafe/encrypt/tests/benchmark.cc")


#==================================================================================================#
# Define MaidSafe libraries and executables                                                        #
#==================================================================================================#
ms_add_static_library(maidsafe_encrypt ${EncryptAllFiles})
target_include_directories(maidsafe_encrypt PUBLIC ${PROJECT_SOURCE_DIR}/include PRIVATE ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(maidsafe_encrypt maidsafe_common)

ms_add_executable(benchmark_encrypt "Tests/Encrypt"
                 ${PROJECT_SOURCE_DIR}/src/maidsafe/encrypt/tests/benchmark.cc
                 ${PROJECT_SOURCE_DIR}/src/maidsafe/encrypt/tests/test_main.cc)
target_include_directories(benchmark_encrypt PRIVATE ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(benchmark_encrypt maidsafe_encrypt maidsafe_test)

if(INCLUDE_TESTS)
  ms_add_executable(test_encrypt "Tests/Encrypt"  ${EncryptTestsAllFiles})
  target_include_directories(test_encrypt PRIVATE ${PROJECT_SOURCE_DIR}/src)
  target_link_libraries(test_encrypt maidsafe_encrypt maidsafe_test)
endif()

ms_rename_outdated_built_exes()


#==================================================================================================#
# Set compiler and linker flags                                                                    #
#==================================================================================================#
include(standard_flags)


#==================================================================================================#
# Tests                                                                                            #
#==================================================================================================#
if(INCLUDE_TESTS)
  ms_add_default_tests()
  ms_add_gtests(test_encrypt)
  if(MAIDSAFE_TEST_TYPE MATCHES "^ALL$|^UNIT$|^FUNC$")
    set(Timeout 300)
    ms_update_test_timeout(Timeout)
    set_property(TEST BasicTest.FUNC_WriteLongAndShort65536SegmentsReadThenRewrite PROPERTY TIMEOUT ${Timeout})
    set_property(TEST LargeFile/BasicOffsetTest.FUNC_EncryptDecrypt/2 PROPERTY TIMEOUT ${Timeout})
  endif()
  ms_test_summary_output()
endif()


#==================================================================================================#
# Package                                                                                          #
#==================================================================================================#
install(TARGETS maidsafe_encrypt COMPONENT Development CONFIGURATIONS Debug Release ARCHIVE DESTINATION lib)
install(DIRECTORY ${PROJECT_SOURCE_DIR}/include/ COMPONENT Development DESTINATION include)

install(TARGETS benchmark_encrypt COMPONENT Benchmarkss CONFIGURATIONS Release RUNTIME DESTINATION bin)

if(INCLUDE_TESTS)
  install(TARGETS test_encrypt COMPONENT Tests CONFIGURATIONS Debug RUNTIME DESTINATION bin/debug)
  install(TARGETS test_encrypt COMPONENT Tests CONFIGURATIONS Release RUNTIME DESTINATION bin)
endif()
