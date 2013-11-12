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

project(encrypt)

include(../../cmake_modules/standard_setup.cmake)


#==================================================================================================#
# Set up all files as GLOBs                                                                        #
#==================================================================================================#
glob_dir(Encrypt ${PROJECT_SOURCE_DIR}/src/maidsafe/encrypt Encrypt)
glob_dir(EncryptTests ${PROJECT_SOURCE_DIR}/src/maidsafe/encrypt/tests Tests)
list(REMOVE_ITEM EncryptTestsAllFiles "${PROJECT_SOURCE_DIR}/src/maidsafe/encrypt/tests/benchmark.cc")

#==================================================================================================#
# Define MaidSafe libraries and executables                                                        #
#==================================================================================================#
ms_add_static_library(encrypt ${EncryptAllFiles})
target_include_directories(maidsafe_encrypt PUBLIC ${PROJECT_SOURCE_DIR}/include PRIVATE ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(maidsafe_encrypt maidsafe_private)

ms_add_executable(benchmark_encrypt "Tests/Encrypt"
                 ${PROJECT_SOURCE_DIR}/src/maidsafe/encrypt/tests/benchmark.cc
                 ${PROJECT_SOURCE_DIR}/src/maidsafe/encrypt/tests/test_main.cc)
target_include_directories(benchmark_encrypt PRIVATE ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(benchmark_encrypt maidsafe_encrypt gmock gtest)

if(MaidsafeTesting)
  ms_add_executable(TESTencrypt "Tests/Encrypt"  ${EncryptTestsAllFiles})
  target_include_directories(TESTencrypt PRIVATE ${PROJECT_SOURCE_DIR}/src)
  target_link_libraries(TESTencrypt maidsafe_encrypt maidsafe_routing maidsafe_nfs_client)
endif()

rename_outdated_built_exes()


#==================================================================================================#
# Set compiler and linker flags                                                                    #
#==================================================================================================#
include(standard_flags)

target_compile_definitions(maidsafe_encrypt PRIVATE $<$<BOOL:${OPENMP_FOUND}>:MAIDSAFE_OMP_ENABLED>)
target_compile_options(maidsafe_encrypt PRIVATE $<$<BOOL:${OPENMP_FOUND}>:${OpenMP_CXX_FLAGS}>)
target_compile_definitions(benchmark_encrypt PRIVATE USE_GTEST)


#==================================================================================================#
# Tests                                                                                            #
#==================================================================================================#
if(MaidsafeTesting)
  add_style_test()
  add_gtests(TESTencrypt)
  add_project_experimental()
  test_summary_output()
endif()
