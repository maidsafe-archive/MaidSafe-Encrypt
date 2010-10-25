/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  none
* Version:      1.0
* Created:      2009-08-13-01.01.27
* Revision:     none
* Compiler:     gcc
* Author:       Team
* Company:      maidsafe.net limited
*
* The following source code is property of maidsafe.net limited and is not
* meant for external use.  The use of this code is governed by the license
* file LICENSE.TXT found in the root of this directory and also on
* www.maidsafe.net.
*
* You are not free to copy, amend or otherwise use this source code without
* the explicit written permission of the board of directors of maidsafe.net.
*
* ============================================================================
*/

#include <maidsafe/base/log.h>
#include <boost/filesystem.hpp>

#include "gtest/gtest.h"

#include "tests/maidsafe/networktest.h"

int main(int argc, char **argv) {
  google::InitGoogleLogging(argv[0]);
  // setting output to be stderr
#ifndef HAVE_GLOG
  bool FLAGS_logtostderr;
#endif
  FLAGS_logtostderr = true;
  testing::InitGoogleTest(&argc, argv);
#ifdef MS_NETWORK_TEST
  try {
    if (boost::filesystem::exists(".kadconfig"))
      boost::filesystem::remove(".kadconfig");
  }
  catch(const std::exception& e) {
    printf("%s\n", e.what());
  }
  testing::AddGlobalTestEnvironment(new maidsafe::test::localvaults::Env(
      maidsafe::test::K(), maidsafe::test::kNetworkSize(),
      maidsafe::test::pdvaults(), maidsafe::test::kadconfig()));
#endif

  int result = RUN_ALL_TESTS();
#ifdef MS_NETWORK_TEST
  try {
    if (boost::filesystem::exists(".kadconfig"))
      boost::filesystem::remove(".kadconfig");
  }
  catch(const std::exception& e) {
    printf("%s\n", e.what());
  }
#endif
  return result;
}
