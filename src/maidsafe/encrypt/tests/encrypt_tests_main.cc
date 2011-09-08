/*******************************************************************************
 *  Copyright 2010-2011 maidsafe.net limited                                   *
 *                                                                             *
 *  The following source code is property of maidsafe.net limited and is not   *
 *  meant for external use.  The use of this code is governed by the license   *
 *  file LICENSE.TXT found in the root of this directory and also on           *
 *  www.maidsafe.net.                                                          *
 *                                                                             *
 *  You are not free to copy, amend or otherwise use this source code without  *
 *  the explicit written permission of the board of directors of maidsafe.net. *
 ***************************************************************************//**
 * @file  encrypt_tests_main.cc
 * @brief Main program for Encrypt tests.
 * @date  2010-10-12
 */

#include "maidsafe/common/test.h"
#include "maidsafe/encrypt/log.h"

int main(int argc, char **argv) {
  google::InitGoogleLogging(argv[0]);
  FLAGS_logtostderr = true;
  FLAGS_alsologtostderr = false;
  FLAGS_minloglevel = google::INFO;
  FLAGS_log_prefix = true;
  FLAGS_v = 0;
  FLAGS_ms_logging_common = true;
  testing::InitGoogleTest(&argc, argv);
  int result(RUN_ALL_TESTS());
  int test_count = testing::UnitTest::GetInstance()->test_to_run_count();
  return (test_count == 0) ? -1 : result;
}
