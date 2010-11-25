/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Description:  Macro definitions to allow network and non-network versions of
*               tests to use the same source files.
* Created:      2010-06-03
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

#include "maidsafe/sharedtest/networktest.h"

#include "maidsafe/common/filesystem.h"
#include "maidsafe/common/chunkstore.h"
#include "maidsafe/sharedtest/testcallback.h"

namespace fs = boost::filesystem;

namespace maidsafe {
namespace test {

static int gTestRunCount = 0;

#ifdef MS_NETWORK_TEST

const boost::uint8_t g_K(4);
const int g_kNetworkSize = g_K + 2;
LocalVaults g_pdvaults;
fs::path g_kad_config_file;

boost::uint8_t K() { return g_K; }
int kNetworkSize() { return g_kNetworkSize; }
LocalVaults *pdvaults() { return &g_pdvaults; }
fs::path *kadconfig() { return &g_kad_config_file; }

#else  // MS_NETWORK_TEST

const boost::uint8_t g_K(16);
boost::uint8_t K() { return g_K; }

#endif  // MS_NETWORK_TEST

NetworkTest::NetworkTest()
    : test_info_(testing::UnitTest::GetInstance()->current_test_info()),
      test_case_name_(test_info_->test_case_name()),
      transport_id_(-1),
#ifdef MS_NETWORK_TEST
      test_dir_(file_system::TempDir() / ("maidsafe_Test" + test_case_name_ +
                "_FUNC_" + base::RandomAlphaNumericString(6))),
#else
      test_dir_(file_system::TempDir() / ("maidsafe_Test" + test_case_name_ +
                "_" + base::RandomAlphaNumericString(6))),
#endif
      transport_(NULL),
      transport_handler_(NULL),
      channel_manager_(NULL),
      chunkstore_(new ChunkStore(std::string(test_dir_.string() +
                                 "/ChunkStore"), 99999999, 0)),
      kad_ops_(),
#ifdef MS_NETWORK_TEST
      store_manager_(new TestStoreManager(chunkstore_, g_K)),
#else
      store_manager_(new TestStoreManager(chunkstore_, g_K, test_dir_)),
#endif
      K_(g_K),
      kUpperThreshold_(static_cast<boost::uint8_t>
                       (g_K * kMinSuccessfulPecentageStore)),
      kLowerThreshold_(kMinSuccessfulPecentageStore > .25 ?
                       static_cast<boost::uint8_t>(g_K * .25) :
                       kUpperThreshold_) {
  ++gTestRunCount;
  try {
    if (fs::exists(test_dir_))
      fs::remove_all(test_dir_);
#ifndef MS_NETWORK_TEST
    if (fs::exists(file_system::LocalStoreManagerDir()))
      fs::remove_all(file_system::LocalStoreManagerDir());
#endif
    fs::create_directories(test_dir_);
  }
  catch(const std::exception &e) {
    printf("NetworkTest constructor - filesystem error: %s\n", e.what());
  }
}

NetworkTest::~NetworkTest() {
  CallbackObject callback;
  store_manager_->Close(
      boost::bind(&CallbackObject::ReturnCodeCallback, &callback, _1), true);
  callback.WaitForReturnCodeResult();

  // Delete test_dir_ after every test
  try {
    if (fs::exists(test_dir_))
      fs::remove_all(test_dir_);
  }
  catch(const std::exception &e) {
    printf("NetworkTest destructor - filesystem error: %s\n", e.what());
  }

  // Delete LocalStoreManagerDir after last test
#ifndef MS_NETWORK_TEST
  if (IsLastTest()) {
    try {
      if (fs::exists(file_system::LocalStoreManagerDir()))
        fs::remove_all(file_system::LocalStoreManagerDir());
    }
    catch(const std::exception &e) {
      printf("NetworkTest destructor - filesystem error: %s\n", e.what());
    }
  }
#endif
}

bool NetworkTest::Init() {
  CallbackObject callback;
  store_manager_->Init(
      boost::bind(&CallbackObject::ReturnCodeCallback, &callback, _1), 0);
  int result = callback.WaitForReturnCodeResult();
  if (result != kSuccess) {
    printf("NetworkTest::Init failed - %i\n", result);
    return false;
  }
#ifdef MS_NETWORK_TEST
  transport_handler_ = &store_manager_->transport_handler_;
  transport_ = &store_manager_->transport_;
  transport_id_ = transport_->transport_id();
  channel_manager_ = &store_manager_->channel_manager_;
  kad_ops_ = store_manager_->kad_ops_;
#endif
  return true;
}

bool NetworkTest::IsLastTest() {
//  return testing::UnitTest::GetInstance()->test_to_run_count() == gTestRunCount;
  return gTestRunCount == 3;
}

}  // namespace test
}  // namespace maidsafe
