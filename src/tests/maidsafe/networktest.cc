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

#include "tests/maidsafe/networktest.h"

#include "maidsafe/chunkstore.h"
#include "tests/maidsafe/testcallback.h"

namespace fs = boost::filesystem;

namespace maidsafe {
namespace test {

#ifdef MS_NETWORK_TEST

const int g_kNetworkSize = kad::K + 2;
LocalVaults g_pdvaults;
fs::path g_kad_config_file;

int kNetworkSize() { return g_kNetworkSize; }
LocalVaults *pdvaults() { return &g_pdvaults; }
fs::path *kadconfig() { return &g_kad_config_file; }

#endif  // MS_NETWORK_TEST

NetworkTest::NetworkTest(const std::string &test_name)
    : transport_id_(-1),
#ifdef MS_NETWORK_TEST
      test_dir_(file_system::TempDir() / ("maidsafe_Test" + test_name +
                                          "_FUNC_" + base::RandomString(6))),
#else
      test_dir_(file_system::TempDir() /
                ("maidsafe_Test" + test_name + "_" + base::RandomString(6))),
#endif
      udt_transport_(NULL),
      transport_handler_(NULL),
      channel_manager_(NULL),
      chunkstore_(new maidsafe::ChunkStore(std::string(test_dir_.string() +
                                           "/ChunkStore"), 99999999, 0)),
      kad_ops_(),
#ifdef MS_NETWORK_TEST
      store_manager_(new TestStoreManager(chunkstore_)) {
#else
      store_manager_(new TestStoreManager(chunkstore_, test_dir_.string())) {
#endif
  try {
    if (fs::exists(test_dir_))
      fs::remove_all(test_dir_);
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
#ifdef MS_NETWORK_TEST
  fs::path cleanup(test_dir_);
#else
  fs::path cleanup(file_system::LocalStoreManagerDir());
#endif
  try {
    if (fs::exists(cleanup))
      fs::remove_all(cleanup);
  }
  catch(const std::exception &e) {
    printf("NetworkTest destructor - filesystem error: %s\n", e.what());
  }
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
  udt_transport_ = &store_manager_->udt_transport_;
  transport_id_ = udt_transport_->transport_id();
  channel_manager_ = &store_manager_->channel_manager_;
  kad_ops_ = store_manager_->kad_ops_;
#endif
  return true;
}

}  // namespace test
}  // namespace maidsafe
