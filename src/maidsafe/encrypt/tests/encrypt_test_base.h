/* Copyright 2011 MaidSafe.net limited

This MaidSafe Software is licensed under the MaidSafe.net Commercial License, version 1.0 or later,
and The General Public License (GPL), version 3. By contributing code to this project You agree to
the terms laid out in the MaidSafe Contributor Agreement, version 1.0, found in the root directory
of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also available at:

http://www.novinet.com/license

Unless required by applicable law or agreed to in writing, software distributed under the License is
distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
implied. See the License for the specific language governing permissions and limitations under the
License.
*/

#ifndef MAIDSAFE_ENCRYPT_TESTS_ENCRYPT_TEST_BASE_H_
#define MAIDSAFE_ENCRYPT_TESTS_ENCRYPT_TEST_BASE_H_

#include <thread>
#include <memory>

#include "boost/scoped_array.hpp"
#include "boost/filesystem/path.hpp"

#include "maidsafe/common/utils.h"
#include "maidsafe/data_store/permanent_store.h"
#include "maidsafe/encrypt/self_encryptor.h"

namespace fs = boost::filesystem;

namespace maidsafe {
namespace encrypt {
namespace test {

typedef data_store::PermanentStore DataStore;
typedef std::shared_ptr<DataStore> DataStorePtr;
typedef std::shared_ptr<nfs::ClientMaidNfs> ClientNfsPtr;
typedef std::shared_ptr<SelfEncryptor> SelfEncryptorPtr;

class EncryptTestBase {
 public:
  explicit EncryptTestBase(int num_procs)
      : test_dir_(maidsafe::test::CreateTestPath()),
        num_procs_(num_procs),
        maid_(maidsafe::passport::Maid::signer_type()),
        routing_(maid_),
        client_nfs_(new nfs::ClientMaidNfs(routing_, maid_)),
        data_store_path_(*test_dir_ / "data_store"),
        data_store_(std::make_shared<DataStore>(data_store_path_,
                                                DiskUsage(uint64_t(4294967296)))),
        data_map_(std::make_shared<DataMap>()),
        self_encryptor_(std::make_shared<SelfEncryptor>(data_map_,
                                                        *client_nfs_,
                                                        *data_store_,
                                                        num_procs_)),
        original_(),
        decrypted_() {}
  virtual ~EncryptTestBase() {}

 protected:
  maidsafe::test::TestPath test_dir_;
  int num_procs_;
  passport::Maid maid_;
  routing::Routing routing_;
  ClientNfsPtr client_nfs_;
  fs::path data_store_path_;
  DataStorePtr data_store_;
  DataMapPtr data_map_;
  SelfEncryptorPtr self_encryptor_;
  boost::scoped_array<char> original_, decrypted_;

 private:
};

}  // namespace test
}  // namespace encrypt
}  // namespace maidsafe

#endif  // MAIDSAFE_ENCRYPT_TESTS_ENCRYPT_TEST_BASE_H_
