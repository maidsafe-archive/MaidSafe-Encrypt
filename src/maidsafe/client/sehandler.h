/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Handler for self-encryption/decryption operations - an
*               interface between the clientcontroller and selfencryption
* Version:      1.0
* Created:      09/09/2008 12:14:35 PM
* Revision:     none
* Compiler:     gcc 4.3
* Author:       David Irvine (di), david.irvine@maidsafe.net
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

#ifndef MAIDSAFE_CLIENT_SEHANDLER_H_
#define MAIDSAFE_CLIENT_SEHANDLER_H_

#include <boost/filesystem.hpp>
#include <boost/multi_index_container.hpp>
#include <boost/signals2.hpp>
#include <boost/thread/mutex.hpp>
#include <gtest/gtest_prod.h>

#include <map>
#include <string>

#include "maidsafe/maidsafe.h"
#include "protobuf/datamaps.pb.h"

namespace bs2 = boost::signals2;
namespace fs = boost::filesystem;
namespace mi = boost::multi_index;

/********************************** Signals **********************************/
typedef bs2::signal<void(const std::string&, int percentage)>
        OnFileNetworkStatus;
/*****************************************************************************/

namespace maidsafe {
class SEHandler;
}  // namespace maidsafe

namespace test_seh {
enum ModificationType { kAdd, kGet, kRemove };
void ModifyUpToDateDms(ModificationType modification_type,
                       const boost::uint16_t &test_size,
                       const std::vector<std::string> &keys,
                       const std::vector<std::string> &enc_dms,
                       boost::shared_ptr<maidsafe::SEHandler> seh);
}  // namespace test_seh

namespace maidsafe {

namespace test {
class SEHandlerTest_BEH_MAID_Check_Entry_Test;
class SEHandlerTest_BEH_MAID_EncryptAndDecryptPrivateDb_Test;
class SEHandlerTest_BEH_MAID_UpToDateDatamapsSingleThread_Test;
class SEHandlerTest_BEH_MAID_UpToDateDatamapsMultiThread_Test;
class SEHandlerTest_BEH_MAID_EncryptAndDecryptPrivateDb_Test;
class SEHandlerTest_BEH_MAID_FailureOfChunkEncryptingFile_Test;
}  // namespace test

class ChunkStore;
class SessionSingleton;
class StoreManagerInterface;

const int kMaxStoreRetries = 2;
const int kMaxLoadRetries = 2;
const int kParallelStores = 1;
const int kParallelLoads = 3;

struct PendingChunks {
  PendingChunks()
      : chunkname(), path(), msid(), done(kPendingResult), tries(1),
        dirtype(PRIVATE) {}
  PendingChunks(const std::string &chunk_name, const std::string &file_path,
                const std::string &id)
      : chunkname(chunk_name), path(file_path), msid(id), done(kPendingResult),
        tries(1), dirtype(PRIVATE) {}
  std::string chunkname, path, msid;
  ReturnCode done;
  boost::uint8_t tries;
  DirType dirtype;
};

// tags
struct by_chunkname {};
struct by_path {};

typedef mi::multi_index_container<
  PendingChunks,
  mi::indexed_by<
    mi::ordered_unique<
      mi::tag<by_chunkname>,
      BOOST_MULTI_INDEX_MEMBER(PendingChunks, std::string, chunkname)
    >,
    mi::ordered_non_unique<
      mi::tag<by_path>,
      BOOST_MULTI_INDEX_MEMBER(PendingChunks, std::string, path)
    >
  >
> PendingChunksSet;

typedef PendingChunksSet::index<by_chunkname>::type PCSbyName;
typedef PendingChunksSet::index<by_path>::type PCSbyPath;

class SEHandler {
 public:
  typedef std::map<std::string, std::string> UpToDateDatamaps;
  SEHandler();
  ~SEHandler();
  void Init(boost::shared_ptr<StoreManagerInterface> storem,
            boost::shared_ptr<ChunkStore> client_chunkstore);

  //  Get the hash of the file contents if bool = true, else hash filename
  std::string SHA512(const std::string &full_entry, bool hash_contents);
  int EncryptFile(const std::string &rel_entry, const DirType &dir_type,
                  const std::string &msid);
  int EncryptString(const std::string &data, std::string *ser_dm);
  bool ProcessMetaData(const std::string &rel_entry, const ItemType &type,
                       const std::string &hash,
                       const boost::uint64_t &file_size, std::string *ser_mdm);
  int DecryptFile(const std::string &rel_entry);
  int DecryptString(const std::string &ser_dm, std::string *dec_string);
  bool MakeElement(const std::string &rel_entry, const ItemType &type,
                   const std::string &directory_key);

  //  Gets a unique DHT key for dir's db identifier
  int GenerateUniqueKey(std::string *key);

  //  Retrieves DHT keys for dir and its parent dir if msid == "" or sets
  //  parent_key to MSID public key if msid != ""
  int GetDirKeys(const std::string &dir_path, const std::string &msid,
                 std::string *key, std::string *parent_key);

  //  Encrypts dir's db and sets ser_dm_ to encrypted datamap of db
  int EncryptDb(const std::string &dir_path, const DirType &dir_type,
                const std::string &dir_key, const std::string &msid,
                const bool &encrypt_dm, DataMap *dm);

  //  Decrypts dir's db by extracting datamap from ser_dm_
  int DecryptDb(const std::string &dir_path, const DirType &dir_type,
                const std::string &encrypted_dm, const std::string &dir_key,
                const std::string &msid, bool dm_encrypted, bool overwrite);

  bs2::connection ConnectToOnFileNetworkStatus(
      const OnFileNetworkStatus::slot_type &slot);

 private:
  SEHandler &operator=(const SEHandler &);
  SEHandler(const SEHandler &);
  friend class test::SEHandlerTest_BEH_MAID_Check_Entry_Test;
  friend class test::SEHandlerTest_BEH_MAID_EncryptAndDecryptPrivateDb_Test;
  friend class test::SEHandlerTest_BEH_MAID_UpToDateDatamapsSingleThread_Test;
  friend class test::SEHandlerTest_BEH_MAID_UpToDateDatamapsMultiThread_Test;
  friend void test_seh::ModifyUpToDateDms(
      test_seh::ModificationType modification_type,
      const boost::uint16_t &test_size,
      const std::vector<std::string> &keys,
      const std::vector<std::string> &enc_dms,
      boost::shared_ptr<maidsafe::SEHandler> seh);
  friend class test::SEHandlerTest_BEH_MAID_FailureOfChunkEncryptingFile_Test;
  ItemType CheckEntry(const fs::path &full_path, boost::uint64_t *file_size,
                      std::string *file_hash);

  //  Encrypt db's datamap for storing on DHT
  int EncryptDm(const std::string &dir_path, const std::string &ser_dm,
                const std::string &msid, std::string *enc_dm);

  //  Decrypt db's datamap
  int DecryptDm(const std::string &dir_path, const std::string &enc_dm,
                const std::string &msid, std::string *ser_dm);
  void StoreChunks(const DataMap &dm, const DirType &dir_type,
                   const std::string &msid, const std::string &path = "");
  int LoadChunks(const DataMap &dm);
  // Returns previous value of enc_dm if dir_key exists in map, else returns "".
  std::string AddToUpToDateDms(const std::string &dir_key,
                               const std::string &enc_dm);
  std::string GetFromUpToDateDms(const std::string &dir_key);
  int RemoveFromUpToDateDms(const std::string &dir_key);
  void PacketOpCallback(const int &store_manager_result, boost::mutex *mutex,
                        boost::condition_variable *cond_var, int *op_result);
  void ChunkDone(const std::string &chunkname, maidsafe::ReturnCode rc);

  boost::shared_ptr<StoreManagerInterface> storem_;
  boost::shared_ptr<ChunkStore> client_chunkstore_;
  SessionSingleton *ss_;
  std::map<std::string, std::string> up_to_date_datamaps_;
  PendingChunksSet pending_chunks_;
  boost::mutex up_to_date_datamaps_mutex_, chunkmap_mutex_;
  boost::signals2::connection connection_to_chunk_uploads_;
  OnFileNetworkStatus file_status_;
};

}  // namespace maidsafe
#endif  // MAIDSAFE_CLIENT_SEHANDLER_H_
