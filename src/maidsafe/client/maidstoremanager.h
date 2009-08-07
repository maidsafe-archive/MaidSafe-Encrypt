/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Manages data storage to Maidsafe network
* Version:      1.0
* Created:      2009-01-28-23.53.44
* Revision:     none
* Compiler:     gcc
* Author:       Fraser Hutchison (fh), fraser.hutchison@maidsafe.net
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

#ifndef MAIDSAFE_CLIENT_MAIDSTOREMANAGER_H_
#define MAIDSAFE_CLIENT_MAIDSTOREMANAGER_H_

#include <boost/tuple/tuple.hpp>
#include <maidsafe/crypto.h>

#include <queue>
#include <string>
#include <vector>

#include "maidsafe/threadpool.h"
#include "maidsafe/client/pdclient.h"
#include "maidsafe/client/storemanager.h"

namespace maidsafe {

class CallbackObj {
 public:
  CallbackObj() : mutex_(), called_(false), result_("") {}
  void CallbackFunc(const std::string &result) {
    boost::mutex::scoped_lock lock(mutex_);
    result_ = result;
    called_ = true;
  }
  bool called() {
    boost::mutex::scoped_lock lock(mutex_);
    return called_;
  }
  std::string result() {
    boost::mutex::scoped_lock lock(mutex_);
    return result_;
  }
 private:
  boost::mutex mutex_;
  bool called_;
  std::string result_;
};

// Tuple of non_hex_chunk_name, dir_type, msid in that order.
typedef boost::tuple<std::string, DirType, std::string> StoreTuple;
typedef std::queue<StoreTuple>StoreQueue;

class ChunkStore;

class MaidsafeStoreManager : public StoreManagerInterface {
 public:
  explicit MaidsafeStoreManager(boost::shared_ptr<ChunkStore> cstore);
  ~MaidsafeStoreManager() {}
  void Init(int port, base::callback_func_type cb);
  void Close(base::callback_func_type cb);
  void CleanUpTransport();
  void LoadChunk(const std::string &hex_chunk_name,
                 base::callback_func_type cb);
// TODO(Fraser#5#): 2009-08-04 - Delete this version of StoreChunk
  void StoreChunk(const std::string &,  // hex_chunk_name,
                  const std::string &,  // content,
                  const std::string &,  // public_key,
                  const std::string &,  // signed_public_key,
                  const std::string &,  // signature,
                  base::callback_func_type) {}
  // Adds the chunk to the store queue.  It must already be in the chunkstore.
  void StoreChunk(const std::string &hex_chunk_name,
                  const DirType dir_type,
                  const std::string &msid);
  void IsKeyUnique(const std::string &hex_key,
                   base::callback_func_type cb);
  void DeletePacket(const std::string &hex_key,
                    const std::string &signature,
                    const std::string &public_key,
                    const std::string &signed_public_key,
                    const ValueType &type,
                    base::callback_func_type cb);
  void StorePacket(const std::string &hex_key,
                   const std::string &value,
                   const std::string &signature,
                   const std::string &public_key,
                   const std::string &signed_public_key,
                   const ValueType &type,
                   bool update,
                   base::callback_func_type cb);
  void LoadPacket(const std::string &hex_key, base::callback_func_type cb);
  void GetMessages(const std::string &hex_key,
                   const std::string &public_key,
                   const std::string &signed_public_key,
                   base::callback_func_type cb);
  // Start the main store thread running.
  void StartStoring();
  // Try to stop the main store thread.  If it doesn't stop within 5 seconds, it
  // is detached.
  void StopStoring();
  // Return the true if the main store thread is running.
  bool StoreThreadRunning();

 private:
  MaidsafeStoreManager &operator=(const MaidsafeStoreManager&);
  MaidsafeStoreManager(const MaidsafeStoreManager&);
  void LoadChunk_Callback(const std::string &result,
                          base::callback_func_type cb);
  void SimpleResult_Callback(const std::string &result,
                             base::callback_func_type cb);
  void IsKeyUnique_Callback(const std::string &result,
                            base::callback_func_type cb);
  void GetMsgs_Callback(const std::string &result, base::callback_func_type cb);
  void StoreChunk_Callback(const std::string &result,
                           const bool &update,
                           base::callback_func_type cb);
  void DeleteChunk_Callback(const std::string &result,
                            base::callback_func_type cb);
  // Used to amend store_thread_running_ bool by main store thread on exit.
  void StoreThreadStopping();
  // Function run in main store thread which spawns up to kMaxStoreThreads
  // child threads.  Always leaves room for at least one priority store thread.
  void StoreThread();
  void GetSignedPubKeyAndRequest(const std::string &non_hex_name,
                                 const DirType dir_type,
                                 const std::string &msid,
                                 std::string *pubkey,
                                 std::string *signed_pubkey,
                                 std::string *signed_request);
  void AddToPriorityStoreQueue(const StoreTuple &store_tuple);
  void AddToNormalStoreQueue(const StoreTuple &store_tuple);
  // Store an individual chunk onto the network
  void SendChunk(const StoreTuple &store_tuple);
  // Set up the values needed to perform the store RPCs
  int PrepareToStore(const StoreTuple &store_tuple,
                     std::string *chunk_name,
                     DirType *dir_type,
                     std::string *msid,
                     std::string *chunk_content,
                     std::string *public_key,
                     std::string *signed_public_key,
                     std::string *signed_request);
  boost::shared_ptr<rpcprotocol::ChannelManager> channel_manager_;
  boost::shared_ptr<kad::KNode> knode_;
  ClientRpcs client_rpcs_;
  PDClient *pdclient_;
  crypto::Crypto co_;
  boost::shared_ptr<ChunkStore> client_chunkstore_;
  boost::thread main_store_thread_;
  bool store_thread_running_;
  StoreQueue priority_store_queue_;
  StoreQueue normal_store_queue_;
  ThreadPool store_thread_pool_;
  boost::mutex store_thread_running_mutex_, ps_queue_mutex_, ns_queue_mutex_;
};

}  // namespace maidsafe

#endif  // MAIDSAFE_CLIENT_MAIDSTOREMANAGER_H_
