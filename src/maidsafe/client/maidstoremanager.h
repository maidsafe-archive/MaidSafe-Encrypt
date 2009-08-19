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

#include <boost/thread/condition_variable.hpp>
#include <boost/thread/locks.hpp>
#include <boost/tuple/tuple.hpp>
#include <maidsafe/crypto.h>
#include <maidsafe/maidsafe-dht_config.h>

#include <queue>
#include <set>
#include <string>
#include <vector>

#include "boost/threadpool.hpp"  // NB - This is NOT an accepted boost lib.
#include "maidsafe/client/pdclient.h"
#include "maidsafe/client/storemanager.h"

namespace maidsafe {

class CallbackObj {
 public:
  CallbackObj() : cond_(),  mutex_(), called_(false), result_("") {}
  void CallbackFunc(const std::string &result) {
    {
      boost::lock_guard<boost::mutex> lock(mutex_);
      result_ = result;
    }
    cond_.notify_one();
  }
  std::string result() {
    boost::mutex::scoped_lock lock(mutex_);
    return called_ ? result_ : "";
  }
  //  Block until callback happens or timeout (milliseconds) passes.
  void WaitForCallback(const int &timeout) {
    boost::system_time now(boost::get_system_time());
    boost::system_time timeout_expires = now +
        boost::posix_time::milliseconds(timeout);
    boost::unique_lock<boost::mutex> lock(mutex_);
    called_ = cond_.timed_wait(lock, timeout_expires);
  }
 private:
  boost::condition_variable cond_;
  boost::mutex mutex_;
  bool called_;
  std::string result_;
};

// Tuple of non_hex_chunk_name, dir_type, msid in that order.
typedef boost::tuple<std::string, DirType, std::string> StoreTuple;

struct StoreIouResultHolder {
  StoreIouResultHolder()
      : store_iou_response_(),
        store_iou_response_returned_(false),
        rpc_id_(0) {}
  StoreIOUResponse store_iou_response_;
  bool store_iou_response_returned_;
  boost::uint32_t rpc_id_;
};

struct HasChunkResultHolder {
  explicit HasChunkResultHolder(const kad::Contact &chunk_holder)
      : chunk_holder_(chunk_holder),
        local_(false),
        check_chunk_response_(),
        check_chunk_response_returned_(false),
        tried_to_get_chunk_(false),
        rpc_id_(0),
        find_mutex_(),
        has_conditional_() {}
  kad::Contact chunk_holder_;
  bool local_;
  CheckChunkResponse check_chunk_response_;
  bool check_chunk_response_returned_;
  bool tried_to_get_chunk_;
  boost::uint32_t rpc_id_;
  boost::mutex *find_mutex_;
  boost::condition_variable *has_conditional_;
};

class ChunkStore;
class SessionSingleton;

class MaidsafeStoreManager : public StoreManagerInterface {
 public:
  explicit MaidsafeStoreManager(boost::shared_ptr<ChunkStore> cstore);
  ~MaidsafeStoreManager() {}
  void Init(int port, base::callback_func_type cb);
  void Close(base::callback_func_type cb, bool cancel_pending_ops);
  void CleanUpTransport();
  int LoadChunk(const std::string &hex_chunk_name, std::string *data);
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
  void AddPriorityStoreTask(const StoreTuple &store_tuple);
  void AddNormalStoreTask(const StoreTuple &store_tuple);
  // Store an individual chunk onto the network.
  void SendChunk(StoreTuple store_tuple);
  // Set up the requests needed to perform the store RPCs.
  int GetStoreRequests(const StoreTuple &store_tuple,
                       const std::string &recipient_id,
                       StorePrepRequest *store_prep_request,
                       StoreRequest *store_request,
                       IOUDoneRequest *iou_done_request);
  // Get the public key, signed public key, and signed request for a chunk.
  void GetSignedPubKeyAndRequest(const std::string &non_hex_name,
                                 const DirType dir_type,
                                 const std::string &msid,
                                 const std::string &recipient_id,
                                 std::string *pubkey,
                                 std::string *signed_pubkey,
                                 std::string *signed_request);
  // Get a new contact from the routing table to try and store a chunk on.  The
  // closest to the ideal_rtt will be chosen from those not in the vector to
  // exclude.  If the ideal_rtt is -1.0, then the contact with the highest rtt
  // will be chosen.
  int GetStorePeer(const float &ideal_rtt,
                   const std::vector<kad::Contact> &exclude,
                   kad::Contact *new_peer,
                   bool *local);
  // Send the "preparation to store" message and wait until called back.
  int SendPrep(const kad::Contact &peer,
               bool local,
               StorePrepRequest *store_prep_request,
               StorePrepResponse *store_prep_response);
  void SendPrepCallback(bool *send_prep_returned, boost::mutex *mutex);
  // Send the actual data content to the peer.
  int SendContent(const kad::Contact &peer,
                  bool local,
                  StoreRequest *store_request);
  void SendContentCallback(bool *send_content_returned, boost::mutex *mutex);
  // Pass the IOU for the peer vault to the k chunk reference holders.
  int StoreIOUs(const std::string &non_hex_chunk_name,
                const boost::uint64_t &chunk_size,
                const StorePrepResponse &store_prep_response);
  // Blocking call to Kademlia Find Nodes.
  int FindKNodes(const std::string &kad_key,
                 std::vector<kad::Contact> *contacts);
  // Blocking call to Kademlia Find Value.
  int FindValue(const std::string &kad_key,
                std::string *value,
                std::vector<std::string> *chunk_holders_ids);
  // Given a vector of vault ids, this gets the contact info for each and
  // attempts to load the data once the first set of contacts is received.
  int FindAndLoadChunk(const std::string &chunk_name,
                       const std::vector<std::string> &chunk_holders_ids,
                       std::string *data);
  // Populates the contact details of a peer vault (with ID chunk_holder_id) and
  // pushes them into the list of contacts provided.  Having done this, it calls
  // notify on the conditional variable.
  void GetChunkHolderContactCallback(
      const std::string &chunk_holder_id,
      const std::string &result,
      std::vector<HasChunkResultHolder> *has_chunk_result_holders,
      boost::mutex *find_mutex,
      boost::condition_variable *find_conditional);
  void HasChunkCallback(HasChunkResultHolder *has_chunk_result_holder);
  // Get a chunk's content from a specific peer.
  void GetChunk(HasChunkResultHolder *has_chunk_result_holder,
                std::string *data);
  void GetChunkCallback(boost::condition_variable *cond);
  // Passes the IOU to an individual reference holder.
  int SendIouToRefHolder(const kad::Contact &ref_holder,
                         StoreIOURequest store_iou_request,
                         boost::mutex *store_iou_mutex,
                         StoreIouResultHolder *store_iou_result_holder);
  void SendIouToRefHolderCallback(bool *store_iou_response_returned,
                                  boost::mutex *store_iou_mutex);
  int HandleStoreIOUResponse(
      const StoreIouResultHolder &store_iou_result_holder,
      std::set<std::string> *ref_holder_ids);
  // Notifies a peer that this vault has passed the IOUs to the appropriate
  // reference holders.
  int SendIOUDone(const kad::Contact &peer,
                  bool local,
                  IOUDoneRequest *iou_done_request);
  void IOUDoneCallback(bool *iou_done_returned, boost::mutex *mutex);
  boost::shared_ptr<rpcprotocol::ChannelManager> channel_manager_;
  boost::shared_ptr<kad::KNode> knode_;
  ClientRpcs client_rpcs_;
  PDClient *pdclient_;
  SessionSingleton *ss_;
  boost::shared_ptr<ChunkStore> client_chunkstore_;
  boost::threadpool::thread_pool<
      boost::threadpool::prio_task_func,
      boost::threadpool::prio_scheduler,
      boost::threadpool::static_size,
      boost::threadpool::resize_controller,
      boost::threadpool::immediately> store_thread_pool_;
  const boost::uint16_t kKadStoreThreshold_;
};

}  // namespace maidsafe

#endif  // MAIDSAFE_CLIENT_MAIDSTOREMANAGER_H_
