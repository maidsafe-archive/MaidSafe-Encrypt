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
#include <gtest/gtest_prod.h>
#include <maidsafe/crypto.h>
#include <maidsafe/maidsafe-dht_config.h>
#include <maidsafe/transportudt.h>
#include <QThreadPool>

#include <list>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "maidsafe/chunkstore.h"
#include "maidsafe/opdata.h"
#include "maidsafe/kadops.h"
#include "maidsafe/clientbufferpackethandler.h"
#include "maidsafe/client/storemanager.h"
#include "maidsafe/client/storetaskshandler.h"

// These forward declarations are to allow PDVaultTest functions to be declared
// as friends of MaidsafeStoreManager.
namespace maidsafe {
class MaidsafeStoreManager;
}  // namespace maidsafe

namespace testpdvault {
size_t CheckStoredCopies(std::map<std::string, std::string> chunks,
                         const int &timeout_seconds,
                         boost::shared_ptr<maidsafe::MaidsafeStoreManager> sm);
}  // namespace testpdvault

namespace maidsafe_vault {
class PDVaultTest;
class RunPDVaults;
}  // namespace maidsafe_vault

namespace maidsafe {

class ClientRpcs;

enum TaskStatus { kPending, kStarted, kCancelled, kCompleted };

class BPCallbackObj {
 public:
  BPCallbackObj(bool *called_back,
                boost::condition_variable *cond_var,
                boost::mutex *mutex,
                ReturnCode *result)
                    : called_back_(called_back),
                      cond_var_(cond_var),
                      mutex_(mutex),
                      result_(result),
                      messages_(NULL) {
    boost::mutex::scoped_lock lock(*mutex_);
    *called_back = false;
    *result_ = kBPAwaitingCallback;
  }
  BPCallbackObj(bool *called_back,
                boost::condition_variable *cond_var,
                boost::mutex *mutex,
                ReturnCode *result,
                std::list<ValidatedBufferPacketMessage> *messages)
                    : called_back_(called_back),
                      cond_var_(cond_var),
                      mutex_(mutex),
                      result_(result),
                      messages_(messages) {
    boost::mutex::scoped_lock lock(*mutex_);
    *called_back = false;
    *result_ = kBPAwaitingCallback;
    messages_->clear();
  }
  void BPOperationCallback(const ReturnCode &return_code) {
    boost::mutex::scoped_lock lock(*mutex_);
    *result_ = return_code;
    *called_back_ = true;
    cond_var_->notify_all();
  }
  void BPGetMessagesCallback(
      const ReturnCode &return_code,
      const std::list<ValidatedBufferPacketMessage> &rec_msgs) {
    boost::mutex::scoped_lock lock(*mutex_);
    if (messages_ == NULL) {
      *result_ = kBPError;
    } else {
      *result_ = return_code;
      *messages_ = rec_msgs;
    }
    *called_back_ = true;
    cond_var_->notify_all();
  }
 private:
  bool *called_back_;
  boost::condition_variable *cond_var_;
  boost::mutex *mutex_;
  ReturnCode *result_;
  std::list<ValidatedBufferPacketMessage> *messages_;
};

class ChunkStore;
class SessionSingleton;

class AddToWatchListTask : public QRunnable {
 public:
  AddToWatchListTask(StoreData store_data, MaidsafeStoreManager *msm)
      : store_data_(store_data),
        msm_(msm) {}
  void run();
 private:
  AddToWatchListTask &operator=(const AddToWatchListTask&);
  AddToWatchListTask(const AddToWatchListTask&);
  StoreData store_data_;
  MaidsafeStoreManager *msm_;
};

class SendChunkCopyTask : public QRunnable {
 public:
  SendChunkCopyTask(StoreData store_data,
                    MaidsafeStoreManager *msm)
      : store_data_(store_data),
        msm_(msm) {}
  void run();
 private:
  SendChunkCopyTask &operator=(const SendChunkCopyTask&);
  SendChunkCopyTask(const SendChunkCopyTask&);
  StoreData store_data_;
  MaidsafeStoreManager *msm_;
};

class StorePacketTask : public QRunnable {
 public:
  StorePacketTask(boost::shared_ptr<StoreData> store_data,
                  MaidsafeStoreManager *msm)
      : store_data_(store_data),
        msm_(msm) {}
  void run();
 private:
  StorePacketTask &operator=(const StorePacketTask&);
  StorePacketTask(const StorePacketTask&);
  boost::shared_ptr<StoreData> store_data_;
  MaidsafeStoreManager *msm_;
};

class DeleteChunkTask : public QRunnable {
 public:
  DeleteChunkTask(StoreData store_data, MaidsafeStoreManager *msm)
      : store_data_(store_data),
        msm_(msm) {}
  void run();
 private:
  DeleteChunkTask &operator=(const DeleteChunkTask&);
  DeleteChunkTask(const DeleteChunkTask&);
  StoreData store_data_;
  MaidsafeStoreManager *msm_;
};

class DeletePacketTask : public QRunnable {
 public:
  DeletePacketTask(boost::shared_ptr<DeletePacketData> delete_data,
                   MaidsafeStoreManager *msm)
      : delete_data_(delete_data),
        msm_(msm) {}
  void run();
 private:
  DeletePacketTask &operator=(const DeletePacketTask&);
  DeletePacketTask(const DeletePacketTask&);
  boost::shared_ptr<DeletePacketData> delete_data_;
  MaidsafeStoreManager *msm_;
};

struct SetLocalVaultOwnedCallbackArgs {
 public:
  explicit SetLocalVaultOwnedCallbackArgs(SetLocalVaultOwnedFunctor functor)
      : cb(functor),
        response(new SetLocalVaultOwnedResponse),
        ctrl(new rpcprotocol::Controller) {}
  SetLocalVaultOwnedFunctor cb;
  SetLocalVaultOwnedResponse *response;
  rpcprotocol::Controller *ctrl;
  ~SetLocalVaultOwnedCallbackArgs() {
    delete response;
    delete ctrl;
  }
 private:
  SetLocalVaultOwnedCallbackArgs(const SetLocalVaultOwnedCallbackArgs&);
  SetLocalVaultOwnedCallbackArgs &operator=(
      const SetLocalVaultOwnedCallbackArgs&);
};

struct LocalVaultOwnedCallbackArgs {
 public:
  explicit LocalVaultOwnedCallbackArgs(LocalVaultOwnedFunctor functor)
      : cb(functor),
        response(new LocalVaultOwnedResponse),
        ctrl(new rpcprotocol::Controller) {}
  ~LocalVaultOwnedCallbackArgs() {
    delete response;
    delete ctrl;
  }
  LocalVaultOwnedFunctor cb;
  LocalVaultOwnedResponse *response;
  rpcprotocol::Controller *ctrl;
 private:
  LocalVaultOwnedCallbackArgs(const LocalVaultOwnedCallbackArgs&);
  LocalVaultOwnedCallbackArgs &operator=(const LocalVaultOwnedCallbackArgs&);
};

class MaidsafeStoreManager : public StoreManagerInterface {
 public:
  explicit MaidsafeStoreManager(boost::shared_ptr<ChunkStore> cstore);
  virtual ~MaidsafeStoreManager() {}
  void Init(int port, base::callback_func_type cb);
  void Close(base::callback_func_type cb, bool cancel_pending_ops);
  void CleanUpTransport();
  void StopRvPing() { transport_handler_.StopPingRendezvous(); }
  bool KeyUnique(const std::string &key, bool check_local);
  void KeyUnique(const std::string &key,
                 bool check_local,
                 const VoidFuncOneInt &cb);
  bool NotDoneWithUploading();
  // Adds the chunk to the store queue.  It must already be in the chunkstore.
  // If the chunk already exists (stored locally or on the net) the function
  // succeeds.  The function returns as soon as the task is enqueued.
  int StoreChunk(const std::string &chunk_name,
                 DirType dir_type,
                 const std::string &msid);
  // Adds the packet to the priority store queue for uploading as a Kad k,v pair
  void StorePacket(const std::string &packet_name,
                   const std::string &value,
                   PacketType system_packet_type,
                   DirType dir_type,
                   const std::string &msid,
                   IfPacketExists if_packet_exists,
                   const VoidFuncOneInt &cb);
  int LoadChunk(const std::string &chunk_name, std::string *data);
  // Blocking call which loads all values stored under the packet name
  int LoadPacket(const std::string &packet_name,
                 std::vector<std::string> *results);
  // Non-blocking call which loads all values stored under the packet name
  void LoadPacket(const std::string &packet_name, const LoadPacketFunctor &lpf);
  int DeleteChunk(const std::string &chunk_name,
                  const boost::uint64_t &chunk_size,
                  DirType dir_type,
                  const std::string &msid);
  // Deletes all values for the specified key
  void DeletePacket(const std::string &packet_name,
                    const std::vector<std::string> values,
                    PacketType system_packet_type,
                    DirType dir_type,
                    const std::string &msid,
                    const VoidFuncOneInt &cb);
  int GetAccountDetails(boost::uint64_t *space_offered,
                        boost::uint64_t *space_given,
                        boost::uint64_t *space_taken);
  // Buffer packet
  virtual int CreateBP();
  virtual int LoadBPMessages(std::list<ValidatedBufferPacketMessage> *messages);
  virtual int ModifyBPInfo(const std::string &info);
  virtual int AddBPMessage(const std::vector<std::string> &receivers,
                           const std::string &message,
                           const MessageType &type);

  // Vault
  void PollVaultInfo(base::callback_func_type cb);
  void VaultContactInfo(base::callback_func_type cb);
  void SetLocalVaultOwned(const std::string &priv_key,
                          const std::string &pub_key,
                          const std::string &signed_pub_key,
                          const boost::uint32_t &port,
                          const std::string &chunkstore_dir,
                          const boost::uint64_t &space,
                          const SetLocalVaultOwnedFunctor &functor);
  void LocalVaultOwned(const LocalVaultOwnedFunctor &functor);
  void GetChunkSignatureKeys(DirType dir_type,
                             const std::string &msid,
                             std::string *key_id,
                             std::string *public_key,
                             std::string *public_key_sig,
                             std::string *private_key);
  void GetPacketSignatureKeys(PacketType packet_type,
                              DirType dir_type,
                              const std::string &msid,
                              std::string *key_id,
                              std::string *public_key,
                              std::string *public_key_sig,
                              std::string *private_key);
  friend void AddToWatchListTask::run();
  friend void SendChunkCopyTask::run();
  friend void StorePacketTask::run();
  friend void DeleteChunkTask::run();
  friend void DeletePacketTask::run();
  friend size_t testpdvault::CheckStoredCopies(
      std::map<std::string, std::string> chunks,
      const int &timeout,
      boost::shared_ptr<MaidsafeStoreManager> sm);
 private:
  MaidsafeStoreManager &operator=(const MaidsafeStoreManager&);
  MaidsafeStoreManager(const MaidsafeStoreManager&);
  FRIEND_TEST(MaidStoreManagerTest, BEH_MAID_MSM_KeyUnique);
  FRIEND_TEST(MaidStoreManagerTest, BEH_MAID_MSM_AddToWatchList);
  FRIEND_TEST(MaidStoreManagerTest, BEH_MAID_MSM_AssessUploadCounts);
  FRIEND_TEST(MaidStoreManagerTest, BEH_MAID_MSM_GetStoreRequests);
  FRIEND_TEST(MaidStoreManagerTest, BEH_MAID_MSM_ValidatePrepResp);
  FRIEND_TEST(MaidStoreManagerTest, BEH_MAID_MSM_SendChunkPrep);
  FRIEND_TEST(MaidStoreManagerTest, BEH_MAID_MSM_SendPrepCallback);
  FRIEND_TEST(MaidStoreManagerTest, BEH_MAID_MSM_SendChunkContent);
  FRIEND_TEST(MaidStoreManagerTest, BEH_MAID_MSM_RemoveFromWatchList);
  FRIEND_TEST(MaidStoreManagerTest, BEH_MAID_MSM_StoreNewPacket);
  FRIEND_TEST(MaidStoreManagerTest, BEH_MAID_MSM_StoreExistingPacket);
  FRIEND_TEST(MaidStoreManagerTest, BEH_MAID_MSM_LoadPacket);
  FRIEND_TEST(MaidStoreManagerTest, BEH_MAID_MSM_DeletePacket);
  FRIEND_TEST(MaidStoreManagerTest, BEH_MAID_MSM_GetAccountDetails);
  FRIEND_TEST(MaidStoreManagerTest, BEH_MAID_MSM_GetFilteredAverage);
  FRIEND_TEST(PDVaultTest, FUNC_MAID_StoreAndGetChunks);
  FRIEND_TEST(PDVaultTest, FUNC_MAID_Cachechunk);
  friend class MsmSetLocalVaultOwnedTest;
  friend class maidsafe_vault::PDVaultTest;
  friend class maidsafe_vault::RunPDVaults;
  // Check the inputs to the public methods are valid
  int ValidateInputs(const std::string &name,
                     const PacketType &packet_type,
                     const DirType &dir_type);
  void AddStorePacketTask(const StoreData &store_data,
                          bool is_mutable,
                          int *return_value,
                          GenericConditionData *generic_cond_data);
  // Sends AddToWatchList requests to each of the k Chunk Info holders.
  virtual void AddToWatchList(StoreData store_data);
  // Assesses each AddToWatchListResponse and if consensus of required chunk
  // upload copies is achieved, begins new SendChunkCopyTask(s) if required.
  void AddToWatchListCallback(boost::uint16_t index,
                              boost::shared_ptr<WatchListOpData> data);
  // Assesses AddToWatchListResponses for consensus of required chunk upload
  // copies.  Returns < 0 if no consensus.  data->mutex should already be locked
  // by method calling this one for duration of this function.
  int AssessUploadCounts(boost::shared_ptr<WatchListOpData> data);
  // Send RemoveFromWatchList requests to each of the k Chunk Info holders.
  void RemoveFromWatchList(const StoreData &store_data);
  // Assesses each RemoveFromWatchListResponse.
  void RemoveFromWatchListCallback(boost::uint16_t index,
                                   boost::shared_ptr<WatchListOpData> data);
  void AccountStatusCallback(boost::shared_ptr<AccountStatusData> data);
  // Calculates the mean of only the values within sqrt(2) std devs from mean
  // TODO(Team#) move to central place for global usage?
  static void GetFilteredAverage(const std::vector<boost::uint64_t> &values,
                                 boost::uint64_t *average,
                                 size_t *n);
  // Returns the current status of the task and sets *task to the task if found.
  virtual TaskStatus AssessTaskStatus(const std::string &data_name,
                                      StoreTaskType task_type,
                                      StoreTask *task);
  // Blocks until either we're online (returns true) or until task is cancelled
  // or finished (returns false)
  virtual bool WaitForOnline(const std::string &data_name,
                             const StoreTaskType &task_type);
  // Assesses the task status and if task is still running, blocks until online.
  // If the task is cancelled, this method stops the subtask in the
  // task_handler_ and deletes the task if no subtasks remain.
  bool AssessTaskAndOnlineStatus(const std::string &data_name,
                                 const StoreTaskType &task_type);
  // Set up the requests needed to perform the store RPCs.
  int GetStoreRequests(boost::shared_ptr<SendChunkData> send_chunk_data);
  // Set up the requests needed to perform the AddToWatchList RPCs.
  int GetAddToWatchListRequests(
      const StoreData &store_data,
      const std::vector<kad::Contact> &recipients,
      std::vector<AddToWatchListRequest> *add_to_watch_list_requests);
  // Set up the requests needed to perform the RemoveFromWatchList RPCs.
  int GetRemoveFromWatchListRequests(
      const StoreData &store_data,
      const std::vector<kad::Contact> &recipients,
      std::vector<RemoveFromWatchListRequest> *remove_from_watch_list_requests);
  // Get the request signature for a chunk / packet.
  void GetRequestSignature(const std::string &name,
                           const DirType dir_type,
                           const std::string &recipient_id,
                           const std::string &public_key,
                           const std::string &public_key_signature,
                           const std::string &private_key,
                           std::string *request_signature);
  // Get the request signature for a chunk / packet store task.
  void GetRequestSignature(const StoreData &store_data,
                           const std::string &recipient_id,
                           std::string *request_signature);
  // Start process of storing a single copy of an individual chunk onto the net
  virtual int SendChunkPrep(const StoreData &store_data);
  void SendPrepCallback(boost::shared_ptr<SendChunkData> send_chunk_data);
  virtual int ValidatePrepResponse(
      const std::string &peer_node_id,
      const SignedSize &request_signed_size,
      StorePrepResponse *const store_prep_response);
  // Send the actual data content to the peer.
  virtual int SendChunkContent(
      boost::shared_ptr<SendChunkData> send_chunk_data);
  void SendContentCallback(boost::shared_ptr<SendChunkData> send_chunk_data);
  // Populates a vector of chunk holders.  Those that are contactable have
  // non-empty contact details and those that have the chunk have their variable
  // check_chunk_response_.result() == kAck.  To stop the function from sending
  // any further RPCs (e.g. if a previous one has yielded a satisfactory result
  // for the calling method), set stop_sending to true.  The function increments
  // check_chunk_rpc_count each time an RPC is sent.
  void FindAvailableChunkHolders(
      const std::string &chunk_name,
      const std::vector<std::string> &chunk_holders_ids,
      boost::shared_ptr<GenericConditionData> cond_data,
      std::vector< boost::shared_ptr<ChunkHolder> > *chunk_holders,
      int *available_chunk_holder_index,
      bool *stop_sending,
      int *check_chunk_rpc_count);
  // Populates the contact details of a peer vault (with ID chunk_holder_id) and
  // pushes them into the list of contacts provided.  If the RPC fails, the
  // chunk holder's status_ is set to kFailedHolder.  Having done this,
  // notify is called on the conditional variable.
  void GetHolderContactCallback(
      const std::string &chunk_holder_id,
      const std::string &result,
      std::vector< boost::shared_ptr<ChunkHolder> > *chunk_holders,
      boost::shared_ptr<GenericConditionData> cond_data);
  // This populates the chunk holder's check_chunk_response_ variable (i.e.
  // confirms whether the peer has the chunk or not).  If the RPC fails, the
  // chunk holder's status_ is set to kFailedHolder.  If not, the chunk holder's
  // index is pushed onto confirmed_chunk_holder_index.  Having done this,
  // notify is called on find_conditional_.
  void HasChunkCallback(boost::shared_ptr<ChunkHolder> chunk_holder,
                        int *available_chunk_holder_index);
  // Given a vector of vault ids, this gets the contact info for each and if
  // load_data is true, attempts to load the data once the first contact info
  // is received.
  virtual int FindAndLoadChunk(
      const std::string &chunk_name,
      const std::vector<std::string> &chunk_holders_ids,
      bool load_data,
      std::string *data);
  // Get a chunk's content from a specific peer.
  int GetChunk(const std::string &chunk_name,
               boost::shared_ptr<ChunkHolder> chunk_holder,
               std::string *data,
               boost::mutex *get_mutex);
  // Get a bufferpacket's content from a specific peer.
  void GetMessages(const std::string &buffer_packet_name,
                   boost::shared_ptr<ChunkHolder> chunk_holder,
                   const std::string &public_key,
                   const std::string &signed_public_key,
                   std::string *serialised_get_messages_response,
                   boost::mutex *get_mutex);
  void GetChunkCallback(boost::mutex *mutex, bool *get_chunk_done);
  virtual void FindCloseNodes(
      const std::vector<std::string> &packet_holder_ids,
      std::vector< boost::shared_ptr<ChunkHolder> > *packet_holders,
      boost::shared_ptr<GenericConditionData> find_cond_data);
  // Callback for blocking version of LoadPacket
  void LoadPacketCallback(const std::vector<std::string> values_in,
                          const int &result_in,
                          boost::mutex *mutex,
                          boost::condition_variable *cond_var,
                          std::vector<std::string> *values_out,
                          int *result_out);
  // Callback for non-blocking version of LoadPacket
  void LoadPacketCallback(const std::string &packet_name,
                          const int &attempt,
                          const std::string &ser_response,
                          const LoadPacketFunctor &lpf);
  // Callback for blocking version of KeyUnique
  void KeyUniqueCallback(const ReturnCode &result_in,
                         boost::mutex *mutex,
                         boost::condition_variable *cond_var,
                         bool *result_out,
                         bool *called_back);
  // Callback for non-blocking version of KeyUnique
  void KeyUniqueCallback(const std::string &ser_response,
                         const VoidFuncOneInt &cb);
  // Assess prior existence of packet on net and handle storing if required.
  virtual void SendPacketPrep(boost::shared_ptr<StoreData> store_data);
  // Store an individual packet to the network as a kademlia value.
  virtual void SendPacket(boost::shared_ptr<StoreData> store_data);
  void SendPacketCallback(const std::string &ser_kad_store_result,
                          boost::shared_ptr<StoreData> store_data);
  void OverwritePacket(boost::shared_ptr<StoreData> store_data,
                       const std::vector<std::string> &values);
  void OverwritePacketStageTwo(boost::shared_ptr<StoreData> store_data,
                               const ReturnCode &delete_result);
  virtual void DeletePacketFromNet(
      boost::shared_ptr<DeletePacketData> delete_data);
  void DeletePacketCallback(const std::string &ser_kad_delete_result,
                            boost::shared_ptr<DeletePacketData> delete_data);
  void DoNothingCallback(const std::string&) {}
  void PollVaultInfoCallback(const VaultStatusResponse *response,
                             base::callback_func_type cb);
//  void VaultContactInfoCallback(const std::string &ser_result,
//                                base::callback_func_type cb);
  void SetLocalVaultOwnedCallback(
      boost::shared_ptr<SetLocalVaultOwnedCallbackArgs> callback_args);
  void LocalVaultOwnedCallback(
      boost::shared_ptr<LocalVaultOwnedCallbackArgs> callback_args);
  transport::TransportUDT udt_transport_;
  transport::TransportHandler transport_handler_;
  rpcprotocol::ChannelManager channel_manager_;
  std::string kad_config_location_;
  boost::shared_ptr<kad::KNode> knode_;
  boost::shared_ptr<ClientRpcs> client_rpcs_;
  boost::shared_ptr<KadOps> kad_ops_;
  SessionSingleton *ss_;
  StoreTasksHandler tasks_handler_;
  boost::shared_ptr<ChunkStore> client_chunkstore_;
  QThreadPool chunk_thread_pool_, packet_thread_pool_;
  boost::mutex store_packet_mutex_;
  boost::condition_variable get_chunk_conditional_;
  boost::shared_ptr<BufferPacketRpcs> bprpcs_;
  ClientBufferPacketHandler cbph_;
  static int kChunkMaxThreadCount_;
  static int kPacketMaxThreadCount_;
};

}  // namespace maidsafe

#endif  // MAIDSAFE_CLIENT_MAIDSTOREMANAGER_H_
