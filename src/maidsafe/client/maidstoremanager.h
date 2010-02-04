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

#include "maidsafe/bufferpacketrpc.h"
#include "maidsafe/chunkstore.h"
#include "maidsafe/clientbufferpackethandler.h"
#include "maidsafe/client/clientrpc.h"
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

namespace maidsafe {

enum ChunkHolderStatus {
  kUnknown,
  kContactable,
  kHasChunk,
  kAwaitingChunk,
  kUpdatingChunk,
  kDone,
  kFailedHolder,
  kFailedChecksum
};

enum TaskStatus { kPending, kStarted, kCancelled, kCompleted };

class CallbackObj {
 public:
  CallbackObj() : mutex_(), called_(false), result_("") {}
  ~CallbackObj() {}
  void CallbackFunc(const std::string &result) {
    boost::mutex::scoped_lock lock(mutex_);
    result_ = result;
    called_ = true;
  }
  std::string result() {
//    printf("Callback obj result() - afore lock\n");
    boost::mutex::scoped_lock lock(mutex_);
//    printf("Callback obj result() - after lock\n");
    return called_ ? result_ : "";
  }
  bool called() {
    boost::mutex::scoped_lock lock(mutex_);
    return called_;
  }
  //  Block until callback happens or timeout (milliseconds) passes.
  void WaitForCallback(const int &timeout) {
    int count = 0;
    while (!called() && count < timeout) {
      count += 10;
      boost::this_thread::sleep(boost::posix_time::milliseconds(10));
    }
  }
  //  Block until callback happens.
  void WaitForCallback() {
//    printf("Callback obj WaitForCallback() - start\n");
    while (!called()) {
//      printf("Callback obj WaitForCallback() - afore sleep\n");
      boost::this_thread::sleep(boost::posix_time::milliseconds(10));
//      printf("Callback obj WaitForCallback() - after slepp\n");
    }
  }
 private:
  boost::mutex mutex_;
  bool called_;
  std::string result_;
};

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

struct StoreData {
  // Default constructor
  StoreData() : non_hex_key(),
                value(),
                size(0),
                msid(),
                key_id(),
                public_key(),
                public_key_signature(),
                private_key(),
                chunk_type(kHashable | kNormal),
                system_packet_type(MID),
                dir_type(PRIVATE),
                if_packet_exists(kDoNothingReturnFailure),
                callback() {}
  // Store chunk constructor
  StoreData(const std::string &non_hex_chunk_name,
            const boost::uint64_t &chunk_size,
            ChunkType ch_type,
            DirType directory_type,
            const std::string &ms_id,
            const std::string &key,
            const std::string &pub_key,
            const std::string &pub_key_signature,
            const std::string &priv_key)
                : non_hex_key(non_hex_chunk_name),
                  value(),
                  size(chunk_size),
                  msid(ms_id),
                  key_id(key),
                  public_key(pub_key),
                  public_key_signature(pub_key_signature),
                  private_key(priv_key),
                  chunk_type(ch_type),
                  system_packet_type(MID),
                  dir_type(directory_type),
                  if_packet_exists(kDoNothingReturnFailure),
                  callback() {}
  // Store packet constructor
  StoreData(const std::string &non_hex_packet_name,
            const std::string &packet_value,
            PacketType sys_packet_type,
            DirType directory_type,
            const std::string &ms_id,
            const std::string &key,
            const std::string &pub_key,
            const std::string &pub_key_signature,
            const std::string &priv_key,
            IfPacketExists if_exists,
            VoidFuncOneInt cb)
                : non_hex_key(non_hex_packet_name),
                  value(packet_value),
                  size(0),
                  msid(ms_id),
                  key_id(key),
                  public_key(pub_key),
                  public_key_signature(pub_key_signature),
                  private_key(priv_key),
                  chunk_type(kHashable | kNormal),
                  system_packet_type(sys_packet_type),
                  dir_type(directory_type),
                  if_packet_exists(if_exists),
                  callback(cb) {}
  std::string non_hex_key, value;
  boost::uint64_t size;
  std::string msid, key_id, public_key, public_key_signature, private_key;
  ChunkType chunk_type;
  PacketType system_packet_type;
  DirType dir_type;
  IfPacketExists if_packet_exists;
  VoidFuncOneInt callback;
};

struct DeletePacketData {
 public:
  DeletePacketData(const std::string &non_hex_name,
                   const std::vector<std::string> &packet_values,
                   PacketType sys_packet_type,
                   DirType directory_type,
                   const std::string &ms_id,
                   const std::string &key,
                   const std::string &pub_key,
                   const std::string &pub_key_signature,
                   const std::string &priv_key,
                   VoidFuncOneInt cb)
                       : non_hex_packet_name(non_hex_name),
                         values(packet_values),
                         msid(ms_id),
                         key_id(key),
                         public_key(pub_key),
                         public_key_signature(pub_key_signature),
                         private_key(priv_key),
                         system_packet_type(sys_packet_type),
                         dir_type(directory_type),
                         callback(cb),
                         mutex(),
                         returned_count(0),
                         called_back(false) {}
  // This ctor effectively allows us to use a StoreData struct for deleting
  // a packet during an OverwritePacket operation
  DeletePacketData(boost::shared_ptr<StoreData> store_data,
                   const std::vector<std::string> &vals,
                   VoidFuncOneInt cb)
                       : non_hex_packet_name(store_data->non_hex_key),
                         values(vals),
                         msid(store_data->msid),
                         key_id(store_data->key_id),
                         public_key(store_data->public_key),
                         public_key_signature(store_data->public_key_signature),
                         private_key(store_data->private_key),
                         system_packet_type(store_data->system_packet_type),
                         dir_type(store_data->dir_type),
                         callback(cb),
                         mutex(),
                         returned_count(0),
                         called_back(false) {}
  std::string non_hex_packet_name;
  std::vector<std::string> values;
  std::string msid, key_id, public_key, public_key_signature, private_key;
  PacketType system_packet_type;
  DirType dir_type;
  VoidFuncOneInt callback;
  boost::mutex mutex;
  size_t returned_count;
  bool called_back;
 private:
};

// This is used to hold the data required to perform a Kad lookup to get a
// group of Chunk Info holders, send each an AddToWatchListRequest or
// RemoveFromWatchListRequest and assess the responses.
struct WatchListOpData {
  struct AddToWatchDataHolder {
    explicit AddToWatchDataHolder(const std::string &id)
        : node_id(id), response(), controller(new rpcprotocol::Controller) {}
    std::string node_id;
    AddToWatchListResponse response;
    boost::shared_ptr<rpcprotocol::Controller> controller;
  };
  struct RemoveFromWatchDataHolder {
    explicit RemoveFromWatchDataHolder(const std::string &id)
        : node_id(id), response(), controller(new rpcprotocol::Controller) {}
    std::string node_id;
    RemoveFromWatchListResponse response;
    boost::shared_ptr<rpcprotocol::Controller> controller;
  };
  explicit WatchListOpData(const StoreData &sd)
      : store_data(sd),
        mutex(),
        contacts(),
        add_to_watchlist_data_holders(),
        remove_from_watchlist_data_holders(),
        returned_count(0),
        successful_delete_count(0),
        required_upload_copies(),
        consensus_upload_copies(-1) {}
  StoreData store_data;
  boost::mutex mutex;
  std::vector<kad::Contact> contacts;
  std::vector<AddToWatchDataHolder> add_to_watchlist_data_holders;
  std::vector<RemoveFromWatchDataHolder> remove_from_watchlist_data_holders;
  boost::uint16_t returned_count;
  boost::uint16_t successful_delete_count;
  std::multiset<int> required_upload_copies;
  int consensus_upload_copies;
};

// This is used to hold the data required to perform a SendChunkPrep followed by
// a SendChunkContent operation.
struct SendChunkData {
  SendChunkData(const StoreData &sd,
                const kad::Contact &node,
                bool node_local)
      : store_data(sd),
        peer(node),
        local(node_local),
        store_prep_request(),
        store_prep_response(),
        store_chunk_request(),
        store_chunk_response(),
        controller(new rpcprotocol::Controller),
        attempt(0) {}
  StoreData store_data;
  kad::Contact peer;
  bool local;
  StorePrepRequest store_prep_request;
  StorePrepResponse store_prep_response;
  StoreChunkRequest store_chunk_request;
  StoreChunkResponse store_chunk_response;
  boost::shared_ptr<rpcprotocol::Controller> controller;
  boost::uint16_t attempt;
};

struct GenericConditionData {
 public:
  explicit GenericConditionData(boost::shared_ptr<boost::condition_variable> cv)
      : cond_flag(false),
        cond_variable(cv),
        cond_mutex() {}
  ~GenericConditionData() {}
  bool cond_flag;
  boost::shared_ptr<boost::condition_variable> cond_variable;
  boost::mutex cond_mutex;
 private:
  GenericConditionData &operator=(const GenericConditionData&);
  GenericConditionData(const GenericConditionData&);
};

struct ChunkHolder {
 public:
  explicit ChunkHolder(const kad::Contact &chunk_holder_contact)
      : chunk_holder_contact(chunk_holder_contact),
        local(false),
        check_chunk_response(),
        status(kUnknown),
        index(-1),
        controller(),
        mutex() {}
  explicit ChunkHolder(const kad::ContactInfo &chunk_holder_contact_info)
      : chunk_holder_contact(chunk_holder_contact_info),
        local(false),
        check_chunk_response(),
        status(kUnknown),
        index(-1),
        controller(),
        mutex() {}
  kad::Contact chunk_holder_contact;
  bool local;
  CheckChunkResponse check_chunk_response;
  ChunkHolderStatus status;
  // This can be set to the index of this ChunkHolder in a container of
  // ChunkHolders.
  int index;
  // This shared pointer will remain NULL if the ChunkHolder's contact details
  // cannot be found via Kademlia.  It is kept here to enable the associated RPC
  // to be cancelled.
  boost::shared_ptr<rpcprotocol::Controller> controller;
  boost::mutex *mutex;
 private:
  ChunkHolder &operator=(const ChunkHolder&);
  ChunkHolder(const ChunkHolder&);
};

class ChunkStore;
class SessionSingleton;

class AddToWatchListTask : public QRunnable {
 public:
  AddToWatchListTask(const StoreData &store_data, MaidsafeStoreManager *msm)
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
  SendChunkCopyTask(const StoreData &store_data,
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
  DeleteChunkTask(const StoreData &store_data, MaidsafeStoreManager *msm)
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

class AmendAccountTask : public QRunnable {
 public:
  AmendAccountTask(const boost::uint64_t &space_offered,
                   MaidsafeStoreManager *msm)
      : space_offered_(space_offered),
        msm_(msm) {}
  void run();
 private:
  AmendAccountTask &operator=(const AmendAccountTask&);
  AmendAccountTask(const AmendAccountTask&);
  boost::uint64_t space_offered_;
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
  bool KeyUnique(const std::string &hex_key, bool check_local);
  bool NotDoneWithUploading();
  // Adds the chunk to the store queue.  It must already be in the chunkstore.
  // If the chunk already exists (stored locally or on the net) the function
  // succeeds.  The function returns as soon as the task is enqueued.
  void StoreChunk(const std::string &hex_chunk_name,
                  DirType dir_type,
                  const std::string &msid);
  // Adds the packet to the priority store queue for uploading as a Kad k,v pair
  void StorePacket(const std::string &hex_packet_name,
                   const std::string &value,
                   PacketType system_packet_type,
                   DirType dir_type,
                   const std::string &msid,
                   IfPacketExists if_packet_exists,
                   const VoidFuncOneInt &cb);
  int LoadChunk(const std::string &hex_chunk_name, std::string *data);
  // Loads the most recently stored value under the packet name
  int LoadPacket(const std::string &hex_packet_name, std::string *result);
  // Loads all values stored under the packet name (most recent first)
  int LoadPacket(const std::string &hex_packet_name,
                 std::vector<std::string> *results);
  int DeleteChunk(const std::string &hex_chunk_name,
                  const boost::uint64_t &chunk_size,
                  DirType dir_type,
                  const std::string &msid);
  // Deletes a single k,v pair
  void DeletePacket(const std::string &hex_packet_name,
                    const std::string &value,
                    PacketType system_packet_type,
                    DirType dir_type,
                    const std::string &msid,
                    const VoidFuncOneInt &cb);
  // Deletes all values for the specified key where values are currently unknown
  void DeletePacket(const std::string &hex_packet_name,
                    PacketType system_packet_type,
                    DirType dir_type,
                    const std::string &msid,
                    const VoidFuncOneInt &cb);
  // Deletes all values for the specified key
  void DeletePacket(const std::string &hex_packet_name,
                    const std::vector<std::string> values,
                    PacketType system_packet_type,
                    DirType dir_type,
                    const std::string &msid,
                    const VoidFuncOneInt &cb);
  int CreateAccount(const boost::uint64_t &space_offered);
  int SetSpaceOffered(const boost::uint64_t &space);
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
  static void GetChunkSignatureKeys(DirType dir_type,
                                    const std::string &msid,
                                    std::string *key_id,
                                    std::string *public_key,
                                    std::string *public_key_sig,
                                    std::string *private_key);
  static void GetPacketSignatureKeys(PacketType packet_type,
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
  friend void AmendAccountTask::run();
  friend size_t testpdvault::CheckStoredCopies(
      std::map<std::string, std::string> chunks,
      const int &timeout,
      boost::shared_ptr<MaidsafeStoreManager> sm);
  friend class MsmSetLocalVaultOwnedTest;
 private:
  MaidsafeStoreManager &operator=(const MaidsafeStoreManager&);
  MaidsafeStoreManager(const MaidsafeStoreManager&);
  FRIEND_TEST(MaidStoreManagerTest, BEH_MAID_MSM_AddToWatchList);
  FRIEND_TEST(MaidStoreManagerTest, BEH_MAID_MSM_AssessUploadCounts);
  FRIEND_TEST(MaidStoreManagerTest, BEH_MAID_MSM_GetStoreRequests);
  FRIEND_TEST(MaidStoreManagerTest, BEH_MAID_MSM_ValidatePrepResp);
  FRIEND_TEST(MaidStoreManagerTest, BEH_MAID_MSM_SendChunkPrep);
  FRIEND_TEST(MaidStoreManagerTest, BEH_MAID_MSM_SendPrepCallback);
  FRIEND_TEST(MaidStoreManagerTest, BEH_MAID_MSM_SendChunkContent);
  FRIEND_TEST(MaidStoreManagerTest, BEH_MAID_MSM_SendContentCallback);
  FRIEND_TEST(MaidStoreManagerTest, BEH_MAID_MSM_StoreNewPacket);
  FRIEND_TEST(MaidStoreManagerTest, BEH_MAID_MSM_StoreExistingPacket);
  FRIEND_TEST(MaidStoreManagerTest, BEH_MAID_MSM_DeletePacket);
  FRIEND_TEST(MaidStoreManagerTest, FUNC_MAID_MSM_LoadPacketAllSucceed);
  FRIEND_TEST(MaidStoreManagerTest, FUNC_MAID_MSM_LoadPacketAllFail);
  FRIEND_TEST(MaidStoreManagerTest, FUNC_MAID_MSM_LoadPacketOneSucceed);
  FRIEND_TEST(PDVaultTest, FUNC_MAID_Cachechunk);

  void AddStorePacketTask(const StoreData &store_data,
                          bool is_mutable,
                          int *return_value,
                          GenericConditionData *generic_cond_data);
  // Sends AddToWatchList requests to each of the k Chunk Info holders.
  virtual void AddToWatchList(const StoreData &store_data);
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
  void GetRequestSignature(const std::string &non_hex_name,
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
  // Get a new contact from the routing table to try and store a chunk on.  The
  // closest to the ideal_rtt will be chosen from those not in the vector to
  // exclude.  If the ideal_rtt is -1.0, then the contact with the highest rtt
  // will be chosen.
  virtual int GetStorePeer(const float &ideal_rtt,
                           const std::vector<kad::Contact> &exclude,
                           kad::Contact *new_peer,
                           bool *local);
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
  // Blocking call to Kademlia Find Nodes.
  virtual int FindKNodes(const std::string &kad_key,
                         std::vector<kad::Contact> *contacts);
  // Blocking call to Kademlia Find Value.  If the maidsafe value is cached,
  // this may yield serialised contact details for a cache copy holder.
  // Otherwise it should yield the values (which may represent chunk holders'
  // IDs).  It also yields the details of the last kad node to not return the
  // value during the lookup.  If check_local is true, it also checks the local
  // chunkstore first.  The values are loaded in reverse order.
  virtual int FindValue(const std::string &kad_key,
                        bool check_local,
                        kad::ContactInfo *cache_holder,
                        std::vector<std::string> *values,
                        std::string *needs_cache_copy_id);
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
  // Returns true if the peer is on the local network
  bool AddressIsLocal(const kad::Contact &peer);
  bool AddressIsLocal(const kad::ContactInfo &peer);
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
/*
  // Non-blocking specialised version of the StorePacketToVaults method used to
  // store encrypted PD dirs only.
  int StorePdDirToVaults(const std::string &hex_packet_name,
                         const std::string &value,
                         DirType dir_type,
                         const std::string &msid);
*/
  virtual void FindCloseNodes(
      const std::vector<std::string> &packet_holder_ids,
      std::vector< boost::shared_ptr<ChunkHolder> > *packet_holders,
      boost::shared_ptr<GenericConditionData> find_cond_data);
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
  void AmendAccount(const boost::uint64_t &space_offered);

//  void VaultContactInfoCallback(const std::string &ser_result,
//                                base::callback_func_type cb);
  void SetLocalVaultOwnedCallback(
      boost::shared_ptr<SetLocalVaultOwnedCallbackArgs> callback_args);
  void LocalVaultOwnedCallback(
      boost::shared_ptr<LocalVaultOwnedCallbackArgs> callback_args);
  transport::TransportUDT udt_transport_;
  transport::TransportHandler transport_handler_;
  rpcprotocol::ChannelManager channel_manager_;
  boost::shared_ptr<kad::KNode> knode_;
  boost::shared_ptr<ClientRpcs> client_rpcs_;
  SessionSingleton *ss_;
  StoreTasksHandler tasks_handler_;
  boost::shared_ptr<ChunkStore> client_chunkstore_;
  QThreadPool chunk_thread_pool_, packet_thread_pool_;
  const boost::uint16_t kKadStoreThreshold_;
  boost::mutex store_packet_mutex_;
  boost::condition_variable get_chunk_conditional_;
  boost::shared_ptr<BufferPacketRpcs> bprpcs_;
  ClientBufferPacketHandler cbph_;
};

}  // namespace maidsafe

#endif  // MAIDSAFE_CLIENT_MAIDSTOREMANAGER_H_
