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
#include <maidsafe/base/crypto.h>
#include <maidsafe/maidsafe-dht_config.h>
#include <maidsafe/transport/transportudt.h>
#include <QThreadPool>

#include <list>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "maidsafe/accountholdersmanager.h"
#include "maidsafe/accountstatusmanager.h"
#include "maidsafe/chunkstore.h"
#include "maidsafe/opdata.h"
#include "maidsafe/kadops.h"
#include "maidsafe/clientbufferpackethandler.h"
#include "maidsafe/client/storemanager.h"
#include "maidsafe/client/storetaskshandler.h"
#include "maidsafe/client/imconnectionhandler.h"
#include "maidsafe/client/imhandler.h"

// These forward declarations are to allow PDVaultTest functions to be declared
// as friends of MaidsafeStoreManager.
namespace maidsafe {
class MaidsafeStoreManager;
namespace test {
class MsmSetLocalVaultOwnedTest;
class NetworkTest;
class CCImMessagingTest;
class CCImMessagingTest_FUNC_MAID_NET_TestImSendPresenceAndMsgs_Test;
class CCImMessagingTest_FUNC_MAID_NET_TestImRecPresenceAndSendMsgs_Test;
class CCImMessagingTest_FUNC_MAID_NET_TestMultipleImToContact_Test;
}  // namespace test
}  // namespace maidsafe

namespace testpdvault {
size_t CheckStoredCopies(std::map<std::string, std::string> chunks,
                         const int &timeout_seconds,
                         boost::shared_ptr<maidsafe::MaidsafeStoreManager> sm);
}  // namespace testpdvault

namespace maidsafe_vault {
class RunPDVaults;
namespace test {
class PDVaultTest;
class PDVaultTest_FUNC_MAID_NET_StoreAndGetChunks_Test;
}  // namespace test
}  // namespace maidsafe_vault

namespace maidsafe {

class ClientRpcs;

enum TaskStatus { kPending, kStarted, kCancelled, kCompleted };

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

class UpdatePacketTask : public QRunnable {
 public:
  UpdatePacketTask(boost::shared_ptr<UpdatePacketData> update_data,
                   MaidsafeStoreManager *msm)
      : update_data_(update_data),
        msm_(msm) {}
  void run();
 private:
  UpdatePacketTask &operator=(const UpdatePacketTask&);
  UpdatePacketTask(const UpdatePacketTask&);
  boost::shared_ptr<UpdatePacketData> update_data_;
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

struct PresenceMessages {
  std::set<std::string> presence_set;
  boost::uint16_t successes;
  bool done;
  boost::mutex mutex;
  boost::condition_variable cond;
};

struct VBPMessages {
  std::set<std::string> presence_set;
  boost::uint16_t successes;
  bool done;
  boost::mutex mutex;
  boost::condition_variable cond;
};

struct BPResults {
  size_t returned_count;
  std::map<std::string, ReturnCode> *results;
  boost::mutex mutex;
  boost::condition_variable cond;
  bool finished;
  ReturnCode rc;
};

class MaidsafeStoreManager : public StoreManagerInterface {
 public:
  MaidsafeStoreManager(boost::shared_ptr<ChunkStore> cstore, boost::uint8_t k);
  virtual ~MaidsafeStoreManager() {}
  void Init(VoidFuncOneInt callback, const boost::uint16_t &port);
  void Close(VoidFuncOneInt callback, bool cancel_pending_ops);
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
  virtual void UpdatePacket(const std::string &packet_name,
                            const std::string &old_value,
                            const std::string &new_value,
                            PacketType system_packet_type,
                            DirType dir_type,
                            const std::string &msid,
                            const VoidFuncOneInt &cb);

  void GetAccountStatus(boost::uint64_t *space_offered,
                        boost::uint64_t *space_given,
                        boost::uint64_t *space_taken);
  // Buffer packet
  virtual int CreateBP();
  virtual int LoadBPMessages(std::list<ValidatedBufferPacketMessage> *messages);
  virtual int ModifyBPInfo(const std::string &info);
  virtual int SendMessage(const std::vector<std::string> &receivers,
                           const std::string &message,
                           const MessageType &type,
                           std::map<std::string, ReturnCode> *add_results);
  virtual int LoadBPPresence(std::list<LivePresence> *messages);
  virtual int AddBPPresence(
      const std::vector<std::string> &receivers,
      std::map<std::string, ReturnCode> *add_results);

  // Vault
  void PollVaultInfo(kad::VoidFunctorOneString cb);
  void VaultContactInfo(kad::VoidFunctorOneString cb);
  void SetLocalVaultOwned(const std::string &priv_key,
                          const std::string &pub_key,
                          const std::string &signed_pub_key,
                          const boost::uint32_t &port,
                          const std::string &vault_dir,
                          const boost::uint64_t &space,
                          const SetLocalVaultOwnedFunctor &functor);
  void LocalVaultOwned(const LocalVaultOwnedFunctor &functor);
  virtual int CreateAccount(const boost::uint64_t &space);

  // Instant messaging send online message
  bool SendPresence(const std::string &contactname);
  void SendLogOutMessage(const std::string &contactname);
  void SetSessionEndPoint();
  void SetInstantMessageNotifier(IMNotifier on_msg,
                                 IMStatusNotifier status_notifier);

//  void ResetSessionSingleton(SessionSingleton *ss) {
//    ss_ = ss;
//  }

 private:
  MaidsafeStoreManager &operator=(const MaidsafeStoreManager&);
  MaidsafeStoreManager(const MaidsafeStoreManager&);
  friend void AddToWatchListTask::run();
  friend void SendChunkCopyTask::run();
  friend void StorePacketTask::run();
  friend void DeleteChunkTask::run();
  friend void DeletePacketTask::run();
  friend void UpdatePacketTask::run();
  friend size_t testpdvault::CheckStoredCopies(
      std::map<std::string, std::string> chunks,
      const int &timeout, boost::shared_ptr<MaidsafeStoreManager> sm);
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
  FRIEND_TEST(MaidStoreManagerTest, BEH_MAID_MSM_UpdatePacket);
  FRIEND_TEST(MaidStoreManagerTest, BEH_MAID_MSM_GetAccountStatus);
  FRIEND_TEST(MaidStoreManagerTest, BEH_MAID_MSM_UpdateAccountStatus);
  FRIEND_TEST(MaidStoreManagerTest, BEH_MAID_MSM_GetFilteredAverage);
  friend class test::MsmSetLocalVaultOwnedTest;
  friend class maidsafe_vault::test::PDVaultTest;
  friend class
      maidsafe_vault::test::PDVaultTest_FUNC_MAID_NET_StoreAndGetChunks_Test;
  friend class maidsafe_vault::RunPDVaults;
  friend class maidsafe::test::NetworkTest;
  friend class test::CCImMessagingTest;
  friend class
      test::CCImMessagingTest_FUNC_MAID_NET_TestImSendPresenceAndMsgs_Test;
  friend class
      test::CCImMessagingTest_FUNC_MAID_NET_TestImRecPresenceAndSendMsgs_Test;
  friend class
      test::CCImMessagingTest_FUNC_MAID_NET_TestMultipleImToContact_Test;

  // Check the inputs to the public methods are valid
  ReturnCode ValidateInputs(const std::string &name,
                            const PacketType &packet_type,
                            const DirType &dir_type);
  void AddStorePacketTask(const StoreData &store_data,
                          bool is_mutable,
                          int *return_value,
                          GenericConditionData *generic_cond_data);
  // Sends AddToWatchList requests to each of the k Chunk Info holders.
  virtual void AddToWatchList(const StoreData& store_data);
  // Callback of FindNodes.  Sends ExpectAmendment requests.
  void AddToWatchListStageTwo(const std::string &response,
                              boost::shared_ptr<WatchListOpData> data);
  // Callback of ExpectAmendment.  Sends AddToWatchList requests.
  void AddToWatchListStageThree(boost::uint16_t index,
                                boost::shared_ptr<WatchListOpData> data);
  // Callback of AddToWatchList.  Assesses response and if consensus of required
  // chunk upload copies is achieved, begins new SendChunkCopyTask(s) if needed.
  void AddToWatchListStageFour(boost::uint16_t index,
                               boost::shared_ptr<WatchListOpData> data);
  // Assesses AddToWatchListResponses for consensus of required chunk upload
  // copies.  Returns < 0 if no consensus.  data->mutex should already be locked
  // by method calling this one for duration of this function.
  int AssessUploadCounts(boost::shared_ptr<WatchListOpData> data);
  // Sends RemoveFromWatchList requests to each of the k Chunk Info holders.
  virtual void RemoveFromWatchList(const StoreData &store_data);
  // Callback of FindNodes.  Sends ExpectAmendment requests.
  void RemoveFromWatchListStageTwo(const std::string &response,
                                   boost::shared_ptr<WatchListOpData> data);
  // Callback of ExpectAmendment.  Sends RemoveFromWatchList requests.
  void RemoveFromWatchListStageThree(boost::uint16_t index,
                                     boost::shared_ptr<WatchListOpData> data);
  // Callback of RemoveFromWatchList, assesses responses.
  void RemoveFromWatchListStageFour(boost::uint16_t index,
                                    boost::shared_ptr<WatchListOpData> data);
  // Contact the chunk info holders to retrieve the list of chunk holders
  bool GetChunkReferences(const std::string &chunk_name,
                          const std::vector<kad::Contact> &chunk_info_holders,
                          std::vector<std::string> *references);
  void UpdateAccountStatus(const bool &force = false);
  void UpdateAccountStatusStageTwo(size_t index,
                                   boost::shared_ptr<AccountStatusData> data);
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
  // Set up the requests needed to perform the ExpectAmendment RPCs.
  int GetExpectAmendmentRequests(
      const StoreData &store_data,
      const AmendAccountRequest::Amendment amendment_type,
      const std::vector<kad::Contact> &account_holders,
      const std::vector<kad::Contact> &chunk_info_holders,
      std::vector<ExpectAmendmentRequest> *expect_amendment_requests);
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
      const StorePrepResponse *store_prep_response);
  // Send the actual data content to the peer.
  virtual int SendChunkContent(
      boost::shared_ptr<SendChunkData> send_chunk_data);
  void SendContentCallback(boost::shared_ptr<SendChunkData> send_chunk_data);
  void LoadChunk_FindCB(const std::string &result,
                        boost::shared_ptr<GetChunkOpData> data);
  void LoadChunk_RefsCB(size_t rsp_idx,
                        boost::shared_ptr<GetChunkOpData> data);
  void LoadChunk_HolderCB(const std::string &result,
                          const std::string &pmid,
                          boost::shared_ptr<GetChunkOpData> data);
  void LoadChunk_CheckCB(std::pair<std::string, size_t> params,
                         boost::shared_ptr<GetChunkOpData> data);
  // Get a chunk's content from a specific peer.
  int GetChunk(const std::string &chunk_name,
               const kad::Contact &chunk_holder,
               std::string *data);
  void GetChunkCallback(
      bool *done,
      std::pair<boost::mutex*, boost::condition_variable*> sync);
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
  // Store an individual packet to the network as a kademlia value.
  virtual void SendPacket(boost::shared_ptr<StoreData> store_data);
  void SendPacketCallback(const std::string &ser_kad_store_result,
                          boost::shared_ptr<StoreData> store_data);
  std::string GetValueFromSignedValue(
      const std::string &serialised_signed_value);
  virtual void DeletePacketFromNet(
      boost::shared_ptr<DeletePacketData> delete_data);
  void DeletePacketCallback(const std::string &ser_kad_delete_result,
                            boost::shared_ptr<DeletePacketData> delete_data);
  virtual void UpdatePacketOnNetwork(
      boost::shared_ptr<UpdatePacketData> update_data);
  void UpdatePacketCallback(const std::string &ser_kad_update_result,
                            boost::shared_ptr<UpdatePacketData> delete_data);
  void DoNothingCallback(const std::string&) {}
  void PollVaultInfoCallback(const VaultStatusResponse *response,
                             kad::VoidFunctorOneString cb);
  void SetLocalVaultOwnedCallback(
      boost::shared_ptr<SetLocalVaultOwnedCallbackArgs> callback_args);
  void LocalVaultOwnedCallback(
      boost::shared_ptr<LocalVaultOwnedCallbackArgs> callback_args);
  void AccountHoldersManagerInitCallback(
      const ReturnCode &result,
      const std::vector<kad::Contact> &account_holder_group,
      boost::shared_ptr<AmendAccountData> data);
  void AmendAccountCallback(size_t index,
                            boost::shared_ptr<AmendAccountData> data);
  void ModifyBpCallback(const ReturnCode &rc,
                        boost::shared_ptr<BPResults> pm);
  void AddToBpCallback(const ReturnCode &rc,
                       const std::string &receiver,
                       boost::shared_ptr<BPResults> results);
  void LoadMessagesCallback(const maidsafe::ReturnCode &res,
                            const std::list<ValidatedBufferPacketMessage> &msgs,
                            bool b,
                            boost::shared_ptr<VBPMessages> vbpms);
  void LoadPresenceCallback(const maidsafe::ReturnCode &res,
                            const std::list<std::string> &pres,
                            bool b,
                            boost::shared_ptr<PresenceMessages> pm);
  std::string ValidatePresence(const std::string &ser_presence);

  // Instant messaging related functions
  void CloseConnection(const std::string &contactname);
  void OnMessage(const std::string &msg);
  void OnNewConnection(const boost::int16_t &trans_id,
      const boost::uint32_t &conn_id, const std::string &msg);
  bool SendIM(const std::string &msg, const std::string &contactname);

  boost::uint8_t K_;
  boost::uint16_t upper_threshold_;
  boost::uint16_t lower_threshold_;
  transport::TransportUDT udt_transport_;
  transport::TransportHandler transport_handler_;
  rpcprotocol::ChannelManager channel_manager_;
  boost::shared_ptr<ClientRpcs> client_rpcs_;
  boost::shared_ptr<KadOps> kad_ops_;
  SessionSingleton *ss_;
  StoreTasksHandler tasks_handler_;
  boost::shared_ptr<ChunkStore> client_chunkstore_;
  QThreadPool chunk_thread_pool_, packet_thread_pool_;
  boost::shared_ptr<BufferPacketRpcs> bprpcs_;
  ClientBufferPacketHandler cbph_;
  static int kChunkMaxThreadCount_;
  static int kPacketMaxThreadCount_;
  IMNotifier im_notifier_;
  IMStatusNotifier im_status_notifier_;
  IMConnectionHandler im_conn_hdler_;
  IMHandler im_handler_;
  AccountHoldersManager account_holders_manager_;
  AccountStatusManager account_status_manager_;
};

}  // namespace maidsafe

#endif  // MAIDSAFE_CLIENT_MAIDSTOREMANAGER_H_
