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
#include <gtest/gtest.h>
#include <maidsafe/crypto.h>
#include <maidsafe/maidsafe-dht_config.h>
#include <QThreadPool>

#include <list>
#include <map>
#include <queue>
#include <set>
#include <string>
#include <vector>

#include "maidsafe/client/pdclient.h"
#include "maidsafe/client/storemanager.h"



// These forward declarations are to allow TestPDVault functions to be declared
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

enum IfExists { kStoreFailure, kStoreSuccess, kOverwrite, kAppend };
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
    boost::mutex::scoped_lock lock(mutex_);
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
    while (!called())
      boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  }
 private:
  boost::mutex mutex_;
  bool called_;
  std::string result_;
};

struct StoreIouResultHolder {
 public:
  StoreIouResultHolder()
      : store_iou_response(),
        store_iou_response_returned(false),
        controller(new rpcprotocol::Controller) {}
  StoreIOUResponse store_iou_response;
  bool store_iou_response_returned;
  boost::shared_ptr<rpcprotocol::Controller> controller;
 private:
  StoreIouResultHolder &operator=(const StoreIouResultHolder&);
  StoreIouResultHolder(const StoreIouResultHolder&);
};

struct StoreData {
  // Default constructor
  StoreData() : non_hex_key_(""),
                value_(""),
                msid_(""),
                key_id_(""),
                public_key_(""),
                public_key_signature_(""),
                private_key_(""),
                system_packet_type_(MID),
                dir_type_(PRIVATE),
                append_(false) {}
  // Store chunk constructor
  StoreData(const std::string &non_hex_chunk_name,
            DirType dir_type,
            const std::string &msid,
            const std::string &key_id,
            const std::string &public_key,
            const std::string &public_key_signature,
            const std::string &private_key)
                : non_hex_key_(non_hex_chunk_name),
                  value_(""),
                  msid_(msid),
                  key_id_(key_id),
                  public_key_(public_key),
                  public_key_signature_(public_key_signature),
                  private_key_(private_key),
                  system_packet_type_(MID),
                  dir_type_(dir_type),
                  append_(false) {}
  // Store packet constructor
  StoreData(const std::string &non_hex_packet_name,
            const std::string &value,
            PacketType system_packet_type,
            DirType dir_type,
            const std::string &msid,
            const std::string &key_id,
            const std::string &public_key,
            const std::string &public_key_signature,
            const std::string &private_key,
            bool append)
                : non_hex_key_(non_hex_packet_name),
                  value_(value),
                  msid_(msid),
                  key_id_(key_id),
                  public_key_(public_key),
                  public_key_signature_(public_key_signature),
                  private_key_(private_key),
                  system_packet_type_(system_packet_type),
                  dir_type_(dir_type),
                  append_(append) {}
  std::string non_hex_key_, value_, msid_, key_id_, public_key_;
  std::string public_key_signature_, private_key_;
  PacketType system_packet_type_;
  DirType dir_type_;
  bool append_;
};

struct GenericConditionData {
 public:
  explicit GenericConditionData(boost::shared_ptr<boost::condition_variable> cv)
      : cond_flag(false),
        cond_mutex(),
        cond_variable(cv) {}
  ~GenericConditionData() {}
  bool cond_flag;
  boost::mutex cond_mutex;
  boost::shared_ptr<boost::condition_variable> cond_variable;
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
        store_packet_response(),
        status(kUnknown),
        index(-1),
        controller(),
        mutex() {}
  explicit ChunkHolder(const kad::ContactInfo &chunk_holder_contact_info)
      : chunk_holder_contact(chunk_holder_contact_info),
        local(false),
        check_chunk_response(),
        store_packet_response(),
        status(kUnknown),
        index(-1),
        controller(),
        mutex() {}
  kad::Contact chunk_holder_contact;
  bool local;
  CheckChunkResponse check_chunk_response;
  StorePacketResponse store_packet_response;
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

class StoreChunkTask : public QRunnable {
 public:
  StoreChunkTask(const StoreData &store_data,
                 IfExists if_exists,
                 MaidsafeStoreManager *msm);
  void run();
 private:
  StoreChunkTask &operator=(const StoreChunkTask&);
  StoreChunkTask(const StoreChunkTask&);
  StoreData store_data_;
  IfExists if_exists_;
  MaidsafeStoreManager *msm_;
};

class StorePacketToVaultsTask : public QRunnable {
 public:
  StorePacketToVaultsTask(const StoreData &store_data,
                          MaidsafeStoreManager *msm,
                          int *return_value,
                          GenericConditionData *generic_cond_data);
  void run();
 private:
  StorePacketToVaultsTask &operator=(const StorePacketToVaultsTask&);
  StorePacketToVaultsTask(const StorePacketToVaultsTask&);
  StoreData store_data_;
  MaidsafeStoreManager *msm_;
  int *return_value_;
  GenericConditionData *generic_cond_data_;
};

class StorePacketToKadTask : public QRunnable {
 public:
  StorePacketToKadTask(const StoreData &store_data,
                  MaidsafeStoreManager *msm,
                  int *return_value,
                  GenericConditionData *generic_cond_data);
  void run();
 private:
  StorePacketToKadTask &operator=(const StorePacketToKadTask&);
  StorePacketToKadTask(const StorePacketToKadTask&);
  StoreData store_data_;
  MaidsafeStoreManager *msm_;
  int *return_value_;
  GenericConditionData *generic_cond_data_;
};

class MaidsafeStoreManager : public StoreManagerInterface {
 public:
  explicit MaidsafeStoreManager(boost::shared_ptr<ChunkStore> cstore);
  virtual ~MaidsafeStoreManager() {}
  void Init(int port, base::callback_func_type cb);
  void Close(base::callback_func_type cb, bool cancel_pending_ops);
  void CleanUpTransport();
  bool KeyUnique(const std::string &hex_key, bool check_local);
  bool NotDoneWithUploading();
  // Adds the chunk to the store queue.  It must already be in the chunkstore.
  // If the chunk already exists (stored locally or on the net) the function
  // succeeds.  The function returns as soon as the task is enqueued.
  void StoreChunk(const std::string &hex_chunk_name,
                  DirType dir_type,
                  const std::string &msid);
  // Stores a system packet to Kademlia (for immutable packets) or to maidsafe
  // vaults (for mutable packets).  The function blocks until the entire store
  // method is complete.
  int StorePacket(const std::string &hex_packet_name,
                  const std::string &value,
                  PacketType system_packet_type,
                  DirType dir_type,
                  const std::string &msid);
  int LoadChunk(const std::string &hex_chunk_name, std::string *data);
  int LoadPacket(const std::string &hex_packet_name, std::string *result);
  int DeletePacket(const std::string &hex_key,
                   const std::string &signature,
                   const std::string &public_key,
                   const std::string &signed_public_key,
                   const ValueType &type,
                   base::callback_func_type cb);

  // Buffer packet
  virtual int CreateBP(const std::string &bufferpacketname,
                       const std::string &ser_packet);
  virtual int LoadBPMessages(const std::string &bufferpacketname,
                             std::list<std::string> *messages);
  virtual int ModifyBPInfo(const std::string &bufferpacketname,
                           const std::string &ser_gp);
  virtual int AddBPMessage(const std::string &bufferpacketname,
                           const std::string &ser_gp);

  // Vault
  void PollVaultInfo(base::callback_func_type cb);
  void VaultContactInfo(base::callback_func_type cb);
  void OwnLocalVault(const std::string &priv_key, const std::string &pub_key,
      const std::string &signed_pub_key, const boost::uint32_t &port,
      const std::string &chunkstore_dir, const boost::uint64_t &space,
      boost::function<void(const OwnVaultResult&, const std::string&)> cb);
  void LocalVaultStatus(boost::function<void(const VaultStatus&)> cb);
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
  friend void StoreChunkTask::run();
  friend void StorePacketToKadTask::run();
  friend void StorePacketToVaultsTask::run();
  friend size_t testpdvault::CheckStoredCopies(
      std::map<std::string, std::string> chunks,
      const int &timeout,
      boost::shared_ptr<MaidsafeStoreManager> sm);

 private:
  MaidsafeStoreManager &operator=(const MaidsafeStoreManager&);
  MaidsafeStoreManager(const MaidsafeStoreManager&);
  FRIEND_TEST(MaidStoreManagerTest, BEH_MAID_MSM_PreSendAnalysis);
  FRIEND_TEST(MaidStoreManagerTest, BEH_MAID_MSM_GetStoreRequests);
  FRIEND_TEST(MaidStoreManagerTest, FUNC_MAID_MSM_StoreIOUs);
  FRIEND_TEST(MaidStoreManagerTest, BEH_MAID_MSM_SendChunk);
  // Replace real ClientRpcs with mock object for testing
  void SetMockRpcs(boost::shared_ptr<ClientRpcs> mock_rpcs) {
    client_rpcs_ = mock_rpcs;
    mock_rpcs_ = true;
  }
  int MutablePacket(PacketType system_packet_type, bool *mutable_packet);
  void SimpleResult_Callback(const std::string &result,
                             base::callback_func_type cb);
  void DeleteChunk_Callback(const std::string &result,
                            base::callback_func_type cb);
  void AddStorePacketTask(const StoreData &store_data,
                          bool is_mutable,
                          int *return_value,
                          GenericConditionData *generic_cond_data);
  virtual void AddStoreChunkTask(const StoreData &store_data,
                                 IfExists if_exists);
  // Assess and select a store method for an individual chunk.
  virtual void PreSendAnalysis(const StoreData &store_data,
                               IfExists if_exists,
                               int *return_value);
  // Store copies of an individual chunk onto the network.
  virtual int SendChunk(
      const StoreData &store_data,
      boost::shared_ptr<boost::condition_variable> cond_variable,
      int copies);
  // Set up the requests needed to perform the store RPCs.
  int GetStoreRequests(const StoreData &store_data,
                       const std::string &recipient_id,
                       StorePrepRequest *store_prep_request,
                       StoreRequest *store_request,
                       IOUDoneRequest *iou_done_request);
  // Set up the request needed to perform the store packet RPCs.  If values
  // vector is not empty, we are sending an entire set of values for a
  // key (e.g. in case of failed existing holder), so append == false and we
  // disregard the single store_data.value_.  Otherwise we use store_data.value_
  // and store_data.append_.
  int GetStorePacketRequest(const StoreData &store_data,
                            const std::string &recipient_id,
                            const std::vector<std::string> &values,
                            StorePacketRequest *store_packet_request);
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
  // Send the "preparation to store" message and wait until called back.
  virtual int SendPrep(
      const kad::Contact &peer,
      bool local,
      boost::shared_ptr<boost::condition_variable> cond_variable,
      StorePrepRequest *store_prep_request,
      StorePrepResponse *store_prep_response);
  void SendPrepCallback(GenericConditionData *send_prep_cond_data);
  // Send the actual data content to the peer.
  virtual int SendContent(
      const kad::Contact &peer,
      bool local,
      boost::shared_ptr<boost::condition_variable> cond_variable,
      StoreRequest *store_request);
  void SendContentCallback(GenericConditionData *send_cond_data);
  // Pass the IOU for the peer vault to the k chunk reference holders.
  virtual int StoreIOUs(const StoreData &store_data,
                        const boost::uint64_t &chunk_size,
                        const StorePrepResponse &store_prep_response);
  // Blocking call to Kademlia Find Nodes.
  virtual int FindKNodes(const std::string &kad_key,
                         std::vector<kad::Contact> *contacts);
  // Blocking call to Kademlia Find Value.  If the maidsafe value is cached,
  // this may yield serialised contact details for a cache copy holder.
  // Otherwise it should yield the reference holders.  It also yields the
  // details of the last kad node to not return the value during the lookup.
  // If check_local is true, it also checks local chunkstore first.  The values
  // (ie chunk_holders_ids) are loaded in reverse order.
  virtual int FindValue(const std::string &kad_key,
                        bool check_local,
                        kad::ContactInfo *cache_holder,
                        std::vector<std::string> *chunk_holders_ids,
                        std::string *needs_cache_copy_id);
  // Populates a vector of chunk holders.  Those that are contactable have
  // non-empty contact details and those that have the chunk have their variable
  // check_chunk_response_.result() == kAck.
  void FindAvailableChunkHolders(
      const std::string &chunk_name,
      const std::vector<std::string> &chunk_holders_ids,
      GenericConditionData *cond_data,
      std::vector< boost::shared_ptr<ChunkHolder> > *chunk_holders,
      int *available_chunk_holder_index);
  // Populates the contact details of a peer vault (with ID chunk_holder_id) and
  // pushes them into the list of contacts provided.  If the RPC fails, the
  // chunk holder's status_ is set to kFailedHolder.  Having done this,
  // notify is called on the conditional variable.
  void GetChunkHolderContactCallback(
      const std::string &chunk_holder_id,
      const std::string &result,
      std::vector< boost::shared_ptr<ChunkHolder> > *chunk_holders,
      GenericConditionData *cond_data);
  // This populates the chunk holder's check_chunk_response_ variable (i.e.
  // confirms whether the peer has the chunk or not).  If the RPC fails, the
  // chunk holder's status_ is set to kFailedHolder.  If not, the chunk holder's
  // index is pushed onto confirmed_chunk_holder_index.  Having done this,
  // notify is called on find_conditional_.
  void HasChunkCallback(boost::shared_ptr<ChunkHolder> chunk_holder,
                        int *available_chunk_holder_index);
  // Given a vector of vault ids, this gets the contact info for each and if
  // load_data is true, attempts to load the data once the first contact info
  // is received.  If public_key and signed_public_key are not empty, then it
  // is assumed we are loading a buffer packet (the bool load_data has no effect
  // in this case) and the GetMessages RPC is used.
  virtual int FindAndLoadChunk(
      const std::string &chunk_name,
      const std::vector<std::string> &chunk_holders_ids,
      bool load_data,
      const std::string &public_key,
      const std::string &signed_public_key,
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
  // Passes the IOU to an individual reference holder.
  virtual int SendIouToRefHolder(
      const kad::Contact &ref_holder,
      StoreIOURequest store_iou_request,
      boost::mutex *store_iou_mutex,
      boost::shared_ptr<StoreIouResultHolder> store_iou_result_holder);
  void SendIouToRefHolderCallback(bool *store_iou_response_returned,
                                  boost::mutex *store_iou_mutex);
  int HandleStoreIOUResponse(
      const boost::shared_ptr<StoreIouResultHolder> store_iou_result_holder,
      std::set<std::string> *ref_holder_ids);
  // Notifies a peer that this vault has passed the IOUs to the appropriate
  // reference holders.
  virtual int SendIOUDone(
      const kad::Contact &peer,
      bool local,
      boost::shared_ptr<boost::condition_variable> cond_variable,
      IOUDoneRequest *iou_done_request);
  void IOUDoneCallback(GenericConditionData *iou_done_cond_data);
  // Adds the packet to the priority store queue for uploading as a maidsafe
  // (i.e. mutable) packet.  If the packet already exists on the net, the
  // value is appended or overwritten depending on the boolean "append".
  // Subsequent loading of the key, values returns the values in the
  // chronological order of storing.  The function blocks until the entire store
  // operation has completed.
  int StorePacketToVaults(const std::string &hex_packet_name,
                          const std::string &value,
                          PacketType system_packet_type,
                          DirType dir_type,
                          const std::string &msid,
                          bool append);
  // Adds the packet to the priority store queue for uploading as a Kademlia
  // key, value.  If the packet already exists on the net, the value is added
  // to the existing one(s).  Subsequent loading of the key, values does not
  // necessarily return the values in the chronological order of storing.  The
  // function blocks until the entire store operation has completed.
  int StorePacketToKad(const std::string &hex_packet_name,
                       const std::string &value,
                       PacketType system_packet_type,
                       DirType dir_type,
                       const std::string &msid);
  // Store an individual packet to maidsafe vaults.
  int SendPacketToVaults(
      const StoreData &store_data,
      boost::shared_ptr<boost::condition_variable> cond_variable);
  void FindPacketHolders(
      const std::vector<std::string> &packet_holders_ids,
      GenericConditionData *cond_data,
      std::vector< boost::shared_ptr<ChunkHolder> > *packet_holders);
  void StorePacketCallback(GenericConditionData *store_cond_data,
                           int *returned_rpc_count);
  int AssessPacketStoreResults(
      std::vector< boost::shared_ptr<ChunkHolder> > *packet_holders,
      std::vector< boost::shared_ptr<ChunkHolder> > *failed_packet_holders,
      std::string *common_checksum);
  // Send the actual packet content to the peer.
  int SendPacketContent(
      const kad::Contact &peer,
      bool local,
      boost::shared_ptr<boost::condition_variable> cond_variable,
      StorePacketRequest *store_packet_request);
  // Store an individual packet to the network as a kademlia value.
  virtual void SendPacketToKad(const StoreData &store_data,
                               int *return_value,
                               GenericConditionData *generic_cond_data);
  // Updates all available copies of a chunk on the network.  The shared pointer
  // to the RPC controller is passed to UpdateChunkCallback purely to avoid a
  // premature destruct being called on the controller.
  virtual int UpdateChunkCopies(
      const StoreData &store_data,
      const std::vector<std::string> &chunk_holders_ids);
  void UpdateChunk(const boost::shared_ptr<ChunkHolder> chunk_holder,
                   const StoreData &store_data,
                   UpdateResponse *update_resonse,
                   boost::condition_variable *update_conditional);
  void UpdateChunkCallback(boost::condition_variable *cond,
                           boost::shared_ptr<rpcprotocol::Controller>);
  int LoadPacketFromVaults(const std::string &hex_packet_name,
                           const std::vector<std::string> &holder_ids,
                           std::string *result);
  // If ret_value pointer is not NULL, sets it to rc and calls
  // notify_all() on store_packet_conditional_ variable.
  virtual void SetStoreReturnValue(ReturnCode rc, int *ret_value);
  void PollVaultInfoCallback(const VaultStatusResponse *response,
                             base::callback_func_type cb);
  void CreateBPCallback(GenericConditionData *send_prep_cond_data);

//  void VaultContactInfoCallback(const std::string &ser_result,
//                                base::callback_func_type cb);
  boost::shared_ptr<rpcprotocol::ChannelManager> channel_manager_;
  boost::shared_ptr<kad::KNode> knode_;
  boost::shared_ptr<ClientRpcs> client_rpcs_;
  PDClient *pdclient_;
  SessionSingleton *ss_;
  boost::shared_ptr<ChunkStore> client_chunkstore_;
  QThreadPool chunk_thread_pool_, packet_thread_pool_;
  const boost::uint16_t kKadStoreThreshold_;
  boost::mutex store_packet_mutex_;
  boost::condition_variable store_packet_conditional_;
  boost::condition_variable get_chunk_conditional_;
  bool mock_rpcs_;
};

}  // namespace maidsafe

#endif  // MAIDSAFE_CLIENT_MAIDSTOREMANAGER_H_
