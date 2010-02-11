/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Description:  Struct declarations for use in PDvault and MSM
* Created:      2010-02-08
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

#ifndef MAIDSAFE_OPDATA_H_
#define MAIDSAFE_OPDATA_H_

#include <boost/thread/condition_variable.hpp>
#include <boost/thread/locks.hpp>
#include <maidsafe/maidsafe-dht_config.h>

#include <set>
#include <string>
#include <vector>

#include "maidsafe/chunkstore.h"
#include "maidsafe/client/storemanager.h"

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

struct StoreData {
  // Default constructor
  StoreData() : data_name(),
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
  StoreData(const std::string &chunk_name,
            const boost::uint64_t &chunk_size,
            ChunkType ch_type,
            DirType directory_type,
            const std::string &ms_id,
            const std::string &key,
            const std::string &pub_key,
            const std::string &pub_key_signature,
            const std::string &priv_key)
                : data_name(chunk_name),
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
  StoreData(const std::string &packet_name,
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
                : data_name(packet_name),
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
  std::string data_name, value;
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
  DeletePacketData(const std::string &name,
                   const std::vector<std::string> &packet_values,
                   PacketType sys_packet_type,
                   DirType directory_type,
                   const std::string &ms_id,
                   const std::string &key,
                   const std::string &pub_key,
                   const std::string &pub_key_signature,
                   const std::string &priv_key,
                   VoidFuncOneInt cb)
                       : packet_name(name),
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
                       : packet_name(store_data->data_name),
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
  std::string packet_name;
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

// This is used to hold the data required to perform a Kad lookup to get a group
// of account holders, send each an AccountStatusRequest and assess the
// responses.
struct AccountStatusData {
  struct AccountStatusDataHolder {
    explicit AccountStatusDataHolder(const std::string &id)
        : node_id(id), response(), controller(new rpcprotocol::Controller) {}
    std::string node_id;
    AccountStatusResponse response;
    boost::shared_ptr<rpcprotocol::Controller> controller;
  };
  explicit AccountStatusData()
      : mutex(),
        condition(),
        contacts(),
        data_holders(),
        returned_count(0) {}
  boost::mutex mutex;
  boost::condition_variable condition;
  std::vector<kad::Contact> contacts;
  std::vector<AccountStatusDataHolder> data_holders;
  boost::uint16_t returned_count;
};

// This is used to hold the data required to perform a Kad lookup to get a group
// of account holders, send each an AmendAccountRequest and assess the
// responses.
struct AmendAccountData {
  struct AmendAccountDataHolder {
    explicit AmendAccountDataHolder(const std::string &id)
        : node_id(id), response(), controller(new rpcprotocol::Controller) {}
    std::string node_id;
    AmendAccountResponse response;
    boost::shared_ptr<rpcprotocol::Controller> controller;
  };
  explicit AmendAccountData()
      : mutex(),
        condition(),
        contacts(),
        data_holders(),
        returned_count(0),
        success_count(0) {}
  boost::mutex mutex;
  boost::condition_variable condition;
  std::vector<kad::Contact> contacts;
  std::vector<AmendAccountDataHolder> data_holders;
  boost::uint16_t returned_count, success_count;
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

}  // namespace maidsafe

#endif  // MAIDSAFE_OPDATA_H_
