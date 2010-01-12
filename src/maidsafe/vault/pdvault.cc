/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Class containing vault logic
* Version:      1.0
* Created:      2009-02-21-23.55.54
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

#include "maidsafe/vault/pdvault.h"

#include <boost/filesystem.hpp>
#include <boost/thread/thread.hpp>
#include <google/protobuf/descriptor.h>
#include <maidsafe/general_messages.pb.h>
#include <maidsafe/kademlia_service_messages.pb.h>
#include <maidsafe/maidsafe-dht.h>


#include "maidsafe/vault/vaultchunkstore.h"
#include "protobuf/maidsafe_messages.pb.h"

namespace fs = boost::filesystem;

namespace maidsafe_vault {

void pdv_dummy_callback(const std::string&) {}

AddToRefPacketTask::AddToRefPacketTask(const IouReadyTuple &iou_ready_details,
                                       PDVault *pdvault)
    : iou_ready_details_(iou_ready_details),
      pdvault_(pdvault) {}

void AddToRefPacketTask::run() {
  if (pdvault_->vault_status() == kVaultStarted)
    pdvault_->AddToRefPacket(iou_ready_details_);
}

PDVault::PDVault(const std::string &pmid_public,
                 const std::string &pmid_private,
                 const std::string &signed_pmid_public,
                 const std::string &chunkstore_dir,
                 const boost::uint16_t &port,
                 bool port_forwarded,
                 bool use_upnp,
                 const std::string &kad_config_file,
                 const boost::uint64_t &available_space,
                 const boost::uint64_t &used_space)
    : port_(port),
      transport_(),
      channel_manager_(&transport_),
      knode_(&channel_manager_, &transport_, kad::VAULT, pmid_private,
          pmid_public, port_forwarded, use_upnp),
      vault_rpcs_(&transport_, &channel_manager_),
      vault_chunkstore_(chunkstore_dir, available_space, used_space),
      vault_service_(),
      kad_joined_(false),
      vault_status_(kVaultStopped),
      vault_status_mutex_(),
      kad_join_cond_(),
      pmid_public_(pmid_public),
      pmid_private_(pmid_private),
      signed_pmid_public_(signed_pmid_public),
      pmid_(""),
      non_hex_pmid_(""),
      signed_non_hex_pmid_(""),
      co_(),
      svc_channel_(),
      kad_config_file_(kad_config_file),
      poh_(),
      thread_pool_(),
      pending_ious_thread_(),
      prune_pending_ops_thread_(),
      kKadStoreThreshold_(kad::K * kad::kMinSuccessfulPecentageStore) {
  vault_chunkstore_.Init();
  co_.set_symm_algorithm(crypto::AES_256);
  co_.set_hash_algorithm(crypto::SHA_512);
  pmid_ = co_.Hash(pmid_public_ + signed_pmid_public_, "",
                   crypto::STRING_STRING, true);
  non_hex_pmid_ = base::DecodeFromHex(pmid_);
  signed_non_hex_pmid_ = co_.AsymSign(non_hex_pmid_, "", pmid_private_,
                                      crypto::STRING_STRING);
  knode_.SetAlternativeStore(&vault_chunkstore_);
  vault_rpcs_.SetOwnId(non_hex_pmid_);
  thread_pool_.setMaxThreadCount(5);
  poh_.SetPmid(non_hex_pmid_);
}

PDVault::~PDVault() {
//  Stop(true);
}

void PDVault::Start(bool first_node) {
  if (vault_status() == kVaultStarted)
    return;
  bool success = channel_manager_.RegisterNotifiersToTransport();
  if (success)
    success = transport_.RegisterOnServerDown(boost::bind(
        &kad::KNode::HandleDeadRendezvousServer, &knode_, _1));
  if (success)
    success = (transport_.Start(port_) == 0);
  if (success)
    success = (channel_manager_.Start() == 0);
  if (success) {
    RegisterMaidService();
    boost::mutex kad_join_mutex;
    if (first_node) {
      boost::asio::ip::address local_ip;
      base::get_local_address(&local_ip);
      knode_.Join(pmid_, kad_config_file_, local_ip.to_string(),
          transport_.listening_port(),
          boost::bind(&PDVault::KadJoinedCallback, this, _1, &kad_join_mutex));
    } else {
      knode_.Join(pmid_, kad_config_file_,
          boost::bind(&PDVault::KadJoinedCallback, this, _1, &kad_join_mutex));
    }
    // Hash check all current chunks in chunkstore
    std::list<std::string> failed_keys;
    if (0 != vault_chunkstore_.HashCheckAllChunks(true, &failed_keys)) {
      return;
    }
    // Block until we've joined the Kademlia network.
    boost::mutex::scoped_lock lock(kad_join_mutex);
    while (!kad_joined_) {
      kad_join_cond_.wait(lock);
    }
    // Set port, so that if vault is restarted before it is destroyed, it
    // re-uses port (unless this port has become unavailable).
    port_ = knode_.host_port();
    if (kad_joined_)
      SetVaultStatus(kVaultStarted);
    // Start repeating pruning worker thread
    prune_pending_ops_thread_ =
        boost::thread(&PDVault::PrunePendingOperations, this);
    // Start repeating pending IOU worker thread
    pending_ious_thread_ = boost::thread(&PDVault::CheckPendingIOUs, this);
  }
}

void PDVault::KadJoinedCallback(const std::string &result,
                                boost::mutex *kad_joined_mutex) {
  boost::mutex::scoped_lock lock(*kad_joined_mutex);
  base::GeneralResponse result_;
  if (!result_.ParseFromString(result)) {
    kad_joined_ = false;
  } else if (result_.result() != kad::kRpcResultSuccess) {
    UnRegisterMaidService();
    kad_joined_ = false;
  } else {
    kad_joined_ = true;
  }
  kad_join_cond_.notify_one();
}

int PDVault::Stop() {
  if (vault_status() == kVaultStopped) {
#ifdef DEBUG
    printf("In PDVault::Stop(), already stopped.\n");
#endif
    return 0;
  }
  if (vault_status() == kVaultStopping) {
#ifdef DEBUG
    printf("In PDVault::Stop(), already stopping.\n");
#endif
    return -2;
  }
  SetVaultStatus(kVaultStopping);
//  thread_pool_.waitForDone();
  prune_pending_ops_thread_.join();
  pending_ious_thread_.join();
  UnRegisterMaidService();
  knode_.Leave();
  kad_joined_ = knode_.is_joined();
  if (kad_joined_)
    SetVaultStatus(kVaultStarted);
  else
    SetVaultStatus(kVaultStopped);
  transport_.Stop();
  channel_manager_.Stop();
  return 0;
}

void PDVault::CleanUp() {
  transport::CleanUp();
}

void PDVault::RegisterMaidService() {
  vault_service_ = boost::shared_ptr<VaultService>(
    new VaultService(pmid_public_,
                     pmid_private_,
                     signed_pmid_public_,
                     &vault_chunkstore_,
                     &knode_,
                     &poh_));
  svc_channel_ = boost::shared_ptr<rpcprotocol::Channel>(
      new rpcprotocol::Channel(&channel_manager_, &transport_));
  svc_channel_->SetService(vault_service_.get());
  channel_manager_.RegisterChannel(
    vault_service_->GetDescriptor()->name(), svc_channel_.get());
}

void PDVault::UnRegisterMaidService() {
  channel_manager_.UnRegisterChannel(
    vault_service_->GetDescriptor()->name());
  svc_channel_.reset();
  vault_service_.reset();
}

std::string PDVault::hex_node_id() const {
  return base::EncodeToHex(knode_.node_id());
}

VaultStatus PDVault::vault_status() {
  boost::mutex::scoped_lock lock(vault_status_mutex_);
  return vault_status_;
}

void PDVault::SetVaultStatus(const VaultStatus &vault_status) {
  boost::mutex::scoped_lock lock(vault_status_mutex_);
  vault_status_ = vault_status;
}

void PDVault::PrunePendingOperations() {
  while (vault_status() == kVaultStarted) {
    poh_.PrunePendingOps();
    boost::this_thread::sleep(boost::posix_time::seconds(1));
  }
}

void PDVault::CheckPendingIOUs() {
  while (vault_status() == kVaultStarted) {
    std::list<IouReadyTuple> iou_readys;
    if (poh_.GetAllIouReadys(&iou_readys) == 0) {
      for (boost::uint16_t i = 0; i < iou_readys.size(); ++i) {
        IouReadyTuple iou_ready_details = iou_readys.front();
        // thread_pool_ handles destruction of task.
        AddToRefPacketTask *task = new AddToRefPacketTask(iou_ready_details,
            this);
        thread_pool_.start(task);
        poh_.AdvanceStatus("", iou_ready_details.get<1>(), 0, "", "", "",
                           IOU_PROCESSING);
        iou_readys.pop_front();
      }
    }
    boost::this_thread::sleep(boost::posix_time::seconds(1));
  }
}

std::string PDVault::GetSignedRequest(const std::string &non_hex_name,
                                      const std::string &recipient_id) {
  return co_.AsymSign(co_.Hash(signed_pmid_public_ + non_hex_name +
      recipient_id, "", crypto::STRING_STRING, false), "", pmid_private_,
      crypto::STRING_STRING);
}

void PDVault::AddToRefPacket(const IouReadyTuple &iou_ready_details) {
// printf("1. Vault %s - contacts size: %u\n", HexSubstr(non_hex_pmid_).c_str(),
//         (*base::PDRoutingTable::getInstance())[base::itos(port_)]->size());
  if (vault_status() != kVaultStarted) {
#ifdef DEBUG
    printf("Vault offline %s\n", pmid_.substr(0, 10).c_str());
#endif
    return;
  }

  // Find the chunk reference holders
  std::vector<kad::Contact> ref_holders;
  if ((FindKNodes(iou_ready_details.get<1>(), &ref_holders) != 0) ||
      (ref_holders.size() < kKadStoreThreshold_)) {
    poh_.EraseOperation(IOU_READY, iou_ready_details.get<0>(),
                        iou_ready_details.get<1>());
    return;
  }
#ifdef DEBUG
// printf("2. Vault %s - contacts size: %u\n", HexSubstr(non_hex_pmid_).c_str(),
//         (*base::PDRoutingTable::getInstance())[base::itos(port_)]->size());
//  for (boost::uint16_t h = 0; h < ref_holders.size(); ++h) {
//    printf("Before - Vault %s,  chunk %s,  ref holder %i: %s\n",
//           HexSubstr(non_hex_pmid_).c_str(),
//           HexSubstr(iou_ready_details.get<1>()).c_str(), h,
//           HexSubstr(ref_holders.at(h).node_id()).c_str());
//  }
#endif
  for (std::vector<kad::Contact>::iterator it = ref_holders.begin();
       it != ref_holders.end(); ++it) {
    if ((*it).node_id() == knode_.node_id()) {
#ifdef DEBUG
//      printf("Vault %s listed as a ref holder to itself for chunk %s\n",
//             HexSubstr((*it).node_id()).c_str(),
//             HexSubstr(iou_ready_details.get<1>()).c_str());
#endif
      ref_holders.erase(it);
      break;
    }
  }
#ifdef DEBUG
//  for (boost::uint16_t h = 0; h < ref_holders.size(); ++h) {
//    printf("After - Vault %s,  chunk %s,  ref holder %i: %s\n",
//           HexSubstr(non_hex_pmid_).c_str(),
//           HexSubstr(iou_ready_details.get<1>()).c_str(), h,
//           HexSubstr(ref_holders.at(h).node_id()).c_str());
//  }
#endif
  bool got_valid_iou(false);
  int successful_count(0);
  int called_back_count(0);
  std::vector<StoreRefResultHolder> results;
  for (boost::uint16_t i = 0; i < ref_holders.size(); ++i) {
    StoreRefResultHolder store_ref_result_holder;
    results.push_back(store_ref_result_holder);
  }
  boost::mutex store_ref_mutex;
  for (boost::uint16_t i = 0; i < ref_holders.size(); ++i) {
    SendToRefPacket(ref_holders.at(i), iou_ready_details, &store_ref_mutex,
                    &results.at(i));
  }
// TODO(Fraser#5#): 2009-08-15 - This loop logic needs tidied.
  int timeout = 30000;
  int time_count = 0;
  while (called_back_count < kad::K && time_count < timeout &&
         successful_count < kKadStoreThreshold_) {
    for (boost::uint16_t i = 0; i < results.size(); ++i) {
      boost::mutex::scoped_lock loch(store_ref_mutex);
      if (results.at(i).store_ref_response_returned_) {
        ++called_back_count;
        int n = HandleStoreRefResponse(iou_ready_details, results.at(i),
                                       &got_valid_iou);
        if (n == 0)
          ++successful_count;
        results.at(i).store_ref_response_returned_ = false;
        break;
      }
    }
    time_count += 10;
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  }
  for (boost::uint16_t j = 0; j < results.size(); ++j) {
    channel_manager_.CancelPendingRequest(
        results.at(j).controller_->req_id());
  }
  if (successful_count < kKadStoreThreshold_ || !got_valid_iou) {
#ifdef DEBUG
  printf("In PDVault::AddToRefPacket (%i) - failed to add ourself (%s) "
         "as ref holder for key %s\n", host_port(),
         HexSubstr(non_hex_pmid_).c_str(),
         HexSubstr(iou_ready_details.get<1>()).c_str());
#endif
    return;  // We've not received enough successful responses or got valid IOU
  }
#ifdef DEBUG
//  printf("In PDVault::AddToRefPacket (%i) - successfully added ourself (%s) "
//         "as ref holder for key %s\n", host_port(),
//         HexSubstr(non_hex_pmid_).c_str(),
//         HexSubstr(iou_ready_details.get<1>()).c_str());
#endif
  poh_.AdvanceStatus("", iou_ready_details.get<1>(), 0, "", "", "",
                     IOU_RANK_RETRIEVED);
// TODO(Fraser#5#): 2009-08-12 - Increment our rank and clear pending op.
}

int PDVault::HandleStoreRefResponse(
    const IouReadyTuple &iou_ready_details,
    const StoreRefResultHolder &store_ref_result_holder,
    bool *got_valid_iou) {
  if (vault_status() != kVaultStarted) {
#ifdef DEBUG
    printf("Vault offline %s\n", pmid_.substr(0, 10).c_str());
#endif
    return kVaultOffline;
  }

  maidsafe::StoreReferenceResponse srr =
      store_ref_result_holder.store_ref_response_;
  if (srr.result() == kNack) {
#ifdef DEBUG
    printf("Response from rpc id %d came back failed (%d).\n",
           store_ref_result_holder.controller_->req_id(), knode_.host_port());
#endif
    return -1;
  }

  if (srr.pmid_id() != co_.Hash(srr.public_key() + srr.signed_public_key(),
      "", crypto::STRING_STRING, false)) {
#ifdef DEBUG
    printf("Someone on rpc id %d is trying to fake identity (%d).\n",
           store_ref_result_holder.controller_->req_id(), knode_.host_port());
#endif
    return -1;
  }

  if (!*got_valid_iou) {
    if (!co_.AsymCheckSig(srr.rank_authority(), srr.signed_rank_authority(),
        srr.public_key(), crypto::STRING_STRING)) {
#ifdef DEBUG
      printf("Rank authrty from rpc id %d didn't pass signature check (%d).\n",
             store_ref_result_holder.controller_->req_id(), knode_.host_port());
#endif
      return -1;
    }

    maidsafe::RankAuthority ra;
    if (!ra.ParseFromString(srr.rank_authority())) {
#ifdef DEBUG
      printf("Rank authority from rpc id %d didn't parse (%d).\n",
             store_ref_result_holder.controller_->req_id(), knode_.host_port());
#endif
      return -1;
    }

    if (ra.data_size() != iou_ready_details.get<2>()) {
#ifdef DEBUG
      printf("Rank authority from rpc id %d has invalid size (%d).\n",
             store_ref_result_holder.controller_->req_id(), knode_.host_port());
#endif
      return -1;
    }

    if (ra.pmid() != non_hex_pmid_) {
#ifdef DEBUG
      printf("Rank authority from rpc id %d is not for this vault (%d).\n",
             store_ref_result_holder.controller_->req_id(), knode_.host_port());
#endif
      return -1;
    }

    maidsafe::IOU iou;
    if (!iou.ParseFromString(srr.iou())) {
#ifdef DEBUG
      printf("IOU from rpc id %d didn't parse (%d).\n",
             store_ref_result_holder.controller_->req_id(), knode_.host_port());
#endif
      return -1;
    }

    if (!co_.AsymCheckSig(iou.signed_iou_authority(), iou.signature(),
        iou_ready_details.get<3>(), crypto::STRING_STRING)) {
#ifdef DEBUG
      printf("IOU from rpc id %d didn't pass client signature check (%d).\n",
             store_ref_result_holder.controller_->req_id(), knode_.host_port());
#endif
      return -1;
    }

    if (!co_.AsymCheckSig(iou.serialised_iou_authority(),
        iou.signed_iou_authority(), pmid_public_, crypto::STRING_STRING)) {
#ifdef DEBUG
      printf("IOUAuthority from rpc id %d didn't pass vault signature check "
             "(%d).\n", store_ref_result_holder.controller_->req_id(),
             knode_.host_port());
#endif
      return -1;
    }

    maidsafe::IOUAuthority iou_authority;
    if (!iou_authority.ParseFromString(iou.serialised_iou_authority())) {
#ifdef DEBUG
      printf("IOUAuthority from rpc id %d didn't parse (%d).\n",
             store_ref_result_holder.controller_->req_id(), knode_.host_port());
#endif
      return -1;
    }

    if (iou_authority.data_size() != iou_ready_details.get<2>()) {
#ifdef DEBUG
      printf("IOUAuthority from rpc id %d has invalid size (%d).\n",
             store_ref_result_holder.controller_->req_id(), knode_.host_port());
#endif
      return -1;
    }

    if (iou_authority.pmid() != non_hex_pmid_) {
#ifdef DEBUG
      printf("IOUAuthority from rpc id %d is not from this vault (%d).\n",
             store_ref_result_holder.controller_->req_id(), knode_.host_port());
#endif
      return -1;
    }
    *got_valid_iou = true;
  }
  return 0;
}

int PDVault::FindKNodes(const std::string &kad_key,
                        std::vector<kad::Contact> *contacts) {
  if (vault_status() != kVaultStarted) {
#ifdef DEBUG
    printf("Vault offline %s\n", pmid_.substr(0, 10).c_str());
#endif
    return kVaultOffline;
  }

  KadCallback kad_callback;
  knode_.FindCloseNodes(kad_key, boost::bind(&KadCallback::SetResponse,
      &kad_callback, _1));
  while (true) {
    if (kad_callback.response() != "")
      break;
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  }
  if (kad_callback.response() == "") {
#ifdef DEBUG
    printf("In PDVault::FindKNodes, fail - timeout.\n");
#endif
    return -1;
  }
  kad::FindResponse find_response;
  if (!find_response.ParseFromString(kad_callback.response())) {
#ifdef DEBUG
    printf("In PDVault::FindKNodes, can't parse result.\n");
#endif
    return -2;
  }
  if (find_response.result() != kad::kRpcResultSuccess) {
#ifdef DEBUG
    printf("In PDVault::FindKNodes, Kademlia operation failed.\n");
#endif
    return -3;
  }
  for (int i = 0; i < find_response.closest_nodes_size(); ++i) {
    kad::Contact contact;
    contact.ParseFromString(find_response.closest_nodes(i));
    contacts->push_back(contact);
  }
  // Insert our own contact details if we are within the k closest.
  kad::Contact our_details(knode_.contact_info());
  kad::InsertKadContact(kad_key, our_details, contacts);
  contacts->pop_back();
#ifdef DEBUG
//  printf("In PDVault::FindKNodes, succeeded.\n");
#endif
  return 0;
}

int PDVault::SendToRefPacket(
    const kad::Contact &ref_holder,
    const IouReadyTuple &iou_ready_details,
    boost::mutex *store_ref_mutex,
    StoreRefResultHolder *store_ref_result_holder) {
  if (vault_status() != kVaultStarted) {
#ifdef DEBUG
    printf("Vault offline %s\n", pmid_.substr(0, 10).c_str());
#endif
    return kVaultOffline;
  }

  maidsafe::StoreReferenceRequest store_ref_request;
  std::string chunk_name = iou_ready_details.get<1>();
  std::string signed_request =  GetSignedRequest(chunk_name,
                                                 ref_holder.node_id());
  store_ref_request.set_chunkname(chunk_name);
  store_ref_request.set_pmid(non_hex_pmid_);
  store_ref_request.set_signed_pmid(signed_non_hex_pmid_);
  store_ref_request.set_public_key(pmid_public_);
  store_ref_request.set_signed_public_key(signed_pmid_public_);
  store_ref_request.set_signed_request(signed_request);
  bool local = (knode_.CheckContactLocalAddress(ref_holder.node_id(),
      ref_holder.local_ip(), ref_holder.local_port(), ref_holder.host_ip())
      == kad::LOCAL);
  google::protobuf::Closure* callback = google::protobuf::NewCallback(this,
      &PDVault::SendToRefPacketCallback,
      store_ref_result_holder, store_ref_mutex);
  vault_rpcs_.StoreChunkReference(ref_holder, local, &store_ref_request,
      &store_ref_result_holder->store_ref_response_,
      store_ref_result_holder->controller_.get(), callback);
  return 0;
}

void PDVault::SendToRefPacketCallback(
    StoreRefResultHolder *store_ref_result_holder,
    boost::mutex *store_ref_mutex) {
#ifdef DEBUG
//  printf("In PDVault::SendToRefPacketCallback.\n");
#endif
  if (vault_status() != kVaultStarted) {
#ifdef DEBUG
    printf("Vault offline %s\n", pmid_.substr(0, 10).c_str());
#endif
    return;
  }
  if (store_ref_mutex) {
    boost::mutex::scoped_lock loch(*store_ref_mutex);
    store_ref_result_holder->store_ref_response_returned_ = true;
  }
}






void PDVault::SyncVault(base::callback_func_type cb) {
  // Process of updating vault:
  // 1. Get the list of all chunk names
  // 2. Do validity check for each chunk with an arbitrary alive partner.
  // 3. If chunk content is stale, synchronize chunk content with the partner.
  // otherwise, do the next vadility check.
  if (vault_status() != kVaultStarted) {
#ifdef DEBUG
    printf("Vault offline %s\n", pmid_.substr(0, 10).c_str());
#endif
    return;
  }
  boost::shared_ptr<SyncVaultData> data(new struct SyncVaultData());
  vault_chunkstore_.GetAllChunks(&data->chunk_names);
  if (!data->chunk_names.empty()) {
    printf("Synchronising vault (One * represents one chunk):\n");
    data->num_chunks = data->chunk_names.size();
    data->cb = cb;
    int parallel_size;
    if (static_cast<int>(data->chunk_names.size()) > kad::kAlpha)
      parallel_size = kad::kAlpha;
    else
      parallel_size = static_cast<int>(data->chunk_names.size());
    for (int i = 0; i < parallel_size; ++i) {
      IterativeSyncVault(data);
    }
  } else {  // no chunks on this vault node
    maidsafe::UpdateResponse local_result;
    std::string local_result_str("");
    local_result.set_result(kAck);
    local_result.SerializeToString(&local_result_str);
    cb(local_result_str);
  }
}

void PDVault::IterativeSyncVault(boost::shared_ptr<SyncVaultData> data) {
  if (vault_status() != kVaultStarted) {
#ifdef DEBUG
    printf("Vault offline %s\n", pmid_.substr(0, 10).c_str());
#endif
    return;
  }
  if (data->is_callbacked) return;
  if (data->chunk_names.empty() && data->active_updating == 0) {
    // no more chunks need to be updated, job done!
    printf("\nVault synchronised.\n");
    maidsafe::UpdateResponse local_result;
    std::string local_result_str("");
    if (static_cast<float>(data->num_updated_chunks) >=
        kMinSuccessfulPecentageOfUpdating*(data->num_chunks))
      local_result.set_result(kAck);
    else
      local_result.set_result(kNack);
    local_result.SerializeToString(&local_result_str);
    data->is_callbacked = true;
    data->cb(local_result_str);
  } else if (!data->chunk_names.empty()) {
    printf("*");
    std::string chunk_name = data->chunk_names.front();
    data->chunk_names.pop_front();
    ++data->active_updating;
    // Look up the chunk references
    knode_.FindValue(chunk_name,
                     false,
                     boost::bind(&PDVault::SyncVault_FindAlivePartner,
                                 this,
                                 _1,
                                 data,
                                 chunk_name));
  }
}

void PDVault::SyncVault_FindAlivePartner(const std::string& result,
                                         boost::shared_ptr<SyncVaultData> data,
                                         std::string chunk_name) {
  if (vault_status() != kVaultStarted) {
#ifdef DEBUG
    printf("Vault offline %s\n", pmid_.substr(0, 10).c_str());
#endif
    return;
  }
  kad::FindResponse result_msg;
  if (!result_msg.ParseFromString(result) ||
      result_msg.result() == kad::kRpcResultFailure ||
      result_msg.values_size() == 0) {
    // no chunk references were found
    // TODO(Haiyang): shall we remove the chunk?!
    --data->active_updating;
    IterativeSyncVault(data);
    return;
  }
  // Get an arbitrary alive chunk holder by using simple ping operation
  boost::shared_ptr<GetAlivePartner>
      partner_data(new GetAlivePartner(
          static_cast<int>(result_msg.values_size()), chunk_name));
  partner_data->data = data;
  bool correct_info = false;
  for (int i = 0; i < result_msg.values_size(); ++i) {
    kad::SignedValue signed_value;
    if (signed_value.ParseFromString(result_msg.values(i))) {
      std::string contact_info = signed_value.value();
      kad::Contact remote;
      if (remote.ParseFromString(contact_info) &&
          remote.node_id() != knode_.node_id()) {
        correct_info = true;
        knode_.Ping(remote,
                    boost::bind(&PDVault::SyncVault_FindAlivePartner_Callback,
                                this,
                                _1,
                                partner_data,
                                remote));
      } else {
        --partner_data->number_partners;
      }
    } else {
      --partner_data->number_partners;
    }
  }
  if (!correct_info) {
    // TODO(Haiyang): shall we remove the chunk?!
    --data->active_updating;
    IterativeSyncVault(data);
  }
}

void PDVault::SyncVault_FindAlivePartner_Callback(
    const std::string& result,
    boost::shared_ptr<GetAlivePartner> partner_data,
    kad::Contact remote) {
  if (vault_status() != kVaultStarted) {
#ifdef DEBUG
    printf("Vault offline %s\n", pmid_.substr(0, 10).c_str());
#endif
    return;
  }
  if (partner_data->is_found) return;
  ++partner_data->contacted_partners;
  kad::PingResponse result_msg;
  if (!result_msg.ParseFromString(result) ||
      result_msg.result() == kad::kRpcResultFailure ||
      !result_msg.has_echo() ||
      result_msg.echo() != "pong") {
    if (partner_data->contacted_partners == partner_data->number_partners &&
        !partner_data->is_found) {
      // TODO(Haiyang): shall we remove the chunk?!
      --partner_data->data->active_updating;
      IterativeSyncVault(partner_data->data);
    }
  } else {
    // we found an alive partner, validate chunk with it
    partner_data->is_found = true;
    ValidityCheck(partner_data->chunk_name,
                  "",
                  remote,
                  0,
                  boost::bind(&PDVault::IterativeSyncVault_SyncChunk,
                              this,
                              _1,
                              partner_data->data,
                              partner_data->chunk_name,
                              remote));
  }
}

void PDVault::ValidityCheck(const std::string &chunk_name,
                            const std::string &random_data,
                            const kad::Contact &remote,
                            int attempt,
                            base::callback_func_type cb) {
  if (vault_status() != kVaultStarted) {
#ifdef DEBUG
    printf("Vault offline %s\n", pmid_.substr(0, 10).c_str());
#endif
    return;
  }
  if (attempt > kValidityCheckRetry) {
    maidsafe::GenericResponse local_result;
    std::string local_result_str("");
    local_result.set_result(kNack);
    local_result.SerializeToString(&local_result_str);
    cb(local_result_str);
    return;
  }
  std::string random_data_("");
  // TODO(Fraser#5#): 2009-03-18 - Make limits for data maidsafe constants
  if (random_data == "" ||
      random_data.size() < 512 ||
      random_data.size() > 1023)
    // generate random string of random length between 512 & 1023 bits inclusive
    random_data_ =
        base::RandomString((base::random_32bit_uinteger() % 512) + 512);
  else
    random_data_ = random_data;
  boost::shared_ptr<ValidityCheckArgs> validity_check_args(
      new ValidityCheckArgs(chunk_name, random_data_, remote, cb));
  boost::shared_ptr<maidsafe::ValidityCheckResponse>
      validity_check_response(new maidsafe::ValidityCheckResponse());
  google::protobuf::Closure* callback = google::protobuf::NewCallback(this,
      &PDVault::ValidityCheckCallback, validity_check_response,
      validity_check_args);
  kad::connect_to_node conn_type =
      knode_.CheckContactLocalAddress(
          validity_check_args->chunk_holder_.node_id(),
          validity_check_args->chunk_holder_.local_ip(),
          validity_check_args->chunk_holder_.local_port(),
          validity_check_args->chunk_holder_.host_ip());
  std::string ip = validity_check_args->chunk_holder_.host_ip();
  uint16_t port = static_cast<uint16_t>(
                      validity_check_args->chunk_holder_.host_port());
  if (conn_type == kad::LOCAL) {
    ip = validity_check_args->chunk_holder_.local_ip();
    port = validity_check_args->chunk_holder_.local_port();
    validity_check_args->retry_remote = true;
  }
  rpcprotocol::Controller *controller = new rpcprotocol::Controller;
  vault_rpcs_.ValidityCheck(validity_check_args->chunk_name_,
      validity_check_args->random_data_, ip, port,
      validity_check_args->chunk_holder_.rendezvous_ip(),
      validity_check_args->chunk_holder_.rendezvous_port(),
      validity_check_response.get(), controller, callback);
}

void PDVault::ValidityCheckCallback(
    boost::shared_ptr<maidsafe::ValidityCheckResponse> validity_check_response,
    boost::shared_ptr<ValidityCheckArgs> validity_check_args) {
  if (vault_status() != kVaultStarted) {
#ifdef DEBUG
    printf("Vault offline %s\n", pmid_.substr(0, 10).c_str());
#endif
    return;
  }
  // TODO(Fraser#5#): 2009-03-18 -Handle timeout: call ValdtyChck with ++attempt

  if (!validity_check_response->IsInitialized())
    return;
  if (!validity_check_response->has_pmid_id() &&
      validity_check_response->pmid_id() !=
          validity_check_args->chunk_holder_.node_id()) {
    if (validity_check_args->retry_remote) {
      validity_check_args->retry_remote = false;
      boost::shared_ptr<maidsafe::ValidityCheckResponse>
          validity_check_response(new maidsafe::ValidityCheckResponse());
      google::protobuf::Closure* callback = google::protobuf::NewCallback(this,
          &PDVault::ValidityCheckCallback, validity_check_response,
          validity_check_args);
      rpcprotocol::Controller *controller = new rpcprotocol::Controller;
      vault_rpcs_.ValidityCheck(validity_check_args->chunk_name_,
          validity_check_args->random_data_,
          validity_check_args->chunk_holder_.host_ip(),
          validity_check_args->chunk_holder_.host_port(),
          validity_check_args->chunk_holder_.rendezvous_ip(),
          validity_check_args->chunk_holder_.rendezvous_port(),
          validity_check_response.get(), controller, callback);
      return;
    }
  }
  if (validity_check_response->result() == kNack ||
      !validity_check_response->has_hash_content()) {
    // TODO(Fraser#5#): 2009-03-18 - We should probably self-check our chunk
    //                  (hash contents == name) then if OK try validity check
    //                  with another chunk holder.
    return;
  }
  std::string remote_hash_content_(validity_check_response->hash_content());
  std::string local_content_("");
  vault_chunkstore_.Load(validity_check_args->chunk_name_, &local_content_);
  std::string local_hash_content_(co_.Hash(local_content_ +
      validity_check_args->random_data_, "", crypto::STRING_STRING,
      true));
  if (local_hash_content_ != remote_hash_content_) {
    // TODO(Fraser#5#): 2009-03-18 - If check fails do we retry once, or try
    //                  with another chunk holder (if available) and/or alert
    //                  the current holder that he has a dirty chunk?
  }
}

void PDVault::IterativeSyncVault_SyncChunk(
    const std::string& result,
    boost::shared_ptr<SyncVaultData> data,
    std::string chunk_name,
    kad::Contact remote) {
  if (vault_status() != kVaultStarted) {
#ifdef DEBUG
    printf("Vault offline %s\n", pmid_.substr(0, 10).c_str());
#endif
    return;
  }
  maidsafe::ValidityCheckResponse result_msg;
  if (!result_msg.ParseFromString(result) ||
      result_msg.result() == kNack) {
    // chunk content is stale, synchronize the chunk
    boost::shared_ptr<SynchArgs>
        synch_args(new SynchArgs(chunk_name, remote, data));
    boost::shared_ptr<maidsafe::GetResponse>
        get_chunk_response(new maidsafe::GetResponse());
    google::protobuf::Closure* callback = google::protobuf::NewCallback(this,
        &PDVault::IterativeSyncVault_UpdateChunk, get_chunk_response,
        synch_args);
    kad::connect_to_node conn_type =
      knode_.CheckContactLocalAddress(synch_args->chunk_holder_.node_id(),
                                      synch_args->chunk_holder_.local_ip(),
                                      synch_args->chunk_holder_.local_port(),
                                      synch_args->chunk_holder_.host_ip());
    std::string ip = synch_args->chunk_holder_.host_ip();
    uint16_t port =
        static_cast<uint16_t>(synch_args->chunk_holder_.host_port());
    if (conn_type == kad::LOCAL) {
      ip = synch_args->chunk_holder_.local_ip();
      port = synch_args->chunk_holder_.local_port();
    }
    rpcprotocol::Controller *controller = new rpcprotocol::Controller;
    vault_rpcs_.Get(synch_args->chunk_name_, ip, port,
        synch_args->chunk_holder_.rendezvous_ip(),
        synch_args->chunk_holder_.rendezvous_port(), get_chunk_response.get(),
        controller, callback);
  } else {
    // chunk is consistent with the partner, move on to the next updating
    --data->active_updating;
    ++data->num_updated_chunks;
    IterativeSyncVault(data);
  }
}

void PDVault::IterativeSyncVault_UpdateChunk(
    boost::shared_ptr<maidsafe::GetResponse> get_chunk_response,
    boost::shared_ptr<SynchArgs> synch_args) {
  if (vault_status() != kVaultStarted) {
#ifdef DEBUG
    printf("Vault offline %s\n", pmid_.substr(0, 10).c_str());
#endif
    return;
  }
  maidsafe::GetResponse result_msg;
  if (!get_chunk_response->IsInitialized() ||
      get_chunk_response->result() == kNack) {
    // TODO(Haiyang): chunk deleted? shall we remove the chunk?!
  } else {
    vault_chunkstore_.UpdateChunk(synch_args->chunk_name_,
                            get_chunk_response->content());
  }
  --synch_args->data_->active_updating;
  ++synch_args->data_->num_updated_chunks;
  IterativeSyncVault(synch_args->data_);
}

void PDVault::RepublishChunkRef(base::callback_func_type cb) {
  boost::shared_ptr<RepublishChunkRefData>
    data(new struct RepublishChunkRefData());
  if (vault_status() != kVaultStarted) {
#ifdef DEBUG
    printf("Vault offline %s\n", pmid_.substr(0, 10).c_str());
#endif
    return;
  }
  vault_chunkstore_.GetAllChunks(&data->chunk_names);
  if (!data->chunk_names.empty()) {
    printf("Republishing chunk references (One * represents one chunk):\n");
    data->num_chunks = data->chunk_names.size();
    data->cb = cb;
    IterativePublishChunkRef(data);
  } else {  // no chunks on this vault node
    maidsafe::GenericResponse local_result;
    std::string local_result_str;
    local_result.set_result(kAck);
    local_result.SerializeToString(&local_result_str);
    cb(local_result_str);
  }
}

void PDVault::IterativePublishChunkRef(
    boost::shared_ptr<RepublishChunkRefData> data) {
  if (vault_status() != kVaultStarted) {
#ifdef DEBUG
    printf("Vault offline %s\n", pmid_.substr(0, 10).c_str());
#endif
    return;
  }
  if (data->is_callbacked) return;
  if (data->chunk_names.empty()) {
    // no more chunks need to be republished, job done!
    maidsafe::GenericResponse local_result;
    std::string local_result_str;
    printf("\nVault republished!\n");
    if (static_cast<float>(data->num_republished_chunks) >=
        kMinSuccessfulPecentageOfUpdating*(data->num_chunks))
      local_result.set_result(kAck);
    else
      local_result.set_result(kNack);
    local_result.SerializeToString(&local_result_str);
    data->is_callbacked = true;
    data->cb(local_result_str);
  } else {
    printf("*");
    std::string chunk_name = data->chunk_names.front();
    data->chunk_names.pop_front();
    std::string non_hex_chunk_name = base::DecodeFromHex(chunk_name);
    std::string signed_request = co_.AsymSign(
        co_.Hash(pmid_public_ + signed_pmid_public_ + non_hex_chunk_name,
                "",
                crypto::STRING_STRING,
                false),
        "",
        pmid_private_,
        crypto::STRING_STRING);
    kad::SignedValue signed_value;
    signed_value.set_value(pmid_);
    signed_value.set_value_signature(co_.AsymSign(pmid_, "", pmid_private_,
        crypto::STRING_STRING));
    kad::SignedRequest sr;
    sr.set_signer_id(non_hex_pmid_);
    sr.set_public_key(pmid_public_);
    sr.set_signed_public_key(signed_pmid_public_);
    sr.set_signed_request(signed_request);
    knode_.StoreValue(chunk_name,
                      signed_value,
                      sr,
                      86400,
                      boost::bind(&PDVault::IterativePublishChunkRef_Next,
                                  this,
                                  _1,
                                  data));
  }
}

void PDVault::IterativePublishChunkRef_Next(
    const std::string& result,
    boost::shared_ptr<RepublishChunkRefData> data) {
  if (vault_status() != kVaultStarted) {
#ifdef DEBUG
    printf("Vault offline %s\n", pmid_.substr(0, 10).c_str());
#endif
    return;
  }
  kad::StoreResponse result_msg;
  if (result_msg.ParseFromString(result))
    if (result_msg.result() == kad::kRpcResultFailure)
      ++data->num_republished_chunks;
  IterativePublishChunkRef(data);
}

void PDVault::GetChunk(const std::string &chunk_name,
                       base::callback_func_type cb) {
  if (vault_status() != kVaultStarted) {
#ifdef DEBUG
    printf("Vault offline %s\n", pmid_.substr(0, 10).c_str());
#endif
    return;
  }
  // preparing the shared pointer with data for the LoadChunk operation
  boost::shared_ptr<LoadChunkData> data(new LoadChunkData(chunk_name, cb));
  FindChunkRef(data);
}

void PDVault::FindChunkRef(boost::shared_ptr<struct LoadChunkData> data) {
  if (vault_status() != kVaultStarted) {
#ifdef DEBUG
    printf("Vault offline %s\n", pmid_.substr(0, 10).c_str());
#endif
    return;
  }
  knode_.FindValue(data->chunk_name, false,
                   boost::bind(&PDVault::FindChunkRefCallback, this, _1, data));
}

void PDVault::FindChunkRefCallback(
    const std::string &result,
    boost::shared_ptr<struct LoadChunkData> data) {
  if (vault_status() != kVaultStarted) {
#ifdef DEBUG
    printf("Vault offline %s\n", pmid_.substr(0, 10).c_str());
#endif
    return;
  }
  if (data->is_callbacked || !knode_.is_joined()) {
    // callback can only be called once
    return;
  }
  kad::FindResponse result_msg;
  if (!result_msg.ParseFromString(result) ||
      result_msg.result() == kad::kRpcResultFailure ||
      result_msg.values_size() == 0) {
    // no chunk references were found
    maidsafe::GetResponse local_result;
    std::string local_result_str("");
    local_result.set_result(kNack);
    local_result.SerializeToString(&local_result_str);
    data->is_callbacked = true;
    data->cb(local_result_str);
    return;
  }
  data->number_holders = result_msg.values_size();
  bool correct_info(false);
  for (int i = 0; i < result_msg.values_size(); ++i) {
    kad::SignedValue signed_value;
    if (signed_value.ParseFromString(result_msg.values(i))) {
      std::string contact_info = signed_value.value();
      kad::Contact remote;
      if (remote.ParseFromString(contact_info)) {
        data->chunk_holders.push_back(remote);
        correct_info = true;
        boost::shared_ptr<GetArgs> get_args_(new GetArgs(remote, data));
        CheckChunk(get_args_);
      } else {
        --data->number_holders;
      }
    } else {
      --data->number_holders;
    }
  }
  if (!correct_info) {
    // could not get contact info from the values retrieved
    maidsafe::GetResponse local_result;
    std::string local_result_str("");
    local_result.set_result(kNack);
    local_result.SerializeToString(&local_result_str);
    data->is_callbacked = true;
    data->cb(local_result_str);
  }
}


void PDVault::CheckChunk(boost::shared_ptr<GetArgs> get_args) {
  if (vault_status() != kVaultStarted) {
#ifdef DEBUG
    printf("Vault offline %s\n", pmid_.substr(0, 10).c_str());
#endif
    return;
  }
  boost::shared_ptr<maidsafe::CheckChunkResponse>
      check_chunk_response(new maidsafe::CheckChunkResponse());
  google::protobuf::Closure* callback = google::protobuf::NewCallback(this,
      &PDVault::CheckChunkCallback, check_chunk_response, get_args);
  kad::connect_to_node conn_type =
      knode_.CheckContactLocalAddress(get_args->chunk_holder_.node_id(),
                                      get_args->chunk_holder_.local_ip(),
                                      get_args->chunk_holder_.local_port(),
                                      get_args->chunk_holder_.host_ip());
  std::string ip = get_args->chunk_holder_.host_ip();
  uint16_t port = static_cast<uint16_t>(get_args->chunk_holder_.host_port());
  if (conn_type == kad::LOCAL) {
    ip = get_args->chunk_holder_.local_ip();
    port = get_args->chunk_holder_.local_port();
    get_args->retry_remote_ = true;
  }
  vault_rpcs_.CheckChunk(get_args->data_->chunk_name, ip, port,
      get_args->chunk_holder_.rendezvous_ip(),
      get_args->chunk_holder_.rendezvous_port(), check_chunk_response.get(),
      get_args->controller_.get(), callback);
}

void PDVault::CheckChunkCallback(
    boost::shared_ptr<maidsafe::CheckChunkResponse> check_chunk_response,
    boost::shared_ptr<GetArgs> get_args) {
  if (vault_status() != kVaultStarted) {
#ifdef DEBUG
    printf("Vault offline %s\n", pmid_.substr(0, 10).c_str());
#endif
    return;
  }
  if (get_args->data_->is_callbacked ||
      !knode_.is_joined()) {
    // callback can only be called once
    return;
  }
  if (check_chunk_response->IsInitialized() &&
      check_chunk_response->has_pmid_id() &&
      check_chunk_response->pmid_id() != get_args->chunk_holder_.node_id()) {
    if (get_args->retry_remote_) {
      get_args->retry_remote_ = false;
//      knode_.UpdatePDRTContactToRemote(get_args->chunk_holder_.node_id());
      boost::shared_ptr<maidsafe::CheckChunkResponse>
          check_chunk_response(new maidsafe::CheckChunkResponse());
      google::protobuf::Closure* callback = google::protobuf::NewCallback(this,
          &PDVault::CheckChunkCallback, check_chunk_response, get_args);
      vault_rpcs_.CheckChunk(get_args->data_->chunk_name,
          get_args->chunk_holder_.host_ip(),
          get_args->chunk_holder_.host_port(),
          get_args->chunk_holder_.rendezvous_ip(),
          get_args->chunk_holder_.rendezvous_port(),
          check_chunk_response.get(), get_args->controller_.get(), callback);
      return;
    }
  }
  if (!check_chunk_response->IsInitialized() ||
      check_chunk_response->result() == kNack) {
    ++get_args->data_->failed_holders;
    if (get_args->data_->failed_holders >=
        get_args->data_->number_holders) {
      // the chunk references did not respond to the check
      maidsafe::GetResponse local_result;
      std::string local_result_str("");
      local_result.set_result(kNack);
      local_result.SerializeToString(&local_result_str);
      get_args->data_->cb(local_result_str);
      get_args->data_->is_callbacked = true;
    }
  } else {
    // only send one contact the get chunk request
    if (!get_args->data_->is_active) {
      get_args->data_->is_active = true;
      // if we're trying to get messages (a buffer packet)
      kad::connect_to_node conn_type =
        knode_.CheckContactLocalAddress(get_args->chunk_holder_.node_id(),
                                        get_args->chunk_holder_.local_ip(),
                                        get_args->chunk_holder_.local_port(),
                                        get_args->chunk_holder_.host_ip());
      std::string ip = get_args->chunk_holder_.host_ip();
      uint16_t port = static_cast<uint16_t>(
                          get_args->chunk_holder_.host_port());
      if (conn_type == kad::LOCAL) {
        ip = get_args->chunk_holder_.local_ip();
        port = get_args->chunk_holder_.local_port();
      }
      if (get_args->data_->get_msgs) {
          boost::shared_ptr<maidsafe::GetBPMessagesResponse>
              get_messages_response(new maidsafe::GetBPMessagesResponse());
        google::protobuf::Closure* callback =
            google::protobuf::NewCallback(this, &PDVault::GetMessagesCallback,
            get_messages_response, get_args);
        vault_rpcs_.GetMessages(get_args->data_->chunk_name,
            get_args->data_->pub_key, get_args->data_->sig_pub_key, ip, port,
            get_args->chunk_holder_.rendezvous_ip(),
            get_args->chunk_holder_.rendezvous_port(),
            get_messages_response.get(), get_args->controller_.get(), callback);
      } else {
       boost::shared_ptr<maidsafe::GetResponse>
          get_response(new maidsafe::GetResponse());
       google::protobuf::Closure* callback = google::protobuf::NewCallback(this,
           &PDVault::GetChunkCallback, get_response, get_args);
        vault_rpcs_.Get(get_args->data_->chunk_name, ip, port,
            get_args->chunk_holder_.rendezvous_ip(),
            get_args->chunk_holder_.rendezvous_port(), get_response.get(),
            get_args->controller_.get(), callback);
      }
    }
  }
}

void PDVault::GetMessages(const std::string &chunk_name,
                           const std::string &public_key,
                           const std::string &signed_public_key,
                           base::callback_func_type cb) {
  if (vault_status() != kVaultStarted) {
#ifdef DEBUG
    printf("Vault offline %s\n", pmid_.substr(0, 10).c_str());
#endif
    return;
  }
  boost::shared_ptr<LoadChunkData> data(new LoadChunkData(chunk_name, cb));
  data->get_msgs = true;
  data->pub_key = public_key;
  data->sig_pub_key = signed_public_key;
  FindChunkRef(data);
}

void PDVault::GetMessagesCallback(
    boost::shared_ptr<maidsafe::GetBPMessagesResponse> get_messages_response,
    boost::shared_ptr<GetArgs> get_args) {
  if (vault_status() != kVaultStarted) {
#ifdef DEBUG
    printf("Vault offline %s\n", pmid_.substr(0, 10).c_str());
#endif
    return;
  }
  if (get_args->data_->is_callbacked)
    return;
  if (get_messages_response->IsInitialized() &&
      get_messages_response->has_pmid_id() &&
      get_messages_response->pmid_id() != get_args->chunk_holder_.node_id()) {
    if (get_args->retry_remote_) {
      get_args->retry_remote_ = false;
//      knode_.UpdatePDRTContactToRemote(get_args->chunk_holder_.node_id());
      boost::shared_ptr<maidsafe::GetBPMessagesResponse>
          get_messages_response(new maidsafe::GetBPMessagesResponse());
      google::protobuf::Closure* callback = google::protobuf::NewCallback(this,
          &PDVault::GetMessagesCallback, get_messages_response, get_args);
      vault_rpcs_.GetMessages(get_args->data_->chunk_name,
          get_args->data_->pub_key, get_args->data_->sig_pub_key,
          get_args->chunk_holder_.host_ip(),
          get_args->chunk_holder_.host_port(),
          get_args->chunk_holder_.rendezvous_ip(),
          get_args->chunk_holder_.rendezvous_port(),
          get_messages_response.get(), get_args->controller_.get(), callback);
      return;
    }
  }
  if (!get_messages_response->IsInitialized() ||
      get_messages_response->result() == kNack) {
    get_args->data_->failed_chunk_holders.push_back(get_args->chunk_holder_);
    RetryGetChunk(get_args->data_);
  } else {
    get_args->data_->is_callbacked = true;
    if (get_messages_response->result() == kAck)
      get_args->data_->cb(kad::kRpcResultSuccess);
    else
      get_args->data_->cb(kad::kRpcResultFailure);
  }
}

void PDVault::GetChunkCallback(
    boost::shared_ptr<maidsafe::GetResponse> get_response,
    boost::shared_ptr<GetArgs> get_args) {
  if (vault_status() != kVaultStarted) {
#ifdef DEBUG
    printf("Vault offline %s\n", pmid_.substr(0, 10).c_str());
#endif
    return;
  }
  if (get_args->data_->is_callbacked)
    return;
  if (get_response->IsInitialized() &&
      get_response->has_pmid_id() &&
      get_response->pmid_id() != get_args->chunk_holder_.node_id()) {
    if (get_args->retry_remote_) {
      get_args->retry_remote_ = false;
//      knode_.UpdatePDRTContactToRemote(get_args->chunk_holder_.node_id());
      boost::shared_ptr<maidsafe::GetResponse>
          get_response(new maidsafe::GetResponse());
      google::protobuf::Closure* callback = google::protobuf::NewCallback(this,
          &PDVault::GetChunkCallback, get_response, get_args);
      vault_rpcs_.Get(get_args->data_->chunk_name,
          get_args->chunk_holder_.host_ip(),
          get_args->chunk_holder_.host_port(),
          get_args->chunk_holder_.rendezvous_ip(),
          get_args->chunk_holder_.rendezvous_port(), get_response.get(),
          get_args->controller_.get(), callback);
      return;
    }
  }
  if (!get_response->IsInitialized() ||
      get_response->result() == kNack) {
    get_args->data_->failed_chunk_holders.push_back(get_args->chunk_holder_);
    RetryGetChunk(get_args->data_);
  } else {
    std::string result_str_("");
    get_response->SerializeToString(&result_str_);
    get_args->data_->is_callbacked = true;
// TODO(Fraser#5#): 2009-04-08 - Should save chunk to chunkstore now and this
//                  vault to chunk ref
    get_args->data_->cb(result_str_);
  }
}

void PDVault::RetryGetChunk(boost::shared_ptr<struct LoadChunkData> data) {
  if (vault_status() != kVaultStarted) {
#ifdef DEBUG
    printf("Vault offline %s\n", pmid_.substr(0, 10).c_str());
#endif
    return;
  }
  if (data->is_callbacked || !knode_.is_joined()) {
    // callback can only be called once
    return;
  }
  bool send_request = false;
  if (data->retry < kMaxChunkLoadRetries) {
    ++data->retry;
    data->number_holders = data->chunk_holders.size() -
      data->failed_chunk_holders.size();
    data->failed_holders = 0;
    data->is_active = false;
    for (int i = 0; i < static_cast<int>(data->chunk_holders.size()); ++i) {
      kad::Contact remote = data->chunk_holders[i];
      bool send = true;
      for (int j = 0; j < static_cast<int>(data->failed_chunk_holders.size())
            && send; ++j)
        if (remote == data->failed_chunk_holders[j])
          send = false;
      if (send) {
        boost::shared_ptr<GetArgs> get_args_(new GetArgs(remote, data));
        CheckChunk(get_args_);
        send_request = true;
      }
    }
  }
  if (!send_request) {
    maidsafe::GetResponse local_result;
    std::string local_result_str("");
    local_result.set_result(kNack);
    local_result.SerializeToString(&local_result_str);
    data->is_callbacked = true;
    data->cb(local_result_str);
  }
}

void PDVault::SwapChunk(const std::string &chunk_name,
                        const std::string &remote_ip,
                        const boost::uint16_t &remote_port,
                        const std::string &rendezvous_ip,
                        const boost::uint16_t &rendezvous_port,
                        base::callback_func_type cb) {
  if (vault_status() != kVaultStarted) {
#ifdef DEBUG
    printf("Vault offline %s\n", pmid_.substr(0, 10).c_str());
#endif
    return;
  }
  boost::shared_ptr<SwapChunkArgs> swap_chunk_args(
      new SwapChunkArgs(chunk_name, remote_ip, remote_port, rendezvous_ip,
      rendezvous_port, cb));
  boost::shared_ptr<maidsafe::SwapChunkResponse>
      swap_chunk_response(new maidsafe::SwapChunkResponse());
  google::protobuf::Closure* callback = google::protobuf::NewCallback(this,
      &PDVault::SwapChunkSendChunk, swap_chunk_response, swap_chunk_args);
  std::string chunkcontent1;
  if (!vault_chunkstore_.Load(swap_chunk_args->chunkname_,
      &chunkcontent1) != 0) {
    maidsafe::SwapChunkResponse local_result;
    std::string local_result_str("");
    local_result.set_request_type(1);
    local_result.set_result(kNack);
    local_result.SerializeToString(&local_result_str);
    cb(local_result_str);
  }
  rpcprotocol::Controller *controller = new rpcprotocol::Controller;
  vault_rpcs_.SwapChunk(0, chunk_name, "", chunkcontent1.size(), remote_ip,
      remote_port, rendezvous_ip, rendezvous_port, swap_chunk_response.get(),
      controller, callback);
}

void PDVault::SwapChunkSendChunk(
    boost::shared_ptr<maidsafe::SwapChunkResponse> swap_chunk_response,
    boost::shared_ptr<SwapChunkArgs> swap_chunk_args) {
  if (vault_status() != kVaultStarted) {
#ifdef DEBUG
    printf("Vault offline %s\n", pmid_.substr(0, 10).c_str());
#endif
    return;
  }
  if (!swap_chunk_response->IsInitialized()
      ||(swap_chunk_response->result() == kNack)) {
    maidsafe::SwapChunkResponse local_result;
    std::string local_result_str("");
    local_result.set_request_type(1);
    local_result.set_result(kNack);
    local_result.SerializeToString(&local_result_str);
    swap_chunk_args->cb_(local_result_str);
    return;
  }
  std::string chunkcontent1;
  if (!vault_chunkstore_.Load(swap_chunk_args->chunkname_,
      &chunkcontent1) != 0) {
    maidsafe::SwapChunkResponse local_result;
    std::string local_result_str("");
    local_result.set_request_type(1);
    local_result.set_result(kNack);
    local_result.SerializeToString(&local_result_str);
    swap_chunk_args->cb_(local_result_str);
  }
  google::protobuf::Closure* callback = google::protobuf::NewCallback(this,
      &PDVault::SwapChunkAcceptChunk, swap_chunk_response, swap_chunk_args);
  rpcprotocol::Controller *controller = new rpcprotocol::Controller;
  vault_rpcs_.SwapChunk(1, swap_chunk_args->chunkname_, chunkcontent1,
      chunkcontent1.size(), swap_chunk_args->remote_ip_,
      swap_chunk_args->remote_port_, swap_chunk_args->rendezvous_ip_,
      swap_chunk_args->rendezvous_port_, swap_chunk_response.get(), controller,
      callback);
}

void PDVault::SwapChunkAcceptChunk(
    boost::shared_ptr<maidsafe::SwapChunkResponse> swap_chunk_response,
    boost::shared_ptr<SwapChunkArgs> swap_chunk_args) {
  if (vault_status() != kVaultStarted) {
#ifdef DEBUG
    printf("Vault offline %s\n", pmid_.substr(0, 10).c_str());
#endif
    return;
  }
  if (!swap_chunk_response->IsInitialized()
      || (swap_chunk_response->result() == kNack
      || (swap_chunk_response->request_type() != 1)
      || (!swap_chunk_response->has_chunkname2())
      || (!swap_chunk_response->has_chunkcontent2()))) {
    maidsafe::SwapChunkResponse local_result;
    std::string local_result_str("");
    local_result.set_request_type(1);
    local_result.set_result(kNack);
    local_result.SerializeToString(&local_result_str);
    swap_chunk_args->cb_(local_result_str);
    return;
  }
  // Accept the swapped chunk
  std::string chunk_name_ = swap_chunk_response->chunkname2();
  vault_chunkstore_.Store(chunk_name_, swap_chunk_response->chunkcontent2());
  // Store chunk reference
  std::string non_hex_chunk_name = base::DecodeFromHex(chunk_name_);
  std::string signed_request = co_.AsymSign(
      co_.Hash(pmid_public_ + signed_pmid_public_ + non_hex_chunk_name,
              "",
              crypto::STRING_STRING,
              false),
      "",
      pmid_private_,
      crypto::STRING_STRING);
  kad::SignedValue signed_value;
  signed_value.set_value(pmid_);
  signed_value.set_value_signature(co_.AsymSign(pmid_, "", pmid_private_,
      crypto::STRING_STRING));
  kad::SignedRequest sr;
  sr.set_signer_id(non_hex_pmid_);
  sr.set_public_key(pmid_public_);
  sr.set_signed_public_key(signed_pmid_public_);
  sr.set_signed_request(signed_request);
  knode_.StoreValue(swap_chunk_args->chunkname_,
                    signed_value,
                    sr,
                    86400,
                    &pdv_dummy_callback);
  maidsafe::SwapChunkResponse local_result;
  std::string local_result_str("");
  local_result.set_request_type(1);
  local_result.set_result(kAck);
  local_result.SerializeToString(&local_result_str);
  swap_chunk_args->cb_(local_result_str);
}

void PDVault::SetKThreshold(const boost::uint16_t &kKadStoreThreshold) {
  kKadStoreThreshold_ = kKadStoreThreshold;
}

}  // namespace maidsafe_vault
