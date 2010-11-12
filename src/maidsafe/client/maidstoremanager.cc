/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Manager allowing maidsafe layer to store data to network
* Version:      1.0
* Created:      09/09/2008 12:14:35 PM
* Revision:     none
* Compiler:     gcc
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

#include "maidsafe/client/maidstoremanager.h"

#include <boost/filesystem/fstream.hpp>
#include <maidsafe/protobuf/general_messages.pb.h>
#include <maidsafe/protobuf/kademlia_service_messages.pb.h>
#include <maidsafe/transport/transporthandler-api.h>

#include <algorithm>

#include "maidsafe/bufferpacketrpc.h"
#include "maidsafe/client/clientrpc.h"
#include "maidsafe/client/sessionsingleton.h"
#include "protobuf/maidsafe_messages.pb.h"

// TODO(Fraser#5#): 2009-12-17 - Reconsider use of ValueType when sending
//                               chunks/packets for storing.  If client chooses
//                               type, there's little incentive to not set all
//                               chunks as Anon to avoiding paying for them.

namespace fs = boost::filesystem;

namespace maidsafe {

void SendChunkCopyTask::run() {
  msm_->DoStoreChunk(send_chunk_data_);
}

void StorePacketTask::run() {
  msm_->SendPacket(store_data_);
}

void DeletePacketTask::run() {
  msm_->DeletePacketFromNet(delete_data_);
}

void UpdatePacketTask::run() {
  msm_->UpdatePacketOnNetwork(update_data_);
}

MaidsafeStoreManager::MaidsafeStoreManager(boost::shared_ptr<ChunkStore> cstore,
                                           boost::uint8_t k)
    : K_(k),
      kUpperThreshold_(
          static_cast<boost::uint16_t>(K_ * kMinSuccessfulPecentageStore)),
      kLowerThreshold_(kMinSuccessfulPecentageStore > .25 ?
          static_cast<boost::uint16_t>(K_ * .25) : kUpperThreshold_),
      transport_(),
      transport_handler_(),
      channel_manager_(&transport_handler_),
      client_rpcs_(new ClientRpcs(&transport_handler_, &channel_manager_)),
      kad_ops_(new KadOps(&transport_handler_, &channel_manager_, kad::CLIENT,
                          "", "", false, false, K_, cstore)),
      ss_(SessionSingleton::getInstance()),
      pd_utils_(),
      tasks_handler_(),
      client_chunkstore_(cstore),
      chunk_thread_pool_(),
      packet_thread_pool_(),
      bprpcs_(new BufferPacketRpcsImpl(&transport_handler_, &channel_manager_)),
      cbph_(bprpcs_, kad_ops_, kUpperThreshold_),
      kChunkMaxThreadCount_(5),
      kPacketMaxThreadCount_(1),
      im_notifier_(),
      im_status_notifier_(),
      im_conn_hdler_(),
      im_handler_(ss_),
      own_vault_(kad_ops_),
      account_holders_manager_(kad_ops_, kLowerThreshold_),
      account_status_manager_(),
      account_status_update_data_() {}

void MaidsafeStoreManager::Init(VoidFuncOneInt callback,
                                const boost::uint16_t &port) {
  Init(callback, "", port);
}

void MaidsafeStoreManager::Init(VoidFuncOneInt callback,
                                const boost::filesystem::path &kad_config,
                                const boost::uint16_t &port) {
  boost::int16_t transport_id;
  transport_handler_.Register(&transport_, &transport_id);
  kad_ops_->set_transport_id(transport_id);
  if (!channel_manager_.RegisterNotifiersToTransport()) {
    callback(kStoreManagerInitError);
    return;
  }
  if (!transport_handler_.RegisterOnServerDown(boost::bind(
          &KadOps::HandleDeadRendezvousServer, kad_ops_, _1))) {
    callback(kStoreManagerInitError);
    return;
  }
  if (!transport_handler_.RegisterOnMessage(boost::bind(
          &IMConnectionHandler::OnMessageArrive, &im_conn_hdler_,
          _1, _2, _3, _4))) {
    callback(kStoreManagerInitError);
    return;
  }
  if (transport_handler_.Start(port, transport_.transport_id()) != 0) {
    callback(kStoreManagerInitError);
    return;
  }
  if (channel_manager_.Start() != 0) {
    callback(kStoreManagerInitError);
    return;
  }
  ReturnCode result = im_conn_hdler_.Start(&transport_handler_,
      boost::bind(&MaidsafeStoreManager::OnMessage, this, _1),
      boost::bind(&MaidsafeStoreManager::OnNewConnection, this, _1, _2, _3));
  if (result != kSuccess) {
    callback(result);
    return;
  }
#ifdef DEBUG
  printf("\tIn MaidsafeStoreManager::Init, before Join.\n");
#endif
  result = kPendingResult;
  boost::mutex mutex;
  boost::condition_variable cond_var;
  kad_ops_->Init(kad_config, false, "", 0, &mutex, &cond_var, &result);
  {
    boost::mutex::scoped_lock lock(mutex);
    while (result == kPendingResult)
      cond_var.wait(lock);
  }
  if (result == kSuccess) {
    chunk_thread_pool_.setMaxThreadCount(kChunkMaxThreadCount_);
    packet_thread_pool_.setMaxThreadCount(kPacketMaxThreadCount_);
#ifdef DEBUG
    printf("\tIn MSM::Init, after Join.  On port %u\n", kad_ops_->Port());
#endif
    own_vault_.Init(ss_->Id(PMID));
    account_holders_manager_.Init(ss_->Id(PMID), boost::bind(
        &MaidsafeStoreManager::AccountHoldersCallback, this, _1, _2));
    account_status_manager_.StartUpdating(boost::bind(
        &MaidsafeStoreManager::UpdateAccountStatus, this));
  }
  callback(result);
}

void MaidsafeStoreManager::AccountHoldersCallback(
    const ReturnCode &result,
    const std::vector<kad::Contact> &holders) {
#ifdef DEBUG
  // printf("MaidsafeStoreManager::AccountHoldersCallback\n");
#endif
  if (result == kSuccess && holders.size() >= kUpperThreshold_)
    account_status_manager_.Update();
  else
    account_status_manager_.UpdateFailed();
}

void MaidsafeStoreManager::Close(VoidFuncOneInt callback,
                                 bool /*cancel_pending_ops*/) {
#ifdef DEBUG
//  printf("\tIn MaidsafeStoreManager::Close, before Leave.\n");
#endif
//  if (cancel_pending_ops)
//    store_thread_pool_.clear();
  chunk_thread_pool_.waitForDone();
  printf("\tIn MaidsafeStoreManager::Close, chunk_thread_pool_ done.\n");
//  if (cancel_pending_ops)
//    packet_thread_pool_.clear();
  packet_thread_pool_.waitForDone();
  printf("\tIn MaidsafeStoreManager::Close, packet_thread_pool_ done.\n");
  im_conn_hdler_.Stop();
  account_status_manager_.StopUpdating();
  // if an update is in flight, return from callbacks ASAP
  if (account_status_update_data_.get()) {
    boost::mutex::scoped_lock lock(account_status_update_data_->mutex);
    account_status_update_data_->success_count = kLowerThreshold_;
    for (size_t i = 0; i < account_status_update_data_->data_holders.size();
         ++i) {
      channel_manager_.CancelPendingRequest(account_status_update_data_->
          data_holders.at(i).controller->request_id());
    }
    account_status_manager_.UpdateFailed();
  }
  kad_ops_->Leave();
#ifdef DEBUG
//  printf("\tIn MaidsafeStoreManager::Close, after Leave. "
//         "Stopping transport.\n");
#endif
  transport_handler_.StopAll();
  channel_manager_.Stop();
#ifdef DEBUG
//  printf("\tIn MaidsafeStoreManager::Close, transport stopped.\n");
#endif
  // Try again to kill the main storing thread in case it failed earlier.
  callback(kSuccess);
}

void MaidsafeStoreManager::CleanUpTransport() {
  // transport::TransportUDT::CleanUp();
}

ReturnCode MaidsafeStoreManager::ValidateInputs(const std::string &name,
                                                const PacketType &packet_type,
                                                const DirType &dir_type) {
  if (name.size() != kKeySize)
    return kIncorrectKeySize;
  if (packet_type < PacketType_MIN || packet_type > PacketType_MAX)
    return kPacketUnknownType;
  if (dir_type < ANONYMOUS || dir_type > PUBLIC_SHARE)
    return kDirUnknownType;
  return kSuccess;
}

int MaidsafeStoreManager::StoreChunk(const std::string &chunk_name,
                                     DirType dir_type,
                                     const std::string &msid) {
#ifdef DEBUG
//   printf("In MSM::StoreChunk (%d) for chunk %s\n",
//          kad_ops_->Port(), HexSubstr(chunk_name).c_str());
#endif
  ReturnCode valid = ValidateInputs(chunk_name, PacketType_MIN, dir_type);
  if (valid != kSuccess) {
#ifdef DEBUG
    printf("In MSM::StoreChunk (%d), invalid input (%i).\n",
           kad_ops_->Port(), valid);
#endif
    return valid;
  }
  ChunkType chunk_type = client_chunkstore_->chunk_type(chunk_name);
  fs::path chunk_path(client_chunkstore_->GetChunkPath(chunk_name, chunk_type,
                                                       false));
  if (chunk_type < 0 || chunk_path.empty()) {
#ifdef DEBUG
    printf("In MSM::StoreChunk (%d), didn't find chunk %s\n",
           kad_ops_->Port(), HexSubstr(chunk_name).c_str());
#endif
    return kStoreChunkError;
  }
  boost::uint64_t chunk_size(0);
  try {
    chunk_size = fs::file_size(chunk_path);
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("MSM::StoreChunk (%d), path: %s - %s\n",
           kad_ops_->Port(), chunk_path.string().c_str(), e.what());
#endif
    return kStoreManagerException;
  }

  if (!account_status_manager_.AbleToStore(chunk_size * kMinChunkCopies)) {
#ifdef DEBUG
    printf("In MSM::StoreChunk (%d), lacking space for chunk %s, "
           "size %llu x %d.\n", kad_ops_->Port(),
           HexSubstr(chunk_name).c_str(), chunk_size, kMinChunkCopies);
#endif
    return kStoreChunkError;
  }

  if (chunk_type & kOutgoing) {
    std::string key_id, public_key, public_key_signature, private_key;
    pd_utils_.GetChunkSignatureKeys(dir_type, msid, &key_id, &public_key,
                          &public_key_signature, &private_key);

    boost::uint64_t reserved_space = kMinChunkCopies * chunk_size;
    boost::shared_ptr<StoreData> store_data(new StoreData(
        chunk_name, chunk_size, chunk_type, dir_type, msid, key_id, public_key,
        public_key_signature, private_key));

    // Add root task for this chunk to the handler. Success depends on the child
    // tasks for AddToWatchList, StorePrep/StoreChunk and amendment conf.
    VoidFuncTaskIdInt callback =
        boost::bind(&MaidsafeStoreManager::StoreChunkTaskCallback, this, _1, _2,
                    reserved_space);
    tasks_handler_.AddTask(chunk_name, kStoreChunk, 3, 0, callback,
                           &store_data->master_task_id);

    // Add master task for AddToWatchList. Success depends on RPC successes.
    callback = boost::bind(&MaidsafeStoreManager::DebugSubTaskCallback,
                           this, _1, _2, "WatchListMaster");
    tasks_handler_.AddChildTask(chunk_name, store_data->master_task_id,
                                kAddToWatchListMaster, 1,
                                kMaxAddToWatchListTries - 1, callback,
                                &store_data->watchlist_master_task_id);

    // Add task to wait for amendment confirmations.
    callback = boost::bind(&MaidsafeStoreManager::DebugSubTaskCallback,
                           this, _1, _2, "AmendmentConfirmation");
    tasks_handler_.AddChildTask(chunk_name,
                                store_data->master_task_id,
                                kSpaceTakenIncConfirmation, kLowerThreshold_,
                                K_ - kUpperThreshold_, callback,
                                &store_data->amendment_task_id);

    account_status_manager_.ReserveSpace(reserved_space);
    return AddToWatchList(store_data);
  } else {
    return kStoreChunkError;
  }
}

void MaidsafeStoreManager::StoreChunkTaskCallback(
    const TaskId &task_id,
    const ReturnCode &result,
    const boost::uint64_t &reserved_space) {
  std::string chunkname(tasks_handler_.DataName(task_id));
#ifdef DEBUG
  printf("In MSM::StoreChunkTaskCallback (%d), overall storing process for "
         "%s %s.\n", kad_ops_->Port(), HexSubstr(chunkname).c_str(),
         result == kSuccess ? "succeeded" : "failed");
#endif
  // Fire store completion signal.
  if (!chunkname.empty())
    sig_chunk_uploaded_(chunkname, result);
  // Tidy up
  tasks_handler_.DeleteTask(task_id, result);
  account_status_manager_.UnReserveSpace(reserved_space);
}

void MaidsafeStoreManager::DebugSubTaskCallback(
    const TaskId &task_id,
    const ReturnCode &result,
    const std::string &task_info) {
#ifdef DEBUG
  printf("In MSM::DebugSubTaskCallback (%d), task \"%s\" for "
         "%s %s.\n",
         kad_ops_->Port(), task_info.c_str(),
         HexSubstr(tasks_handler_.DataName(task_id)).c_str(),
         result == kSuccess ? "succeeded" : "failed");
#endif
}

void MaidsafeStoreManager::StorePacket(const std::string &packet_name,
                                       const std::string &value,
                                       PacketType system_packet_type,
                                       DirType dir_type,
                                       const std::string &msid,
                                       const VoidFuncOneInt &cb) {
#ifdef DEBUG
//  printf("In MaidsafeStoreManager::StorePacket (%i), packet_name = %s\n",
//         kad_ops_->Port(), HexSubstr(packet_name).c_str());
#endif
  ReturnCode valid = ValidateInputs(packet_name, system_packet_type, dir_type);
  if (valid != kSuccess) {
#ifdef DEBUG
    printf("In MSM::StorePacket (%d), invalid input.  Error %i, packetname(%s),"
           " system_packet_type(%i), dir_type(%i)\n", kad_ops_->Port(),
           valid, HexSubstr(packet_name).c_str(), system_packet_type, dir_type);
#endif
    cb(valid);
    printf("MSM::StorePacket (%d), not validated.\n", kad_ops_->Port());
    return;
  }
  std::string key_id, public_key, public_key_signature, private_key;
  pd_utils_.GetPacketSignatureKeys(system_packet_type, dir_type, msid, &key_id,
      &public_key, &public_key_signature, &private_key);
  boost::shared_ptr<StoreData> store_data(new StoreData(packet_name, value,
      system_packet_type, dir_type, msid, key_id, public_key,
      public_key_signature, private_key, cb));
#ifdef DEBUG
//  printf("PN: %s\nV: %s\nK: %s\nPK: %s\nPKS: %s\n",
//         HexSubstr(packet_name).c_str(),
//         HexSubstr(value).c_str(),
//         HexSubstr(key_id).c_str(),
//         HexSubstr(public_key).c_str(),
//         HexSubstr(public_key_signature).c_str());
#endif
  // packet_thread_pool_ handles destruction of store_packet_task.
  StorePacketTask *store_packet_task = new StorePacketTask(store_data, this);
  packet_thread_pool_.start(store_packet_task);
}

int MaidsafeStoreManager::LoadChunk(const std::string &chunk_name,
                                    std::string *data) {
  // TODO(Team#) make LoadChunk non-blocking, keep stages parallel
#ifdef DEBUG
//  printf("In MaidsafeStoreManager::LoadChunk (%i), chunk_name = %s\n",
//         kad_ops_->Port(), HexSubstr(chunk_name).c_str());
#endif
  if (data == NULL) {
#ifdef DEBUG
    printf("In MSM::LoadChunk (%d), data == NULL\n", kad_ops_->Port());
#endif
    return kLoadChunkFailure;
  }

  data->clear();
  ReturnCode valid = ValidateInputs(chunk_name, PacketType_MIN, PRIVATE);
  if (valid != kSuccess) {
#ifdef DEBUG
    printf("In MSM::LoadChunk (%d), invalid input (%i).\n",
           kad_ops_->Port(), valid);
#endif
    return valid;
  }

  if (client_chunkstore_->Load(chunk_name, data) == kSuccess) {
#ifdef DEBUG
//    printf("In MSM::LoadChunk (%i) Found chunk %s in local chunkstore.\n",
//           kad_ops_->Port(), HexSubstr(chunk_name).c_str());
#endif
    return kSuccess;
  }

/**
 * The chunk retrieval process works as follows:
 *  1  Find a cached chunk copy if it exists, otherwise the chunk info holders.
 *  2  Get the chunk references from the chunk info holders.
 *  3  Look up the potential chunk holders to get their contact details.
 *  4  Contact potential chunk holders to confirm they have the chunk stored.
 *  5  Retrieve the chunk from one of the verified chunk holders.
 * These stages are parallelised, one stage commencing once the previous stage
 * generated enough (new) information to work with. On success, outstanding RPCs
 * will be cancelled. The whole process is effectively blocking, though.
 */

  boost::shared_ptr<GetChunkOpData> opdata(new GetChunkOpData(chunk_name));
  opdata->ref_responses.reserve(K_);
  opdata->check_responses.reserve(K_ * kMinChunkCopies);  // enough?
  boost::mutex::scoped_lock lock(opdata->mutex);

  // #1 Find a cached chunk copy if it exists, otherwise the chunk info holders.
  kad_ops_->FindValue(chunk_name, false,
      boost::bind(&MaidsafeStoreManager::LoadChunk_FindCB, this, _1, opdata));

  // Main loop of retrieval process, stages reversed for early bail-out.
  while (!opdata->failed) {
    opdata->condition.wait(lock);
    if (opdata->failed)
      break;
    if (!opdata->find_value_done)  // if the condition gets magically triggered
      continue;

    std::set<std::string>::iterator it;
    int concurrency;  // used to set the no. of parallel lookups per stage

    // #5 Retrieve the chunk from one of the verified chunk holders.
    {
      bool done(false);
      for (it = opdata->chunk_holders[kHolderHasChunk].begin();
           !done && it != opdata->chunk_holders[kHolderHasChunk].end();) {
#ifdef DEBUG
//        printf("In MSM::LoadChunk, getting chunk %s from %s...\n",
//               HexSubstr(chunk_name).c_str(), HexSubstr(*it).c_str());
#endif
        kad::Contact holder(opdata->chunk_holder_contacts[*it]);
        opdata->mutex.unlock();  // so other returning RPCs don't cause deadlock
        if (kSuccess == GetChunk(chunk_name, holder, data))  // blocking!
          done = true;
        opdata->mutex.lock();

        if (!done)
          opdata->chunk_holders[kHolderFailed].insert(*it);
        opdata->chunk_holders[kHolderHasChunk].erase(it++);
      }
      if (done)
        break;
    }

    // #4 Contact potential chunk holders to confirm they have the chunk stored.
    for (it = opdata->chunk_holders[kHolderContactable].begin(),
             concurrency = 3;
         it != opdata->chunk_holders[kHolderContactable].end() &&
             concurrency > 0;
         --concurrency) {
#ifdef DEBUG
//      printf("In MSM::LoadChunk, checking chunk %s on %s...\n",
//             HexSubstr(chunk_name).c_str(), HexSubstr(*it).c_str());
#endif
      CheckChunkRequest request;
      {
        CheckChunkResponse response;
        opdata->check_responses.push_back(response);
      }
      size_t rsp_idx(opdata->check_responses.size() - 1);
      request.set_chunkname(chunk_name);

      boost::shared_ptr<rpcprotocol::Controller>
          controller(new rpcprotocol::Controller);
      opdata->controllers.push_back(controller);
      google::protobuf::Closure* callback = google::protobuf::NewCallback(this,
          &MaidsafeStoreManager::LoadChunk_CheckCB, make_pair(*it, rsp_idx),
          opdata);
      client_rpcs_->CheckChunk(opdata->chunk_holder_contacts[*it],
          kad_ops_->AddressIsLocal(opdata->chunk_holder_contacts[*it]),
          transport_.transport_id(), &request,
          &opdata->check_responses[rsp_idx],
          controller.get(), callback);

      opdata->chunk_holders[kHolderPending].insert(*it);
      opdata->chunk_holders[kHolderContactable].erase(it++);
    }

    // #3 Look up the potential chunk holders to get their contact details.
    for (it = opdata->chunk_holders[kHolderNew].begin(), concurrency = 2;
         it != opdata->chunk_holders[kHolderNew].end() && concurrency > 0;
         --concurrency) {
#ifdef DEBUG
//      printf("In MSM::LoadChunk, looking up holder %s...\n",
//             HexSubstr(*it).c_str());
#endif
      kad_ops_->GetNodeContactDetails(*it, boost::bind(
            &MaidsafeStoreManager::LoadChunk_HolderCB, this, _1, _2, *it,
            opdata), false);
      opdata->chunk_holders[kHolderPending].insert(*it);
      opdata->chunk_holders[kHolderNew].erase(it++);
    }

    // check for chunk holder failure
    if (opdata->num_info_responses == opdata->chunk_info_holders.size() &&
        opdata->idx_info == opdata->num_info_responses) {
      // no more new chunk holders to expect
      if (!opdata->found_chunk_holder) {
        // all RPCs failed or didn't return anything
        opdata->failed = true;
      } else if (opdata->chunk_holders[kHolderPending].empty()) {
        // nothing being done, which means all holders must have failed
        opdata->failed = true;
      }
      // could potentially try again with the failed ones
    } else {
      // #2 Get the chunk references from the chunk info holders.
      for (concurrency = 3;
           opdata->idx_info < opdata->chunk_info_holders.size() &&
               concurrency > 0 &&
               opdata->chunk_holders[kHolderPending].empty();
           ++opdata->idx_info, --concurrency) {
#ifdef DEBUG
//        printf("In MSM::LoadChunk, getting refs for %s from %s...\n",
//               HexSubstr(chunk_name).c_str(), HexSubstr(
//             opdata->chunk_info_holders[opdata->idx_info].node_id()).c_str());
#endif
        GetChunkReferencesRequest request;
        {
          GetChunkReferencesResponse response;
          opdata->ref_responses.push_back(response);
        }
        size_t rsp_idx(opdata->ref_responses.size() - 1);
        request.set_chunkname(chunk_name);

        boost::shared_ptr<rpcprotocol::Controller>
            controller(new rpcprotocol::Controller);
        opdata->controllers.push_back(controller);
        google::protobuf::Closure* callback = google::protobuf::NewCallback(
            this, &MaidsafeStoreManager::LoadChunk_RefsCB, rsp_idx, opdata);
        client_rpcs_->GetChunkReferences(
            opdata->chunk_info_holders[opdata->idx_info],
            kad_ops_->AddressIsLocal(
                opdata->chunk_info_holders[opdata->idx_info]),
            transport_.transport_id(), &request,
            &opdata->ref_responses.back(),
            controller.get(), callback);
      }
    }
  }  // while

  // cancel all outstanding RPCs
  std::list< boost::shared_ptr<rpcprotocol::Controller> >::iterator
      controllers_it = opdata->controllers.begin();
  while (!opdata->controllers.empty()) {
    channel_manager_.CancelPendingRequest((*controllers_it)->request_id());
    controllers_it = opdata->controllers.erase(controllers_it);
  }

  if (opdata->failed) {
    if (!opdata->found_chunk_holder) {
#ifdef DEBUG
      printf("In MSM::LoadChunk (%i), unable to locate chunk copy holders for "
             "%s.\n", kad_ops_->Port(), HexSubstr(chunk_name).c_str());
#endif
      return kLoadChunkFindNodesFailure;
    }
#ifdef DEBUG
    printf("In MSM::LoadChunk (%i), failed loading chunk %s.\n",
           kad_ops_->Port(), HexSubstr(chunk_name).c_str());
#endif
    return kLoadChunkFailure;
  }

  if (data->empty()) {
#ifdef DEBUG
    printf("In MSM::LoadChunk (%i), loaded chunk %s was empty.\n",
           kad_ops_->Port(), HexSubstr(chunk_name).c_str());
#endif
    return kLoadChunkFailure;
  }

// TODO(Fraser#5#): 2009-08-31 - Store cache copy to needs_cache_copy_id
    // if (!opdata->needs_cache_copy_id.empty())
    //   CacheChunk(*data, !opdata->needs_cache_copy_id);

  return kSuccess;
}

void MaidsafeStoreManager::LoadChunk_FindCB(const std::string &result,
    boost::shared_ptr<GetChunkOpData> data) {
  boost::mutex::scoped_lock lock(data->mutex);
  data->find_value_done = true;

  if (result.empty()) {
#ifdef DEBUG
    printf("In MSM::LoadChunk_FindCB (%d), finding value %s timed out.\n",
           kad_ops_->Port(), HexSubstr(data->chunk_name).c_str());
#endif
    data->failed = true;
    data->condition.notify_one();
    return;
  }

  kad::FindResponse find_rsp;
  if (!find_rsp.ParseFromString(result)) {
#ifdef DEBUG
    printf("In MSM::LoadChunk_FindCB (%d), can't parse FindValue result.\n",
           kad_ops_->Port());
#endif
    data->failed = true;
    data->condition.notify_one();
    return;
  }

  for (int i = 0; i < find_rsp.closest_nodes_size(); ++i) {
    kad::Contact contact;
    contact.ParseFromString(find_rsp.closest_nodes(i));
    data->chunk_info_holders.push_back(contact);
  }

  if (find_rsp.has_needs_cache_copy())
    data->needs_cache_copy_id = find_rsp.needs_cache_copy();

  // If the response has an alternative_value, then the value is the ID of a
  // peer which has a cached copy of the chunk.
  if (find_rsp.result() == kad::kRpcResultSuccess &&
      find_rsp.has_alternative_value_holder()) {
  kad::Contact cache_holder(find_rsp.alternative_value_holder());
#ifdef DEBUG
    printf("In MSM::LoadChunk_FindCB (%d), node %s has cached chunk %s.\n",
           kad_ops_->Port(),
           HexSubstr(cache_holder.node_id().String()).c_str(),
           HexSubstr(data->chunk_name).c_str());
#endif
    data->AddChunkHolder(cache_holder);
    data->condition.notify_one();
    return;
  }

  if (find_rsp.closest_nodes_size() == 0)
    data->failed = true;
  data->condition.notify_one();
}

void MaidsafeStoreManager::LoadChunk_RefsCB(size_t rsp_idx,
    boost::shared_ptr<GetChunkOpData> data) {
  boost::mutex::scoped_lock lock(data->mutex);
  ++data->num_info_responses;
  const GetChunkReferencesResponse &response = data->ref_responses[rsp_idx];
  if (!response.IsInitialized()) {
#ifdef DEBUG
    printf("In MSM::LoadChunk_RefsCB (%d), response %d is uninitialised.\n",
           kad_ops_->Port(), rsp_idx);
#endif
  } else if (response.result() != kAck) {
#ifdef DEBUG
    printf("In MSM::LoadChunk_RefsCB (%d), response %d is negative.\n",
           kad_ops_->Port(), rsp_idx);
#endif
  } else {
    if (response.references_size() > 0)
      data->found_chunk_holder = true;
    for (int i = 0; i < response.references_size(); ++i)
      data->AddChunkHolder(response.references(i));
#ifdef DEBUG
//  printf("In MSM::LoadChunk_RefsCB, got %d chunk holders with response %d.\n",
//           response.references_size(), rsp_idx);
#endif
  }
  data->condition.notify_one();
}

void MaidsafeStoreManager::LoadChunk_HolderCB(
    const ReturnCode &result, const kad::Contact &chunk_holder,
    const std::string &pmid, boost::shared_ptr<GetChunkOpData> data) {
  boost::mutex::scoped_lock lock(data->mutex);
  if (result != kSuccess) {
#ifdef DEBUG
    printf("In MSM::LoadChunk_HolderCB (%d), could not get contact for %s.\n",
           kad_ops_->Port(), HexSubstr(pmid).c_str());
#endif
    data->chunk_holders[kHolderFailed].insert(pmid);
  } else {
    data->chunk_holder_contacts[pmid] = chunk_holder;
    data->chunk_holders[kHolderContactable].insert(pmid);
  }

  data->chunk_holders[kHolderPending].erase(pmid);
  data->condition.notify_one();
}

void MaidsafeStoreManager::LoadChunk_CheckCB(
    std::pair<std::string, size_t> params,  // pmid & response index
    boost::shared_ptr<GetChunkOpData> data) {
  boost::mutex::scoped_lock lock(data->mutex);
  const CheckChunkResponse &response = data->check_responses[params.second];
  bool fail(true);
  if (!response.IsInitialized()) {
#ifdef DEBUG
    printf("In MSM::LoadChunk_CheckCB (%d), response %d from %s is "
           "uninitialised.\n",
           kad_ops_->Port(), params.second, HexSubstr(params.first).c_str());
#endif
  } else if (response.result() != kAck) {
#ifdef DEBUG
    printf("In MSM::LoadChunk_CheckCB (%d), %s doesn't have chunk %s.\n",
           kad_ops_->Port(), HexSubstr(params.first).c_str(),
           HexSubstr(data->chunk_name).c_str());
#endif
  } else {
    fail = false;
  }

  if (fail)
    data->chunk_holders[kHolderFailed].insert(params.first);
  else
    data->chunk_holders[kHolderHasChunk].insert(params.first);

  data->chunk_holders[kHolderPending].erase(params.first);
  data->condition.notify_one();
}

int MaidsafeStoreManager::LoadPacket(const std::string &packet_name,
                                     std::vector<std::string> *results) {
#ifdef DEBUG
//  printf("In MaidsafeStoreManager::LoadPacket (%i), packet_name = %s\n",
//         kad_ops_->Port(), HexSubstr(packet_name).c_str());
#endif
  if (results == NULL) {
#ifdef DEBUG
    printf("In MSM::LoadPacket (%d), results == NULL\n", kad_ops_->Port());
#endif
    return kLoadPacketFailure;
  }
  results->clear();
  boost::mutex mutex;
  boost::condition_variable cond_var;
  int op_result(kGeneralError);
  LoadPacket(packet_name, boost::bind(&MaidsafeStoreManager::LoadPacketCallback,
                                      this, _1, _2, &mutex, &cond_var, results,
                                      &op_result));
  {
    boost::mutex::scoped_lock lock(mutex);
    while (op_result == kGeneralError)
      cond_var.wait(lock);
  }
  return op_result;
}

void MaidsafeStoreManager::LoadPacketCallback(
    const std::vector<std::string> values_in,
    const int &result_in,
    boost::mutex *mutex,
    boost::condition_variable *cond_var,
    std::vector<std::string> *values_out,
    int *result_out) {
  if (mutex == NULL || cond_var == NULL || values_out == NULL ||
      result_out == NULL) {
    return;
  }
  boost::mutex::scoped_lock lock(*mutex);
  *values_out = values_in;
  *result_out = result_in;
  cond_var->notify_one();
}

void MaidsafeStoreManager::LoadPacket(const std::string &packet_name,
                                      const LoadPacketFunctor &lpf) {
#ifdef DEBUG
//  printf("In MaidsafeStoreManager::LoadPacket2 (%i), packet_name = %s\n",
//         kad_ops_->Port(), HexSubstr(packet_name).c_str());
#endif
  std::vector<std::string> results;
  ReturnCode valid = ValidateInputs(packet_name, PacketType_MIN, PRIVATE);
  if (valid != kSuccess) {
#ifdef DEBUG
    printf("In MSM::LoadPacket2 (%d), invalid input.  Error %i\n",
           kad_ops_->Port(), valid);
#endif
    lpf(results, valid);
    return;
  }
  kad_ops_->FindValue(packet_name, false,
                      boost::bind(&MaidsafeStoreManager::LoadPacketCallback,
                                  this, packet_name, 1, _1, lpf));
}

void MaidsafeStoreManager::LoadPacketCallback(const std::string &packet_name,
                                              const int &attempt,
                                              const std::string &ser_response,
                                              const LoadPacketFunctor &lpf) {
  int ret_value(kSuccess);
  if (ser_response.empty()) {
#ifdef DEBUG
    printf("In MSM::LoadPacketCallback (%d), fail - timeout.\n",
           kad_ops_->Port());
#endif
    ret_value = kFindValueError;
  }
  kad::FindResponse find_response;
  if ((ret_value == kSuccess) && !find_response.ParseFromString(ser_response)) {
#ifdef DEBUG
    printf("In MSM::LoadPacketCallback (%d), can't parse result.\n",
           kad_ops_->Port());
#endif
    ret_value = kFindValueParseError;
  }
  if ((ret_value == kSuccess) &&
      (find_response.result() != kad::kRpcResultSuccess)) {
#ifdef DEBUG
    printf("In MSM::LoadPacketCallback (%d), failed to find value for key %s"
           " (found %i nodes and %i values)\n",
           kad_ops_->Port(), HexSubstr(packet_name).c_str(),
           find_response.closest_nodes_size(),
           find_response.signed_values_size());
//    printf("Found alt val holder: %i\n",
//           find_response.has_alternative_value_holder());
#endif
    ret_value = kFindValueFailure;
  }
  // If the response has an alternative_value, then the value is the ID of a
  // peer which has a cached copy of the packet.  Packets should not be cached.
  if ((ret_value == kSuccess) && find_response.has_alternative_value_holder()) {
#ifdef DEBUG
    printf("In MSM::LoadPacketCallback (%d), node %s has cached the value.\n",
           kad_ops_->Port(),
           HexSubstr(find_response.alternative_value_holder().node_id()).
           c_str());
#endif
    ret_value = kLoadPacketCached;
  }
  std::vector<std::string> values;
  if (ret_value == kSuccess) {
    bool empty(true);
    for (int i = 0; i < find_response.signed_values_size(); ++i) {
      if (!find_response.signed_values(i).value().empty())
        empty = false;
      values.push_back(find_response.signed_values(i).SerializeAsString());
    }
#ifdef DEBUG
    printf("In MSM::LoadPacketCallback (%d), returned %i values.\n",
           kad_ops_->Port(), values.size());
#endif
    if (empty)
      ret_value = kFindValueFailure;
  }
  if ((ret_value != kSuccess) && (attempt <= kMaxChunkLoadRetries - 1)) {
    kad_ops_->FindValue(packet_name, false,
                        boost::bind(&MaidsafeStoreManager::LoadPacketCallback,
                                    this, packet_name, attempt + 1, _1, lpf));
  } else {
    lpf(values, static_cast<ReturnCode>(ret_value));
    return;
  }
}

bool MaidsafeStoreManager::KeyUnique(const std::string &key, bool check_local) {
#ifdef DEBUG
//  printf("In MaidsafeStoreManager::KeyUnique (%i), key = %s\n",
//         kad_ops_->Port(), HexSubstr(key).c_str());
#endif
  bool unique(false);
  bool called_back(false);
  boost::mutex mutex;
  boost::condition_variable cond_var;
  KeyUnique(key, check_local, boost::bind(
      &MaidsafeStoreManager::KeyUniqueCallback, this, _1, &mutex, &cond_var,
      &unique, &called_back));
  {
    boost::mutex::scoped_lock lock(mutex);
    while (!called_back)
      cond_var.wait(lock);
  }
  return unique;
}

void MaidsafeStoreManager::KeyUniqueCallback(
    const ReturnCode &result_in,
    boost::mutex *mutex,
    boost::condition_variable *cond_var,
    bool *result_out,
    bool *called_back) {
  if (mutex == NULL || cond_var == NULL || result_out == NULL ||
      called_back == NULL) {
    return;
  }
  boost::mutex::scoped_lock lock(*mutex);
  *result_out = result_in == kKeyUnique;
  *called_back = true;
  cond_var->notify_one();
}

void MaidsafeStoreManager::KeyUnique(const std::string &key,
                                     bool check_local,
                                     const VoidFuncOneInt &cb) {
#ifdef DEBUG
//  printf("In MaidsafeStoreManager::KeyUnique2 (%i), key = %s\n",
//         kad_ops_->Port(), HexSubstr(key).c_str());
#endif
  ReturnCode valid = ValidateInputs(key, PacketType_MIN, PRIVATE);
  if (valid != kSuccess) {
    cb(kStoreManagerError);
    return;
  }
  kad_ops_->FindValue(key, check_local, boost::bind(
      &MaidsafeStoreManager::KeyUniqueCallback, this, _1, cb));
}

void MaidsafeStoreManager::KeyUniqueCallback(
    const std::string &ser_response,
    const VoidFuncOneInt &cb) {
  ReturnCode ret_value(kKeyUnique);
  if (ser_response.empty()) {
#ifdef DEBUG
    printf("In MSM::KeyUniqueCallback (%d), fail - timeout.\n",
           kad_ops_->Port());
#endif
    ret_value = kKeyNotUnique;
  }
  kad::FindResponse find_response;
  if (ret_value && !find_response.ParseFromString(ser_response)) {
#ifdef DEBUG
    printf("In MSM::KeyUniqueCallback (%d), can't parse result.\n",
           kad_ops_->Port());
#endif
    ret_value = kKeyNotUnique;
  }
  if (ret_value && (find_response.result() == kad::kRpcResultSuccess))
    ret_value = kKeyNotUnique;
  if (ret_value && find_response.has_alternative_value_holder())
    ret_value = kKeyNotUnique;
  cb(ret_value);
}

int MaidsafeStoreManager::DeleteChunk(const std::string &chunk_name,
                                      const boost::uint64_t &chunk_size,
                                      DirType dir_type,
                                      const std::string &msid) {
#ifdef DEBUG
//  printf("In MaidsafeStoreManager::DeleteChunk (%i), chunk_name = %s\n",
//         kad_ops_->Port(), HexSubstr(chunk_name).c_str());
#endif
  ReturnCode valid = ValidateInputs(chunk_name, PacketType_MIN, dir_type);
  if (valid != kSuccess) {
#ifdef DEBUG
    printf("In MSM::DeleteChunk (%d), invalid input.  Error %i\n",
           kad_ops_->Port(), valid);
#endif
    return valid;
  }
  ChunkType chunk_type = client_chunkstore_->chunk_type(chunk_name);
  fs::path chunk_path(client_chunkstore_->GetChunkPath(chunk_name, chunk_type,
                                                       false));

  boost::uint64_t size(chunk_size);
  if (size < 2) {
    if (chunk_type < 0 || chunk_path.empty()) {
#ifdef DEBUG
      printf("In MSM::DeleteChunk (%i), didn't find chunk %s in local "
             "chunkstore - can't delete without valid size.\n",
             kad_ops_->Port(), HexSubstr(chunk_name).c_str());
#endif
      return kDeleteSizeError;
    }
    try {
      size = fs::file_size(chunk_path);
    }
    catch(const std::exception &e) {
  #ifdef DEBUG
      printf("In MSM::DeleteChunk (%i), didn't find chunk %s in local "
             "chunkstore - can't delete without valid size.\n%s\n",
             kad_ops_->Port(), HexSubstr(chunk_name).c_str(), e.what());
  #endif
      return kDeleteSizeError;
    }
  }

  ChunkType new_type(chunk_type);
  if (chunk_type >= 0) {
    // Move chunk to TempCache.
    if (chunk_type & kNormal)
      new_type = chunk_type ^ (kNormal | kTempCache);
    else if (chunk_type & kOutgoing)
      new_type = chunk_type ^ (kOutgoing | kTempCache);
    else if (chunk_type & kCache)
      new_type = chunk_type ^ (kCache | kTempCache);
    if (!(new_type < 0) &&
        client_chunkstore_->ChangeChunkType(chunk_name, new_type) != kSuccess) {
  #ifdef DEBUG
      printf("In MSM::DeleteChunk (%d), failed to change chunk type.\n",
             kad_ops_->Port());
  #endif
    }
  }

  std::string key_id, public_key, public_key_signature, private_key;
  pd_utils_.GetChunkSignatureKeys(dir_type, msid, &key_id, &public_key,
      &public_key_signature, &private_key);

  boost::shared_ptr<StoreData> store_data(new StoreData(
      chunk_name, size, new_type, dir_type, msid, key_id, public_key,
      public_key_signature, private_key));

  // Add root task for this chunk to the handler.
  VoidFuncTaskIdInt callback =
      boost::bind(&MaidsafeStoreManager::DeleteChunkTaskCallback, this, _1, _2);
  tasks_handler_.AddTask(chunk_name, kDeleteChunk, 1, 0, callback,
                         &store_data->master_task_id);

  // Add master task for RemoveFromWatchList.
  tasks_handler_.AddChildTask(chunk_name, store_data->master_task_id,
                              kRemoveFromWatchListMaster, 1,
                              kMaxRemoveFromWatchListFailures, NULL,
                              &store_data->watchlist_master_task_id);

  return RemoveFromWatchList(store_data);
}

void MaidsafeStoreManager::DeleteChunkTaskCallback(const TaskId &task_id,
                                                   const ReturnCode &result) {
#ifdef DEBUG
  printf("In MSM::DeleteChunkTaskCallback (%d), deletion process for %s %s.\n",
         kad_ops_->Port(), HexSubstr(tasks_handler_.DataName(task_id)).c_str(),
         result == kSuccess ? "succeeded" : "failed");
#endif
}

void MaidsafeStoreManager::DeletePacket(const std::string &packet_name,
                                        const std::vector<std::string> values,
                                        PacketType system_packet_type,
                                        DirType dir_type,
                                        const std::string &msid,
                                        const VoidFuncOneInt &cb) {
#ifdef DEBUG
//  printf("In MaidsafeStoreManager::DeletePacket (%i), packet_name = %s\n",
//         kad_ops_->Port(), HexSubstr(packet_name).c_str());
#endif
  ReturnCode valid = ValidateInputs(packet_name, system_packet_type, dir_type);
  if (valid != kSuccess) {
#ifdef DEBUG
    printf("In MSM::DeletePacket (%d), invalid input.  Error %i\n",
           kad_ops_->Port(), valid);
#endif
    cb(valid);
    return;
  }

  std::vector<std::string> vals(values);
  if (vals.empty()) {
    int result = LoadPacket(packet_name, &vals);
    if (result == kFindValueFailure) {  // packet doesn't exist on net
      cb(kSuccess);
      return;
    } else if (result != kSuccess || vals.empty()) {
      cb(kDeletePacketFindValueFailure);
      return;
    } else {
      std::transform(vals.begin(), vals.end(), vals.begin(),
                     boost::bind(&MaidsafeStoreManager::GetValueFromSignedValue,
                                 this, _1));
    }
  }
  std::string key_id, public_key, public_key_signature, private_key;
  pd_utils_.GetPacketSignatureKeys(system_packet_type, dir_type, msid, &key_id,
      &public_key, &public_key_signature, &private_key);
  boost::shared_ptr<DeletePacketData> delete_data(new DeletePacketData(
      packet_name, vals, system_packet_type, dir_type, msid, key_id,
      public_key, public_key_signature, private_key, cb));
  // packet_thread_pool_ handles destruction of delete_packet_task.
  DeletePacketTask *delete_packet_task =
      new DeletePacketTask(delete_data, this);
  packet_thread_pool_.start(delete_packet_task);
}

void MaidsafeStoreManager::UpdatePacket(const std::string &packet_name,
                                        const std::string &old_value,
                                        const std::string &new_value,
                                        PacketType system_packet_type,
                                        DirType dir_type,
                                        const std::string &msid,
                                        const VoidFuncOneInt &cb) {
  ReturnCode valid = ValidateInputs(packet_name, system_packet_type, dir_type);
  if (valid != kSuccess) {
#ifdef DEBUG
    printf("In MSM::UpdatePacket (%d), invalid input.  Error %i\n",
           kad_ops_->Port(), valid);
#endif
    cb(valid);
    return;
  }

  std::string key_id, public_key, public_key_signature, private_key;
  pd_utils_.GetPacketSignatureKeys(system_packet_type, dir_type, msid, &key_id,
                         &public_key, &public_key_signature, &private_key);
  boost::shared_ptr<UpdatePacketData> update_data(new UpdatePacketData(
      packet_name, old_value, new_value, system_packet_type, dir_type, msid,
      key_id, public_key, public_key_signature, private_key, cb));

  // QThreadPool handles destruction of update_packet_task
  UpdatePacketTask *update_packet_task = new UpdatePacketTask(update_data,
                                                              this);
  packet_thread_pool_.start(update_packet_task);
//  UpdatePacketOnNetwork(update_data);
}

void MaidsafeStoreManager::UpdatePacketOnNetwork(
    boost::shared_ptr<UpdatePacketData> update_data) {
  crypto::Crypto co;
  kad::VoidFunctorOneString cb(boost::bind(
                                  &MaidsafeStoreManager::UpdatePacketCallback,
                                  this, _1, update_data));
  boost::mutex::scoped_lock lock(update_data->mutex);
  kad::SignedValue osv;
  osv.set_value(update_data->old_value);
  osv.set_value_signature(co.AsymSign(osv.value(), "", update_data->private_key,
                                      crypto::STRING_STRING));
  kad::SignedValue nsv;
  nsv.set_value(update_data->new_value);
  nsv.set_value_signature(co.AsymSign(nsv.value(), "", update_data->private_key,
                                      crypto::STRING_STRING));

  std::string request_signature(co.AsymSign(
                                    co.Hash(update_data->public_key +
                                            update_data->public_key_signature +
                                            update_data->packet_name,
                                            "", crypto::STRING_STRING, false),
                                "", update_data->private_key,
                                crypto::STRING_STRING));
  kad::SignedRequest sr;
  sr.set_signer_id(update_data->key_id);
  sr.set_public_key(update_data->public_key);
  sr.set_signed_public_key(update_data->public_key_signature);
  sr.set_signed_request(request_signature);
  kad_ops_->UpdateValue(update_data->packet_name, osv, nsv, sr, cb);
}

void MaidsafeStoreManager::UpdatePacketCallback(
    const std::string &ser_kad_update_result,
    boost::shared_ptr<UpdatePacketData> update_data) {
  if (ser_kad_update_result.empty()) {
#ifdef DEBUG
    printf("In MSM::UpdatePacketCallback (%d), fail - timeout.\n",
           kad_ops_->Port());
#endif
    boost::mutex::scoped_lock lock(update_data->mutex);
    update_data->callback(kUpdatePacketError);
    return;
  }
  kad::UpdateResponse update_response;
  if (!update_response.ParseFromString(ser_kad_update_result)) {
#ifdef DEBUG
    printf("In MSM::UpdatePacketCallback (%d), can't parse result.\n",
           kad_ops_->Port());
#endif
    boost::mutex::scoped_lock lock(update_data->mutex);
    update_data->callback(kUpdatePacketParseError);
    return;
  }
  if (update_response.result() != kad::kRpcResultSuccess) {
#ifdef DEBUG
    printf("In MSM::UpdatePacketCallback (%d), Kademlia operation failed.\n",
           kad_ops_->Port());
#endif
    boost::mutex::scoped_lock lock(update_data->mutex);
    update_data->callback(kUpdatePacketFailure);
    return;
  }
  update_data->callback(kSuccess);
}

void MaidsafeStoreManager::GetFilteredAverage(
    const std::vector<boost::uint64_t> &values,
    boost::uint64_t *average,
    size_t *n) {
  /**
   * note: keep values smaller than 2^(64-log2(n)); 53 bits precision!
   */
  boost::uint64_t sum(0);  // no double to keep precision within filtered vals
  double sum2(0), mean(0), stddev(0), comp(0);
  *average = 0;
  *n = 0;

  if (values.empty())
    return;

  // first pass: calculate mean
  for (size_t i = 0; i < values.size(); ++i) {
    sum += values[i];
  }
  mean = 1.0 * sum / values.size();

  // second pass: calculate standard deviation (using Kahan summation)
  for (size_t i = 0; i < values.size(); ++i) {
    double diff = values[i] - mean;
    comp += diff;
    sum2 += diff * diff;
  }
  stddev = sqrt((sum2 - comp * comp / values.size()) / values.size());

  // third pass: only count values within sqrt(2) standard deviations from mean
  for (size_t i = 0; i < values.size(); ++i) {
    if (fabs(values[i] - mean) > 1.414213562 * stddev)
      sum -= values[i];
    else
      ++(*n);
  }
  *average = sum / *n;
}

void MaidsafeStoreManager::GetAccountStatus(boost::uint64_t *space_offered,
                                            boost::uint64_t *space_given,
                                            boost::uint64_t *space_taken) {
  account_status_manager_.AccountStatus(space_offered, space_given,
                                        space_taken);
}

void MaidsafeStoreManager::UpdateAccountStatus() {
  if (ss_->ConnectionStatus() != 0) {  // offline
    account_status_manager_.UpdateFailed();
    return;
  }

  // Find the account holders
  account_status_update_data_ =
      boost::shared_ptr<AccountStatusData>(new AccountStatusData);
  account_status_update_data_->contacts =
      account_holders_manager_.account_holder_group();
  if (account_status_update_data_->contacts.size() < kUpperThreshold_) {
#ifdef DEBUG
    printf("In MSM::UpdateAccountStatus (%d), no account holders available.\n",
           kad_ops_->Port());
#endif
    // TODO(Team#) possibly schedule retry dependent on AH manager update
    account_holders_manager_.Update();
    account_status_manager_.UpdateFailed();
    return;
  }

  // Create the requests
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);
  AccountStatusRequest account_status_request;
  account_status_request.set_account_pmid(ss_->Id(PMID));
  account_status_request.set_public_key(ss_->PublicKey(PMID));
  account_status_request.set_public_key_signature(ss_->SignedPublicKey(PMID));
  std::vector<AccountStatusRequest> account_status_requests;
  for (size_t i = 0; i < account_status_update_data_->contacts.size(); ++i) {
    std::string request_signature = co.AsymSign(co.Hash(
        ss_->SignedPublicKey(PMID) + account_holders_manager_.account_name() +
        account_status_update_data_->contacts.at(i).node_id().String(), "",
        crypto::STRING_STRING, false), "", ss_->PrivateKey(PMID),
        crypto::STRING_STRING);
    account_status_request.set_request_signature(request_signature);
    account_status_requests.push_back(account_status_request);
    AccountStatusData::AccountStatusDataHolder holder(
        account_status_update_data_->contacts.at(i).node_id().String());
    account_status_update_data_->data_holders.push_back(holder);
  }

  // Send the requests
  boost::mutex::scoped_lock lock(account_status_update_data_->mutex);
  for (size_t i = 0; i < account_status_update_data_->contacts.size(); ++i) {
    google::protobuf::Closure* callback = google::protobuf::NewCallback(this,
        &MaidsafeStoreManager::UpdateAccountStatusStageTwo, i,
        account_status_update_data_);
    client_rpcs_->AccountStatus(account_status_update_data_->contacts.at(i),
        kad_ops_->AddressIsLocal(account_status_update_data_->contacts.at(i)),
        transport_.transport_id(),
        &account_status_requests.at(i),
        &account_status_update_data_->data_holders.at(i).response,
        account_status_update_data_->data_holders.at(i).controller.get(),
        callback);
  }
}

void MaidsafeStoreManager::UpdateAccountStatusStageTwo(
    size_t index,
    boost::shared_ptr<AccountStatusData> data) {
  boost::mutex::scoped_lock lock(data->mutex);
  if (data->success_count >= kLowerThreshold_)
    return;
  ++data->returned_count;

  AccountStatusData::AccountStatusDataHolder &holder =
      data->data_holders.at(index);
  if (!holder.response.IsInitialized()) {
#ifdef DEBUG
    printf("In MSM::UpdateAccountStatusStageTwo (%d), response %u is "
           "uninitialised.\n",
           kad_ops_->Port(), index);
#endif
    account_holders_manager_.ReportFailure(holder.node_id);
  } else if (holder.response.pmid() != holder.node_id) {
#ifdef DEBUG
    printf("In MSM::UpdateAccountStatusStageTwo (%d), resp %u from %s has pmid "
           "%s.\n",
           kad_ops_->Port(), index, HexSubstr(holder.node_id).c_str(),
           HexSubstr(holder.response.pmid()).c_str());
#endif
    // TODO(Fraser#5#): 2010-01-08 - Send alert to holder.node_id's A/C holders
  } else {
    ++data->success_count;
    if (holder.response.result() == kAck &&
        holder.response.has_space_offered() &&
        holder.response.has_space_given() &&
        holder.response.has_space_taken()) {
      data->offered_values.push_back(holder.response.space_offered());
      data->given_values.push_back(holder.response.space_given());
      data->taken_values.push_back(holder.response.space_taken());
    } else {
      // treat as non-existing account
      data->offered_values.push_back(0);
      data->given_values.push_back(0);
      data->taken_values.push_back(0);
    }
    NotifyTaskHandlerOfAccountAmendments(holder.response);
  }

  if (data->returned_count < kLowerThreshold_ ||
      (data->returned_count < data->contacts.size() &&
       data->success_count < kLowerThreshold_)) {
    // still waiting for enough responses
    return;
  } else if (data->success_count < kLowerThreshold_) {
    // failed to get enough responses
#ifdef DEBUG
    printf("In MSM::UpdateAccountStatusStageTwo (%d), received %u responses - "
           "need at least %u.\n",
           kad_ops_->Port(), data->success_count, kLowerThreshold_);
#endif
    account_status_manager_.UpdateFailed();
    for (size_t i = 0; i < data->data_holders.size(); ++i) {
      channel_manager_.CancelPendingRequest(
          data->data_holders.at(i).controller->request_id());
    }
    return;
  }

  boost::uint64_t offered_avg, given_avg, taken_avg;
  size_t offered_n, given_n, taken_n;

  // calculate filtered averages for our account values
  GetFilteredAverage(data->offered_values, &offered_avg, &offered_n);
  GetFilteredAverage(data->given_values, &given_avg, &given_n);
  GetFilteredAverage(data->taken_values, &taken_avg, &taken_n);

  // require at least 4 non-outliers of each
  if (offered_n < kLowerThreshold_ ||
      given_n   < kLowerThreshold_ ||
      taken_n   < kLowerThreshold_) {
#ifdef DEBUG
    if (data->returned_count >= data->contacts.size())
      printf("In MSM::UpdateAccountStatusStageTwo (%d), no consensus on values "
            "reached.\n",
             kad_ops_->Port());
#endif
    account_status_manager_.UpdateFailed();
  } else {
    account_status_manager_.SetAccountStatus(offered_avg, given_avg, taken_avg);
  }

  // cancel outstanding rpcs and clear account_status_update_data_
  for (size_t i = 0; i < data->data_holders.size(); ++i) {
    channel_manager_.CancelPendingRequest(
        data->data_holders.at(i).controller->request_id());
  }
}

void MaidsafeStoreManager::NotifyTaskHandlerOfAccountAmendments(
    const AccountStatusResponse &account_status_response) {
  for (int i = 0; i < account_status_response.amendment_results_size(); ++i) {
    const AccountStatusResponse::AmendmentResult &kAmendmentResult =
        account_status_response.amendment_results(i);
    if (!kAmendmentResult.IsInitialized())
      continue;
    bool success = kAmendmentResult.result() == kAck;
#ifdef DEBUG
    printf("In MSM::NotifyTaskHandlerOfAccountAmendments (%d), "
           "amendment to %s for %s %s.\n",
           kad_ops_->Port(),
           HexSubstr(account_status_response.pmid()).c_str(),
           HexSubstr(kAmendmentResult.chunkname()).c_str(),
           success ? "succeeded" : "failed");
#endif
    TaskId task_id(kRootTask);
    if (kAmendmentResult.amendment_type() ==
        AmendAccountRequest::kSpaceTakenInc) {
      // client tried to save a chunk
      task_id = tasks_handler_.GetOldestActiveTaskByDataNameAndType(
          kAmendmentResult.chunkname(), kSpaceTakenIncConfirmation);
    } else if (kAmendmentResult.amendment_type() ==
               AmendAccountRequest::kSpaceTakenDec) {
      // client tried to delete a chunk
      task_id = tasks_handler_.GetOldestActiveTaskByDataNameAndType(
          kAmendmentResult.chunkname(), kRemoveFromWatchList);
    }
    if (task_id != kRootTask) {
      if (success)
        tasks_handler_.NotifyTaskSuccess(task_id);
      else
        tasks_handler_.NotifyTaskFailure(task_id, kAmendAccountFailure);
    }
  }
}

////////////// BUFFER PACKET //////////////

int MaidsafeStoreManager::CreateBP() {
  BPInputParameters bpip = {ss_->Id(MPID),
                            ss_->PublicKey(MPID),
                            ss_->PrivateKey(MPID)};
  boost::shared_ptr<BPResults> bp_results(new BPResults);
  bp_results->finished = false;
  boost::mutex::scoped_lock loch_glascarnoch(bp_results->mutex);
  cbph_.CreateBufferPacket(bpip,
                           boost::bind(&MaidsafeStoreManager::ModifyBpCallback,
                                       this, _1, bp_results),
                           transport_.transport_id());
  while (!bp_results->finished)
    bp_results->cond.wait(loch_glascarnoch);
  return bp_results->rc;
}

int MaidsafeStoreManager::ModifyBPInfo(const std::string &info) {
  BPInputParameters bpip = {ss_->Id(MPID),
                            ss_->PublicKey(MPID),
                            ss_->PrivateKey(MPID)};
  boost::shared_ptr<BPResults> bp_results(new BPResults);
  bp_results->finished = false;
  BufferPacketInfo buffer_packet_info;
  if (!buffer_packet_info.ParseFromString(info))
    return kBPInfoParseError;

  std::vector<std::string> users;
  for (int i = 0; i < buffer_packet_info.users_size(); ++i)
    users.push_back(buffer_packet_info.users(i));
  boost::mutex::scoped_lock loch_glascarnoch(bp_results->mutex);
  cbph_.ModifyOwnerInfo(bpip, users,
                        boost::bind(&MaidsafeStoreManager::ModifyBpCallback,
                                    this, _1, bp_results),
                        transport_.transport_id());
  while (!bp_results->finished)
    bp_results->cond.wait(loch_glascarnoch);
  return bp_results->rc;
}

int MaidsafeStoreManager::LoadBPMessages(
    std::list<ValidatedBufferPacketMessage> *messages) {
  if (!messages)
    return kBPError;

  BPInputParameters bpip = {ss_->Id(MPID),
                            ss_->PublicKey(MPID),
                            ss_->PrivateKey(MPID)};
  boost::shared_ptr<VBPMessages> bpm(new VBPMessages);
  boost::mutex::scoped_lock loch_oich(bpm->mutex);
  cbph_.GetMessages(bpip,
                    boost::bind(&MaidsafeStoreManager::LoadMessagesCallback,
                                this, _1, _2, _3, bpm),
                    transport_.transport_id());
  while (!bpm->done)
    bpm->cond.wait(loch_oich);

  ValidatedBufferPacketMessage vbpm;
  std::set<std::string>::iterator it;
  for (it = bpm->presence_set.begin();
       it != bpm->presence_set.end(); ++it) {
    vbpm.ParseFromString(*it);
    messages->push_back(vbpm);
  }

  return bpm->successes;
}

int MaidsafeStoreManager::SendMessage(
    const std::vector<std::string> &receivers,
    const std::string &message,
    const MessageType &type,
    std::map<std::string, ReturnCode> *add_results) {
  BPInputParameters bpip = {ss_->Id(MPID),
                            ss_->PublicKey(MPID),
                            ss_->PrivateKey(MPID)};
  boost::shared_ptr<BPResults> bp_results(new BPResults);
  bp_results->returned_count = 0;
  bp_results->results = add_results;

  std::set<std::string> sss(receivers.begin(), receivers.end());
  std::vector<std::string> recs;
  std::set<std::string>::iterator it;
  if (sss.size() != receivers.size()) {
    for (it = sss.begin(); it != sss.end(); ++it)
      recs.push_back(*it);
  } else {
    recs = receivers;
  }

  if (type == maidsafe::INSTANT_MSG) {
    std::vector<std::string>::iterator it = recs.begin();
    while (it != recs.end()) {
      if (SendIM(message, *it)) {
        bp_results->results->insert(std::pair<std::string, ReturnCode>
                                             (*it,         kSuccess));
        it = recs.erase(it);
      } else {
        ++it;
      }
    }
  }

  boost::mutex::scoped_lock loch_quoich(bp_results->mutex);
  for (size_t n = 0; n < recs.size(); ++n)
    bp_results->results->insert(std::pair<std::string, ReturnCode>
                                         (recs[n],     kBPAwaitingCallback));
  // Add the message to each receiver's bp
  for (size_t i = 0; i < recs.size(); ++i) {
    cbph_.AddMessage(bpip, ss_->PublicUsername(),
                     ss_->GetContactPublicKey(recs[i]), recs[i], message, type,
                     boost::bind(&MaidsafeStoreManager::AddToBpCallback,
                                 this, _1, recs[i], bp_results),
                     transport_.transport_id());
  }

  while (bp_results->returned_count < recs.size())
    bp_results->cond.wait(loch_quoich);

  int successes(0);
  std::map<std::string, ReturnCode>::iterator map_it;
  for (map_it = bp_results->results->begin();
       map_it != bp_results->results->end(); ++map_it)
    if (map_it->second == kSuccess)
      ++successes;

  return successes;
}

int MaidsafeStoreManager::LoadBPPresence(std::list<LivePresence> *messages) {
  if (!messages)
    return kBPError;

  BPInputParameters bpip = {ss_->Id(MPID),
                            ss_->PublicKey(MPID),
                            ss_->PrivateKey(MPID)};
  boost::shared_ptr<PresenceMessages> bp_pm(new PresenceMessages);
  boost::mutex::scoped_lock loch_shin(bp_pm->mutex);
  cbph_.GetPresence(bpip,
                    boost::bind(&MaidsafeStoreManager::LoadPresenceCallback,
                                this, _1, _2, _3, bp_pm),
                    transport_.transport_id());

  while (!bp_pm->done)
    bp_pm->cond.wait(loch_shin);

  LivePresence lp;
  std::set<std::string>::iterator it;
  for (it = bp_pm->presence_set.begin();
       it != bp_pm->presence_set.end(); ++it) {
    lp.ParseFromString(*it);
    messages->push_back(lp);
  }

  return bp_pm->successes;
}

int MaidsafeStoreManager::AddBPPresence(
    const std::vector<std::string> &receivers,
    std::map<std::string, ReturnCode> *add_results) {
  if (!add_results)
    return kBPError;
  if (receivers.empty())
    return kSuccess;

  BPInputParameters bpip = {ss_->Id(MPID),
                            ss_->PublicKey(MPID),
                            ss_->PrivateKey(MPID)};
  boost::shared_ptr<BPResults> bp_results(new BPResults);
  bp_results->returned_count = 0;
  bp_results->results = add_results;

  std::set<std::string> sss(receivers.begin(), receivers.end());
  std::vector<std::string> recs;
  std::set<std::string>::iterator it;
  if (sss.size() != receivers.size()) {
    for (it = sss.begin(); it != sss.end(); ++it)
      recs.push_back(*it);
  } else {
    recs = receivers;
  }

  for (size_t n = 0; n < recs.size(); ++n)
    bp_results->results->insert(std::pair<std::string,  ReturnCode>
                                         (recs[n],      kBPAwaitingCallback));

  boost::mutex::scoped_lock loch_quoich(bp_results->mutex);
  for (size_t a = 0; a < recs.size(); ++a) {
    cbph_.AddPresence(bpip, ss_->PublicUsername(),
                      ss_->GetContactPublicKey(recs[a]), recs[a],
                      boost::bind(&MaidsafeStoreManager::AddToBpCallback, this,
                                  _1, recs[a], bp_results),
                      transport_.transport_id());
  }

  while (bp_results->returned_count < recs.size())
    bp_results->cond.wait(loch_quoich);

  int successes(0);
  std::map<std::string, ReturnCode>::iterator map_it;
  for (map_it = bp_results->results->begin();
       map_it != bp_results->results->end(); ++map_it)
    if (map_it->second == kSuccess)
      ++successes;

  return successes;
}

////////////// END BUFFER PACKET //////////////

int MaidsafeStoreManager::AddToWatchList(
    boost::shared_ptr<maidsafe::StoreData> store_data) {
#ifdef DEBUG
//   printf("In MSM::AddToWatchList (%d) for chunk %s\n",
//          kad_ops_->Port(), HexSubstr(store_data->data_name).c_str());
#endif
  // check store chunk master task still active
  if (tasks_handler_.Status(store_data->master_task_id) != kTaskActive) {
#ifdef DEBUG
    printf("In MSM::AddToWatchList (%d), StoreChunk task not active (%s).\n",
           kad_ops_->Port(), HexSubstr(store_data->data_name).c_str());
#endif
    return kGeneralError;
  }

  // TODO(Team): This block isn't really needed, but removal causes
  //             segfault :(
  if (tasks_handler_.Status(store_data->watchlist_master_task_id) !=
      kTaskActive) {
#ifdef DEBUG
    printf("In MSM::AddToWatchList (%d), no active master task (%s).\n",
           kad_ops_->Port(), HexSubstr(store_data->data_name).c_str());
#endif
    return kGeneralError;
  }

  // Add sub-task for the following operations
  boost::shared_ptr<WatchListOpData> data(new WatchListOpData(store_data));
  VoidFuncTaskIdInt callback =
      boost::bind(&MaidsafeStoreManager::AddToWatchListTaskCallback, this, _2,
                  store_data, store_data->amendment_task_id);
  if (tasks_handler_.AddChildTask(store_data->data_name,
      store_data->watchlist_master_task_id, kAddToWatchList, 1, 0, callback,
      &data->task_id) != kSuccess) {
#ifdef DEBUG
    printf("In MSM::AddToWatchList (%d), could not add sub-task to %s.\n",
           kad_ops_->Port(), HexSubstr(store_data->data_name).c_str());
#endif
    return kGeneralError;
  }

  // Find the Chunk Info holders
  kad_ops_->FindKClosestNodes(store_data->data_name,
      boost::bind(&MaidsafeStoreManager::AddToWatchListStageTwo, this, _1, _2,
                  data));
  return kSuccess;
}

void MaidsafeStoreManager::AddToWatchListTaskCallback(
    const ReturnCode &result,
    boost::shared_ptr<StoreData> store_data,
    const TaskId &amendment_task_id) {
  if (result == kSuccess) {
#ifdef DEBUG
//     printf("In MSM::AddToWatchListTaskCallback (%d), sucessfully added to "
//            "watch list for %s\n",
//            kad_ops_->Port(), HexSubstr(store_data->data_name).c_str());
#endif
  } else {
#ifdef DEBUG
    printf("In MSM::AddToWatchListTaskCallback (%d), retrying due to failure "
           "(%s).\n",
           kad_ops_->Port(), HexSubstr(store_data->data_name).c_str());
#endif
    // reset confirmation task
    // TODO(Team#5#): don't reset in case only failed ops are retried!
    tasks_handler_.ResetTaskProgress(amendment_task_id);

    // retry, will stop when max no. of failures reached
    AddToWatchList(store_data);
  }
}

void MaidsafeStoreManager::AddToWatchListStageTwo(
    const ReturnCode &result,
    const std::vector<kad::Contact> &chunk_info_holders,
    boost::shared_ptr<WatchListOpData> data) {
#ifdef DEBUG
//   printf("In MSM::AddToWatchListStageTwo (%d) for chunk %s\n",
//          kad_ops_->Port(), HexSubstr(data->store_data->data_name).c_str());
#endif

  if (result != kSuccess || chunk_info_holders.size() < kUpperThreshold_) {
#ifdef DEBUG
    printf("In MSM::AddToWatchListStageTwo (%d), could not find chunk info "
           "holders for %s.\n", kad_ops_->Port(),
           HexSubstr(data->store_data->data_name).c_str());
#endif
    tasks_handler_.NotifyTaskFailure(data->task_id,
                                     kStoreChunkFindNodesFailure);
    return;
  }

  data->chunk_info_holders = chunk_info_holders;

  ExpectAmendment(data->store_data->data_name,
                  AmendAccountRequest::kSpaceTakenInc,
                  data->store_data->key_id,
                  data->store_data->public_key,
                  data->store_data->public_key_signature,
                  data->store_data->private_key,
                  data->store_data->dir_type,
                  chunk_info_holders,
                  boost::bind(&MaidsafeStoreManager::AddToWatchListStageThree,
                              this, _1, data));
}

void MaidsafeStoreManager::AddToWatchListStageThree(
    const ReturnCode &result,
    boost::shared_ptr<WatchListOpData> data) {
  boost::mutex::scoped_lock lock(data->mutex);
  if (result != kSuccess) {
#ifdef DEBUG
    printf("In MSM::AddToWatchListStageThree (%d), ExpectAmendment failed.\n", 
           kad_ops_->Port());
#endif
    tasks_handler_.NotifyTaskFailure(data->task_id, result);
    return;
  }

  // Set up holders for forthcoming AddToWatchList RPCs
  std::vector<AddToWatchListRequest> add_to_watch_list_requests;
  if (GetAddToWatchListRequests(data->store_data, data->chunk_info_holders,
      &add_to_watch_list_requests) != kSuccess) {
#ifdef DEBUG
    printf("In MSM::AddToWatchListStageThree (%d), failed to generate AW "
           "requests.\n", kad_ops_->Port());
#endif
    tasks_handler_.NotifyTaskFailure(data->task_id, kStoreChunkError);
    return;
  }

  for (size_t i = 0; i < data->chunk_info_holders.size(); ++i) {
    WatchListOpData::AddToWatchDataHolder holder(
        data->chunk_info_holders.at(i).node_id().String());
    data->add_to_watchlist_data_holders.push_back(holder);
  }

  // Send AddToWatchList RPCs
  for (boost::uint16_t j = 0; j < data->chunk_info_holders.size(); ++j) {
    google::protobuf::Closure* callback = google::protobuf::NewCallback(this,
        &MaidsafeStoreManager::AddToWatchListStageFour, j, data);
    client_rpcs_->AddToWatchList(data->chunk_info_holders.at(j),
        kad_ops_->AddressIsLocal(data->chunk_info_holders.at(j)),
        transport_.transport_id(),
        &add_to_watch_list_requests.at(j),
        &data->add_to_watchlist_data_holders.at(j).response,
        data->add_to_watchlist_data_holders.at(j).controller.get(), callback);
  }
}

void MaidsafeStoreManager::AddToWatchListStageFour(
    boost::uint16_t index,
    boost::shared_ptr<WatchListOpData> data) {
  boost::mutex::scoped_lock lock(data->mutex);
#ifdef DEBUG
//   printf("In MSM::AddToWatchListStageFour (%d) for chunk %s\n",
//          kad_ops_->Port(), HexSubstr(data->store_data->data_name).c_str());
#endif
  if (data->consensus_upload_copies >= 0)
    // Consensus has already been achieved and acted upon
    return;
  ++data->returned_count;
  WatchListOpData::AddToWatchDataHolder &holder =
      data->add_to_watchlist_data_holders.at(index);

  if (!holder.response.IsInitialized()) {
#ifdef DEBUG
    printf("In MSM::AddToWatchListStageFour (%d), response %u is uninitialised."
           "\n", kad_ops_->Port(), index);
#endif
  } else if (holder.response.result() != kAck) {
#ifdef DEBUG
    printf("In MSM::AddToWatchListStageFour (%d), response %u has result %i.\n",
           kad_ops_->Port(), index, holder.response.result());
#endif
  } else if (holder.response.pmid() != holder.node_id) {
#ifdef DEBUG
    printf("In MSM::AddToWatchListStageFour (%d), resp %u from %s has pmid %s."
           "\n", kad_ops_->Port(), index, HexSubstr(holder.node_id).c_str(),
           HexSubstr(holder.response.pmid()).c_str());
#endif
    // TODO(Fraser#5#): 2010-01-08 - Send alert to holder.node_id's A/C holders
  } else if (holder.response.upload_count() > kMinChunkCopies) {
#ifdef DEBUG
    printf("In MSM::AddToWatchListStageFour (%d), response %u from %s has "
           "upload_count of %u.\n", kad_ops_->Port(), index,
           HexSubstr(holder.node_id).c_str(), holder.response.upload_count());
#endif
    // TODO(Fraser#5#): 2010-01-08 - Send alert to holder.node_id's A/C holders
  } else {
    data->required_upload_copies.insert(holder.response.upload_count());
    data->payment_values.push_back(holder.response.total_payment());
  }

  int result = AssessUploadCounts(data);
  if (result == kSuccess) {
    boost::uint64_t payment;
    size_t n;
    GetFilteredAverage(data->payment_values, &payment, &n);
    account_status_manager_.AmendmentDone(AmendAccountRequest::kSpaceTakenInc,
                                          payment);
    // TODO(#Steve) if no payment, success for confirmation task

    if (data->consensus_upload_copies > 0) {
      // create chunk copy master task, depends on success of copy uploads
      VoidFuncTaskIdInt callback =
          boost::bind(&MaidsafeStoreManager::DebugSubTaskCallback, this, _1, _2,
                      "ChunkCopyMaster");
      int task_res = tasks_handler_.AddChildTask(data->store_data->data_name,
          data->store_data->master_task_id, kChunkCopyMaster,
          data->consensus_upload_copies, kMaxStoreFailures, callback,
          &data->store_data->chunk_copy_master_task_id);
      if (task_res != kSuccess) {
#ifdef DEBUG
        printf("In MSM::AddToWatchListStageFour (%d), could not create master "
               "task for copy of chunk %s (%d).\n", kad_ops_->Port(),
               HexSubstr(data->store_data->data_name).c_str(), task_res);
#endif
        tasks_handler_.NotifyTaskFailure(data->task_id,
                                         static_cast<ReturnCode>(task_res));
        return;
      }

      // store copy on own vault
//       kad::Contact vault_contact_;
//       if (own_vault_.GetContact(&vault_contact_))
//         StoreChunkCopy(data->store_data, vault_contact_);

      // store copies on peer vaults
      for (int i = 0; i < data->consensus_upload_copies; ++i)
        StoreChunkCopy(data->store_data);
    }
    tasks_handler_.NotifyTaskSuccess(data->task_id);
  } else if (result != kRequestPendingConsensus) {
#ifdef DEBUG
    printf("In MSM::AddToWatchListStageFour (%d), could not reach consensus "
           "for number of copies of chunk %s (%d).\n", kad_ops_->Port(),
           HexSubstr(data->store_data->data_name).c_str(), result);
#endif
    tasks_handler_.NotifyTaskFailure(data->task_id,
                                     static_cast<ReturnCode>(result));
  }
}

void MaidsafeStoreManager::ExpectAmendment(
    const std::string &chunkname,
    const AmendAccountRequest::Amendment &amendment_type,
    const std::string &pmid,
    const std::string &public_key,
    const std::string &public_key_signature,
    const std::string &private_key,
    DirType dir_type,
    const std::vector<kad::Contact> &chunk_info_holders,
    const VoidFuncOneInt &callback) {
  std::vector<kad::Contact> account_holders =
      account_holders_manager_.account_holder_group();
  if (account_holders.size() < kUpperThreshold_) {
#ifdef DEBUG
    printf("In MSM::ExpectAmendment (%d), no account holders available.\n",
            kad_ops_->Port());
#endif
    // TODO(Team#) rather schedule retry dependent on AH manager update?
    account_holders_manager_.Update();
    callback(kFindAccountHoldersError);
    return;
  }

  if (chunk_info_holders.empty()) {
#ifdef DEBUG
    printf("In MSM::ExpectAmendment (%d), no Chunk Info Holders passed.\n",
            kad_ops_->Port());
#endif
    callback(kGeneralError);
    return;
  }

  std::vector<ExpectAmendmentRequest> expect_amendment_requests;
  ExpectAmendmentRequest request;
  request.set_amendment_type(amendment_type);
  request.set_chunkname(chunkname);
  request.set_account_pmid(pmid);
  request.set_public_key(public_key);
  request.set_public_key_signature(public_key_signature);
  for (size_t i = 0; i < chunk_info_holders.size(); ++i) {
    request.add_amender_pmids(
        chunk_info_holders.at(i).node_id().String());
  }
  for (size_t i = 0; i < account_holders.size(); ++i) {
    std::string signature;
    GetRequestSignature(chunkname, dir_type,
                        account_holders.at(i).node_id().String(),
                        public_key, public_key_signature, private_key,
                        &signature);
    if (signature.empty()) {
#ifdef DEBUG
      printf("In MSM::ExpectAmendment (%d), failed to generate request "
             "signature.\n", kad_ops_->Port());
#endif
      callback(kGetRequestSigError);
      return;
    }
    request.set_request_signature(signature);
    expect_amendment_requests.push_back(request);
  }

  boost::shared_ptr<ExpectAmendmentOpData> data(new ExpectAmendmentOpData);
  data->callback = callback;

  // Set up holders for forthcoming RPCs
  for (size_t i = 0; i < account_holders.size(); ++i) {
    ExpectAmendmentOpData::AccountDataHolder holder(
        account_holders.at(i).node_id().String());
    data->account_data_holders.push_back(holder);
  }

  // Send ExpectAmendment RPCs
  boost::mutex::scoped_lock lock(data->mutex);
  for (size_t j = 0; j < account_holders.size(); ++j) {
    google::protobuf::Closure* callback = google::protobuf::NewCallback(this,
        &MaidsafeStoreManager::ExpectAmendmentCallback, j, data);
    client_rpcs_->ExpectAmendment(account_holders.at(j),
        kad_ops_->AddressIsLocal(account_holders.at(j)),
        transport_.transport_id(), &expect_amendment_requests.at(j),
        &data->account_data_holders.at(j).response,
        data->account_data_holders.at(j).controller.get(), callback);
  }
}

void MaidsafeStoreManager::ExpectAmendmentCallback(
    size_t index,
    boost::shared_ptr<ExpectAmendmentOpData> data) {
  ReturnCode result(kGeneralError);
  VoidFuncOneInt callback;
  {
    boost::mutex::scoped_lock lock(data->mutex);
#ifdef DEBUG
//     printf("In MSM::ExpectAmendmentCallback (%d) for chunk %s\n",
//            kad_ops_->Port(), HexSubstr(data->chunkname).c_str());
#endif
    if (data->success_count >= kUpperThreshold_)
      return;
    ++data->returned_count;
    ExpectAmendmentOpData::AccountDataHolder &holder =
        data->account_data_holders.at(index);

    if (!holder.response.IsInitialized()) {
#ifdef DEBUG
      printf("In MSM::ExpectAmendmentCallback (%d), response %u is "
            "uninitialised.\n", kad_ops_->Port(), index);
#endif
      account_holders_manager_.ReportFailure(holder.node_id);
    } else if (holder.response.result() != kAck) {
#ifdef DEBUG
      printf("In MSM::ExpectAmendmentCallback (%d), response %u has result "
            "%i.\n", kad_ops_->Port(), index, holder.response.result());
#endif
    } else if (holder.response.pmid() != holder.node_id) {
#ifdef DEBUG
      printf("In MSM::ExpectAmendmentCallback (%d), resp %u from %s has pmid "
            "%s.\n", kad_ops_->Port(), index,
            HexSubstr(holder.node_id).c_str(),
            HexSubstr(holder.response.pmid()).c_str());
#endif
      // TODO(Fraser#5#): 2010-01-08 - Send alert to holder.node_id's A/C hldrs
    } else {
      ++data->success_count;
    }

    if (data->returned_count < kUpperThreshold_ ||
        (data->returned_count < data->account_data_holders.size() &&
        data->success_count < kUpperThreshold_)) {
      // still waiting for consensus
      return;
    } else if (data->success_count < kUpperThreshold_) {
      // failed to get enough positive responses
#ifdef DEBUG
      printf("In MSM::ExpectAmendmentCallback (%d), not enough positive "
             "responses.\n", kad_ops_->Port());
#endif
      result = kRequestFailedConsensus;
    } else {
      result = kSuccess;
    }

    callback = data->callback;
  }

  if (callback)
    callback(result);
}

int MaidsafeStoreManager::AssessUploadCounts(
    boost::shared_ptr<WatchListOpData> data) {
  int discrete_opinions(0);
  size_t max_count(0);
  std::multiset<int>::iterator it;
  // data->mutex should already be locked, but just in case...
  boost::mutex::scoped_try_lock lock(data->mutex);
  if (data->returned_count < kUpperThreshold_)
    return kRequestPendingConsensus;

  // Get most common upload_copies figure
  std::multiset<int> copy_required_upload_copies(data->required_upload_copies);
  while (!copy_required_upload_copies.empty()) {
    int current_copies = *(copy_required_upload_copies.begin());
    size_t current_count = copy_required_upload_copies.erase(current_copies);
    if (current_count > max_count) {
      max_count = current_count;
      data->consensus_upload_copies = current_copies;
    } else if (current_count == max_count &&
               current_copies > data->consensus_upload_copies) {
      data->consensus_upload_copies = current_copies;
    }
    ++discrete_opinions;
  }

  if (discrete_opinions == 1 && max_count >= kUpperThreshold_)
    return kSuccess;

  // If no more results due, try to get consensus.
  if (data->returned_count >= data->add_to_watchlist_data_holders.size()) {
    if (discrete_opinions == 0) {
      data->consensus_upload_copies = 0;
      return kRequestFailedConsensus;
    }
  } else {
    data->consensus_upload_copies = -1;
    return kRequestPendingConsensus;
  }

  // If not enough for consensus, return error and set copies to -1.
  if (static_cast<int>(data->required_upload_copies.count(
      data->consensus_upload_copies)) < kLowerThreshold_) {
    data->consensus_upload_copies = 0;
    return kRequestFailedConsensus;
  }

  return kSuccess;
}

bool MaidsafeStoreManager::WaitForOnline(const TaskId &task_id) {
  while (ss_->ConnectionStatus() != 0) {  // offline
  // check task still active
    if (tasks_handler_.Status(task_id) != kTaskActive) {
#ifdef DEBUG
      printf("In MSM::WaitForOnline (%d), task not active (%u).\n",
             kad_ops_->Port(), task_id);
#endif
      return false;
    }
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  }
  return true;
}

int MaidsafeStoreManager::GetStoreRequests(
    boost::shared_ptr<SendChunkData> send_chunk_data) {
  boost::shared_ptr<StoreData> store_data = send_chunk_data->store_data;
  StorePrepRequest &store_prep_request = send_chunk_data->store_prep_request;
  StoreChunkRequest &store_chunk_request = send_chunk_data->store_chunk_request;
  store_prep_request.Clear();
  store_chunk_request.Clear();
  ValueType data_type = DATA;
  if (store_data->dir_type == ANONYMOUS)
    data_type = PDDIR_NOTSIGNED;
  ChunkType chunk_type = store_data->chunk_type;
  fs::path chunk_path(client_chunkstore_->GetChunkPath(store_data->data_name,
                                                       chunk_type, false));
  if (chunk_path.empty())
    return kChunkNotInChunkstore;
  boost::uint64_t chunk_size = store_data->size;
  std::string chunk_content;
  try {
    boost::scoped_ptr<char>
        temp(new char[static_cast<unsigned int>(chunk_size)]);
    fs::ifstream fstr;
    fstr.open(chunk_path, std::ios_base::binary);
    fstr.read(temp.get(), static_cast<std::streamsize>(chunk_size));
    fstr.close();
    chunk_content = std::string(static_cast<const char*>(temp.get()),
                                static_cast<boost::uint64_t>(chunk_size));
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("MaidsafeStoreManager::GetStoreRequests (%d), path: %s - %s\n",
           kad_ops_->Port(), chunk_path.string().c_str(), e.what());
#endif
    return kStoreManagerException;
  }
  std::string request_signature;
  GetRequestSignature(store_data,
      send_chunk_data->peer.node_id().String(), &request_signature);
  if (request_signature.empty())
    return kGetRequestSigError;
  store_prep_request.set_chunkname(store_data->data_name);
  SignedSize *mutable_signed_size = store_prep_request.mutable_signed_size();
  mutable_signed_size->set_data_size(chunk_size);
  mutable_signed_size->set_pmid(store_data->key_id);
  if (store_data->dir_type == ANONYMOUS) {
    mutable_signed_size->set_signature(request_signature);
    mutable_signed_size->set_public_key(" ");
    mutable_signed_size->set_public_key_signature(" ");
    store_prep_request.set_request_signature(request_signature);
  } else {
    crypto::Crypto co;
    co.set_symm_algorithm(crypto::AES_256);
    mutable_signed_size->set_signature(
        co.AsymSign(boost::lexical_cast<std::string>(chunk_size),
                    "", store_data->private_key, crypto::STRING_STRING));
    mutable_signed_size->set_public_key(store_data->public_key);
    mutable_signed_size->set_public_key_signature(
        store_data->public_key_signature);
    store_prep_request.set_request_signature(request_signature);
  }
  store_chunk_request.set_chunkname(store_data->data_name);
  store_chunk_request.set_data(chunk_content);
  store_chunk_request.set_pmid(store_data->key_id);
  store_chunk_request.set_public_key(store_data->public_key);
  store_chunk_request.set_public_key_signature(
      store_data->public_key_signature);
  store_chunk_request.set_request_signature(request_signature);
  store_chunk_request.set_data_type(data_type);
  return kSuccess;
}

int MaidsafeStoreManager::GetAddToWatchListRequests(
    boost::shared_ptr<StoreData> store_data,
    const std::vector<kad::Contact> &recipients,
    std::vector<AddToWatchListRequest> *add_to_watch_list_requests) {
  add_to_watch_list_requests->clear();
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);
  AddToWatchListRequest request;
  request.set_chunkname(store_data->data_name);
  SignedSize *mutable_signed_size = request.mutable_signed_size();
  mutable_signed_size->set_data_size(store_data->size);
  mutable_signed_size->set_signature(
      co.AsymSign(boost::lexical_cast<std::string>(store_data->size), "",
                  store_data->private_key, crypto::STRING_STRING));
  mutable_signed_size->set_pmid(store_data->key_id);
  mutable_signed_size->set_public_key(store_data->public_key);
  mutable_signed_size->set_public_key_signature(
      store_data->public_key_signature);
  for (size_t i = 0; i < recipients.size(); ++i) {
    std::string signature;
    GetRequestSignature(store_data->data_name, store_data->dir_type,
        recipients.at(i).node_id().String(), store_data->public_key,
        store_data->public_key_signature, store_data->private_key, &signature);
    if (signature.empty()) {
      add_to_watch_list_requests->clear();
      return kGetRequestSigError;
    }
    request.set_request_signature(signature);
    add_to_watch_list_requests->push_back(request);
  }
  return kSuccess;
}

int MaidsafeStoreManager::GetRemoveFromWatchListRequests(
    boost::shared_ptr<StoreData> store_data,
    const std::vector<kad::Contact> &recipients,
    std::vector<RemoveFromWatchListRequest> *remove_from_watch_list_requests) {
  remove_from_watch_list_requests->clear();
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);
  RemoveFromWatchListRequest request;
  request.set_chunkname(store_data->data_name);
  request.set_pmid(store_data->key_id);
  request.set_public_key(store_data->public_key);
  request.set_public_key_signature(store_data->public_key_signature);
  for (size_t i = 0; i < recipients.size(); ++i) {
    std::string signature;
    GetRequestSignature(store_data->data_name, store_data->dir_type,
        recipients.at(i).node_id().String(), store_data->public_key,
        store_data->public_key_signature, store_data->private_key, &signature);
    if (signature.empty()) {
      remove_from_watch_list_requests->clear();
      return kGetRequestSigError;
    }
    request.set_request_signature(signature);
    remove_from_watch_list_requests->push_back(request);
  }
  return kSuccess;
}

void MaidsafeStoreManager::GetRequestSignature (
    const std::string &name,
    const DirType dir_type,
    const std::string &recipient_id,
    const std::string &public_key,
    const std::string &public_key_signature,
    const std::string &private_key,
    std::string *request_signature) {
  request_signature->clear();
  if (dir_type == ANONYMOUS) {
    *request_signature = kAnonymousRequestSignature;
  } else if (name.empty()) {
#ifdef DEBUG
    printf("In MSM::GetRequestSignature, the data name is empty.\n");
#endif
    return;
  } else if (recipient_id.empty()) {
#ifdef DEBUG
    printf("In MSM::GetRequestSignature, the recipient ID is empty.\n");
#endif
    return;
  } else if (public_key.empty() ||
             public_key_signature.empty() ||
             private_key.empty()) {
#ifdef DEBUG
    printf("In MSM::GetRequestSignature, a passed key is empty.\n");
#endif
    return;
  } else {
    crypto::Crypto co;
    co.set_symm_algorithm(crypto::AES_256);
    co.set_hash_algorithm(crypto::SHA_512);
    *request_signature = co.AsymSign(co.Hash(public_key_signature + name +
        recipient_id, "", crypto::STRING_STRING, false), "", private_key,
        crypto::STRING_STRING);
  }
}

void MaidsafeStoreManager::GetRequestSignature (
    boost::shared_ptr<StoreData> store_data,
    const std::string &recipient_id,
    std::string *request_signature) {
  GetRequestSignature(store_data->data_name, store_data->dir_type,
      recipient_id, store_data->public_key, store_data->public_key_signature,
      store_data->private_key, request_signature);
}

void MaidsafeStoreManager::StoreChunkCopy(
    boost::shared_ptr<StoreData> store_data) {
  kad::Contact contact;
  StoreChunkCopy(store_data, contact);
}

void MaidsafeStoreManager::StoreChunkCopy(
    boost::shared_ptr<StoreData> store_data,
    const kad::Contact &force_peer) {
#ifdef DEBUG
//   printf("In MSM::StoreChunkCopy (%d) for chunk %s\n",
//          kad_ops_->Port(), HexSubstr(store_data->data_name).c_str());
#endif
  // check store chunk copy master task still active
  if (tasks_handler_.Status(store_data->chunk_copy_master_task_id) !=
      kTaskActive) {
#ifdef DEBUG
    printf("In MSM::StoreChunkCopy (%d), no active chunk copy master task found"
           " (%s).\n",
           kad_ops_->Port(), HexSubstr(store_data->data_name).c_str());
#endif
    return;
  }

  boost::shared_ptr<SendChunkData>
      send_chunk_data(new SendChunkData(store_data));

  // add worker task
  int task_res = tasks_handler_.AddChildTask(store_data->data_name,
      store_data->chunk_copy_master_task_id, kChunkCopy, 2,
      kMaxPerPeerStoreFailures, NULL, &send_chunk_data->chunk_copy_task_id);
  if (task_res != kSuccess) {
#ifdef DEBUG
    printf("In MSM::StoreChunkCopy (%d), could not create worker task for copy "
           "of chunk %s (%d).\n", kad_ops_->Port(),
           HexSubstr(store_data->data_name).c_str(), task_res);
#endif
    tasks_handler_.NotifyTaskFailure(store_data->chunk_copy_master_task_id,
                                     static_cast<ReturnCode>(task_res));
    return;
  }

  if (force_peer.node_id().String() != kad::kZeroId) {
    printf("*** using forced peer: %s\n", HexSubstr(force_peer.node_id().String()).c_str());
    send_chunk_data->peer = force_peer;
  } else {
    double ideal_rtt = 1.0;

    // Ensure we don't find own vault
    if (store_data->exclude_peers.empty())
      store_data->exclude_peers.push_back(kad::Contact(ss_->Id(PMID), "", 0));
    int peer_result =
        kad_ops_->GetStorePeer(ideal_rtt, store_data->exclude_peers,
                              &send_chunk_data->peer, &send_chunk_data->local);

    // If GetStorePeer failed, record failure
    if (peer_result != kSuccess) {
      tasks_handler_.NotifyTaskFailure(send_chunk_data->chunk_copy_task_id,
                                      kGetStorePeerError);
  #ifdef DEBUG
      printf("In MSM::StoreChunkCopy (%d), error getting store peer for %s (%d)."
            "\n", kad_ops_->Port(), HexSubstr(store_data->data_name).c_str(),
            peer_result);
  #endif
      return;
    }
  }

  // Ensure next call of StoreChunkCopy doesn't use same vault
  store_data->exclude_peers.push_back(send_chunk_data->peer);

  DoStorePrep(send_chunk_data);
}


void MaidsafeStoreManager::DoStorePrep(
    boost::shared_ptr<maidsafe::SendChunkData> send_chunk_data) {
#ifdef DEBUG
//   printf("In MSM::DoStorePrep (%d) for chunk %s\n", kad_ops_->Port(),
//          HexSubstr(send_chunk_data->store_data->data_name).c_str());
#endif
  // check chunk copy worker task still active
  if (tasks_handler_.Status(send_chunk_data->chunk_copy_task_id) !=
      kTaskActive) {
#ifdef DEBUG
    printf("In MSM::DoStorePrep (%d), no active chunk copy worker task found "
           "(%s).\n", kad_ops_->Port(),
           HexSubstr(send_chunk_data->store_data->data_name).c_str());
#endif
    return;
  }

  TaskId prep_task_id(kRootTask);
  VoidFuncTaskIdInt cback =
      boost::bind(&MaidsafeStoreManager::ChunkCopyPrepTaskCallback, this, _2,
                  send_chunk_data);
  int task_res =
      tasks_handler_.AddChildTask(send_chunk_data->store_data->data_name,
                                  send_chunk_data->chunk_copy_task_id,
                                  kChunkCopyPrep, 1, 0, cback, &prep_task_id);
  if (task_res != kSuccess) {
#ifdef DEBUG
    printf("In MSM::DoStorePrep (%d), could not create prep task for copy of "
           "chunk %s (%d).\n", kad_ops_->Port(),
           HexSubstr(send_chunk_data->store_data->data_name).c_str(),
           task_res);
#endif
    tasks_handler_.NotifyTaskFailure(send_chunk_data->chunk_copy_task_id,
                                     static_cast<ReturnCode>(task_res));
    return;
  }

  // Form store requests
  int result = GetStoreRequests(send_chunk_data);
  if (result != kSuccess) {
#ifdef DEBUG
    printf("In MSM::DoStorePrep (%d), error getting store requests for %s (%d)."
           "\n", kad_ops_->Port(),
           HexSubstr(send_chunk_data->store_data->data_name).c_str(), result);
#endif
    tasks_handler_.NotifyTaskFailure(send_chunk_data->chunk_copy_task_id,
                                     static_cast<ReturnCode>(result));
    return;
  }

  // Send prep
  google::protobuf::Closure* callback = google::protobuf::NewCallback<
      MaidsafeStoreManager, TaskId, boost::shared_ptr<SendChunkData> >
      (this, &MaidsafeStoreManager::StorePrepCallback, prep_task_id,
      send_chunk_data);
  send_chunk_data->store_prep_response.Clear();
  client_rpcs_->StorePrep(send_chunk_data->peer,
                          send_chunk_data->local,
                          transport_.transport_id(),
                          &send_chunk_data->store_prep_request,
                          &send_chunk_data->store_prep_response,
                          send_chunk_data->controller.get(),
                          callback);
}

void MaidsafeStoreManager::ChunkCopyPrepTaskCallback(
    const ReturnCode &result,
    boost::shared_ptr<SendChunkData> send_chunk_data) {
  if (result != kSuccess)
    DoStorePrep(send_chunk_data);
}

void MaidsafeStoreManager::StorePrepCallback(
    TaskId prep_task_id,
    boost::shared_ptr<SendChunkData> send_chunk_data) {
#ifdef DEBUG
//   printf("In MSM::StorePrepCallback (%d) for chunk %s\n", kad_ops_->Port(),
//          HexSubstr(send_chunk_data->store_data->data_name).c_str());
#endif
  int result = ValidatePrepResponse(
                   send_chunk_data->peer.node_id().String(),
                   send_chunk_data->store_prep_request.signed_size(),
                   &send_chunk_data->store_prep_response);
  if (result != kSuccess) {
#ifdef DEBUG
    printf("In MSM::StorePrepCallback (%d), could not validate prep response "
           "for copy of chunk %s (%d).\n", kad_ops_->Port(),
           HexSubstr(send_chunk_data->store_data->data_name).c_str(),
           result);
#endif
    tasks_handler_.NotifyTaskFailure(prep_task_id,
                                     static_cast<ReturnCode>(result));
    return;
  }

  tasks_handler_.NotifyTaskSuccess(prep_task_id);

  SendChunkCopyTask *send_chunk_copy_task =
      new SendChunkCopyTask(send_chunk_data, this);
  packet_thread_pool_.start(send_chunk_copy_task);
}

int MaidsafeStoreManager::ValidatePrepResponse(
    const std::string &peer_node_id,
    const SignedSize &request_signed_size,
    const StorePrepResponse *store_prep_response) {
  // Check response is initialised and from correct peer
  if (!store_prep_response->IsInitialized())
    return kSendPrepResponseUninitialised;
  StoreContract store_contract = store_prep_response->store_contract();
  if (!store_contract.IsInitialized())
    return kSendPrepResponseUninitialised;
  StoreContract::InnerContract inner_contract = store_contract.inner_contract();
  if (!inner_contract.IsInitialized())
    return kSendPrepResponseUninitialised;
  if (store_contract.pmid() != peer_node_id)
    return kSendPrepPeerError;
  // Check original SignedSize is unaltered
  std::string ser_req_signed_size, ser_resp_signed_size;
  request_signed_size.SerializeToString(&ser_req_signed_size);
  inner_contract.signed_size().SerializeToString(&ser_resp_signed_size);
  if (ser_req_signed_size != ser_resp_signed_size)
    return kSendPrepSignedSizeAltered;
  // Check response is kAck & peer PMID validates
  if (inner_contract.result() != kAck)
    return kSendPrepFailure;
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  if (store_contract.pmid() != co.Hash(store_contract.public_key() +
      store_contract.public_key_signature(), "", crypto::STRING_STRING, false))
    return kSendPrepInvalidId;
  // Check peer correctly signed StoreContract and InnerContract
  std::string ser_store_contract, ser_inner_contract;
  store_contract.SerializeToString(&ser_store_contract);
  inner_contract.SerializeToString(&ser_inner_contract);
  if (!co.AsymCheckSig(ser_store_contract,
                       store_prep_response->response_signature(),
                       store_contract.public_key(),
                       crypto::STRING_STRING))
    return kSendPrepInvalidResponseSignature;
  if (!co.AsymCheckSig(ser_inner_contract, store_contract.signature(),
                       store_contract.public_key(), crypto::STRING_STRING))
    return kSendPrepInvalidContractSignature;
  return kSuccess;
}

void MaidsafeStoreManager::DoStoreChunk(
    boost::shared_ptr<SendChunkData> send_chunk_data) {
#ifdef DEBUG
//   printf("In MSM::DoStoreChunk (%d) for chunk %s\n", kad_ops_->Port(),
//          HexSubstr(send_chunk_data->store_data->data_name).c_str());
#endif
  if (!WaitForOnline(send_chunk_data->chunk_copy_task_id)) {
    return;
  }

  TaskId data_task_id(kRootTask);
  VoidFuncTaskIdInt cback =
      boost::bind(&MaidsafeStoreManager::ChunkCopyDataTaskCallback, this, _2,
                  send_chunk_data);
  int task_res =
      tasks_handler_.AddChildTask(send_chunk_data->store_data->data_name,
                                  send_chunk_data->chunk_copy_task_id,
                                  kChunkCopyData, 1, 0, cback, &data_task_id);
  if (task_res != kSuccess) {
#ifdef DEBUG
    printf("In MSM::DoStoreChunk (%d), could not create data task for copy of "
           "chunk %s (%d).\n", kad_ops_->Port(),
           HexSubstr(send_chunk_data->store_data->data_name).c_str(), task_res);
#endif
    tasks_handler_.NotifyTaskFailure(send_chunk_data->chunk_copy_task_id,
                                     static_cast<ReturnCode>(task_res));
    return;
  }

  // Send chunk content
  google::protobuf::Closure* callback = google::protobuf::NewCallback<
      MaidsafeStoreManager, TaskId, boost::shared_ptr<SendChunkData> >
      (this, &MaidsafeStoreManager::StoreChunkCallback, data_task_id,
      send_chunk_data);
  client_rpcs_->StoreChunk(send_chunk_data->peer,
                           send_chunk_data->local,
                           transport_.transport_id(),
                           &send_chunk_data->store_chunk_request,
                           &send_chunk_data->store_chunk_response,
                           send_chunk_data->controller.get(),
                           callback);
}

void MaidsafeStoreManager::ChunkCopyDataTaskCallback(
    const ReturnCode &result,
    boost::shared_ptr<SendChunkData> send_chunk_data) {
  if (result != kSuccess)
    DoStoreChunk(send_chunk_data);
}

void MaidsafeStoreManager::StoreChunkCallback(
    TaskId data_task_id,
    boost::shared_ptr<SendChunkData> send_chunk_data) {
#ifdef DEBUG
//   printf("In MSM::StoreChunkCallback (%d) for chunk %s\n", kad_ops_->Port(),
//          HexSubstr(send_chunk_data->store_data->data_name).c_str());
#endif
  StoreChunkResponse &response = send_chunk_data->store_chunk_response;
  int result(kSuccess);
  if (!response.IsInitialized()) {
#ifdef DEBUG
    printf("In MSM::StoreChunkCallback (%d), resp from pmid %s uninitialised."
           "\n", kad_ops_->Port(),
          HexSubstr(send_chunk_data->peer.node_id().String()).c_str());
#endif
    result = kSendContentFailure;
  } else if (response.pmid() !=
             send_chunk_data->peer.node_id().String()) {
#ifdef DEBUG
    printf("In MSM::StoreChunkCallback (%d), IDs are not OK: response pmid %s, "
           "peer node ID %s\n", kad_ops_->Port(),
           HexSubstr(response.pmid()).c_str(),
           HexSubstr(send_chunk_data->peer.node_id().String()).c_str());
#endif
    result = kSendContentFailure;
  } else if (response.result() != kAck) {
#ifdef DEBUG
    printf("In MSM::StoreChunkCallback (%d), resp from PMID %s returned %u\n",
           kad_ops_->Port(),
           HexSubstr(send_chunk_data->peer.node_id().String()).c_str(),
           response.result());
#endif
    result = kSendContentFailure;
  }

  if (result != kSuccess) {
    tasks_handler_.NotifyTaskFailure(data_task_id,
                                     static_cast<ReturnCode>(result));
    return;
  }

  std::string chunkname = send_chunk_data->store_data->data_name;
#ifdef DEBUG
//  printf("In MSM::StoreChunkCallback (%d), successfully stored copy of %s.\n",
//           kad_ops_->Port(), HexSubstr(chunkname).c_str());
#endif
  tasks_handler_.NotifyTaskSuccess(data_task_id);

  // TODO(Fraser#5#): 2009-08-14 - Check later that there are enough vaults
  // listed in ref & watch lists to ensure upload ultimately successful.

  // Move chunk from Outgoing to Normal.  If this operation fails, still
  // return kSuccess as this is non-critical.
  ChunkType chunk_type = client_chunkstore_->chunk_type(chunkname);
  ChunkType new_type = chunk_type ^ (kOutgoing | kNormal);
  if (client_chunkstore_->ChangeChunkType(chunkname, new_type) != kSuccess) {
#ifdef DEBUG
    printf("In MSM::StoreChunkCallback (%d), failed to change chunk type.\n",
           kad_ops_->Port());
#endif
  }
}

int MaidsafeStoreManager::RemoveFromWatchList(
    boost::shared_ptr<StoreData> store_data) {
  // TODO(Team#) Merge following stages with AddToWatchList, much redundancy

  // check for DeleteChunk task and RemFromWL master task, added by DeleteChunk
  if (tasks_handler_.Status(store_data->master_task_id) != kTaskActive) {
#ifdef DEBUG
    printf("In MSM::RemoveFromWatchList (%d), DeleteChunk task not active (%s)."
           "\n", kad_ops_->Port(), HexSubstr(store_data->data_name).c_str());
#endif
    return kGeneralError;
  }

  TaskId parent_task_id(store_data->watchlist_master_task_id);
  if (tasks_handler_.Status(parent_task_id) != kTaskActive) {
#ifdef DEBUG
    printf("In MSM::RemoveFromWatchList (%d), no active master task (%s).\n",
           kad_ops_->Port(), HexSubstr(store_data->data_name).c_str());
#endif
    return kGeneralError;
  }

  // Add sub-task, for potential re-tries
  VoidFuncTaskIdInt callback =
      boost::bind(&MaidsafeStoreManager::RemoveFromWatchListTaskCallback, this,
                  _2, store_data);
  boost::shared_ptr<WatchListOpData> data(new WatchListOpData(store_data));
  if (tasks_handler_.AddChildTask(store_data->data_name, parent_task_id,
      kRemoveFromWatchList, 1, 0, callback, &data->task_id) != kSuccess) {
#ifdef DEBUG
    printf("In MSM::RemoveFromWatchList (%d), could not add sub-task to %s.\n",
           kad_ops_->Port(), HexSubstr(store_data->data_name).c_str());
#endif
    return kGeneralError;
  }

  // Find the Chunk Info holders
  kad_ops_->FindKClosestNodes(store_data->data_name,
      boost::bind(&MaidsafeStoreManager::RemoveFromWatchListStageTwo, this, _1,
                  _2, data));
  return kSuccess;
}

void MaidsafeStoreManager::RemoveFromWatchListTaskCallback(
    const ReturnCode &result,
    boost::shared_ptr<StoreData> store_data) {
  if (result != kSuccess) {
#ifdef DEBUG
    printf("In MSM::RemoveFromWatchListTaskCallback (%d), removing %s failed "
           "(%d).\n", kad_ops_->Port(),
           HexSubstr(store_data->data_name).c_str(), result);
#endif
    RemoveFromWatchList(store_data);
  }
}

void MaidsafeStoreManager::RemoveFromWatchListStageTwo(
    const ReturnCode &result,
    const std::vector<kad::Contact> &chunk_info_holders,
    boost::shared_ptr<WatchListOpData> data) {
  if (result != kSuccess || chunk_info_holders.size() < kUpperThreshold_) {
#ifdef DEBUG
    printf("In MSM::RemoveFromWatchListStageTwo (%d), could not find chunk "
           "info holders for %s.\n", kad_ops_->Port(),
           HexSubstr(data->store_data->data_name).c_str());
#endif
    tasks_handler_.NotifyTaskFailure(data->task_id,
                                     kDeleteChunkFindNodesFailure);
    return;
  }

  data->chunk_info_holders = chunk_info_holders;

  // TODO(Steve#) don't expect amendment in every case (long WL or last entry)
  ExpectAmendment(data->store_data->data_name,
                  AmendAccountRequest::kSpaceTakenDec,
                  data->store_data->key_id,
                  data->store_data->public_key,
                  data->store_data->public_key_signature,
                  data->store_data->private_key,
                  data->store_data->dir_type,
                  chunk_info_holders,
                  boost::bind(
                      &MaidsafeStoreManager::RemoveFromWatchListStageThree,
                      this, _1, data));
}

void MaidsafeStoreManager::RemoveFromWatchListStageThree(
    const ReturnCode &result,
    boost::shared_ptr<WatchListOpData> data) {
  boost::mutex::scoped_lock lock(data->mutex);
  if (result != kSuccess) {
#ifdef DEBUG
    printf("In MSM::RemoveFromWatchListStageThree (%d), ExpectAmendment "
           "failed.\n", kad_ops_->Port());
#endif
    tasks_handler_.NotifyTaskFailure(data->task_id, result);
    return;
  }

  // Set up holders for forthcoming RemoveFromWatchList RPCs
  std::vector<RemoveFromWatchListRequest> remove_from_watch_list_requests;
  if (GetRemoveFromWatchListRequests(data->store_data, data->chunk_info_holders,
      &remove_from_watch_list_requests) != kSuccess) {
#ifdef DEBUG
    printf("In MSM::RemoveFromWatchListStageThree (%d), failed to generate "
           "requests.\n", kad_ops_->Port());
#endif
    tasks_handler_.NotifyTaskFailure(data->task_id, kDeleteChunkError);
    return;
  }

  for (size_t i = 0; i < data->chunk_info_holders.size(); ++i) {
    WatchListOpData::RemoveFromWatchDataHolder holder(
        data->chunk_info_holders.at(i).node_id().String());
    data->remove_from_watchlist_data_holders.push_back(holder);
  }

  // Send RemoveFromWatchList RPCs
  for (boost::uint16_t j = 0; j < data->chunk_info_holders.size(); ++j) {
    google::protobuf::Closure* callback = google::protobuf::NewCallback(this,
        &MaidsafeStoreManager::RemoveFromWatchListStageFour, j, data);
    client_rpcs_->RemoveFromWatchList(data->chunk_info_holders.at(j),
        kad_ops_->AddressIsLocal(data->chunk_info_holders.at(j)),
        transport_.transport_id(),
        &remove_from_watch_list_requests.at(j),
        &data->remove_from_watchlist_data_holders.at(j).response,
        data->remove_from_watchlist_data_holders.at(j).controller.get(),
        callback);
  }
}

void MaidsafeStoreManager::RemoveFromWatchListStageFour(
    boost::uint16_t index,
    boost::shared_ptr<WatchListOpData> data) {
  boost::mutex::scoped_lock lock(data->mutex);
  if (data->success_count >= kUpperThreshold_)
    // Success has already been achieved and acted upon
    return;
  ++data->returned_count;
  WatchListOpData::RemoveFromWatchDataHolder &holder =
      data->remove_from_watchlist_data_holders.at(index);

  if (!holder.response.IsInitialized()) {
#ifdef DEBUG
    printf("In MSM::RemoveFromWatchListStageFour (%d), response %u "
           "uninitialised.\n", kad_ops_->Port(), index);
#endif
  } else if (holder.response.result() != kAck) {
#ifdef DEBUG
    printf("In MSM::RemoveFromWatchListStageFour (%d), response %u has result "
           "%i.\n", kad_ops_->Port(), index, holder.response.result());
#endif
  } else if (holder.response.pmid() != holder.node_id) {
#ifdef DEBUG
    printf("In MSM::RemoveFromWatchListStageFour (%d), response %u from %s has "
           "pmid %s.\n", kad_ops_->Port(), index,
           HexSubstr(holder.node_id).c_str(),
           HexSubstr(holder.response.pmid()).c_str());
#endif
    // TODO(Fraser#5#): 2010-01-08 - Send alert to holder.node_id's A/C holders
  } else {
    ++data->success_count;
  }

  // Overall success
  if (data->success_count >= kUpperThreshold_) {
    tasks_handler_.NotifyTaskSuccess(data->task_id);
    account_status_manager_.AmendmentDone(
        AmendAccountRequest::kSpaceTakenDec, data->store_data->size);
    return;
  }
  // Overall failure
  if (data->returned_count >= data->chunk_info_holders.size())
    tasks_handler_.NotifyTaskFailure(data->task_id, kDeleteChunkFailure);
}

int MaidsafeStoreManager::GetChunk(const std::string &chunk_name,
                                   const kad::Contact &chunk_holder,
                                   std::string *data) {
  // TODO(Team#) make GetChunk non-blocking
  GetChunkRequest request;
  request.set_chunkname(chunk_name);
  GetChunkResponse response;
  bool done(false);
  boost::mutex mutex;
  boost::condition_variable condition;

  google::protobuf::Closure* callback = google::protobuf::NewCallback(this,
      &MaidsafeStoreManager::GetChunkCallback, &done,
      std::pair<boost::mutex*, boost::condition_variable*>(&mutex, &condition));
  rpcprotocol::Controller controller;
  {
    boost::mutex::scoped_lock lock(mutex);
    client_rpcs_->GetChunk(chunk_holder, kad_ops_->AddressIsLocal(chunk_holder),
                           transport_.transport_id(), &request, &response,
                           &controller, callback);
    while (!done)
      condition.wait(lock);
  }

  if (!response.IsInitialized() || response.result() != kAck) {
#ifdef DEBUG
    printf("In MSM::GetChunk (%d), could not get chunk %s.\n",
           kad_ops_->Port(), HexSubstr(chunk_name).c_str());
#endif
    return kGetChunkFailure;
  }

  *data = response.content();
  return kSuccess;
}

void MaidsafeStoreManager::GetChunkCallback(bool *done,
    std::pair<boost::mutex*, boost::condition_variable*> sync) {
#ifdef DEBUG
  // printf("In MaidsafeStoreManager::GetChunkCallback\n");
#endif
  boost::mutex::scoped_lock lock(*sync.first);
  *done = true;
  sync.second->notify_one();
}

void MaidsafeStoreManager::SendPacket(boost::shared_ptr<StoreData> store_data) {
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);
  kad::SignedValue signed_value;
  signed_value.set_value(store_data->value);
  signed_value.set_value_signature(co.AsymSign(store_data->value, "",
      store_data->private_key, crypto::STRING_STRING));
  std::string signed_request = co.AsymSign(co.Hash(store_data->public_key +
      store_data->public_key_signature + store_data->data_name, "",
      crypto::STRING_STRING, false), "", store_data->private_key,
      crypto::STRING_STRING);
  kad::SignedRequest sr;
  sr.set_signer_id(store_data->key_id);
  sr.set_public_key(store_data->public_key);
  sr.set_signed_public_key(store_data->public_key_signature);
  sr.set_signed_request(signed_request);
  kad::VoidFunctorOneString cb = boost::bind(
      &MaidsafeStoreManager::SendPacketCallback, this, _1, store_data);
  kad_ops_->StoreValue(store_data->data_name, signed_value, sr, cb);
}

void MaidsafeStoreManager::SendPacketCallback(
    const std::string &ser_kad_store_result,
    boost::shared_ptr<StoreData> store_data) {
  if (ser_kad_store_result.empty()) {
#ifdef DEBUG
    printf("In MSM::SendPacketCallback (%d), fail - timeout.\n",
           kad_ops_->Port());
#endif
    store_data->callback(kSendPacketError);
    return;
  }
  kad::StoreResponse store_response;
  if (!store_response.ParseFromString(ser_kad_store_result)) {
#ifdef DEBUG
    printf("In MSM::SendPacketCallback (%d), can't parse result.\n",
           kad_ops_->Port());
#endif
    store_data->callback(kSendPacketParseError);
    return;
  }
  if (store_response.result() != kad::kRpcResultSuccess) {
#ifdef DEBUG
    printf("In MSM::SendPacketCallback (%d), Kademlia operation failed.\n",
           kad_ops_->Port());
#endif
    store_data->callback(kSendPacketFailure);
    return;
  }
  store_data->callback(kSuccess);
}

std::string MaidsafeStoreManager::GetValueFromSignedValue(
    const std::string &serialised_signed_value) {
  kad::SignedValue signed_value;
  if (!signed_value.ParseFromString(serialised_signed_value)) {
#ifdef DEBUG
    printf("In MSM::GetValueFromSignedValue, can't parse signed value.\n");
#endif
    return "";
  } else {
    return signed_value.value();
  }
}

void MaidsafeStoreManager::DeletePacketFromNet(
    boost::shared_ptr<DeletePacketData> delete_data) {
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);
  kad::VoidFunctorOneString cb = boost::bind(
      &MaidsafeStoreManager::DeletePacketCallback, this, _1, delete_data);
  boost::mutex::scoped_lock lock(delete_data->mutex);
  for (size_t i = 0; i < delete_data->values.size(); ++i) {
    kad::SignedValue signed_value;
    signed_value.set_value(delete_data->values.at(i));
    signed_value.set_value_signature(co.AsymSign(delete_data->values.at(i), "",
        delete_data->private_key, crypto::STRING_STRING));
    std::string signed_request = co.AsymSign(co.Hash(delete_data->public_key +
        delete_data->public_key_signature + delete_data->packet_name,
        "", crypto::STRING_STRING, false), "", delete_data->private_key,
        crypto::STRING_STRING);
    kad::SignedRequest sr;
    sr.set_signer_id(delete_data->key_id);
    sr.set_public_key(delete_data->public_key);
    sr.set_signed_public_key(delete_data->public_key_signature);
    sr.set_signed_request(signed_request);
    kad_ops_->DeleteValue(delete_data->packet_name, signed_value, sr, cb);
  }
}

void MaidsafeStoreManager::DeletePacketCallback(
    const std::string &ser_kad_delete_result,
    boost::shared_ptr<DeletePacketData> delete_data) {
  if (delete_data->called_back)
    return;
  if (ser_kad_delete_result.empty()) {
#ifdef DEBUG
    printf("In MSM::DeletePacketCallback (%d), fail - timeout.\n",
           kad_ops_->Port());
#endif
    boost::mutex::scoped_lock lock(delete_data->mutex);
    delete_data->callback(kDeletePacketError);
    delete_data->called_back = true;
    return;
  }
  kad::DeleteResponse delete_response;
  if (!delete_response.ParseFromString(ser_kad_delete_result)) {
#ifdef DEBUG
    printf("In MSM::DeletePacketCallback (%d), can't parse result.\n",
           kad_ops_->Port());
#endif
    boost::mutex::scoped_lock lock(delete_data->mutex);
    delete_data->callback(kDeletePacketParseError);
    delete_data->called_back = true;
    return;
  }
  if (delete_response.result() != kad::kRpcResultSuccess) {
#ifdef DEBUG
    printf("In MSM::DeletePacketCallback (%d), Kademlia operation failed.\n",
           kad_ops_->Port());
#endif
    boost::mutex::scoped_lock lock(delete_data->mutex);
    delete_data->callback(kDeletePacketFailure);
    delete_data->called_back = true;
    return;
  }
  boost::mutex::scoped_lock lock(delete_data->mutex);
  ++delete_data->returned_count;
  if (delete_data->returned_count >= delete_data->values.size()) {
    delete_data->callback(kSuccess);
    delete_data->called_back = true;
  }
}

void MaidsafeStoreManager::PollVaultInfo(kad::VoidFunctorOneString cb) {
  VaultCommunication vc;
  vc.set_chunkstore("YES");
  vc.set_offered_space(0);
  vc.set_free_space(0);
  vc.set_ip("YES");
  vc.set_port(0);
  vc.set_timestamp(base::GetEpochTime());
  std::string ser_vc;
  vc.SerializeToString(&ser_vc);
  crypto::Crypto co;
  std::string enc_ser_vc = co.AsymEncrypt(ser_vc, "", ss_->PublicKey(PMID),
                           crypto::STRING_STRING);
  VaultStatusResponse vault_status_response;
  google::protobuf::Closure *done =
      google::protobuf::NewCallback<MaidsafeStoreManager,
      const VaultStatusResponse*, kad::VoidFunctorOneString>
      (this, &MaidsafeStoreManager::PollVaultInfoCallback,
      &vault_status_response, cb);
  rpcprotocol::Controller *controller = new rpcprotocol::Controller;
  rpcprotocol::Channel *channel = new rpcprotocol::Channel(
      &channel_manager_, &transport_handler_, transport_.transport_id(),
      ss_->VaultIP(), ss_->VaultPort(), "", 0, "", 0);
  client_rpcs_->PollVaultInfo(enc_ser_vc, &vault_status_response, controller,
      channel, done);
}

void MaidsafeStoreManager::PollVaultInfoCallback(
    const VaultStatusResponse *response,
    kad::VoidFunctorOneString cb) {
  std::string result;
  if (!response->IsInitialized()) {
    cb("FAIL");
    return;
  }
  if (response->result() != kAck) {
    cb("FAIL");
    return;
  }

  crypto::Crypto co;
  std::string unenc = co.AsymDecrypt(response->encrypted_response(), "",
                      ss_->PrivateKey(PMID), crypto::STRING_STRING);

  VaultCommunication vc;
  if (!vc.ParseFromString(unenc)) {
    cb("FAIL");
    return;
  }

  if (vc.chunkstore().empty() && vc.offered_space() == 0 &&
      vc.free_space() == 0 && vc.ip().empty() && vc.port() == 0) {
    cb("FAIL");
    return;
  }

  std::string ser_vc;
  vc.SerializeToString(&ser_vc);
  cb(ser_vc);
}

bool MaidsafeStoreManager::VaultContactInfo(kad::Contact *contact) {
//   return kSuccess == kad_ops_->BlockingGetNodeContactDetails(ss_->Id(PMID),
//                                                              contact, false);
  own_vault_.WaitForUpdate();
  return own_vault_.GetContact(contact);
}

void MaidsafeStoreManager::SetLocalVaultOwned(
    const std::string &priv_key,
    const std::string &pub_key,
    const std::string &signed_pub_key,
    const boost::uint32_t &port,
    const std::string &vault_dir,
    const boost::uint64_t &space,
    const SetLocalVaultOwnedFunctor &functor) {
  boost::shared_ptr<SetLocalVaultOwnedCallbackArgs>
      cb_args(new SetLocalVaultOwnedCallbackArgs(functor));
  // 20 seconds, since the rpc is replied after the vault has
  // started successfully
  cb_args->ctrl->set_timeout(20);
  SetLocalVaultOwnedRequest request;
  request.set_private_key(priv_key);
  request.set_public_key(pub_key);
  request.set_signed_public_key(signed_pub_key);
  request.set_port(port);
  request.set_vault_dir(vault_dir);
  request.set_space(space);
  rpcprotocol::Channel channel(&channel_manager_, &transport_handler_,
                               transport_.transport_id(), "127.0.0.1",
                               kLocalPort, "", 0, "", 0);
  google::protobuf::Closure *done = google::protobuf::NewCallback(this,
      &MaidsafeStoreManager::SetLocalVaultOwnedCallback, cb_args);
  client_rpcs_->SetLocalVaultOwned(&request, cb_args->response, cb_args->ctrl,
      &channel, done);
}

void MaidsafeStoreManager::SetLocalVaultOwnedCallback(
    boost::shared_ptr<SetLocalVaultOwnedCallbackArgs> callback_args) {
  if (callback_args->ctrl->Failed() ||
      !callback_args->response->IsInitialized()) {
    if (callback_args->ctrl->ErrorText() == rpcprotocol::kTimeOut)
      callback_args->cb(VAULT_IS_DOWN, "");
    else
      callback_args->cb(INVALID_OWNREQUEST, "");
    return;
  }
  std::string pmid_name;
  if (callback_args->response->has_pmid_name())
    pmid_name = callback_args->response->pmid_name();
  OwnLocalVaultResult result = callback_args->response->result();
  callback_args->cb(result, pmid_name);
}

void MaidsafeStoreManager::LocalVaultOwned(
    const LocalVaultOwnedFunctor &functor) {
  boost::shared_ptr<LocalVaultOwnedCallbackArgs>
      cb_args(new LocalVaultOwnedCallbackArgs(functor));
  rpcprotocol::Channel channel(&channel_manager_, &transport_handler_,
                               transport_.transport_id(), "127.0.0.1",
                               kLocalPort, "", 0, "", 0);
  google::protobuf::Closure *done = google::protobuf::NewCallback(this,
      &MaidsafeStoreManager::LocalVaultOwnedCallback, cb_args);
  client_rpcs_->LocalVaultOwned(cb_args->response, cb_args->ctrl, &channel,
      done);
}

void MaidsafeStoreManager::LocalVaultOwnedCallback(
    boost::shared_ptr<LocalVaultOwnedCallbackArgs> callback_args) {
  if (callback_args->ctrl->Failed() ||
      !callback_args->response->IsInitialized()) {
    if (callback_args->ctrl->ErrorText() == rpcprotocol::kTimeOut)
      callback_args->cb(DOWN);
    else
      callback_args->cb(ISOWNRPC_CANCELLED);
    return;
  }
  VaultStatus result = callback_args->response->status();
  callback_args->cb(result);
}

bool MaidsafeStoreManager::NotDoneWithUploading() {
#ifdef DEBUG
  printf("MaidsafeStoreManager::NotDoneWithUploading %d -- %d -- %u\n",
         chunk_thread_pool_.activeThreadCount(),
         packet_thread_pool_.activeThreadCount(),
         tasks_handler_.TasksCount());
#endif
  if (chunk_thread_pool_.activeThreadCount() == 0 &&
      packet_thread_pool_.activeThreadCount() == 0) {
    return false;
  } else {
    return true;
  }
}

int MaidsafeStoreManager::CreateAccount(const boost::uint64_t &space) {
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);
  std::string account_name = co.Hash(ss_->Id(PMID) + kAccount, "",
                                     crypto::STRING_STRING, false);

  boost::shared_ptr<AmendAccountData> data(new AmendAccountData);
  boost::mutex::scoped_lock lock(data->mutex);

#ifdef DEBUG
  printf("In MSM::CreateAccount, name of PMID: %s, name of account: %s\n",
         HexSubstr(ss_->Id(PMID)).c_str(), HexSubstr(account_name).c_str());
#endif

  data->contacts = account_holders_manager_.account_holder_group();

  if (data->contacts.size() < kUpperThreshold_) {
#ifdef DEBUG
    printf("In MSM::CreateAccount (%d), account holders not available.\n",
           kad_ops_->Port());
#endif
    // TODO(Team#) possibly schedule retry dependent on AH manager update
    account_holders_manager_.Update();
    return kFindAccountHoldersError;
  }

  // Create the request
  AmendAccountRequest request;
  request.set_amendment_type(AmendAccountRequest::kSpaceOffered);
  SignedSize *mutable_signed_size = request.mutable_signed_size();
  mutable_signed_size->set_data_size(space);
  mutable_signed_size->set_pmid(ss_->Id(PMID));
  mutable_signed_size->set_signature(
      co.AsymSign(boost::lexical_cast<std::string>(space),
                                     "", ss_->PrivateKey(PMID),
                                     crypto::STRING_STRING));
  mutable_signed_size->set_public_key(ss_->PublicKey(PMID));
  mutable_signed_size->set_public_key_signature(ss_->SignedPublicKey(PMID));
  request.set_account_pmid(ss_->Id(PMID));
  for (boost::uint16_t i = 0; i < data->contacts.size(); ++i) {
    AmendAccountData::AmendAccountDataHolder holder(
        data->contacts.at(i).node_id().String());
    data->data_holders.push_back(holder);
  }

  // Send the requests
  data->returned_count = data->success_count = 0;
  for (size_t i = 0; i < data->contacts.size(); ++i) {
    google::protobuf::Closure* callback = google::protobuf::NewCallback(this,
        &MaidsafeStoreManager::AmendAccountCallback, i, data);
    client_rpcs_->AmendAccount(data->contacts.at(i), false,
                               transport_.transport_id(), &request,
                               &data->data_holders.at(i).response,
                               data->data_holders.at(i).controller.get(),
                               callback);
  }

  // wait for the RPCs to return or timeout, or enough positive responses
  while (data->returned_count < data->contacts.size() &&
         data->success_count < kUpperThreshold_) {
    data->condition.wait(lock);
  }

  // kill all remaining RPCs before the data object is destroyed
  for (size_t i = 0; i < data->contacts.size(); ++i) {
    channel_manager_.CancelPendingRequest(
      data->data_holders.at(i).controller->request_id());
  }

  if (data->success_count < kUpperThreshold_) {
#ifdef DEBUG
    printf("In MSM::CreateAccount (%d), not enough positive responses "
           "received (%d of %d).\n", kad_ops_->Port(), data->success_count,
           kUpperThreshold_);
#endif
    return maidsafe::kRequestFailedConsensus;
  }

  account_status_manager_.AmendmentDone(AmendAccountRequest::kSpaceOffered,
                                        space);
  return kSuccess;
}

void MaidsafeStoreManager::AmendAccountCallback(size_t index,
    boost::shared_ptr<AmendAccountData> data) {
  boost::mutex::scoped_lock lock(data->mutex);
  ++data->returned_count;
  AmendAccountData::AmendAccountDataHolder &holder =
      data->data_holders.at(index);
  if (!holder.response.IsInitialized()) {
#ifdef DEBUG
    printf("In MSM::AmendAccountCallback (%d), response %u is uninitialised.\n",
           kad_ops_->Port(), index);
#endif
  } else if (holder.response.result() != kAck) {
#ifdef DEBUG
    printf("In MSM::AmendAccountCallback (%d), response %u has result %i.\n",
           kad_ops_->Port(), index, holder.response.result());
#endif
  } else if (holder.response.pmid() != holder.node_id) {
#ifdef DEBUG
    printf("In MSM::AmendAccountCallback (%d), response %u from %s has PMID "
           "%s.\n", kad_ops_->Port(), index,
           HexSubstr(holder.node_id).c_str(),
           HexSubstr(holder.response.pmid()).c_str());
#endif
    // TODO(Fraser#5#): Send alert to holder.node_id's A/C holders
  } else {
    // everything OK
    ++data->success_count;
  }
  data->condition.notify_one();
}

void MaidsafeStoreManager::ModifyBpCallback(
    const ReturnCode &rc,
    boost::shared_ptr<BPResults> pm) {
  boost::mutex::scoped_lock loch_assynt(pm->mutex);
  pm->rc = rc;
  pm->finished = true;
  pm->cond.notify_one();
}

void MaidsafeStoreManager::AddToBpCallback(
    const ReturnCode &rc,
    const std::string &receiver,
    boost::shared_ptr<BPResults> bp_results) {
  boost::mutex::scoped_lock loch_arkaig(bp_results->mutex);
  (*bp_results->results)[receiver] = rc;
  ++bp_results->returned_count;
  bp_results->cond.notify_one();
}

void MaidsafeStoreManager::LoadMessagesCallback(
    const maidsafe::ReturnCode &res,
    const std::list<ValidatedBufferPacketMessage> &msgs,
    bool b,
    boost::shared_ptr<VBPMessages> vbpms) {
  boost::mutex::scoped_lock loch_mullardoch(vbpms->mutex);
  if (res == kSuccess)
    ++vbpms->successes;

  if (b)
    vbpms->done = true;

  std::list<ValidatedBufferPacketMessage>::const_iterator it;
  ValidatedBufferPacketMessage vbpm;
  for (it = msgs.begin(); it != msgs.end(); ++it) {
    vbpms->presence_set.insert(it->SerializeAsString());
  }
  vbpms->cond.notify_one();
}

void MaidsafeStoreManager::LoadPresenceCallback(
    const maidsafe::ReturnCode &res,
    const std::list<std::string> &pres,
    bool b,
    boost::shared_ptr<PresenceMessages> pm) {
  boost::mutex::scoped_lock loch_fannich(pm->mutex);
  if (res == kSuccess)
    ++pm->successes;

  if (b)
    pm->done = true;

  std::list<std::string>::const_iterator it;
  std::string validated_presence;
  for (it = pres.begin(); it != pres.end(); ++it) {
    validated_presence = ValidatePresence(*it);
    if (validated_presence.empty())
      continue;
    pm->presence_set.insert(validated_presence);
  }
  pm->cond.notify_one();
}

std::string MaidsafeStoreManager::ValidatePresence(
    const std::string &ser_presence) {
  std::string result;
  GenericPacket gp;
  if (!gp.ParseFromString(ser_presence))
    return result;
  LivePresence lp;
  if (!lp.ParseFromString(gp.data()))
    return result;

  std::string publickey(ss_->GetContactPublicKey(lp.contact_id()));
  if (publickey.empty())
    return result;

  crypto::Crypto co;
  if (!co.AsymCheckSig(gp.data(), gp.signature(), publickey,
      crypto::STRING_STRING))
    return result;

  result = co.AsymDecrypt(lp.end_point(), "", ss_->PrivateKey(MPID),
                          crypto::STRING_STRING);
  if (result.empty())
    return result;

  EndPoint ep;
  if (!ep.ParseFromString(result))
    return "";

  lp.set_end_point(result);

  return lp.SerializeAsString();
}

// Instant messaging operations

void MaidsafeStoreManager::OnNewConnection(const boost::int16_t &trans_id,
      const boost::uint32_t &conn_id, const std::string &msg) {
  if (kSuccess == im_conn_hdler_.AddConnection(trans_id, conn_id)) {
    std::string ser_im;
    maidsafe::MessageType type;
    if (im_handler_.ValidateMessage(msg, &type, &ser_im) &&
        type == maidsafe::HELLO_PING) {
      maidsafe::InstantMessage im;
      im.ParseFromString(ser_im);
      if (kSuccess != ss_->AddLiveContact(im.sender(), im.endpoint(), 0)) {
        ss_->ModifyConnectionId(im.sender(), conn_id);
        ss_->ModifyTransportId(im.sender(), trans_id);
      } else {
        ss_->ModifyConnectionId(im.sender(), conn_id);
        ss_->ModifyTransportId(im.sender(), trans_id);
        ss_->ModifyEndPoint(im.sender(), im.endpoint());
      }
      im_status_notifier_(im.sender(), im.status());
    } else if (type == maidsafe::LOGOUT_PING) {
      maidsafe::InstantMessage im;
      im.ParseFromString(ser_im);
      CloseConnection(im.sender());
      // TODO(team): define status as not connected
      im_status_notifier_(im.sender(), 1);
    } else {
      im_conn_hdler_.CloseConnection(trans_id, conn_id);
    }
  } else {
    im_conn_hdler_.CloseConnection(trans_id, conn_id);
  }
}

void MaidsafeStoreManager::OnMessage(const std::string &msg) {
  std::string ser_im;
  maidsafe::MessageType type;
  if (im_handler_.ValidateMessage(msg, &type, &ser_im)) {
    if (type == maidsafe::INSTANT_MSG) {
      im_notifier_(ser_im);
    } else if (type == maidsafe::LOGOUT_PING) {
      maidsafe::InstantMessage im;
      im.ParseFromString(ser_im);
      CloseConnection(im.sender());
      // TODO(team): define status as not connected
      im_status_notifier_(im.sender(), 1);
    }
  }
}

void MaidsafeStoreManager::CloseConnection(const std::string &contactname) {
  maidsafe::EndPoint ep;
  boost::uint16_t t_id;
  boost::uint32_t c_id, time_stamp;
  int status;
  if (kSuccess != ss_->LiveContactDetails(contactname, &ep, &t_id,
          &c_id, &status, &time_stamp)) {
    return;
  }
  im_conn_hdler_.CloseConnection(t_id, c_id);
  ss_->DeleteLiveContact(contactname);
  return;
}

void MaidsafeStoreManager::SetInstantMessageNotifier(IMNotifier on_msg,
      IMStatusNotifier status_notifier) {
  im_notifier_ = on_msg;
  im_status_notifier_ = status_notifier;
}

bool MaidsafeStoreManager::SendIM(const std::string &msg,
      const std::string &contactname) {
  ConnectionDetails info;
  if (kSuccess != ss_->LiveContactDetails(contactname,
                  &info.ep, &info.transport, &info.connection_id, &info.status,
                  &info.init_timestamp)) {
    return false;
  }

  std::string ser_msg(im_handler_.CreateMessage(msg, contactname));

  // Find if there is a connection available to send
  if (kSuccess != im_conn_hdler_.SendMessage(info.transport, info.connection_id,
        ser_msg)) {
    // try to create a connection to known endpoint
    if (kSuccess != im_conn_hdler_.CreateConnection(info.transport, info.ep,
          &info.connection_id)) {
      // TODO(team): define status as not connected
      im_status_notifier_(contactname, 1);
      ss_->DeleteLiveContact(contactname);
      return false;
    } else {
      std::string ep_msg(im_handler_.CreateMessageEndpoint(contactname));
      if (kSuccess != im_conn_hdler_.SendMessage(info.transport,
                                                 info.connection_id,
                                                 ep_msg) ||
          kSuccess != im_conn_hdler_.SendMessage(info.transport,
                                                 info.connection_id,
                                                 ser_msg)) {
        im_status_notifier_(contactname, 1);
        ss_->DeleteLiveContact(contactname);
        im_conn_hdler_.CloseConnection(info.transport, info.connection_id);
        return false;
      } else {
        ss_->ModifyConnectionId(contactname, info.connection_id);
      }
    }
  }
  return true;
}

void MaidsafeStoreManager::SetSessionEndPoint() {
  EndPoint this_endpoint;
  kad_ops_->SetThisEndpoint(&this_endpoint);
  ss_->SetEp(this_endpoint);
}

void MaidsafeStoreManager::SendLogOutMessage(const std::string &contactname) {
  ConnectionDetails info;
  if (kSuccess != ss_->LiveContactDetails(contactname,
                  &info.ep, &info.transport, &info.connection_id, &info.status,
                  &info.init_timestamp)) {
    return;
  }
  std::string ser_msg(im_handler_.CreateLogOutMessage(contactname));
  if (kSuccess != im_conn_hdler_.SendMessage(info.transport, info.connection_id,
        ser_msg)) {
    // try to create a connection to known endpoint
    if (kSuccess == im_conn_hdler_.CreateConnection(info.transport, info.ep,
          &info.connection_id)) {
      std::string ep_msg(im_handler_.CreateMessageEndpoint(contactname));
      if (kSuccess == im_conn_hdler_.SendMessage(info.transport,
                                                 info.connection_id,
                                                 ep_msg)) {
        im_conn_hdler_.SendMessage(info.transport, info.connection_id, ser_msg);
      }
    }
  }
}

bool MaidsafeStoreManager::SendPresence(const std::string &contactname) {
  ConnectionDetails info;
  if (kSuccess != ss_->LiveContactDetails(contactname,
                  &info.ep, &info.transport, &info.connection_id, &info.status,
                  &info.init_timestamp)) {
    return false;
  }
  std::string ser_msg(im_handler_.CreateMessageEndpoint(contactname));
  if (kSuccess != im_conn_hdler_.SendMessage(info.transport, info.connection_id,
        ser_msg)) {
    if (kSuccess != im_conn_hdler_.CreateConnection(info.transport, info.ep,
          &info.connection_id)) {
      ss_->DeleteLiveContact(contactname);
      im_status_notifier_(contactname, 1);
      return false;
    }
    if (kSuccess != im_conn_hdler_.SendMessage(info.transport,
                                               info.connection_id,
                                               ser_msg)) {
      ss_->DeleteLiveContact(contactname);
      im_status_notifier_(contactname, 1);
      im_conn_hdler_.CloseConnection(info.transport, info.connection_id);
      return false;
    } else {
      ss_->ModifyConnectionId(contactname, info.connection_id);
    }
  }
  return true;
}
}  // namespace maidsafe
