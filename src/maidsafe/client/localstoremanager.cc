/*
 * copyright maidsafe.net limited 2008
 * The following source code is property of maidsafe.net limited and
 * is not meant for external use. The use of this code is governed
 * by the license file LICENSE.TXT found in the root of this directory and also
 * on www.maidsafe.net.
 *
 * You are not free to copy, amend or otherwise use this source code without
 * explicit written permission of the board of directors of maidsafe.net
 *
 *  Created on: Nov 13, 2008
 *      Author: Team
 */
#include <boost/filesystem/fstream.hpp>
#include <boost/scoped_ptr.hpp>
#include <maidsafe/signed_kadvalue.pb.h>

#include <vector>

#include "fs/filesystem.h"
#include "maidsafe/chunkstore.h"
#include "maidsafe/client/localstoremanager.h"
#include "maidsafe/client/sessionsingleton.h"
#include "protobuf/maidsafe_messages.pb.h"
#include "protobuf/maidsafe_service_messages.pb.h"

namespace fs = boost::filesystem;

namespace maidsafe {

void ExecuteSuccessCallback(const base::callback_func_type &cb,
                            boost::mutex *mutex) {
  boost::mutex::scoped_lock gaurd(*mutex);
  std::string ser_result;
  GenericResponse result;
  result.set_result(kAck);
  result.SerializeToString(&ser_result);
  cb(ser_result);
}

void ExecuteFailureCallback(const base::callback_func_type &cb,
                            boost::mutex *mutex) {
  boost::mutex::scoped_lock gaurd(*mutex);
  std::string ser_result;
  GenericResponse result;
  result.set_result(kNack);
  result.SerializeToString(&ser_result);
  cb(ser_result);
}

void ExecCallbackVaultInfo(const base::callback_func_type &cb,
                           boost::mutex *mutex) {
  boost::mutex::scoped_lock loch(*mutex);
  VaultCommunication vc;
  vc.set_chunkstore("/home/Smer/ChunkStore");
  vc.set_offered_space(base::random_32bit_uinteger());
  boost::uint32_t fspace = base::random_32bit_uinteger();
  while (fspace >= vc.offered_space())
    fspace = base::random_32bit_uinteger();
  vc.set_free_space(fspace);
  vc.set_ip("127.0.0.1");
  vc.set_port((base::random_32bit_uinteger() % 64512) + 1000);
  vc.set_timestamp(base::get_epoch_time());
  std::string ser_vc;
  vc.SerializeToString(&ser_vc);
  cb(ser_vc);
}

void ExecReturnCodeCallback(const VoidFuncOneInt &cb,
                            const ReturnCode rc) {
  cb(rc);
}

void ExecReturnLoadPacketCallback(const LoadPacketFunctor &cb,
                                  std::vector<std::string> results,
                                  const ReturnCode rc) {
  cb(results, rc);
}

LocalStoreManager::LocalStoreManager(
    boost::shared_ptr<ChunkStore> client_chunkstore)
        : db_(), vbph_(), mutex_(),
          local_sm_dir_(file_system::LocalStoreManagerDir().string()),
          client_chunkstore_(client_chunkstore),
          ss_(SessionSingleton::getInstance()) {}

void LocalStoreManager::Init(int, base::callback_func_type cb) {
  try {
    if (!fs::exists(local_sm_dir_ + "/StoreChunks")) {
      fs::create_directories(local_sm_dir_ + "/StoreChunks");
    }
    if (fs::exists(local_sm_dir_ + "/KademilaDb.db")) {
      db_.open(std::string(local_sm_dir_ + "/KademilaDb.db").c_str());
    } else {
      boost::mutex::scoped_lock loch(mutex_);
      db_.open(std::string(local_sm_dir_ + "/KademilaDb.db").c_str());
      db_.execDML(
        "create table network(key text,value text, primary key(key,value));");
    }
    boost::thread thr(&ExecuteSuccessCallback, cb, &mutex_);
  }
  catch(CppSQLite3Exception &e) {  // NOLINT
    std::cerr << e.errorCode() << ":" << e.errorMessage() << std::endl;
    boost::thread thr(&ExecuteFailureCallback, cb, &mutex_);
  }
}

void LocalStoreManager::Close(base::callback_func_type cb, bool) {
  try {
    boost::mutex::scoped_lock loch(mutex_);
    db_.close();
    boost::thread thr(&ExecuteSuccessCallback, cb, &mutex_);
  }
  catch(CppSQLite3Exception &e) {  // NOLINT
    std::cerr << e.errorCode() << ":" << e.errorMessage() << std::endl;
    boost::thread thr(&ExecuteFailureCallback, cb, &mutex_);
  }
}

int LocalStoreManager::LoadChunk(const std::string &chunk_name,
                                 std::string *data) {
  return FindAndLoadChunk(chunk_name, data);
}

int LocalStoreManager::StoreChunk(const std::string &chunk_name,
                                  const DirType,
                                  const std::string&) {
  std::string hex_chunk_name(base::EncodeToHex(chunk_name));
  fs::path file_path(local_sm_dir_ + "/StoreChunks");
  file_path = file_path / hex_chunk_name;
  client_chunkstore_->Store(chunk_name, file_path);

  ChunkType type = client_chunkstore_->chunk_type(chunk_name);
  fs::path current = client_chunkstore_->GetChunkPath(chunk_name, type, false);
  try {
    if (!fs::exists(file_path)) {
      fs::copy_file(current, file_path);
    }
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("%s\n", e.what());
#endif
  }
  // Move chunk from Outgoing to Normal.
  ChunkType chunk_type =
      client_chunkstore_->chunk_type(chunk_name);
  ChunkType new_type = chunk_type ^ (kOutgoing | kNormal);
  if (client_chunkstore_->ChangeChunkType(chunk_name, new_type) != 0) {
#ifdef DEBUG
    printf("In LocalStoreManager::SendContent, failed to change chunk type.\n");
#endif
  }
  return kSuccess;
}

int LocalStoreManager::DeleteChunk(const std::string &chunk_name,
                                   const boost::uint64_t &chunk_size,
                                   DirType,
                                   const std::string &) {
  ChunkType chunk_type = client_chunkstore_->chunk_type(chunk_name);
    fs::path chunk_path(client_chunkstore_->GetChunkPath(chunk_name, chunk_type,
                                                         false));
  boost::uint64_t size(chunk_size);
  if (size < 2) {
    if (chunk_type < 0 || chunk_path.empty()) {
#ifdef DEBUG
      printf("In LSM::DeleteChunk, didn't find chunk %s in local chunkstore - "
             "cant delete without valid size\n", HexSubstr(chunk_name).c_str());
#endif
      return kDeleteSizeError;
    }
    try {
      size = fs::file_size(chunk_path);
    }
    catch(const std::exception &e) {
  #ifdef DEBUG
      printf("In LSM::DeleteChunk, didn't find chunk %s in local chunkstore - "
             "can't delete without valid size.\n%s\n",
             HexSubstr(chunk_name).c_str(), e.what());
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
      printf("In LSM::DeleteChunk, failed to change chunk type.\n");
  #endif
    }
  }
  return kSuccess;
}

bool LocalStoreManager::KeyUnique(const std::string &key, bool) {
  bool result = false;
  std::string hex_key(base::EncodeToHex(key));
  try {
    boost::mutex::scoped_lock loch(mutex_);
    std::string s = "select * from network where key='" + hex_key;
    s += "';";
    CppSQLite3Query q = db_.execQuery(s.c_str());
    if (q.eof())
      result = true;
    else
      while (!q.eof()) {
        printf("a\n");
        q.nextRow();
      }
  }
  catch(CppSQLite3Exception &e) {  // NOLINT
    std::cerr << e.errorCode() << ":" << e.errorMessage() << std::endl;
    result = false;
  }
  if (result) {
    fs::path file_path(local_sm_dir_ + "/StoreChunks");
    file_path = file_path / hex_key;
    result = (!fs::exists(file_path));
  }
  return result;
}

void LocalStoreManager::KeyUnique(const std::string &key,
                                  bool check_local,
                                  const VoidFuncOneInt &cb) {
  if (KeyUnique(key, check_local))
    boost::thread thr(&ExecReturnCodeCallback, cb, kKeyUnique);
  else
    boost::thread thr(&ExecReturnCodeCallback, cb, kKeyNotUnique);
}

int LocalStoreManager::LoadPacket(const std::string &packet_name,
                                  std::vector<std::string> *results) {
  return GetValue_FromDB(packet_name, results);
}

void LocalStoreManager::LoadPacket(const std::string &packetname,
                                   const LoadPacketFunctor &lpf) {
  std::vector<std::string> results;
  ReturnCode rc(static_cast<ReturnCode>(GetValue_FromDB(packetname, &results)));
  boost::thread thr(&ExecReturnLoadPacketCallback, lpf, results, rc);
}

void LocalStoreManager::DeletePacket(const std::string &packet_name,
                                     const std::vector<std::string> values,
                                     PacketType system_packet_type,
                                     DirType dir_type,
                                     const std::string &msid,
                                     const VoidFuncOneInt &cb) {
  std::string public_key;
  SigningPublicKey(system_packet_type, dir_type, msid, &public_key);
  if (public_key.empty()) {
    boost::thread thr(&ExecReturnCodeCallback, cb, kNoPublicKeyToCheck);
    return;
  }
  std::vector<std::string> vals(values);
  bool empty(true);
  for (size_t i = 0; i < vals.size(); ++i) {
    if (!vals.at(i).empty()) {
      empty = false;
      break;
    }
  }
  if (empty) {
    ReturnCode res =
        static_cast<ReturnCode>(GetValue_FromDB(packet_name, &vals));
    if (res == kFindValueFailure) {  // packet doesn't exist on net
      boost::thread thr(&ExecReturnCodeCallback, cb, kSuccess);
      return;
    } else if (res != kSuccess || vals.empty()) {
      boost::thread thr(&ExecReturnCodeCallback, cb,
                        kDeletePacketFindValueFailure);
      return;
    }
  }

  std::vector<std::string> ser_gps;
  for (size_t a = 0; a < values.size(); ++a) {
    std::string ser_gp;
    CreateSerialisedSignedValue(values[a], system_packet_type, msid, &ser_gp);
    ser_gps.push_back(ser_gp);
  }

  crypto::Crypto co;
  for (size_t n = 0; n < ser_gps.size(); ++n) {
    kad::SignedValue sv;
    if (sv.ParseFromString(ser_gps[n])) {
      if (!co.AsymCheckSig(sv.value(), sv.value_signature(), public_key,
          crypto::STRING_STRING)) {
        boost::thread thr(&ExecReturnCodeCallback, cb, kDeletePacketFailure);
        return;
      }
    }
  }
  ReturnCode rc = DeletePacket_DeleteFromDb(packet_name, ser_gps, public_key);
  boost::thread thr(&ExecReturnCodeCallback, cb, rc);
}

ReturnCode LocalStoreManager::DeletePacket_DeleteFromDb(
    const std::string &key,
    const std::vector<std::string> &values,
    const std::string &public_key) {
  std::string hex_key(base::EncodeToHex(key));
  boost::mutex::scoped_lock loch(mutex_);
  try {
    std::string s("select value from network where key='" + hex_key + "';");
    CppSQLite3Query q = db_.execQuery(s.c_str());
    if (q.eof()) {
#ifdef DEBUG
      printf("LocalStoreManager::DeletePacket_DeleteFromDb - value not there "
             "anyway.\n");
#endif
      return kSuccess;
    } else {
      kad::SignedValue ksv;
      if (ksv.ParseFromString(q.getStringField(0))) {
        crypto::Crypto co;
        if (!co.AsymCheckSig(ksv.value(), ksv.value_signature(), public_key,
            crypto::STRING_STRING)) {
#ifdef DEBUG
          printf("LocalStoreManager::DeletePacket_DeleteFromDb - "
                 "current value failed validation.\n");
#endif
          return kDeletePacketFailure;
        }
      }
    }
  }
  catch(CppSQLite3Exception &e1) {  // NOLINT (Fraser)
#ifdef DEBUG
    printf("Error(%i): %s\n", e1.errorCode(),  e1.errorMessage());
#endif
    return kStoreManagerError;
  }

  int deleted(values.size());
  if (0 == values.size()) {
    try {
      std::string s("delete from network where key='" + hex_key + "';");
      int a = db_.execDML(s.c_str());
    } catch(CppSQLite3Exception &e2) {  // NOLINT (Fraser)
#ifdef DEBUG
      printf("Error(%i): %s\n", e2.errorCode(),  e2.errorMessage());
#endif
      return kStoreManagerError;
    }
  } else {
    for (size_t n = 0; n < values.size(); ++n) {
      try {
        std::string hex_value(base::EncodeToHex(values[n]));
        std::string s("delete from network where key='" + hex_key + "' "
                      "and value='" + hex_value + "';");
        int a = db_.execDML(s.c_str());
        if (a == 1) {
          --deleted;
        } else {
#ifdef DEBUG
          printf("LocalStoreManager::DeletePacket_DeleteFromDb - failure to"
                 " delete <key, value>(%s, %s).\n", hex_key.substr(0, 10).c_str(),
                 HexSubstr(values[n]).c_str());
          printf("%d rows affected\n", a);
#endif
          return kDeletePacketFailure;
        }
      }
      catch(CppSQLite3Exception &e2) {  // NOLINT (Fraser)
#ifdef DEBUG
        printf("Error(%i): %s\n", e2.errorCode(),  e2.errorMessage());
#endif
        return kStoreManagerError;
      }
    }
  }

  return kSuccess;
}

void LocalStoreManager::StorePacket(const std::string &packet_name,
                                    const std::string &value,
                                    PacketType system_packet_type,
                                    DirType dir_type,
                                    const std::string& msid,
                                    IfPacketExists if_packet_exists,
                                    const VoidFuncOneInt &cb) {
  std::string ser_gp;
  CreateSerialisedSignedValue(value, system_packet_type, msid, &ser_gp);
  if (ser_gp.empty()) {
    boost::thread thr(&ExecReturnCodeCallback, cb, kNoPublicKeyToCheck);
    return;
  }

  std::string public_key;
  kad::SignedValue sv;
  if (sv.ParseFromString(ser_gp)) {
    SigningPublicKey(system_packet_type, dir_type, msid, &public_key);
    if (public_key.empty()) {
      boost::thread thr(&ExecReturnCodeCallback, cb, kNoPublicKeyToCheck);
      return;
    } else {
      crypto::Crypto co;
      if (!co.AsymCheckSig(sv.value(), sv.value_signature(), public_key,
          crypto::STRING_STRING)) {
        boost::thread thr(&ExecReturnCodeCallback, cb, kSendPacketFailure);
        return;
      }
    }
  }

  std::vector<std::string> values;
  int n = GetValue_FromDB(packet_name, &values);
  if (n == kFindValueError) {
    boost::thread thr(&ExecReturnCodeCallback, cb, kStoreManagerError);
    return;
  }

  ReturnCode rc;
  if (values.empty()) {
    rc = StorePacket_InsertToDb(packet_name, ser_gp, public_key, false);
  } else {
    switch (if_packet_exists) {
      case kDoNothingReturnFailure:
          rc = kSendPacketFailure;
          break;
      case kDoNothingReturnSuccess:
          rc = kSuccess;
          break;
      case kOverwrite:
          rc = StorePacket_InsertToDb(packet_name, ser_gp, public_key, false);
          break;
      case kAppend:
          rc = StorePacket_InsertToDb(packet_name, ser_gp, public_key, true);
          break;
    }
  }
  boost::thread thr(&ExecReturnCodeCallback, cb, rc);
}

ReturnCode LocalStoreManager::StorePacket_InsertToDb(const std::string &key,
                                                     const std::string &value,
                                                     const std::string &pub_key,
                                                     const bool &append) {
  try {
    if (key.length() != kKeySize) {
      return kIncorrectKeySize;
    }
    std::string hex_key = base::EncodeToHex(key);
    std::string s = "select value from network where key='" + hex_key + "';";
    boost::mutex::scoped_lock loch(mutex_);
    CppSQLite3Query q = db_.execQuery(s.c_str());
    if (!q.eof()) {
      std::string dec_value = base::DecodeFromHex(q.getStringField(0));
      kad::SignedValue sv;
      if (sv.ParseFromString(dec_value)) {
        crypto::Crypto co;
        if (!co.AsymCheckSig(sv.value(), sv.value_signature(), pub_key,
            crypto::STRING_STRING)) {
#ifdef DEBUG
          printf("LocalStoreManager::StorePacket_InsertToDb - "
                 "Signature didn't validate.\n");
#endif
          return kStoreManagerError;
        }
      }
    }

    if (!append) {
      s = "delete from network where key='" + hex_key + "';";
      db_.execDML(s.c_str());
    }

    CppSQLite3Buffer bufSQL;
    std::string hex_value = base::EncodeToHex(value);
    s = "insert into network values ('" + hex_key + "', '" + hex_value + "');";
    int a = db_.execDML(s.c_str());
    if (a != 1) {
#ifdef DEBUG
      printf("LocalStoreManager::StorePacket_InsertToDb - "
             "Insert failed.\n");
#endif
      return kStoreManagerError;
    }
    return kSuccess;
  }
  catch(CppSQLite3Exception &e) {  // NOLINT
#ifdef DEBUG
    printf("Error(%i): %s\n", e.errorCode(),  e.errorMessage());
#endif
    return kStoreManagerError;
  }
}

void LocalStoreManager::SigningPublicKey(PacketType packet_type,
                                         DirType,
                                         const std::string &msid,
                                         std::string *public_key) {
  public_key->clear();
  switch (packet_type) {
    case MID:
    case ANMID:
      *public_key = ss_->PublicKey(ANMID);
      break;
    case SMID:
    case ANSMID:
      *public_key = ss_->PublicKey(ANSMID);
      break;
    case TMID:
    case ANTMID:
      *public_key = ss_->PublicKey(ANTMID);
      break;
    case MPID:
    case ANMPID:
      *public_key = ss_->PublicKey(ANMPID);
      break;
    case MAID:
    case ANMAID:
      *public_key = ss_->PublicKey(ANMAID);
      break;
    case PMID:
      *public_key = ss_->PublicKey(MAID);
      break;
    case MSID: {
      std::string priv_key;
      if (ss_->GetShareKeys(msid, public_key, &priv_key) != kSuccess)
        public_key->clear();
      break;
    }
    case PD_DIR:
      *public_key = ss_->PublicKey(PMID);
      break;
    default:
      break;
  }
}

void LocalStoreManager::SigningPrivateKey(PacketType packet_type,
                                          DirType,
                                          const std::string &msid,
                                          std::string *private_key) {
  private_key->clear();
  switch (packet_type) {
    case MID:
    case ANMID:
      *private_key = ss_->PrivateKey(ANMID);
      break;
    case SMID:
    case ANSMID:
      *private_key = ss_->PrivateKey(ANSMID);
      break;
    case TMID:
    case ANTMID:
      *private_key = ss_->PrivateKey(ANTMID);
      break;
    case MPID:
    case ANMPID:
      *private_key = ss_->PrivateKey(ANMPID);
      break;
    case MAID:
    case ANMAID:
      *private_key = ss_->PrivateKey(ANMAID);
      break;
    case PMID:
      *private_key = ss_->PrivateKey(MAID);
      break;
    case MSID: {
      std::string pub_key;
      ss_->GetShareKeys(msid, &pub_key, private_key);
      break;
    }
    case PD_DIR:
      *private_key = ss_->PrivateKey(PMID);
      break;
    default:
      break;
  }
}

bool LocalStoreManager::ValidateGenericPacket(std::string ser_gp,
                                              std::string public_key) {
  GenericPacket gp;
  crypto::Crypto co;
  if (!gp.ParseFromString(ser_gp))
    return false;
  if (!co.AsymCheckSig(gp.data(), gp.signature(), public_key,
      crypto::STRING_STRING))
    return false;
  return true;
}

// Buffer packet
int LocalStoreManager::CreateBP() {
  if (ss_->Id(MPID) == "")
    return -666;

  std::string bufferpacketname(BufferPacketName()), ser_packet;
  BufferPacket buffer_packet;
  GenericPacket *ser_owner_info = buffer_packet.add_owner_info();
  BufferPacketInfo buffer_packet_info;
  buffer_packet_info.set_owner(ss_->Id(MPID));
  buffer_packet_info.set_ownerpublickey(ss_->PublicKey(MPID));
  buffer_packet_info.set_online(1);
  EndPoint *ep = buffer_packet_info.mutable_ep();
  ep->set_ip("127.0.0.1");
  ep->set_port(12700);
  ser_owner_info->set_data(buffer_packet_info.SerializeAsString());
  crypto::Crypto co;
  ser_owner_info->set_signature(co.AsymSign(ser_owner_info->data(), "",
                                ss_->PrivateKey(MPID), crypto::STRING_STRING));
  buffer_packet.SerializeToString(&ser_packet);
  return FlushDataIntoChunk(bufferpacketname, ser_packet, false);
}

int LocalStoreManager::LoadBPMessages(
    std::list<ValidatedBufferPacketMessage> *messages) {
  if (ss_->Id(MPID) == "")
    return -666;

  std::string bp_in_chunk;
  std::string bufferpacketname(BufferPacketName());
  if (FindAndLoadChunk(bufferpacketname, &bp_in_chunk) != 0) {
#ifdef DEBUG
    printf("LocalStoreManager::LoadBPMessages - Failed to find BP chunk.\n");
#endif
    return -1;
  }
  std::vector<std::string> msgs;
  if (!vbph_.GetMessages(&bp_in_chunk, &msgs)) {
#ifdef DEBUG
    printf("LocalStoreManager::LoadBPMessages - Failed to get messages.\n");
#endif
    return -1;
  }
  messages->clear();
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  for (size_t n = 0; n < msgs.size(); ++n) {
    ValidatedBufferPacketMessage valid_message;
    if (valid_message.ParseFromString(msgs[n])) {
      std::string aes_key = co.AsymDecrypt(valid_message.index(), "",
                            ss_->PrivateKey(MPID), crypto::STRING_STRING);
      valid_message.set_message(co.SymmDecrypt(valid_message.message(),
                                "", crypto::STRING_STRING, aes_key));
      messages->push_back(valid_message);
    }
  }
  if (FlushDataIntoChunk(bufferpacketname, bp_in_chunk, true) != 0) {
#ifdef DEBUG
    printf("LSM::LoadBPMessages - Failed to flush BP to chunk.\n");
#endif
    return -1;
  }
  return 0;
}

int LocalStoreManager::ModifyBPInfo(const std::string &info) {
  if (ss_->Id(MPID) == "")
    return -666;

  std::string bp_in_chunk;
  std::string bufferpacketname(BufferPacketName()), ser_gp;
  GenericPacket gp;
  gp.set_data(info);
  crypto::Crypto co;
  gp.set_signature(co.AsymSign(gp.data(), "", ss_->PrivateKey(MPID),
                   crypto::STRING_STRING));
  gp.SerializeToString(&ser_gp);
  if (FindAndLoadChunk(bufferpacketname, &bp_in_chunk) != 0) {
#ifdef DEBUG
    printf("LocalStoreManager::ModifyBPInfo - Failed to find BP chunk(%s).\n",
           bufferpacketname.substr(0, 10).c_str());
#endif
    return -1;
  }
  std::string new_bp;
  if (!vbph_.ChangeOwnerInfo(ser_gp, &bp_in_chunk, ss_->PublicKey(MPID))) {
#ifdef DEBUG
    printf("LocalStoreManager::ModifyBPInfo - Failed to change owner info.\n");
#endif
    return -2;
  }
  if (FlushDataIntoChunk(bufferpacketname, bp_in_chunk, true) != 0) {
#ifdef DEBUG
    printf("LocalStoreManager::ModifyBPInfo - Failed to flush BP to chunk.\n");
#endif
    return -3;
  }
  return 0;
}

int LocalStoreManager::AddBPMessage(const std::vector<std::string> &receivers,
                                    const std::string &message,
                                    const MessageType &m_type) {
  if (ss_->Id(MPID) == "")
    return -666;

  std::string bp_in_chunk, ser_gp;
  int fails = 0;
  boost::uint32_t timestamp = base::get_epoch_time();
  for (size_t n = 0; n < receivers.size(); ++n) {
    std::string rec_pub_key(ss_->GetContactPublicKey(receivers[n]));
    std::string bufferpacketname(BufferPacketName(receivers[n], rec_pub_key));
    if (FindAndLoadChunk(bufferpacketname, &bp_in_chunk) != 0) {
#ifdef DEBUG
      printf("LocalStoreManager::AddBPMessage - Failed to find BP chunk (%s)\n",
             receivers[n].c_str());
#endif
      ++fails;
      continue;
    }

    std::string updated_bp;
    if (!vbph_.AddMessage(bp_in_chunk,
        CreateMessage(message, rec_pub_key, m_type, timestamp), "",
        &updated_bp)) {
#ifdef DEBUG
      printf("LocalStoreManager::AddBPMessage - Failed to add message (%s).\n",
             receivers[n].c_str());
#endif
      ++fails;
      continue;
    }

    if (FlushDataIntoChunk(bufferpacketname, updated_bp, true) != 0) {
#ifdef DEBUG
      printf("LSM::AddBPMessage - Failed to flush BP into chunk. (%s).\n",
             receivers[n].c_str());
#endif
      ++fails;
      continue;
    }
  }
  return fails;
}

void LocalStoreManager::ContactInfo(const std::string &public_username,
                                    const std::string &me,
                                    ContactInfoNotifier cin) {
  std::string rec_pub_key(ss_->GetContactPublicKey(public_username));
  std::string bufferpacketname(BufferPacketName(public_username, rec_pub_key));
  std::string bp_in_chunk;
  EndPoint ep;
  boost::uint16_t status(1);
  if (FindAndLoadChunk(bufferpacketname, &bp_in_chunk) != 0) {
    boost::thread thr(cin, kGetBPInfoError, ep, status);
#ifdef DEBUG
    printf("LocalStoreManager::ContactInfo - Failed to find BP chunk(%s).\n",
           bufferpacketname.substr(0, 10).c_str());
#endif
    return;
  }

  if (!vbph_.ContactInfo(bp_in_chunk, me, &ep, &status)) {
    boost::thread thr(cin, kGetBPInfoError, ep, status);
#ifdef DEBUG
    printf("LocalStoreManager::ContactInfo - Failed(%i) to get info (%s).\n",
           kGetBPInfoError, public_username.c_str());
#endif
    return;
  }

  boost::thread thr(cin, kSuccess, ep, status);
}

int LocalStoreManager::FindAndLoadChunk(const std::string &chunkname,
                                        std::string *data) {
  std::string hex_chunkname(base::EncodeToHex(chunkname));
  fs::path file_path(local_sm_dir_ + "/StoreChunks");
  file_path = file_path / hex_chunkname;
  try {
    if (!fs::exists(file_path)) {
#ifdef DEBUG
      printf("LocalStoreManager::FindAndLoadChunk - didn't find the BP.\n");
#endif
      return -1;
    }
    boost::uintmax_t size = fs::file_size(file_path);
    boost::scoped_ptr<char> temp(new char[size]);
    fs::ifstream fstr;
    fstr.open(file_path, std::ios_base::binary);
    fstr.read(temp.get(), size);
    fstr.close();
    *data = std::string((const char*)temp.get(), size);
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("LocalStoreManager::FindAndLoadChunk - %s\n", e.what());
#endif
    return -1;
  }
  return 0;
}

int LocalStoreManager::FlushDataIntoChunk(const std::string &chunkname,
                                          const std::string &data,
                                          const bool &overwrite) {
  std::string hex_chunkname(base::EncodeToHex(chunkname));
  fs::path file_path(local_sm_dir_ + "/StoreChunks");
  file_path = file_path / hex_chunkname;
  try {
    if (boost::filesystem::exists(file_path) && !overwrite) {
#ifdef DEBUG
      printf("This BP (%s) already exists\n.",
             hex_chunkname.substr(0, 10).c_str());
#endif
      return -1;
    }
    boost::filesystem::ofstream bp_file(file_path.string().c_str(),
                                        boost::filesystem::ofstream::binary);
    bp_file << data;
    bp_file.close();
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("%s\n", e.what());
#endif
    return -1;
  }
  return 0;
}

std::string LocalStoreManager::BufferPacketName() {
  return BufferPacketName(ss_->Id(MPID), ss_->PublicKey(MPID));
}

std::string LocalStoreManager::BufferPacketName(const std::string &pub_username,
                                                const std::string &public_key) {
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  return co.Hash(pub_username + public_key, "", crypto::STRING_STRING, false);
}

std::string LocalStoreManager::CreateMessage(const std::string &message,
                                             const std::string &rec_public_key,
                                             const MessageType &m_type,
                                             const boost::uint32_t &timestamp) {
  BufferPacketMessage bpm;
  GenericPacket gp;

  bpm.set_sender_id(ss_->Id(MPID));
  bpm.set_sender_public_key(ss_->PublicKey(MPID));
  bpm.set_type(m_type);
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  co.set_symm_algorithm(crypto::AES_256);
  int iter = base::random_32bit_uinteger() % 1000 +1;
  std::string aes_key = co.SecurePassword(co.Hash(message, "",
                        crypto::STRING_STRING, false), iter);
  bpm.set_rsaenc_key(co.AsymEncrypt(aes_key, "", rec_public_key,
                                    crypto::STRING_STRING));
  bpm.set_aesenc_message(co.SymmEncrypt(message, "", crypto::STRING_STRING,
                         aes_key));
  bpm.set_timestamp(timestamp);
  std::string ser_bpm;
  bpm.SerializeToString(&ser_bpm);
  gp.set_data(ser_bpm);
  gp.set_signature(co.AsymSign(gp.data(), "", ss_->PrivateKey(MPID),
                   crypto::STRING_STRING));
  std::string ser_gp;
  gp.SerializeToString(&ser_gp);
  return ser_gp;
}

int LocalStoreManager::GetValue_FromDB(const std::string &key,
                                       std::vector<std::string> *results) {
  results->clear();
  std::string hex_key = base::EncodeToHex(key);
  try {
    boost::mutex::scoped_lock loch(mutex_);
    std::string s = "select value from network where key='" + hex_key + "';";
    CppSQLite3Query q = db_.execQuery(s.c_str());
    while (!q.eof()) {
      results->push_back(base::DecodeFromHex(q.getStringField(0)));
      q.nextRow();
    }
  }
  catch(CppSQLite3Exception &e) {  // NOLINT
#ifdef DEBUG
    printf("Error(%i): %s\n", e.errorCode(),  e.errorMessage());
#endif
    return kFindValueError;
  }
  return (results->size() > 0) ? kSuccess : kFindValueFailure;
}

void LocalStoreManager::PollVaultInfo(base::callback_func_type cb) {
  boost::thread thr(&ExecCallbackVaultInfo, cb, &mutex_);
}

void LocalStoreManager::VaultContactInfo(base::callback_func_type cb) {
  boost::thread thr(&ExecuteSuccessCallback, cb, &mutex_);
}

void LocalStoreManager::SetLocalVaultOwned(const std::string&,
                                           const std::string &pub_key,
                                           const std::string &signed_pub_key,
                                           const boost::uint32_t&,
                                           const std::string&,
                                           const boost::uint64_t&,
                                           const SetLocalVaultOwnedFunctor &f) {
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  std::string pmid_name = co.Hash(pub_key + signed_pub_key, "",
                          crypto::STRING_STRING, false);
  boost::thread thr(f, OWNED_SUCCESS, pmid_name);
}

void LocalStoreManager::LocalVaultOwned(const LocalVaultOwnedFunctor &functor) {
  boost::thread thr(functor, NOT_OWNED);
}

bool LocalStoreManager::NotDoneWithUploading() { return false; }

void LocalStoreManager::CreateSerialisedSignedValue(const std::string value,
                                                    const PacketType &pt,
                                                    const std::string &msid,
                                                    std::string *ser_gp) {
  *ser_gp = "";
  std::string private_key;
  SigningPrivateKey(pt, PRIVATE, msid, &private_key);
  if (private_key.empty())
    return;
  crypto::Crypto co;
  GenericPacket gp;
  gp.set_data(value);
  gp.set_signature(co.AsymSign(value, "", private_key, crypto::STRING_STRING));
  gp.SerializeToString(ser_gp);
}

}  // namespace maidsafe
