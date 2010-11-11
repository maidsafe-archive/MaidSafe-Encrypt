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
#include <maidsafe/protobuf/signed_kadvalue.pb.h>

#include <vector>
#include <set>

#include "fs/filesystem.h"
#include "maidsafe/chunkstore.h"
#include "maidsafe/maidsafevalidator.h"
#include "maidsafe/client/localstoremanager.h"
#include "maidsafe/client/sessionsingleton.h"
#include "maidsafe/pdutils.h"
#include "protobuf/maidsafe_messages.pb.h"
#include "protobuf/maidsafe_service_messages.pb.h"

namespace fs = boost::filesystem;

namespace maidsafe {

void ExecuteSuccessCallback(const kad::VoidFunctorOneString &cb,
                            boost::mutex *mutex) {
  boost::mutex::scoped_lock gaurd(*mutex);
  std::string ser_result;
  GenericResponse result;
  result.set_result(kAck);
  result.SerializeToString(&ser_result);
  cb(ser_result);
}

void ExecuteFailureCallback(const kad::VoidFunctorOneString &cb,
                            boost::mutex *mutex) {
  boost::mutex::scoped_lock gaurd(*mutex);
  std::string ser_result;
  GenericResponse result;
  result.set_result(kNack);
  result.SerializeToString(&ser_result);
  cb(ser_result);
}

void ExecCallbackVaultInfo(const kad::VoidFunctorOneString &cb,
                           boost::mutex *mutex) {
  boost::mutex::scoped_lock loch(*mutex);
  VaultCommunication vc;
  vc.set_chunkstore("/home/Smer/ChunkStore");
  vc.set_offered_space(base::RandomUint32());
  boost::uint32_t fspace = base::RandomUint32();
  while (fspace >= vc.offered_space())
    fspace = base::RandomUint32();
  vc.set_free_space(fspace);
  vc.set_ip("127.0.0.1");
  vc.set_port((base::RandomUint32() % 64512) + 1000);
  vc.set_timestamp(base::GetEpochTime());
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
    boost::shared_ptr<ChunkStore> client_chunkstore,
    const boost::uint8_t &k,
    const fs::path &db_directory)
        : K_(k),
          kUpperThreshold_(
              static_cast<boost::uint16_t>(K_ * kMinSuccessfulPecentageStore)),
          db_(), vbph_(), mutex_(),
          local_sm_dir_(db_directory.string()),
          client_chunkstore_(client_chunkstore),
          ss_(SessionSingleton::getInstance()) {}

LocalStoreManager::~LocalStoreManager() {
  bool t(false);
  while (!t) {
    {
      boost::mutex::scoped_lock loch_etive(signal_mutex_);
      t = chunks_pending_.empty();
    }
    if (!t)
      boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  }
}

void LocalStoreManager::Init(VoidFuncOneInt callback, const boost::uint16_t&) {
#ifdef LOCAL_PDVAULT
  // Simulate knode join
//  boost::this_thread::sleep(boost::posix_time::seconds(3));
#endif
  if (local_sm_dir_.empty())
    local_sm_dir_ = file_system::LocalStoreManagerDir().string();
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
    ExecReturnCodeCallback(callback, kSuccess);
  }
  catch(CppSQLite3Exception &e) {  // NOLINT
    std::cerr << e.errorCode() << ":" << e.errorMessage() << std::endl;
    ExecReturnCodeCallback(callback, kStoreManagerInitError);
  }
}

void LocalStoreManager::Close(VoidFuncOneInt callback, bool) {
  bool t(false);
  while (!t) {
    {
      boost::mutex::scoped_lock loch_etive(signal_mutex_);
      t = chunks_pending_.empty();
    }
    if (!t)
      boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  }
#ifdef LOCAL_PDVAULT
  // Simulate chunk threadpool join and knode leave
//  boost::this_thread::sleep(boost::posix_time::seconds(3));
#endif
  try {
    boost::mutex::scoped_lock loch(mutex_);
    db_.close();
    ExecReturnCodeCallback(callback, kSuccess);
  }
  catch(CppSQLite3Exception &e) {  // NOLINT
    std::cerr << e.errorCode() << ":" << e.errorMessage() << std::endl;
    ExecReturnCodeCallback(callback, kStoreManagerError);
  }
}

int LocalStoreManager::LoadChunk(const std::string &chunk_name,
                                 std::string *data) {
  if (client_chunkstore_->Load(chunk_name, data) == kSuccess) {
#ifdef DEBUG
//    printf("In LSM::LoadChunk, found chunk %s in local chunkstore.\n",
//           HexSubstr(chunk_name).c_str());
#endif
    return kSuccess;
  }
  return FindAndLoadChunk(chunk_name, data);
}

int LocalStoreManager::StoreChunk(const std::string &chunk_name, const DirType,
                                  const std::string&) {
//  #ifdef LOCAL_PDVAULT
//  // Simulate knode lookup in AddToWatchList
//  boost::this_thread::sleep(boost::posix_time::seconds(2));
//  #endif
  std::string hex_chunk_name(base::EncodeToHex(chunk_name));
  fs::path file_path(local_sm_dir_ + "/StoreChunks");
  file_path = file_path / hex_chunk_name;
  client_chunkstore_->Store(chunk_name, file_path);

  ChunkType type = client_chunkstore_->chunk_type(chunk_name);
  fs::path current = client_chunkstore_->GetChunkPath(chunk_name, type, false);
  try {
    if (fs::exists(current)) {
      if (!fs::exists(file_path)) {
        fs::copy_file(current, file_path);
      }
    } else {
#ifdef DEBUG
      printf("Chunk(%s) to store doesn't exist.\n", hex_chunk_name.c_str());
#endif
      signal_mutex_.lock();
      chunks_pending_.insert(chunk_name);
      signal_mutex_.unlock();
      boost::thread thr(boost::bind(&LocalStoreManager::ExecuteReturnSignal,
                                    this, chunk_name, kSendChunkFailure));
      return kChunkStorePending;
    }
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("LocalStoreManager::StoreChunk - Exception: %s\n", e.what());
#endif
    signal_mutex_.lock();
    chunks_pending_.insert(chunk_name);
    signal_mutex_.unlock();
    boost::thread thr(boost::bind(&LocalStoreManager::ExecuteReturnSignal, this,
                                  chunk_name, kSendChunkFailure));
    return kChunkStorePending;
  }

  // Move chunk from Outgoing to Normal.
  ChunkType chunk_type = client_chunkstore_->chunk_type(chunk_name);
  ChunkType new_type = chunk_type ^ (kOutgoing | kNormal);
  if (client_chunkstore_->ChangeChunkType(chunk_name, new_type) != 0) {
#ifdef DEBUG
    printf("In LocalStoreManager::SendContent, failed to change chunk type.\n");
#endif
  }
  signal_mutex_.lock();
  chunks_pending_.insert(chunk_name);
  signal_mutex_.unlock();
  boost::thread thr(boost::bind(&LocalStoreManager::ExecuteReturnSignal, this,
                                chunk_name, kSuccess));
  return kChunkStorePending;
}

int LocalStoreManager::DeleteChunk(const std::string &chunk_name,
                                   const boost::uint64_t &chunk_size,
                                   DirType, const std::string&) {
#ifdef LOCAL_PDVAULT
  // Simulate knode lookup in RemoveFromWatchList
//  boost::this_thread::sleep(boost::posix_time::seconds(2));
#endif
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
#ifdef LOCAL_PDVAULT
  // Simulate knode findvalue in AddToWatchList
//  boost::this_thread::sleep(boost::posix_time::seconds(2));
#endif
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
    try {
      result = (!fs::exists(file_path));
    }
    catch(const std::exception &e) {
#ifdef DEBUG
      printf("LocalStoreManager::KeyUnique - Failed to check path existance\n");
#endif
      return false;
    }
  }
  return result;
}

void LocalStoreManager::KeyUnique(const std::string &key, bool check_local,
                                  const VoidFuncOneInt &cb) {
  if (KeyUnique(key, check_local))
    ExecReturnCodeCallback(cb, kKeyUnique);
  else
    ExecReturnCodeCallback(cb, kKeyNotUnique);
}

int LocalStoreManager::LoadPacket(const std::string &packet_name,
                                  std::vector<std::string> *results) {
  return GetValue_FromDB(packet_name, results);
}

void LocalStoreManager::LoadPacket(const std::string &packetname,
                                   const LoadPacketFunctor &lpf) {
  std::vector<std::string> results;
  ReturnCode rc(static_cast<ReturnCode>(GetValue_FromDB(packetname, &results)));
  ExecReturnLoadPacketCallback(lpf, results, rc);
}

void LocalStoreManager::DeletePacket(const std::string &packet_name,
                                     const std::vector<std::string> values,
                                     PacketType system_packet_type,
                                     DirType dir_type, const std::string &msid,
                                     const VoidFuncOneInt &cb) {
  std::string key_id, public_key, public_key_signature, private_key;
  PdUtils pd_utils;
  pd_utils.GetPacketSignatureKeys(system_packet_type, dir_type, msid, &key_id,
      &public_key, &public_key_signature, &private_key);
  MaidsafeValidator msv;
  if (!msv.ValidateSignerId(key_id, public_key, public_key_signature)) {
    ExecReturnCodeCallback(cb, kDeletePacketFailure);
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
      ExecReturnCodeCallback(cb, kSuccess);
      return;
    } else if (res != kSuccess || vals.empty()) {
      ExecReturnCodeCallback(cb, kDeletePacketFindValueFailure);
      return;
    }
  }

  std::vector<std::string> ser_gps;
  for (size_t a = 0; a < values.size(); ++a) {
    std::string ser_gp;
    CreateSerialisedSignedValue(values[a], private_key, &ser_gp);
    ser_gps.push_back(ser_gp);
  }

  crypto::Crypto co;
  for (size_t n = 0; n < ser_gps.size(); ++n) {
    kad::SignedValue sv;
    if (sv.ParseFromString(ser_gps[n])) {
      if (!co.AsymCheckSig(sv.value(), sv.value_signature(), public_key,
          crypto::STRING_STRING)) {
        ExecReturnCodeCallback(cb, kDeletePacketFailure);
        return;
      }
    }
  }
  ReturnCode rc = DeletePacket_DeleteFromDb(packet_name, ser_gps, public_key);
  ExecReturnCodeCallback(cb, rc);
}

ReturnCode LocalStoreManager::DeletePacket_DeleteFromDb(
    const std::string &key, const std::vector<std::string> &values,
    const std::string &public_key) {
#ifdef LOCAL_PDVAULT
  // Simulate knode lookup
//  boost::this_thread::sleep(boost::posix_time::seconds(2));
#endif
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
      if (ksv.ParseFromString(base::DecodeFromHex(q.getStringField(0)))) {
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

  int deleted(values.size()), a(0);
  if (0 == values.size()) {
    try {
      std::string s("delete from network where key='" + hex_key + "';");
      a = db_.execDML(s.c_str());
    } catch(CppSQLite3Exception &e2) {  // NOLINT (Fraser)
#ifdef DEBUG
      printf("Error(%i): %s - ", e2.errorCode(),  e2.errorMessage());
      printf("%d rows affected\n", a);
#endif
      return kStoreManagerError;
    }
  } else {
    for (size_t n = 0; n < values.size(); ++n) {
      try {
        std::string hex_value(base::EncodeToHex(values[n]));
        std::string s("delete from network where key='" + hex_key + "' "
                      "and value='" + hex_value + "';");
        a = db_.execDML(s.c_str());
        if (a == 1) {
          --deleted;
        } else {
#ifdef DEBUG
          printf("LocalStoreManager::DeletePacket_DeleteFromDb - failure to"
                 " delete <key, value>(%s, %s).\n",
                 hex_key.substr(0, 10).c_str(), HexSubstr(values[n]).c_str());
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
                                    DirType dir_type, const std::string& msid,
                                    const VoidFuncOneInt &cb) {
  std::string key_id, public_key, public_key_signature, private_key;
  PdUtils pd_utils;
  pd_utils.GetPacketSignatureKeys(system_packet_type, dir_type, msid, &key_id,
                                  &public_key, &public_key_signature,
                                  &private_key);
  MaidsafeValidator msv;
  if (!msv.ValidateSignerId(key_id, public_key, public_key_signature)) {
    ExecReturnCodeCallback(cb, kSendPacketFailure);
    return;
  }

  std::string ser_gp;
  CreateSerialisedSignedValue(value, private_key, &ser_gp);
  if (ser_gp.empty()) {
    ExecReturnCodeCallback(cb, kSendPacketFailure);
    return;
  }

  kad::SignedValue sv;
  if (sv.ParseFromString(ser_gp)) {
    crypto::Crypto co;
    if (!co.AsymCheckSig(sv.value(), sv.value_signature(), public_key,
        crypto::STRING_STRING)) {
      ExecReturnCodeCallback(cb, kSendPacketFailure);
#ifdef DEBUG
      printf("%s\n", sv.value().c_str());
#endif
      return;
    }
  }

  std::vector<std::string> values;
  int n = GetValue_FromDB(packet_name, &values);
  if (n == kFindValueError) {
    ExecReturnCodeCallback(cb, kStoreManagerError);
    return;
  }

  ReturnCode rc = StorePacket_InsertToDb(packet_name, ser_gp, public_key, true);
  ExecReturnCodeCallback(cb, rc);
}

ReturnCode LocalStoreManager::StorePacket_InsertToDb(const std::string &key,
                                                     const std::string &value,
                                                     const std::string &pub_key,
                                                     const bool &append) {
#ifdef LOCAL_PDVAULT
  // Simulate knode lookup
//  boost::this_thread::sleep(boost::posix_time::seconds(2));
#endif
  try {
    if (key.length() != kKeySize) {
      return kIncorrectKeySize;
    }
    std::string hex_key(base::EncodeToHex(key));
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

void LocalStoreManager::UpdatePacket(const std::string &packet_name,
                                     const std::string &old_value,
                                     const std::string &new_value,
                                     PacketType system_packet_type,
                                     DirType dir_type, const std::string &msid,
                                     const VoidFuncOneInt &cb) {
  std::string key_id, public_key, public_key_signature, private_key;
  PdUtils pd_utils;
  pd_utils.GetPacketSignatureKeys(system_packet_type, dir_type, msid, &key_id,
      &public_key, &public_key_signature, &private_key);
  MaidsafeValidator msv;
  if (!msv.ValidateSignerId(key_id, public_key, public_key_signature)) {
    ExecReturnCodeCallback(cb, kUpdatePacketFailure);
#ifdef DEBUG
    printf("LSM::UpdatePacket - Signing key doesn't validate.\n");
#endif
    return;
  }

  std::string old_ser_gp;
  CreateSerialisedSignedValue(old_value, private_key, &old_ser_gp);
  std::string new_ser_gp;
  CreateSerialisedSignedValue(new_value, private_key, &new_ser_gp);
  if (old_ser_gp.empty() || new_ser_gp.empty()) {
    ExecReturnCodeCallback(cb, kNoPublicKeyToCheck);
#ifdef DEBUG
    printf("LSM::UpdatePacket - Empty old or new.\n");
#endif
    return;
  }

  kad::SignedValue old_sv, new_sv;
  if (!old_sv.ParseFromString(old_ser_gp) ||
      !new_sv.ParseFromString(new_ser_gp)) {
#ifdef DEBUG
    printf("LSM::UpdatePacket - Old or new doesn't parse.\n");
#endif
  }

  crypto::Crypto co;
  if (!co.AsymCheckSig(old_sv.value(), old_sv.value_signature(), public_key,
      crypto::STRING_STRING)) {
    ExecReturnCodeCallback(cb, kUpdatePacketFailure);
#ifdef DEBUG
    printf("LSM::UpdatePacket - Old fails validation.\n");
#endif
    return;
  }
  if (!co.AsymCheckSig(new_sv.value(), new_sv.value_signature(), public_key,
      crypto::STRING_STRING)) {
#ifdef DEBUG
    printf("LSM::UpdatePacket - New fails validation.\n");
#endif
    ExecReturnCodeCallback(cb, kUpdatePacketFailure);
    return;
  }

  std::vector<std::string> values;
  int n = GetValue_FromDB(packet_name, &values);
  if (n == kFindValueError || values.empty()) {
    ExecReturnCodeCallback(cb, kStoreManagerError);
#ifdef DEBUG
    printf("LSM::UpdatePacket - Key not there.\n");
#endif
    return;
  }

  std::set<std::string> the_values(values.begin(), values.end());
  std::set<std::string>::iterator it = the_values.find(old_ser_gp);
  if (it == the_values.end()) {
    ExecReturnCodeCallback(cb, kStoreManagerError);
#ifdef DEBUG
    printf("LSM::UpdatePacket - Old value not there.\n");
#endif
    return;
  }
  it = the_values.find(new_ser_gp);
  if (it != the_values.end()) {
    ExecReturnCodeCallback(cb, kStoreManagerError);
#ifdef DEBUG
    printf("LSM::UpdatePacket - New value already there.\n");
#endif
    return;
  }

  ReturnCode rc = UpdatePacketInDb(packet_name, old_ser_gp, new_ser_gp);
  ExecReturnCodeCallback(cb, rc);
}

ReturnCode LocalStoreManager::UpdatePacketInDb(const std::string &key,
                                               const std::string &old_value,
                                               const std::string &new_value) {
  try {
    if (key.length() != kKeySize) {
      return kIncorrectKeySize;
    }

    std::string hex_key(base::EncodeToHex(key));
    std::string hex_old_value(base::EncodeToHex(old_value));
    std::string hex_new_value(base::EncodeToHex(new_value));
    std::string statement("update network set value='");
    statement += hex_new_value + "' where key='" + hex_key + "' and value='" +
                 hex_old_value + "';";
    int n = db_.execDML(statement.c_str());
    if (n != 1) {
#ifdef DEBUG
      printf("LocalStoreManager::UpdatePacketInDb - Update failed(%d).\n", n);
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

////////////// BUFFER PACKET //////////////

int LocalStoreManager::CreateBP() {
  if (ss_->Id(MPID) == "")
    return -666;

  std::string bufferpacketname(BufferPacketName()), ser_packet;
  BufferPacket buffer_packet;
  GenericPacket *ser_owner_info = buffer_packet.add_owner_info();
  BufferPacketInfo buffer_packet_info;
  buffer_packet_info.set_owner(ss_->Id(MPID));
  buffer_packet_info.set_owner_publickey(ss_->PublicKey(MPID));
  ser_owner_info->set_data(buffer_packet_info.SerializeAsString());
  crypto::Crypto co;
  ser_owner_info->set_signature(co.AsymSign(ser_owner_info->data(), "",
                                ss_->PrivateKey(MPID), crypto::STRING_STRING));
  buffer_packet.SerializeToString(&ser_packet);
  return FlushDataIntoChunk(bufferpacketname, ser_packet, false);
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
  if (!vbph_.ChangeOwnerInfo(ser_gp, ss_->PublicKey(MPID), &bp_in_chunk)) {
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

int LocalStoreManager::LoadBPMessages(
    std::list<ValidatedBufferPacketMessage> *messages) {
  if (ss_->Id(MPID) == "") {
#ifdef DEBUG
    printf("LocalStoreManager::LoadBPMessages - No MPID.\n");
#endif
    return 0;
  }

  std::string bp_in_chunk;
  std::string bufferpacketname(BufferPacketName());
  if (FindAndLoadChunk(bufferpacketname, &bp_in_chunk) != 0) {
#ifdef DEBUG
    printf("LocalStoreManager::LoadBPMessages - Failed to find BP chunk.\n");
#endif
    return 0;
  }
  std::vector<std::string> msgs;
  if (!vbph_.GetMessages(&bp_in_chunk, &msgs)) {
#ifdef DEBUG
    printf("LocalStoreManager::LoadBPMessages - Failed to get messages.\n");
#endif
    return 0;
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
      valid_message.set_index("");
      messages->push_back(valid_message);
    }
  }
  if (FlushDataIntoChunk(bufferpacketname, bp_in_chunk, true) != 0) {
#ifdef DEBUG
    printf("LSM::LoadBPMessages - Failed to flush BP to chunk.\n");
#endif
    return 0;
  }
  return kUpperThreshold_;
}

int LocalStoreManager::SendMessage(
    const std::vector<std::string> &receivers, const std::string &message,
    const MessageType &m_type, std::map<std::string, ReturnCode> *add_results) {
  if (!add_results)
    return -660;
  if (ss_->Id(MPID) == "")
    return -666;

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
    add_results->insert(std::pair<std::string, ReturnCode>
                                 (recs[n],     kBPAwaitingCallback));

  std::string bp_in_chunk, ser_gp;
  int successes = 0;
  boost::uint32_t timestamp = base::GetEpochTime();
  for (size_t n = 0; n < recs.size(); ++n) {
    std::string rec_pub_key(ss_->GetContactPublicKey(recs[n]));
    std::string bufferpacketname(BufferPacketName(recs[n], rec_pub_key));
    if (FindAndLoadChunk(bufferpacketname, &bp_in_chunk) != 0) {
#ifdef DEBUG
      printf("LocalStoreManager::AddBPMessage - Failed to find BP chunk (%s)\n",
             recs[n].c_str());
#endif
      (*add_results)[recs[n]] = kBPAddMessageError;
      continue;
    }

    std::string updated_bp;
    if (!vbph_.AddMessage(bp_in_chunk,
        CreateMessage(message, rec_pub_key, m_type, timestamp), "",
        &updated_bp)) {
#ifdef DEBUG
      printf("LocalStoreManager::AddBPMessage - Failed to add message (%s).\n",
             recs[n].c_str());
#endif
      (*add_results)[recs[n]] = kBPAddMessageError;
      continue;
    }

    if (FlushDataIntoChunk(bufferpacketname, updated_bp, true) != 0) {
#ifdef DEBUG
      printf("LSM::AddBPMessage - Failed to flush BP into chunk. (%s).\n",
             recs[n].c_str());
#endif
      (*add_results)[recs[n]] = kBPAddMessageError;
      continue;
    }
    (*add_results)[recs[n]] = kSuccess;
    ++successes;
  }
  return successes;
}

int LocalStoreManager::LoadBPPresence(std::list<LivePresence>*) {
  return kUpperThreshold_;
}

int LocalStoreManager::AddBPPresence(const std::vector<std::string> &receivers,
                                     std::map<std::string, ReturnCode>*) {
  return receivers.size();
}

////////////// END BUFFER PACKET //////////////

int LocalStoreManager::FindAndLoadChunk(const std::string &chunkname,
                                        std::string *data) {
#ifdef LOCAL_PDVAULT
  // Simulate knode lookup
//  boost::this_thread::sleep(boost::posix_time::seconds(2));
#endif
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
  std::string aes_key =
      base::RandomString(crypto::AES256_KeySize + crypto::AES256_IVSize);
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
#ifdef LOCAL_PDVAULT
  // Simulate knode lookup
//  boost::this_thread::sleep(boost::posix_time::seconds(2));
#endif
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

void LocalStoreManager::PollVaultInfo(kad::VoidFunctorOneString cb) {
  VaultCommunication vc;
  vc.set_chunkstore("/home/Smer/ChunkStore");
  vc.set_offered_space(base::RandomUint32());
  boost::uint32_t fspace = base::RandomUint32();
  while (fspace >= vc.offered_space())
    fspace = base::RandomUint32();
  vc.set_free_space(fspace);
  vc.set_ip("127.0.0.1");
  vc.set_port((base::RandomUint32() % 64512) + 1000);
  vc.set_timestamp(base::GetEpochTime());
  std::string ser_vc;
  vc.SerializeToString(&ser_vc);
  boost::thread t(cb, ser_vc);
}

bool LocalStoreManager::VaultContactInfo(kad::Contact *contact) {
  kad::Contact ctc;
  *contact = ctc;
  return true;
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

void LocalStoreManager::CreateSerialisedSignedValue(
    const std::string &value, const std::string &private_key,
    std::string *ser_gp) {
  ser_gp->clear();
  crypto::Crypto co;
  GenericPacket gp;
  gp.set_data(value);
  gp.set_signature(co.AsymSign(value, "", private_key, crypto::STRING_STRING));
  gp.SerializeToString(ser_gp);
}

void LocalStoreManager::ExecuteReturnSignal(const std::string &chunkname,
                                            ReturnCode rc) {
  int sleep_seconds((base::RandomInt32() % 5) + 1);
  boost::this_thread::sleep(boost::posix_time::seconds(sleep_seconds));
  sig_chunk_uploaded_(chunkname, rc);
  boost::mutex::scoped_lock loch_laggan(signal_mutex_);
  chunks_pending_.erase(chunkname);
}

void LocalStoreManager::ExecStringCallback(kad::VoidFunctorOneString cb,
                                           MaidsafeRpcResult result) {
  std::string ser_result;
  GenericResponse response;
  response.set_result(result);
  response.SerializeToString(&ser_result);
  boost::thread t(cb, ser_result);
}

void LocalStoreManager::ExecReturnCodeCallback(VoidFuncOneInt cb,
                                               ReturnCode rc) {
  boost::thread t(cb, rc);
}

void LocalStoreManager::ExecReturnLoadPacketCallback(
    LoadPacketFunctor cb, std::vector<std::string> results, ReturnCode rc) {
  boost::thread t(cb, results, rc);
}

}  // namespace maidsafe
