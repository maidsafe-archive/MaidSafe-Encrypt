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
#include <vector>

#include "maidsafe/chunkstore.h"
#include "maidsafe/client/localstoremanager.h"
#include "maidsafe/client/sessionsingleton.h"
#include "protobuf/maidsafe_messages.pb.h"
#include "protobuf/maidsafe_service_messages.pb.h"

namespace fs = boost::filesystem;

namespace maidsafe {

void ExecuteSuccessCallback(const base::callback_func_type &cb,
                            boost::recursive_mutex *mutex) {
  base::pd_scoped_lock gaurd(*mutex);
  std::string ser_result;
  GenericResponse result;
  result.set_result(kAck);
  result.SerializeToString(&ser_result);
  cb(ser_result);
}

void ExecuteFailureCallback(const base::callback_func_type &cb,
                            boost::recursive_mutex *mutex) {
  base::pd_scoped_lock gaurd(*mutex);
  std::string ser_result;
  GenericResponse result;
  result.set_result(kNack);
  result.SerializeToString(&ser_result);
  cb(ser_result);
}

void ExeCallbackLoad(const base::callback_func_type &cb, std::string content,
                     boost::recursive_mutex *mutex) {
  base::pd_scoped_lock gaurd(*mutex);
  GetResponse result;
  std::string ser_result;
  result.set_result(kAck);
  result.set_content(content);
  result.SerializeToString(&ser_result);
  cb(ser_result);
}

void ExeCallbackGetMsgs(const base::callback_func_type &cb,
                        const std::vector<std::string> &msgs,
                        boost::recursive_mutex *mutex) {
  base::pd_scoped_lock gaurd(*mutex);
  GetMessagesResponse result;
  std::string ser_result;
  result.set_result(kAck);
  for (uint16_t i = 0; i < msgs.size(); i++)
    result.add_messages(msgs[i]);
  result.SerializeToString(&ser_result);
  cb(ser_result);
}

void ExecCallbackVaultInfo(const base::callback_func_type &cb,
                           boost::recursive_mutex *mutex) {
  base::pd_scoped_lock loch(*mutex);
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

LocalStoreManager::LocalStoreManager(
    boost::recursive_mutex *mutex,
    boost::shared_ptr<ChunkStore> client_chunkstore)
        : db_(),
          vbph_(),
          crypto_obj_(),
          mutex_(mutex),
          client_chunkstore_(client_chunkstore) {}

void LocalStoreManager::Init(int, base::callback_func_type cb) {
  try {
    if (fs::exists("KademilaDb.db")) {
      db_.open("KademilaDb.db");
    } else {
      db_.open("KademilaDb.db");
      db_.execDML("create table network(key text primary key,value text);");
    }
    crypto_obj_.set_symm_algorithm(crypto::AES_256);
    crypto_obj_.set_hash_algorithm(crypto::SHA_512);
    if (!fs::exists("StoreChunks")) {
      fs::create_directory("StoreChunks");
    }
    boost::thread thr(boost::bind(&ExecuteSuccessCallback, cb, mutex_));
  }
  catch(CppSQLite3Exception &e) {  // NOLINT
    std::cerr << e.errorCode() << ":" << e.errorMessage() << std::endl;
    boost::thread thr(boost::bind(&ExecuteFailureCallback, cb, mutex_));
  }
}

void LocalStoreManager::Close(base::callback_func_type cb, bool) {
  try {
    db_.close();
    boost::thread thr(boost::bind(&ExecuteSuccessCallback, cb, mutex_));
  }
  catch(CppSQLite3Exception &e) {  // NOLINT
    std::cerr << e.errorCode() << ":" << e.errorMessage() << std::endl;
    boost::thread thr(boost::bind(&ExecuteFailureCallback, cb, mutex_));
  }
}

int LocalStoreManager::LoadChunk(const std::string &hex_chunk_name,
                                 std::string *data) {
#ifdef DEBUG
  printf("LocalStoreManager::LoadChunk - %s\n",
          hex_chunk_name.substr(0, 10).c_str());
#endif
  fs::path file_path("StoreChunks");
#ifdef DEBUG
  printf("LocalStoreManager::LoadChunk - NALGAAAAAAAAAAA\n");
#endif
  file_path = file_path / hex_chunk_name;
#ifdef DEBUG
  printf("LocalStoreManager::LoadChunk - SENOOOOOOOOOOOOOO\n");
#endif
  try {
      if (!fs::exists(file_path)) {
#ifdef DEBUG
        printf("LocalStoreManager::LoadChunk - didn't find the chunk.\n");
#endif
        return -1;
      }
#ifdef DEBUG
      printf("LocalStoreManager::LoadChunk - PUCHAAAAAAAAAAAAAAAA\n");
#endif
      boost::uintmax_t size = fs::file_size(file_path);
      boost::scoped_ptr<char> temp(new char[size]);
      fs::ifstream fstr;
      fstr.open(file_path, std::ios_base::binary);
      fstr.read(temp.get(), size);
      fstr.close();
      *data = std::string((const char*)temp.get(), size);
#ifdef DEBUG
      printf("LocalStoreManager::LoadChunk - NALGAAAAAAAAAAA\n");
#endif
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("LocalStoreManager::LoadChunk - %s\n", e.what());
#endif
    return -1;
  }
  return 0;
}

void LocalStoreManager::StoreChunk(const std::string &hex_chunk_name,
                                   const DirType,
                                   const std::string&) {
#ifdef DEBUG
  printf("LocalStoreManager::StoreChunk - %s\n",
          hex_chunk_name.substr(0, 10).c_str());
#endif
  fs::path file_path("StoreChunks");
  file_path = file_path / hex_chunk_name;
  std::string non_hex("");
  base::decode_from_hex(hex_chunk_name, &non_hex);
  client_chunkstore_->Store(non_hex, file_path);

  ChunkType type = client_chunkstore_->chunk_type(non_hex);
  fs::path current = client_chunkstore_->GetChunkPath(non_hex, type, false);
  try {
    if (!fs::exists(file_path)) {
      fs::copy_file(current, file_path);
    }
  }
  catch(const std::exception &e) {
    printf("%s\n", e.what());
  }
  // Move chunk from Outgoing to Normal.
  ChunkType chunk_type =
      client_chunkstore_->chunk_type(non_hex);
  ChunkType new_type = chunk_type ^ (kOutgoing | kNormal);
  if (client_chunkstore_->ChangeChunkType(non_hex, new_type) != 0) {
#ifdef DEBUG
    printf("In LocalStoreManager::SendContent, failed to change chunk type.\n");
#endif
  }
}

void LocalStoreManager::IsKeyUnique(const std::string &hex_key,
                                    base::callback_func_type cb) {
  bool result = false;
  try {
    std::string s = "select * from network where key='" + hex_key;
    s += "';";
    CppSQLite3Query q = db_.execQuery(s.c_str());
    if (q.eof())
      result = true;
    else
      result = false;
  }
  catch(CppSQLite3Exception &e) {  // NOLINT
    std::cerr << e.errorCode() << ":" << e.errorMessage() << std::endl;
    result = false;
  }
  if (result) {
    fs::path file_path("StoreChunks");
    file_path = file_path / hex_key;
    result = (!fs::exists(file_path));
  }
  if (result) {
    ExecuteSuccessCallback(cb, mutex_);
  } else {
    ExecuteFailureCallback(cb, mutex_);
  }
}

void LocalStoreManager::DeletePacket(const std::string &hex_key,
                                     const std::string &signature,
                                     const std::string &public_key,
                                     const std::string &signed_public_key,
                                     const ValueType &type,
                                     base::callback_func_type cb) {
  std::string key("");
  base::decode_from_hex(hex_key, &key);
  if (!crypto_obj_.AsymCheckSig(public_key, signed_public_key, public_key,
      crypto::STRING_STRING)) {
    boost::thread thr(boost::bind(&ExecuteFailureCallback, cb, mutex_));
    return;
  }

  if (!crypto_obj_.AsymCheckSig(crypto_obj_.Hash(
      public_key + signed_public_key + key, "", crypto::STRING_STRING, false),
      signature, public_key, crypto::STRING_STRING)) {
    boost::thread thr(boost::bind(&ExecuteFailureCallback, cb, mutex_));
    return;
  }

  std::string result = "";
  try {
    std::string s = "select value from network where key='" + hex_key + "';";
    CppSQLite3Query q = db_.execQuery(s.c_str());
    if (q.eof()) {
      boost::thread thr(boost::bind(&ExecuteFailureCallback, cb, mutex_));
      return;
    }
    std::string val = q.fieldValue(static_cast<unsigned int>(0));
    base::decode_from_hex(val, &result);
  }
  catch(CppSQLite3Exception &e) {  // NOLINT
    boost::thread thr(boost::bind(&ExecuteFailureCallback, cb, mutex_));
    return;
  }

  if (result == "") {
    boost::thread thr(boost::bind(&ExecuteFailureCallback, cb, mutex_));
    return;
  }

  packethandler::GenericPacket syspacket;
  switch (type) {
    case SYSTEM_PACKET:
        if (!syspacket.ParseFromString(result)) {
          boost::thread thr(boost::bind(&ExecuteFailureCallback, cb, mutex_));
          return;
        }
        if (!crypto_obj_.AsymCheckSig(syspacket.data(), syspacket.signature(),
            public_key, crypto::STRING_STRING)) {
          boost::thread thr(boost::bind(&ExecuteFailureCallback, cb, mutex_));
          return;
        }
        break;
    case BUFFER_PACKET:
        if (!vbph_.ValidateOwnerSignature(public_key, result)) {
          boost::thread thr(boost::bind(&ExecuteFailureCallback, cb, mutex_));
          return;
        }
        break;
    case BUFFER_PACKET_MESSAGE:
        if (!vbph_.ValidateOwnerSignature(public_key, result)) {
          boost::thread thr(boost::bind(&ExecuteFailureCallback, cb, mutex_));
          return;
        }
        if (!vbph_.ClearMessages(&result)) {
          boost::thread thr(boost::bind(&ExecuteFailureCallback, cb, mutex_));
          return;
        }
        break;
    case BUFFER_PACKET_INFO: break;
    case CHUNK_REFERENCE: break;
    case WATCH_LIST: break;
    case DATA: break;
    case PDDIR_SIGNED: break;
    case PDDIR_NOTSIGNED: break;
  }
  try {
    CppSQLite3Buffer bufSQL;
    bufSQL.format("delete from network where key=%Q;", hex_key.c_str());
    int nRows = db_.execDML(bufSQL);
    if ( nRows > 0 ) {
      if (type != BUFFER_PACKET_MESSAGE) {
        boost::thread thr(boost::bind(&ExecuteSuccessCallback, cb, mutex_));
        return;
      } else {
        std::string enc_value("");
        base::encode_to_hex(result, &enc_value);
        bufSQL.format("insert into network values ('%s', %Q);",
          hex_key.c_str(), enc_value.c_str());
        db_.execDML(bufSQL);
        boost::thread thr(boost::bind(&ExecuteSuccessCallback, cb, mutex_));
        return;
      }
    } else {
      boost::thread thr(boost::bind(&ExecuteFailureCallback, cb, mutex_));
      return;
    }
  }
  catch(CppSQLite3Exception &e) {  // NOLINT
    std::cerr << e.errorCode() << "ddddddd:" << e.errorMessage() << std::endl;
    boost::thread thr(boost::bind(&ExecuteFailureCallback, cb, mutex_));
    return;
  }
}

int LocalStoreManager::StorePacket(const std::string &hex_packet_name,
                                   const std::string &value,
                                   packethandler::SystemPackets type,
                                   DirType,
                                   const std::string&) {
  std::string local_value = value;
  std::string local_key = hex_packet_name;
  std::string mpid_pub_key =
      SessionSingleton::getInstance()->PublicKey(MPID);
  std::string sender_id;
  packethandler::MessageType bp_msg_type;
  std::string ser_bp;
  switch (type) {
    case packethandler::BUFFER_MESSAGE:
        if (vbph_.CheckMsgStructure(value, &sender_id, &bp_msg_type)) {
          ser_bp = GetValue_FromDB(hex_packet_name);
          if (ser_bp == "") {
#ifdef DEBUG
            printf("bp not there.\n");
#endif
            return -1;
          }
          if (!vbph_.AddMessage(ser_bp, value, mpid_pub_key, &local_value))
            return -2;
        } else {
#ifdef DEBUG
          printf("Invalid msg struct.\n");
#endif
          return -3;
        }
        break;
    case packethandler::BUFFER_INFO:
        if (!ModifyBufferPacketInfo(local_key, &local_value,
            mpid_pub_key)) {
          printf("Failed to modify buffer packet info.\n");
          return -4;
        }
        break;
    default:
        break;
  }
  StorePacket_InsertToDb(hex_packet_name, local_value);
  return 0;
}

int LocalStoreManager::StorePacket_InsertToDb(const std::string &hex_key,
                                              const std::string &value) {
  std::string local_value = value;
  std::string local_key = hex_key;

  try {
    if (local_key == "") {
      return -1;
    }
    std::string s = "select value from network where key='" + local_key + "';";
    std::string enc_value;
    CppSQLite3Query q = db_.execQuery(s.c_str());
    CppSQLite3Buffer bufSQL;

    enc_value = "";
    base::encode_to_hex(local_value, &enc_value);

    if (!q.eof()) {
      std::string s1 = "delete from network where key='" + local_key + "';";
      CppSQLite3Query q = db_.execQuery(s1.c_str());
    }
    bufSQL.format("insert into network values ('%s', %Q);", local_key.c_str(),
      enc_value.c_str());
    db_.execDML(bufSQL);
    return 0;
  }
  catch(CppSQLite3Exception &e) {  // NOLINT
    std::cerr << e.errorCode() << "error:" << e.errorMessage() << std::endl;
    return -2;
  }
}

void LocalStoreManager::LoadPacket(const std::string &hex_key,
                                   base::callback_func_type cb) {
  std::string result;
  result = GetValue_FromDB(hex_key);
  if (result == "") {
    boost::thread thr(boost::bind(&ExecuteFailureCallback, cb, mutex_));
    return;
  }
  boost::thread thr(boost::bind(&ExeCallbackLoad, cb, result, mutex_));
}

void LocalStoreManager::GetMessages(const std::string &hex_key,
                                    const std::string &public_key,
                                    const std::string &signed_public_key,
                                    base::callback_func_type cb) {
  std::vector<std::string> result;
  if (!crypto_obj_.AsymCheckSig(public_key, signed_public_key, public_key,
      crypto::STRING_STRING)) {
    boost::thread thr(boost::bind(&ExecuteFailureCallback, cb, mutex_));
    return;
  }

  std::string ser_bp = GetValue_FromDB(hex_key);
  if (ser_bp == "") {
    boost::thread thr(boost::bind(&ExecuteFailureCallback, cb, mutex_));
    return;
  }

  // Valitading singature with packet to see if owner is trying to get messages
  if (!vbph_.ValidateOwnerSignature(public_key, ser_bp)) {
    boost::thread thr(boost::bind(&ExecuteFailureCallback, cb, mutex_));
    return;
  }

  vbph_.GetMessages(ser_bp, &result);
  boost::thread thr(boost::bind(&ExeCallbackGetMsgs, cb, result, mutex_));
}

bool LocalStoreManager::ValidateGenericPacket(std::string ser_gp,
                                              std::string public_key) {
  packethandler::GenericPacket gp;
  if (!gp.ParseFromString(ser_gp))
    return false;
  if (!crypto_obj_.AsymCheckSig(gp.data(), gp.signature(), public_key,
      crypto::STRING_STRING))
    return false;
  return true;
}

bool LocalStoreManager::ModifyBufferPacketInfo(const std::string &hex_key,
                                               std::string *value,
                                               const std::string &public_key) {
  // Validating that owner is sending request
  CppSQLite3Binary blob;
  std::string ser_bp("");
  try {
    std::string s = "select value from network where key='" + hex_key + "';";
    CppSQLite3Query q = db_.execQuery(s.c_str());
    if (q.eof()) {
      return false;
    }
    std::string val = q.fieldValue(static_cast<unsigned int>(0));
    base::decode_from_hex(val, &ser_bp);
  }
  catch(CppSQLite3Exception &e) {  // NOLINT
    return false;
  }
  if (!vbph_.ChangeOwnerInfo(*value, &ser_bp, public_key))
    return false;
  *value = ser_bp;
  return true;
}

std::string LocalStoreManager::GetValue_FromDB(const std::string &hex_key) {
  CppSQLite3Binary blob;
  std::string result("");
  try {
    std::string s = "select value from network where key='" + hex_key + "';";
    CppSQLite3Query q = db_.execQuery(s.c_str());
    if (q.eof()) {
      return "";
    }
    std::string val = q.fieldValue(static_cast<unsigned int>(0));
    base::decode_from_hex(val, &result);
  }
  catch(CppSQLite3Exception &e) {  // NOLINT
    return "";
  }
  return result;
}

void LocalStoreManager::PollVaultInfo(base::callback_func_type cb) {
  boost::thread thr(boost::bind(&ExecCallbackVaultInfo, cb, mutex_));
}

void LocalStoreManager::VaultContactInfo(base::callback_func_type cb) {
  boost::thread thr(boost::bind(&ExecuteSuccessCallback, cb, mutex_));
}

void LocalStoreManager::OwnLocalVault(const std::string &,
      const std::string &pub_key, const std::string &signed_pub_key,
      const boost::uint32_t &, const std::string &, const boost::uint64_t &,
      boost::function<void(const OwnVaultResult&, const std::string&)> cb) {
  std::string pmid_name = crypto_obj_.Hash(pub_key + signed_pub_key, "",
      crypto::STRING_STRING, false);
  boost::thread thr(cb, maidsafe::OWNED_SUCCESS, pmid_name);
}

void LocalStoreManager::LocalVaultStatus(boost::function< void(
      const VaultStatus&) > cb) {
  boost::thread thr(cb, maidsafe::NOT_OWNED);
}

}  // namespace maidsafe
