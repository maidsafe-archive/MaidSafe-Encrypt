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

void ExeCallbackLoad(const base::callback_func_type &cb, std::string content,
                     boost::mutex *mutex) {
  boost::mutex::scoped_lock gaurd(*mutex);
  GetResponse result;
  std::string ser_result;
  result.set_result(kAck);
  result.set_content(content);
  result.SerializeToString(&ser_result);
  cb(ser_result);
}

void ExeCallbackGetMsgs(const base::callback_func_type &cb,
                        const std::vector<std::string> &msgs,
                        boost::mutex *mutex) {
  boost::mutex::scoped_lock gaurd(*mutex);
  GetBPMessagesResponse result;
  std::string ser_result;
  result.set_result(kAck);
  for (uint16_t i = 0; i < msgs.size(); i++)
    result.add_messages(msgs[i]);
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

LocalStoreManager::LocalStoreManager(
    boost::shared_ptr<ChunkStore> client_chunkstore)
        : db_(), vbph_(), mutex_(), client_chunkstore_(client_chunkstore),
          ss_(SessionSingleton::getInstance()) {}

void LocalStoreManager::Init(int, base::callback_func_type cb) {
  try {
    if (fs::exists("KademilaDb.db")) {
      db_.open("KademilaDb.db");
    } else {
      boost::mutex::scoped_lock loch(mutex_);
      db_.open("KademilaDb.db");
      db_.execDML("create table network(key text primary key,value text);");
    }
    if (!fs::exists("StoreChunks")) {
      fs::create_directory("StoreChunks");
    }
    boost::thread thr(boost::bind(&ExecuteSuccessCallback, cb, &mutex_));
  }
  catch(CppSQLite3Exception &e) {  // NOLINT
    std::cerr << e.errorCode() << ":" << e.errorMessage() << std::endl;
    boost::thread thr(boost::bind(&ExecuteFailureCallback, cb, &mutex_));
  }
}

void LocalStoreManager::Close(base::callback_func_type cb, bool) {
  try {
    boost::mutex::scoped_lock loch(mutex_);
    db_.close();
    boost::thread thr(boost::bind(&ExecuteSuccessCallback, cb, &mutex_));
  }
  catch(CppSQLite3Exception &e) {  // NOLINT
    std::cerr << e.errorCode() << ":" << e.errorMessage() << std::endl;
    boost::thread thr(boost::bind(&ExecuteFailureCallback, cb, &mutex_));
  }
}

int LocalStoreManager::LoadChunk(const std::string &hex_chunk_name,
                                 std::string *data) {
  return FindAndLoadChunk(hex_chunk_name, data);
}

void LocalStoreManager::LoadPacket(const std::string &hex_key,
                                   std::string *result) {
  std::string value = GetValue_FromDB(hex_key);
  GetResponse gr;
  std::string ser_result;
  if (value != "") {
    gr.set_result(kAck);
    gr.set_content(value);
  } else {
    gr.set_result(kNack);
  }
  gr.SerializeToString(result);
  return;
}

//  int LocalStoreManager::LoadBPMessages(const std::string &bufferpacket_name,
//                                        std::list<std::string> *messages) {
//    messages->clear();
//    if (!co.AsymCheckSig(public_key, signed_public_key, public_key,
//        crypto::STRING_STRING)) {
//      return -1;
//    }
//    std::string ser_bp = GetValue_FromDB(hex_key);
//    if (ser_bp == "") {
//      return -2;
//    }
//    // Valitading singature with packet to see
//    // if owner is trying to get messages
//    if (!vbph_.ValidateOwnerSignature(public_key, ser_bp)) {
//      return -3;
//    }
//    std::vector<std::string> result;
//    if (!vbph_.GetMessages(&ser_bp, &result)) {
//      return -4;
//    }
//    for (boost::uint32_t i = 0; i < result.size(); ++i)
//      messages->push_back(result.at(i));
//    return 0;
//  }

void LocalStoreManager::StoreChunk(const std::string &hex_chunk_name,
                                   const DirType,
                                   const std::string&) {
#ifdef DEBUG
//  printf("LocalStoreManager::StoreChunk - %s\n",
//          hex_chunk_name.substr(0, 10).c_str());
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

bool LocalStoreManager::KeyUnique(const std::string &hex_key, bool) {
  bool result = false;
  try {
    boost::mutex::scoped_lock loch(mutex_);
    std::string s = "select * from network where key='" + hex_key;
    s += "';";
    CppSQLite3Query q = db_.execQuery(s.c_str());
    if (q.eof())
      result = true;
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
  return result;
}

void LocalStoreManager::DeletePacket(const std::string &hex_key,
                                     const std::string &signature,
                                     const std::string &public_key,
                                     const std::string &signed_public_key,
                                     const ValueType &type,
                                     base::callback_func_type cb) {
  std::string key("");
  base::decode_from_hex(hex_key, &key);
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  if (!co.AsymCheckSig(public_key, signed_public_key, public_key,
      crypto::STRING_STRING)) {
    boost::thread thr(boost::bind(&ExecuteFailureCallback, cb, &mutex_));
    return;
  }

  if (!co.AsymCheckSig(co.Hash(
      public_key + signed_public_key + key, "", crypto::STRING_STRING, false),
      signature, public_key, crypto::STRING_STRING)) {
    boost::thread thr(boost::bind(&ExecuteFailureCallback, cb, &mutex_));
    return;
  }

  std::string result = "";
  try {
    boost::mutex::scoped_lock loch(mutex_);
    std::string s = "select value from network where key='" + hex_key + "';";
    CppSQLite3Query q = db_.execQuery(s.c_str());
    if (q.eof()) {
      boost::thread thr(boost::bind(&ExecuteFailureCallback, cb, &mutex_));
      return;
    }
    std::string val = q.fieldValue(static_cast<unsigned int>(0));
    base::decode_from_hex(val, &result);
  }
  catch(CppSQLite3Exception &e) {  // NOLINT
    boost::thread thr(boost::bind(&ExecuteFailureCallback, cb, &mutex_));
    return;
  }

  if (result == "") {
    boost::thread thr(boost::bind(&ExecuteFailureCallback, cb, &mutex_));
    return;
  }

  GenericPacket syspacket;
  switch (type) {
    case SYSTEM_PACKET:
        if (!syspacket.ParseFromString(result)) {
          boost::thread thr(boost::bind(&ExecuteFailureCallback, cb, &mutex_));
          return;
        }
        if (!co.AsymCheckSig(syspacket.data(), syspacket.signature(),
            public_key, crypto::STRING_STRING)) {
          boost::thread thr(boost::bind(&ExecuteFailureCallback, cb, &mutex_));
          return;
        }
        break;
//    case BUFFER_PACKET:
//        if (!vbph_.ValidateOwnerSignature(public_key, result)) {
//          boost::thread thr(boost::bind(&ExecuteFailureCallback, cb, mutex_));
//          return;
//        }
//        break;
//    case BUFFER_PACKET_MESSAGE:
//        if (!vbph_.ValidateOwnerSignature(public_key, result)) {
//          boost::thread thr(boost::bind(&ExecuteFailureCallback, cb, mutex_));
//          return;
//        }
//        if (!vbph_.ClearMessages(&result)) {
//          boost::thread thr(boost::bind(&ExecuteFailureCallback, cb, mutex_));
//          return;
//        }
//        break;
//    case BUFFER_PACKET_INFO: break;
    case CHUNK_REFERENCE: break;
    case WATCH_LIST: break;
    case DATA: break;
    case PDDIR_SIGNED: break;
    case PDDIR_NOTSIGNED: break;
    default: break;
  }
  try {
    boost::mutex::scoped_lock loch(mutex_);
    CppSQLite3Buffer bufSQL;
    bufSQL.format("delete from network where key=%Q;", hex_key.c_str());
    int nRows = db_.execDML(bufSQL);
    if ( nRows > 0 ) {
      if (type != BUFFER_PACKET_MESSAGE) {
        boost::thread thr(boost::bind(&ExecuteSuccessCallback, cb, &mutex_));
        return;
      } else {
        std::string enc_value("");
        base::encode_to_hex(result, &enc_value);
        bufSQL.format("insert into network values ('%s', %Q);",
          hex_key.c_str(), enc_value.c_str());
        db_.execDML(bufSQL);
        boost::thread thr(boost::bind(&ExecuteSuccessCallback, cb, &mutex_));
        return;
      }
    } else {
      boost::thread thr(boost::bind(&ExecuteFailureCallback, cb, &mutex_));
      return;
    }
  }
  catch(CppSQLite3Exception &e) {  // NOLINT
    std::cerr << e.errorCode() << "ddddddd:" << e.errorMessage() << std::endl;
    boost::thread thr(boost::bind(&ExecuteFailureCallback, cb, &mutex_));
    return;
  }
}

int LocalStoreManager::StorePacket(const std::string &hex_packet_name,
                                   const std::string &value,
                                   PacketType, DirType, const std::string&) {
  StorePacket_InsertToDb(hex_packet_name, value);
  return 0;
}

int LocalStoreManager::StorePacket_InsertToDb(const std::string &hex_key,
                                              const std::string &value) {
  try {
    if (hex_key == "") {
      return -1;
    }
    std::string s = "select value from network where key='" + hex_key + "';";
    std::string enc_value;
    boost::mutex::scoped_lock loch(mutex_);
    CppSQLite3Query q = db_.execQuery(s.c_str());
    CppSQLite3Buffer bufSQL;

    enc_value = "";
    base::encode_to_hex(value, &enc_value);

    if (!q.eof()) {
      std::string s1 = "delete from network where key='" + hex_key + "';";
      CppSQLite3Query q = db_.execQuery(s1.c_str());
    }
    bufSQL.format("insert into network values ('%s', %Q);", hex_key.c_str(),
                  enc_value.c_str());
    db_.execDML(bufSQL);
    return 0;
  }
  catch(CppSQLite3Exception &e) {  // NOLINT
    std::cerr << e.errorCode() << "error:" << e.errorMessage() << std::endl;
    return -2;
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
int LocalStoreManager::CreateBP(const std::string &bufferpacketname,
                                const std::string &ser_packet) {
#ifdef DEBUG
    printf("LocalStoreManager::CreateBP - BP chunk(%s).\n",
           bufferpacketname.substr(0, 10).c_str());
#endif
  return FlushDataIntoChunk(bufferpacketname, ser_packet, false);
}

int LocalStoreManager::LoadBPMessages(const std::string &bufferpacketname,
                                      std::list<std::string> *messages) {
  std::string bp_in_chunk;
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
  for (unsigned int n = 0; n < msgs.size(); ++n)
    messages->push_back(msgs[n]);
  if (FlushDataIntoChunk(bufferpacketname, bp_in_chunk, true) != 0) {
#ifdef DEBUG
    printf("LocalStoreManager::LoadBPMessages - "
           "Failed to flush BP into chunk.\n");
#endif
    return -1;
  }
  return 0;
}

int LocalStoreManager::ModifyBPInfo(const std::string &bufferpacketname,
                                    const std::string &ser_gp) {
  std::string bp_in_chunk;
  if (FindAndLoadChunk(bufferpacketname, &bp_in_chunk) != 0) {
#ifdef DEBUG
    printf("LocalStoreManager::LoadBPMessages - Failed to find BP chunk(%s).\n",
           bufferpacketname.substr(0, 10).c_str());
#endif
    return -1;
  }
  std::string new_bp;
  if (!vbph_.ChangeOwnerInfo(ser_gp, &bp_in_chunk, ss_->PublicKey(MPID))) {
#ifdef DEBUG
    printf("LocalStoreManager::LoadBPMessages - Failed to get messages.\n");
#endif
    return -2;
  }
  if (FlushDataIntoChunk(bufferpacketname, bp_in_chunk, true) != 0) {
#ifdef DEBUG
    printf("LocalStoreManager::LoadBPMessages - "
           "Failed to flush BP into chunk.\n");
#endif
    return -3;
  }
  return 0;
}

int LocalStoreManager::AddBPMessage(const std::string &bufferpacketname,
                                    const std::string &ser_gp) {
  std::string bp_in_chunk;
  if (FindAndLoadChunk(bufferpacketname, &bp_in_chunk) != 0) {
#ifdef DEBUG
    printf("LocalStoreManager::LoadBPMessages - Failed to find BP chunk.\n");
#endif
    return -1;
  }

  std::vector<std::string> msgs;
  std::string updated_bp;
  if (!vbph_.AddMessage(bp_in_chunk, ser_gp, "", &updated_bp)) {
#ifdef DEBUG
    printf("LocalStoreManager::LoadBPMessages - Failed to get messages.\n");
#endif
    return -1;
  }

  if (FlushDataIntoChunk(bufferpacketname, updated_bp, true) != 0) {
#ifdef DEBUG
    printf("LocalStoreManager::LoadBPMessages - "
           "Failed to flush BP into chunk.\n");
#endif
    return -1;
  }
  return 0;
}

int LocalStoreManager::FindAndLoadChunk(const std::string &chunkname,
                                        std::string *data) {
  fs::path file_path("StoreChunks");
  file_path = file_path / chunkname;
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
  fs::path file_path("StoreChunks");
  file_path = file_path / chunkname;
  try {
    if (boost::filesystem::exists(file_path) && !overwrite) {
#ifdef DEBUG
      printf("This BP (%s) already exists\n.", chunkname.substr(0, 10).c_str());
#endif
      return -1;
    }
    boost::filesystem::ofstream bp_file(file_path.string().c_str(),
                                        boost::filesystem::ofstream::binary);
    bp_file << data;
    bp_file.close();
  }
  catch(const std::exception &e) {
    return -1;
  }
  return 0;
}

//  int LocalStoreManager::ModifyBPInfo(const std::string &hex_key,
//                                      const std::string &value) {
//    // Validating that owner is sending request
//    CppSQLite3Binary blob;
//    std::string ser_bp("");
//    try {
//      std::string s = "select value from network where key='"+ hex_key + "';";
//      CppSQLite3Query q = db_.execQuery(s.c_str());
//      if (q.eof()) {
//        return false;
//      }
//      std::string val = q.fieldValue(static_cast<unsigned int>(0));
//      base::decode_from_hex(val, &ser_bp);
//    }
//    catch(CppSQLite3Exception &e) {  // NOLINT
//      return false;
//    }
//    if (!vbph_.ChangeOwnerInfo(value, &ser_bp,
//        maidsafe::SessionSingleton::getInstance()->PublicKey(MPID)))
//      return false;
//  //  value = ser_bp;
//    return true;
//  }

std::string LocalStoreManager::GetValue_FromDB(const std::string &hex_key) {
  CppSQLite3Binary blob;
  std::string result;
  try {
    boost::mutex::scoped_lock loch(mutex_);
    std::string s = "select value from network where key='" + hex_key + "';";
    CppSQLite3Query q = db_.execQuery(s.c_str());
    if (q.eof()) {
      return result;
    }
    std::string val = q.fieldValue(static_cast<unsigned int>(0));
    base::decode_from_hex(val, &result);
  }
  catch(CppSQLite3Exception &e) {  // NOLINT
    return result;
  }
  return result;
}

void LocalStoreManager::PollVaultInfo(base::callback_func_type cb) {
  boost::thread thr(boost::bind(&ExecCallbackVaultInfo, cb, &mutex_));
}

void LocalStoreManager::VaultContactInfo(base::callback_func_type cb) {
  boost::thread thr(boost::bind(&ExecuteSuccessCallback, cb, &mutex_));
}

void LocalStoreManager::OwnLocalVault(const std::string &,
      const std::string &pub_key, const std::string &signed_pub_key,
      const boost::uint32_t &, const std::string &, const boost::uint64_t &,
      boost::function<void(const OwnVaultResult&, const std::string&)> cb) {
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  std::string pmid_name = co.Hash(pub_key + signed_pub_key, "",
                          crypto::STRING_STRING, false);
  boost::thread thr(cb, maidsafe::OWNED_SUCCESS, pmid_name);
}

void LocalStoreManager::LocalVaultStatus(boost::function< void(
      const VaultStatus&) > cb) {
  boost::thread thr(cb, maidsafe::NOT_OWNED);
}

bool LocalStoreManager::NotDoneWithUploading() { return false; }

}  // namespace maidsafe
