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
#include <cryptopp/hex.h>
#include <vector>

#include "maidsafe/utils.h"
#include "maidsafe/client/localstoremanager.h"
#include "protobuf/general_messages.pb.h"
#include "protobuf/maidsafe_service_messages.pb.h"

namespace boost_fs = boost::filesystem;

namespace maidsafe {

void ExecuteSuccessCallback(const base::callback_func_type &cb,
                            boost::recursive_mutex *mutex) {
  base::pd_scoped_lock gaurd(*mutex);
  std::string ser_result;
  base::GeneralResponse result;
  result.set_result(kCallbackSuccess);
  result.SerializeToString(&ser_result);
  cb(ser_result);
}

void ExecuteFailureCallback(const base::callback_func_type &cb,
                            boost::recursive_mutex *mutex) {
  base::pd_scoped_lock gaurd(*mutex);
  std::string ser_result;
  base::GeneralResponse result;
  result.set_result(kCallbackFailure);
  result.SerializeToString(&ser_result);
  cb(ser_result);
}

void ExeCallbackLoad(const base::callback_func_type &cb, std::string content,
                     boost::recursive_mutex *mutex) {
  base::pd_scoped_lock gaurd(*mutex);
  GetResponse result;
  std::string ser_result;
  result.set_result(kCallbackSuccess);
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
  result.set_result(kCallbackSuccess);
  for (uint16_t i = 0; i < msgs.size(); i++)
    result.add_messages(msgs[i]);
  result.SerializeToString(&ser_result);
  cb(ser_result);
}

LocalStoreManager::LocalStoreManager(boost::recursive_mutex *mutex)
    : db_(), vbph_(), crypto_obj_(), mutex_(mutex) {}

bool LocalStoreManager::ValidateGenericPacket(std::string ser_gp,
                                              std::string public_key) {
  packethandler::GenericPacket gp;
  if (!gp.ParseFromString(ser_gp))
    return false;
  if (!crypto_obj_.AsymCheckSig(gp.data(), gp.signature(),
    public_key, maidsafe_crypto::STRING_STRING))
    return false;
  return true;
}

bool LocalStoreManager::ModifyBufferPacketInfo(const std::string &key,
                                               std::string *value,
                                               const std::string &public_key) {
  if (!ValidateGenericPacket(*value, public_key)) {
    return false;
  }

  // Validating that owner is sending request
  CppSQLite3Binary blob;
  std::string ser_bp;
  try {
    std::string s = "select value from network where key='" + key + "';";
    CppSQLite3Query q = db_.execQuery(s.c_str());
    if (q.eof()) {
      return false;
    }
    std::string val = q.fieldValue(static_cast<unsigned int>(0));
    CryptoPP::StringSource(val, true,
      new CryptoPP::HexDecoder(new CryptoPP::StringSink(ser_bp)));
  }
  catch(CppSQLite3Exception &e) {  // NOLINT
    return false;
  }
  if (!vbph_.ChangeOwnerInfo(*value, &ser_bp, public_key))
    return false;
  *value = ser_bp;
  return true;
}

void LocalStoreManager::StorePacket(const std::string &key,
                                    const std::string &value,
                                    const std::string &signature,
                                    const std::string &public_key,
                                    const std::string &signed_public_key,
                                    const value_types &type,
                                    bool,
                                    base::callback_func_type cb) {
  if (type != DATA && type != PDDIR_NOTSIGNED) {
    if (!crypto_obj_.AsymCheckSig(public_key, signed_public_key,
      public_key, maidsafe_crypto::STRING_STRING)) {
#ifdef DEBUG
      printf("\n\n\nFail check signed pubkey.\n\n\n");
#endif
      boost::thread thr(boost::bind(&ExecuteFailureCallback, cb, mutex_));
      return;
    }

    if (!crypto_obj_.AsymCheckSig(crypto_obj_.Hash(
      public_key + signed_public_key + key, "", maidsafe_crypto::STRING_STRING,
      true), signature, public_key, maidsafe_crypto::STRING_STRING)) {
#ifdef DEBUG
      printf("Fail check signed request.\n");
#endif
      boost::thread thr(boost::bind(&ExecuteFailureCallback, cb, mutex_));
      return;
    }
  }

  std::string local_value = value;
  std::string local_key = key;
  std::string local_public_key = public_key;
  std::string sender_id;
  packethandler::MessageType bp_msg_type;

  switch (type) {
    case BUFFER_PACKET_MESSAGE:
        if (vbph_.CheckMsgStructure(value, sender_id, bp_msg_type)) {
          std::string ser_bp = GetValue_FromDB(key);
            if (ser_bp == "") {
#ifdef DEBUG
              printf("bp not there.\n");
#endif
              boost::thread thr(boost::bind(\
                  &ExecuteFailureCallback, cb, mutex_));
              return;
            }
            if (!vbph_.AddMessage(ser_bp, value, signed_public_key,
                &local_value)) {
              boost::thread thr(boost::bind(\
                  &ExecuteFailureCallback, cb, mutex_));
              return;
              }
        } else {
#ifdef DEBUG
          printf("Invalid msg struct.\n");
#endif
          boost::thread thr(boost::bind(&ExecuteFailureCallback, cb, mutex_));
          return;
        }
        break;
    case SYSTEM_PACKET:
        if (signature != kAnonymousSignedRequest) {
          if (!ValidateGenericPacket(local_value, local_public_key)) {
            boost::thread thr(boost::bind(&ExecuteFailureCallback, cb, mutex_));
            return;
          }
        }
        break;
    case BUFFER_PACKET_INFO:
        if (!ModifyBufferPacketInfo(local_key, &local_value,
          local_public_key)) {
          boost::thread thr(boost::bind(&ExecuteFailureCallback, cb, mutex_));
          return;
        }
        break;
    case BUFFER_PACKET:
        if (!vbph_.ValidateOwnerSignature(local_public_key, local_value)) {
          boost::thread thr(boost::bind(&ExecuteFailureCallback, cb, mutex_));
          return;
        }
    default: break;
  }
  StorePacket_InsertToDb(key, local_value, cb);
}

void LocalStoreManager::StorePacket_InsertToDb(const std::string &key,
                                               const std::string &value,
                                               base::callback_func_type cb) {
  std::string local_value = value;
  std::string local_key = key;

  try {
    if (local_key == "") {
      boost::thread thr(boost::bind(&ExecuteFailureCallback, cb, mutex_));
      return;
    }
    std::string s = "select value from network where key='" + local_key + "';";
    std::string enc_value;
    CppSQLite3Query q = db_.execQuery(s.c_str());
    CppSQLite3Buffer bufSQL;

    CryptoPP::StringSource(local_value, true,
      new CryptoPP::HexEncoder(new CryptoPP::StringSink(enc_value), false));

    if (!q.eof()) {
      std::string s1 = "delete from network where key='" + local_key + "';";
      CppSQLite3Query q = db_.execQuery(s1.c_str());
    }
    bufSQL.format("insert into network values ('%s', %Q);", local_key.c_str(),
      enc_value.c_str());
    db_.execDML(bufSQL);
    boost::thread thr(boost::bind(&ExecuteSuccessCallback, cb, mutex_));
  }
  catch(CppSQLite3Exception &e) {  // NOLINT
    std::cerr << e.errorCode() << "error:" << e.errorMessage() << std::endl;
    boost::thread thr(boost::bind(&ExecuteFailureCallback, cb, mutex_));
    return;
  }
}


void LocalStoreManager::StoreChunk(const std::string &chunk_name,
                                   const std::string &content,
                                   const std::string &,
                                   const std::string &,
                                   const std::string &,
                                   base::callback_func_type cb) {
  boost_fs::path file_path("StoreChunks");
  file_path = file_path/chunk_name;
  boost_fs::ofstream ofs;
  ofs.open(file_path, std::ios_base::binary);
  ofs << content;
  ofs.close();

  boost::thread thr(boost::bind(&ExecuteSuccessCallback, cb, mutex_));
}

void LocalStoreManager::LoadChunk(const std::string &chunk_name,
                                  base::callback_func_type cb) {
  boost_fs::path file_path("StoreChunks");
  file_path = file_path / chunk_name;
  if (!boost_fs::exists(file_path)) {
    boost::thread thr(boost::bind(&ExecuteFailureCallback, cb, mutex_));
    return;
  }
  boost::uintmax_t size = boost_fs::file_size(file_path);
  boost::scoped_ptr<char> temp(new char[size]);
  boost_fs::ifstream fstr;
  fstr.open(file_path, std::ios_base::binary);
  fstr.read(temp.get(), size);
  fstr.close();
  std::string result((const char*)temp.get(), size);
  boost::thread thr(boost::bind(&ExeCallbackLoad, cb, result, mutex_));
}

void LocalStoreManager::DeletePacket(const std::string &key,
                                     const std::string &signature,
                                     const std::string &public_key,
                                     const std::string &signed_public_key,
                                     const value_types &type,
                                     base::callback_func_type cb) {
  if (!crypto_obj_.AsymCheckSig(public_key, signed_public_key,
    public_key, maidsafe_crypto::STRING_STRING)) {
    boost::thread thr(boost::bind(&ExecuteFailureCallback, cb, mutex_));
    return;
  }

  if (!crypto_obj_.AsymCheckSig(crypto_obj_.Hash(
    public_key + signed_public_key + key, "", maidsafe_crypto::STRING_STRING,
    true), signature, public_key, maidsafe_crypto::STRING_STRING)) {
    boost::thread thr(boost::bind(&ExecuteFailureCallback, cb, mutex_));
    return;
  }

  std::string result = "";
  try {
    std::string s = "select value from network where key='" + key + "';";
    CppSQLite3Query q = db_.execQuery(s.c_str());
    if (q.eof()) {
      boost::thread thr(boost::bind(&ExecuteFailureCallback, cb, mutex_));
      return;
    }
    std::string val = q.fieldValue(static_cast<unsigned int>(0));

    CryptoPP::StringSource(val, true,
      new CryptoPP::HexDecoder(new CryptoPP::StringSink(result)));
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
            public_key, maidsafe_crypto::STRING_STRING)) {
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
    bufSQL.format("delete from network where key=%Q;", key.c_str());
    int nRows = db_.execDML(bufSQL);
    if ( nRows > 0 ) {
      if (type != BUFFER_PACKET_MESSAGE) {
        boost::thread thr(boost::bind(&ExecuteSuccessCallback, cb, mutex_));
        return;
      } else {
        std::string enc_value;
        CryptoPP::StringSource(result, true, new CryptoPP::HexEncoder(
          new CryptoPP::StringSink(enc_value), false));
        bufSQL.format("insert into network values ('%s', %Q);",
          key.c_str(), enc_value.c_str());
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

void LocalStoreManager::LoadPacket(const std::string &key,
                                   base::callback_func_type cb) {
  std::string result;
  result = GetValue_FromDB(key);
  if (result == "") {
    boost::thread thr(boost::bind(&ExecuteFailureCallback, cb, mutex_));
    return;
  }
  boost::thread thr(boost::bind(&ExeCallbackLoad, cb, result, mutex_));
}

void LocalStoreManager::IsKeyUnique(const std::string &key,
                                    base::callback_func_type cb) {
  bool result = false;
  try {
    std::string s = "select * from network where key='" + key;
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
    boost_fs::path file_path("StoreChunks");
    file_path = file_path / key;
    result = (!boost_fs::exists(file_path));
  }
  if (result) {
    ExecuteSuccessCallback(cb, mutex_);
  } else {
    ExecuteFailureCallback(cb, mutex_);
  }
}

void LocalStoreManager::Init(base::callback_func_type cb) {
  try {
    if (boost_fs::exists("KademilaDb.db")) {
      db_.open("KademilaDb.db");
    } else {
      db_.open("KademilaDb.db");
      db_.execDML("create table network(key text primary key,value text);");
    }
    crypto_obj_.set_symm_algorithm("AES_256");
    crypto_obj_.set_hash_algorithm("SHA512");
    if (!boost_fs::exists("StoreChunks")) {
      boost_fs::create_directory("StoreChunks");
    }
    boost::thread thr(boost::bind(&ExecuteSuccessCallback, cb, mutex_));
  }
  catch(CppSQLite3Exception &e) {  // NOLINT
    std::cerr << e.errorCode() << ":" << e.errorMessage() << std::endl;
    boost::thread thr(boost::bind(&ExecuteFailureCallback, cb, mutex_));
  }
}

void LocalStoreManager::Close(base::callback_func_type cb) {
  try {
    db_.close();
    boost::thread thr(boost::bind(&ExecuteSuccessCallback, cb, mutex_));
  }
  catch(CppSQLite3Exception &e) {  // NOLINT
    std::cerr << e.errorCode() << ":" << e.errorMessage() << std::endl;
    boost::thread thr(boost::bind(&ExecuteFailureCallback, cb, mutex_));
  }
}

void LocalStoreManager::GetMessages(const std::string &key,
                                    const std::string &public_key,
                                    const std::string &signed_public_key,
                                    base::callback_func_type cb) {
  std::vector<std::string> result;
  if (!crypto_obj_.AsymCheckSig(public_key, signed_public_key,
    public_key, maidsafe_crypto::STRING_STRING)) {
    boost::thread thr(boost::bind(&ExecuteFailureCallback, cb, mutex_));
    return;
  }

  std::string ser_bp = GetValue_FromDB(key);
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

std::string LocalStoreManager::GetValue_FromDB(const std::string &key) {
  CppSQLite3Binary blob;
  std::string result;
  try {
    std::string s = "select value from network where key='"+key+"';";
    CppSQLite3Query q = db_.execQuery(s.c_str());
    if (q.eof()) {
      return "";
    }
    std::string val = q.fieldValue(static_cast<unsigned int>(0));
    CryptoPP::StringSource(val, true, new CryptoPP::HexDecoder(
      new CryptoPP::StringSink(result)));
  }
  catch(CppSQLite3Exception &e) {  // NOLINT
    return "";
  }
  return result;
}

}  // namespace maidsafe
