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

LocalStoreManager::LocalStoreManager(
    boost::shared_ptr<ChunkStore> client_chunkstore)
        : db_(),
          vbph_(),
          mutex_(),
          local_sm_dir_(file_system::FileSystem::LocalStoreManagerDir()),
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
      db_.execDML("create table network(key text primary key,value text);");
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

int LocalStoreManager::LoadPacket(const std::string &hex_key,
                                  std::string *result) {
  *result = GetValue_FromDB(hex_key);
  return kSuccess;
}

void LocalStoreManager::StoreChunk(const std::string &hex_chunk_name,
                                   const DirType,
                                   const std::string&) {
#ifdef DEBUG
//  printf("LocalStoreManager::StoreChunk - %s\n",
//          hex_chunk_name.substr(0, 10).c_str());
#endif
  fs::path file_path(local_sm_dir_ + "/StoreChunks");
  file_path = file_path / hex_chunk_name;
  std::string non_hex = base::DecodeFromHex(hex_chunk_name);
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
    fs::path file_path(local_sm_dir_ + "/StoreChunks");
    file_path = file_path / hex_key;
    result = (!fs::exists(file_path));
  }
  return result;
}
/*
int LocalStoreManager::DeletePacket(const std::string &hex_key,
                                    const std::string &signature,
                                    const std::string &public_key,
                                    const std::string &signed_public_key,
                                    const ValueType &type,
                                    base::callback_func_type cb) {
  std::string key = base::DecodeFromHex(hex_key);
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  if (!co.AsymCheckSig(public_key, signed_public_key, public_key,
      crypto::STRING_STRING)) {
    boost::thread thr(boost::bind(&ExecuteFailureCallback, cb, &mutex_));
    return -2;
  }

  if (!co.AsymCheckSig(co.Hash(
      public_key + signed_public_key + key, "", crypto::STRING_STRING, false),
      signature, public_key, crypto::STRING_STRING)) {
    boost::thread thr(boost::bind(&ExecuteFailureCallback, cb, &mutex_));
    return -3;
  }

  std::string result = "";
  try {
    boost::mutex::scoped_lock loch(mutex_);
    std::string s = "select value from network where key='" + hex_key + "';";
    CppSQLite3Query q = db_.execQuery(s.c_str());
    if (q.eof()) {
      boost::thread thr(boost::bind(&ExecuteFailureCallback, cb, &mutex_));
      return -4;
    }
    std::string val = q.fieldValue(static_cast<unsigned int>(0));
    result = base::DecodeFromHex(val);
  }
  catch(CppSQLite3Exception &e) {  // NOLINT
    boost::thread thr(boost::bind(&ExecuteFailureCallback, cb, &mutex_));
    return -5;
  }

  if (result == "") {
    boost::thread thr(boost::bind(&ExecuteFailureCallback, cb, &mutex_));
    return -6;
  }

  GenericPacket syspacket;
  switch (type) {
    case SYSTEM_PACKET:
        if (!syspacket.ParseFromString(result)) {
          boost::thread thr(boost::bind(&ExecuteFailureCallback, cb, &mutex_));
          return -7;
        }
        if (!co.AsymCheckSig(syspacket.data(), syspacket.signature(),
            public_key, crypto::STRING_STRING)) {
          boost::thread thr(boost::bind(&ExecuteFailureCallback, cb, &mutex_));
          return -8;
        }
        break;
//    case BUFFER_PACKET:
//        if (!vbph_.ValidateOwnerSignature(public_key, result)) {
//          boost::thread thr(boost::bind(&ExecuteFailureCallback, cb, mutex_));
//          return -9;
//        }
//        break;
//    case BUFFER_PACKET_MESSAGE:
//        if (!vbph_.ValidateOwnerSignature(public_key, result)) {
//          boost::thread thr(boost::bind(&ExecuteFailureCallback, cb, mutex_));
//          return -10;
//        }
//        if (!vbph_.ClearMessages(&result)) {
//          boost::thread thr(boost::bind(&ExecuteFailureCallback, cb, mutex_));
//          return -11;
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
        return 0;
      } else {
        std::string enc_value = base::EncodeToHex(result);
        bufSQL.format("insert into network values ('%s', %Q);",
          hex_key.c_str(), enc_value.c_str());
        db_.execDML(bufSQL);
        boost::thread thr(boost::bind(&ExecuteSuccessCallback, cb, &mutex_));
        return 0;
      }
    } else {
      boost::thread thr(boost::bind(&ExecuteFailureCallback, cb, &mutex_));
      return -12;
    }
  }
  catch(CppSQLite3Exception &e) {  // NOLINT
    std::cerr << e.errorCode() << "ddddddd:" << e.errorMessage() << std::endl;
    boost::thread thr(boost::bind(&ExecuteFailureCallback, cb, &mutex_));
    return -13;
  }
}

*/
void LocalStoreManager::DeletePacket(const std::string &hex_packet_name,
                                     const std::string &value,
                                     PacketType system_packet_type,
                                     DirType dir_type,
                                     const std::string &msid,
                                     const VoidFuncOneInt &cb) {
}

void LocalStoreManager::DeletePacket(const std::string &hex_packet_name,
                                     PacketType system_packet_type,
                                     DirType dir_type,
                                     const std::string &msid,
                                     const VoidFuncOneInt &cb) {
}

void LocalStoreManager::DeletePacket(const std::string &hex_packet_name,
                                     const std::vector<std::string> values,
                                     PacketType system_packet_type,
                                     DirType dir_type,
                                     const std::string &msid,
                                     const VoidFuncOneInt &cb) {
}


void LocalStoreManager::StorePacket(const std::string &hex_packet_name,
                                    const std::string &value,
                                    PacketType,
                                    DirType,
                                    const std::string&,
                                    IfPacketExists if_packet_exists,
                                    const VoidFuncOneInt &cb) {
  int result = StorePacket_InsertToDb(hex_packet_name, value);
  // TODO(Fraser#5#): 2010-01-26 - Fix logic to match MSM - actions variy
  //                               depending on if_packet_exists value.
  cb(-11111111);
//  cb(result);
}

int LocalStoreManager::StorePacket_InsertToDb(const std::string &hex_key,
                                              const std::string &value) {
  try {
    if (hex_key.length() != 2 * kKeySize) {
      return kIncorrectKeySize;
    }
    std::string s = "select value from network where key='" + hex_key + "';";
    std::string enc_value;
    boost::mutex::scoped_lock loch(mutex_);
    CppSQLite3Query q = db_.execQuery(s.c_str());
    CppSQLite3Buffer bufSQL;

    enc_value = base::EncodeToHex(value);

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
int LocalStoreManager::CreateBP() {
  if (ss_->Id(MPID) == "")
    return -666;

  std::string bufferpacketname(BufferPacketName()), ser_packet;
#ifdef DEBUG
  printf("LocalStoreManager::CreateBP - BP chunk(%s).\n",
         bufferpacketname.substr(0, 10).c_str());
#endif
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
    printf("LocalStoreManager::LoadBPMessages - "
           "Failed to flush BP into chunk.\n");
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
      printf("LocalStoreManager::AddBPMessage - "
             "Failed to flush BP into chunk. (%s).\n",
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
  fs::path file_path(local_sm_dir_ + "/StoreChunks");
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
  fs::path file_path(local_sm_dir_ + "/StoreChunks");
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

std::string LocalStoreManager::BufferPacketName() {
  return BufferPacketName(ss_->Id(MPID), ss_->PublicKey(MPID));
}

std::string LocalStoreManager::BufferPacketName(
    const std::string &publicusername,
    const std::string &public_key) {
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  return co.Hash(publicusername + public_key, "", crypto::STRING_STRING, true);
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
                        crypto::STRING_STRING, true), iter);
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
    result = base::DecodeFromHex(val);
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

void LocalStoreManager::SetLocalVaultOwned(
    const std::string &,
    const std::string &pub_key,
    const std::string &signed_pub_key,
    const boost::uint32_t &,
    const std::string &,
    const boost::uint64_t &,
    const SetLocalVaultOwnedFunctor &functor) {
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  std::string pmid_name = co.Hash(pub_key + signed_pub_key, "",
                          crypto::STRING_STRING, false);
  boost::thread thr(functor, OWNED_SUCCESS, pmid_name);
}

void LocalStoreManager::LocalVaultOwned(const LocalVaultOwnedFunctor &functor) {
  boost::thread thr(functor, NOT_OWNED);
}

bool LocalStoreManager::NotDoneWithUploading() { return false; }

}  // namespace maidsafe
