/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Singleton class which controls all maidsafe client operations
* Version:      1.0
* Created:      2009-01-28-10.59.46
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

#include "maidsafe/client/clientcontroller.h"

#ifdef MAIDSAFE_WIN32
#include <shlwapi.h>
#endif

#include <boost/scoped_ptr.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/filesystem/fstream.hpp>
#include <cstdio>

#include "maidsafe/client/contacts.h"
#include "maidsafe/client/dataatlashandler.h"
#include "maidsafe/client/privateshares.h"
#include "maidsafe/client/selfencryption.h"
#include "maidsafe/client/sessionsingleton.h"
#include "maidsafe/client/storemanager.h"
#include "protobuf/general_messages.pb.h"
#include "protobuf/maidsafe_service_messages.pb.h"
#include "protobuf/packet.pb.h"
#ifdef LOCAL_PDVAULT
  #include "maidsafe/client/localstoremanager.h"
#else
  #include "maidsafe/client/maidstoremanager.h"
#endif

namespace maidsafe {

CC_CallbackResult::CC_CallbackResult() : result("") {}

void CC_CallbackResult::Reset() {
  result = "";
}

void CC_CallbackResult::CallbackFunc(const std::string &res) {
  result = res;
}

void ClientController::WaitForResult(const CC_CallbackResult &cb) {
  while (true) {
    {
      boost::recursive_mutex::scoped_lock gaurd(mutex_);
      if (cb.result != "")
        return;
    }
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  }
}


ClientController *ClientController::single = 0;

ClientController::ClientController(): auth_(), sm_(), ss_(),
  msgh_(), cbph_(), ser_da_(), db_enc_queue_(), seh_(),  mutex_(),
  messages_(), bp_messages_(false), fsys_() {
#ifdef LOCAL_PDVAULT
    sm_ = new LocalStoreManager(&mutex_);
#else
    sm_ = new MaidsafeStoreManager();
#endif
}

boost::mutex cc_mutex;

ClientController *ClientController::getInstance() {
  if (single == 0) {
    boost::mutex::scoped_lock lock(cc_mutex);
    if (single == 0)
      single = new ClientController();
  }
  return single;
}

void ClientController::Destroy() {
  delete single;
  single = 0;
}

bool ClientController::Init() {
  auth_ = new Authentication(sm_, &mutex_);
  ss_ = SessionSingleton::getInstance();
  cbph_ = new packethandler::ClientBufferPacketHandler(sm_, &mutex_);
  return true;
}

bool ClientController::JoinKademlia() {
  CC_CallbackResult cb;
#ifdef DEBUG
  printf("Before bootstrap in CC.\n");
#endif
  sm_->Init(boost::bind(&CC_CallbackResult::CallbackFunc, &cb, _1));
#ifdef DEBUG
  printf("After bootstrap in CC.\n");
#endif
  WaitForResult(cb);
  base::GeneralResponse result;
  if ((!result.ParseFromString(cb.result)) ||
      (result.result() == kCallbackFailure))
    return false;
  else
    return true;
}

int ClientController::ParseDa() {
  DataAtlas data_atlas;
  if (!data_atlas.ParseFromString(ser_da_)) {
#ifdef DEBUG
    printf("TMID brought doesn't parse as a DA.\n");
#endif
    return -9000;
  }
  if (!data_atlas.has_root_db_key()) {
#ifdef DEBUG
    printf("DA doesn't have a root db key.\n");
#endif
    return -9001;
  }
  ss_->SetRootDbKey(data_atlas.root_db_key());

  if (data_atlas.dms_size() < 3) {
#ifdef DEBUG
    printf("Not enough datamaps in the DA.\n");
#endif
    return -9002;
  }

  DataMap dm_root, dm_keys, dm_shares;
  dm_root = data_atlas.dms(0);
  dm_keys = data_atlas.dms(1);
  dm_shares = data_atlas.dms(2);
  std::string ser_dm_root, ser_dm_keys, ser_dm_shares;
  dm_root.SerializeToString(&ser_dm_root);
  dm_keys.SerializeToString(&ser_dm_keys);
  dm_shares.SerializeToString(&ser_dm_shares);
#ifdef DEBUG
  // printf("ser_dm_root_ = %s\n", ser_dm_root_);
  // printf("ser_dm_keys_ = %s\n", ser_dm_keys_);
#endif
  int i = seh_->DecryptDb(kRoot,
                          PRIVATE,
                          ser_dm_root,
                          "",
                          "",
                          false,
                          false);
#ifdef DEBUG
  // printf("result of decrypt root: %i\n", i);
#endif
  i = seh_->DecryptDb(kKeysDb,
                      PRIVATE,
                      ser_dm_keys,
                      "",
                      "",
                      false,
                      false);
#ifdef DEBUG
  // printf("result of decrypt keysdb: %i\n", i);
#endif
  seh_->DecryptDb(base::TidyPath(kRootSubdir[1][0]),
                  PRIVATE,
                  ser_dm_shares,
                  "",
                  "",
                  false,
                  false);
  return 0;
}

int ClientController::SerialiseDa() {
  DataAtlas data_atlas_;
  data_atlas_.set_root_db_key(ss_->RootDbKey());
  std::string ser_dm_root_ = "Return the serialised datamap please old boy.";
  std::string ser_dm_keys_ = "And for me too, old chap.";
  std::string ser_dm_shares_ = "I'd like one as well old chum.";
  seh_->EncryptDb(kRoot, PRIVATE, "", "", false, &ser_dm_root_);
  seh_->EncryptDb(kKeysDb, PRIVATE, "", "", false, &ser_dm_keys_);
  seh_->EncryptDb(base::TidyPath(kRootSubdir[1][0]),
                  PRIVATE,
                  "",
                  "",
                  false,
                  &ser_dm_shares_);
  DataMap *dm1_;
  DataMap dm2_;
  dm1_ = data_atlas_.add_dms();
  dm2_.ParseFromString(ser_dm_root_);
  *dm1_ = dm2_;
  dm1_ = data_atlas_.add_dms();
  dm2_.ParseFromString(ser_dm_keys_);
  *dm1_ = dm2_;
  dm1_ = data_atlas_.add_dms();
  dm2_.ParseFromString(ser_dm_shares_);
  *dm1_ = dm2_;
#ifdef DEBUG
  // printf("data_atlas_.dms(0).file_hash(): %s\n",
  //   data_atlas_.dms(0).file_hash());
  // printf("data_atlas_.dms(1).file_hash(): %s\n",
  //   data_atlas_.dms(1).file_hash());
#endif
  data_atlas_.SerializeToString(&ser_da_);
  // delete dm1_;
  return 0;
}

exitcode ClientController::CheckUserExists(const std::string &username,
                                           const std::string &pin,
                                           base::callback_func_type cb,
                                           DefConLevels level) {
  ss_->ResetSession();
  ss_->SetDefConLevel(level);
  return auth_->GetUserInfo(username, pin, cb);
}

bool ClientController::CreateUser(const std::string &username,
                                  const std::string &pin,
                                  const std::string &password) {
  ser_da_ = "";
  exitcode result_ = auth_->CreateUserSysPackets(username,
                                                 pin,
                                                 password,
                                                 ser_da_);
#ifdef DEBUG
  printf("\n\n\n88888888888888888888888888888888888888\n");
  printf("88888888888888888888888888888888888888\n");
  printf("Finished with CreateUserSysPackets\n");
  printf("88888888888888888888888888888888888888\n");
  printf("88888888888888888888888888888888888888\n\n\n\n");
#endif

  if (result_ == OK) {
    ss_->SetSessionName(false);
    std::string root_db_key_;
    seh_ = new SEHandler(sm_, &mutex_);
    int result = seh_->GenerateUniqueKey(PRIVATE, "", 0, &root_db_key_);
    ss_->SetRootDbKey(root_db_key_);
//    fsys_.SetDirNames();
    fsys_.Mount();
    fsys_.FuseMountPoint();
    boost::scoped_ptr<DataAtlasHandler> dah_(new DataAtlasHandler());
    msgh_ = new MessageHandler(sm_, &mutex_);
    DataAtlas da_;

    result += dah_->Init(true);

    // set up root subdirs
    for (int i = 0; i < kRootSubdirSize; ++i) {
      MetaDataMap mdm_;
      std::string ser_mdm_, ser_dm_, key_;
      mdm_.set_id(-2);
      mdm_.set_display_name(base::TidyPath(kRootSubdir[i][0]));
      mdm_.set_type(EMPTY_DIRECTORY);
      mdm_.set_stats("");
      mdm_.set_tag("");
      mdm_.set_file_size_high(0);
      mdm_.set_file_size_low(0);
      boost::uint32_t current_time_ = base::get_epoch_time();
      mdm_.set_creation_time(current_time_);
      mdm_.SerializeToString(&ser_mdm_);
      if (kRootSubdir[i][1] == "") {
        seh_->GenerateUniqueKey(PRIVATE, "", 0, &key_);
      } else {
        key_ = kRootSubdir[i][1];
      }
      result += dah_->AddElement(base::TidyPath(kRootSubdir[i][0]),
                                 ser_mdm_,
                                 "",
                                 key_,
                                 true);
      seh_->EncryptDb(base::TidyPath(kRootSubdir[i][0]),
                      PRIVATE,
                      key_,
                      "",
                      true,
                      &ser_dm_);
    }

    // set up share subdirs
    for (int i = 0; i < kSharesSubdirSize; ++i) {
      fs::path subdir_(kSharesSubdir[i][0], fs::native);
      std::string subdir_name_ = subdir_.filename();
      MetaDataMap mdm_;
      std::string ser_mdm_, ser_dm_, key_;
      mdm_.set_id(-2);
      mdm_.set_display_name(subdir_name_);
      mdm_.set_type(EMPTY_DIRECTORY);
      mdm_.set_stats("");
      mdm_.set_tag("");
      mdm_.set_file_size_high(0);
      mdm_.set_file_size_low(0);
      boost::uint32_t current_time_ = base::get_epoch_time();
      mdm_.set_creation_time(current_time_);
      mdm_.SerializeToString(&ser_mdm_);
      if (kSharesSubdir[i][1] == "") {  // ie no preassigned key so not public
        seh_->GenerateUniqueKey(PRIVATE, "", 0, &key_);
        result += dah_->AddElement(base::TidyPath(kSharesSubdir[i][0]),
                                   ser_mdm_,
                                   "",
                                   key_,
                                   true);
        seh_->EncryptDb(base::TidyPath(kSharesSubdir[i][0]),
                        PRIVATE,
                        key_,
                        "",
                        true,
                        &ser_dm_);
      } else {
        key_ = kSharesSubdir[i][1];
        result += dah_->AddElement(base::TidyPath(kSharesSubdir[i][0]),
                                   ser_mdm_,
                                   "",
                                   key_,
                                   true);
        if (seh_->DecryptDb(base::TidyPath(kSharesSubdir[i][0]),
                            ANONYMOUS,
                            "",
                            key_,
                            "",
                            true,
                            true)) {
          // ie Public and Anon have never been saved before on the network
          std::string ser_dm_;
          seh_->EncryptDb(base::TidyPath(kSharesSubdir[i][0]),
                          PRIVATE,
                          kSharesSubdir[i][1],
                          "",
                          true,
                          &ser_dm_);
        }
      }
    }

    if (result == 0)
      result = !da_.ParseFromString(ser_da_);
    if (result == 0) {
      // insert keys
      for (int n = 0; n < da_.keys_size(); ++n) {
        std::stringstream out;
        out << da_.keys(n).type();
        result += dah_->AddKeys(out.str(),
                                da_.keys(n).id().c_str(),
                                da_.keys(n).private_key().c_str(),
                                da_.keys(n).public_key().c_str());
      }
    }
    if (0 != result) {
      delete seh_;
      delete msgh_;
      return false;
    }
    result = SetVaultConfig(dah_->GetPublicKey(base::itos(PMID)),
                            dah_->GetPrivateKey(base::itos(PMID)));
    if (0 != result) {
      delete seh_;
      delete msgh_;
      return false;
    }
    return true;
  }
  ss_->ResetSession();
  return false;
}

int ClientController::SetVaultConfig(const std::string &pmid_public,
                                     const std::string &pmid_private) {
  fs::path vault_path(fsys_.ApplicationDataDir(), fs::native);
  vault_path /= "vault";
  try {
    if (!fs::exists(vault_path))
      fs::create_directory(vault_path);
  }
  catch(const std::exception &ex_) {
#ifdef DEBUG
    printf("Can't create maidsafe vault dir.\n%s\n", ex_.what());
#endif
    return -1;
  }
  maidsafe_crypto::Crypto co_;
  co_.set_symm_algorithm("AES_256");
  co_.set_hash_algorithm("SHA1");
  fs::path config_file(vault_path);
  config_file /= ".config";
  base::VaultConfig vault_config;
  vault_config.set_pmid_public(pmid_public);
  vault_config.set_pmid_private(pmid_private);
  //  vault_config.set_port(6666);
  vault_config.set_signed_pmid_public(
      co_.AsymSign(pmid_public, "", pmid_private,
      maidsafe_crypto::STRING_STRING));
  fs::path chunkstore_path(vault_path);
  chunkstore_path /= "Chunkstore";
  chunkstore_path /= co_.Hash(pmid_public, "", maidsafe_crypto::STRING_STRING,
                              true);
  vault_config.set_chunkstore_dir(chunkstore_path.string());
  fs::path datastore_path(vault_path);
  datastore_path /= "Datastore";
  datastore_path /= co_.Hash(pmid_public, "", maidsafe_crypto::STRING_STRING,
                             true);
  vault_config.set_datastore_dir(datastore_path.string());
  std::fstream output(config_file.string().c_str(),
                      std::ios::out | std::ios::trunc | std::ios::binary);
  if (!vault_config.SerializeToOstream(&output)) {
#ifdef DEBUG
    printf("Failed to write vault configuration file.\n");
#endif
    return -2;
  }
  output.close();
  return 0;
}

bool ClientController::ValidateUser(const std::string &password,
  std::list<std::string> *msgs) {
  ser_da_ = "";
  exitcode result = auth_->GetUserData(password, ser_da_);

  if (result == OK) {
    ss_->SetSessionName(false);
    fsys_.Mount();
    boost::scoped_ptr<DataAtlasHandler> dah_(new DataAtlasHandler());
    seh_ = new SEHandler(sm_, &mutex_);
    msgh_ = new MessageHandler(sm_, &mutex_);
    ParseDa();
    if (dah_->Init(false)) {
      delete seh_;
      delete msgh_;
      return false;
      ss_->ResetSession();
      return false;
    }
    // Setting on session singleton the MAID, MPID, and PMID keys
    std::stringstream out;
    out << MAID;
    ss_->SetPublicKey(dah_->GetPublicKey(out.str()), MAID_BP);
    ss_->SetPrivateKey(dah_->GetPrivateKey(out.str()), MAID_BP);

    out.str("");
    out << PMID;
    if (dah_->GetPackageID(out.str()) != "") {
      ss_->SetPublicKey(dah_->GetPublicKey(out.str()), PMID_BP);
      ss_->SetPrivateKey(dah_->GetPrivateKey(out.str()), PMID_BP);
    }

    out.str("");
    out << MPID;
    ss_->SetPublicUsername(dah_->GetPackageID(out.str()));
    fsys_.FuseMountPoint();
    if (ss_->PublicUsername() != "") {
      // CHANGE CONNECTION STATUS
      int connection_status(1);
      int n = ChangeConnectionStatus(connection_status);
      if (n != 0) {
        // Alert for BP problems
      }
      ss_->SetConnectionStatus(connection_status);

      // GET MESSAGES AND CLEAR THEM
//      CC_CallbackResult cb;
      ss_->SetPublicKey(dah_->GetPublicKey(out.str()), MPID_BP);
      ss_->SetPrivateKey(dah_->GetPrivateKey(out.str()), MPID_BP);
//      cbph_->GetBufferPacket(MPID_BP, boost::bind(
//          &CC_CallbackResult::CallbackFunc,
//          &cb,
//          _1));
//      WaitForResult(cb);
//      GetMessagesResponse get_bufpacket_result;
//      if ((get_bufpacket_result.ParseFromString(cb.result)) &&
//          (get_bufpacket_result.result() == kCallbackSuccess)) {
//        for (int i = 0; i < get_bufpacket_result.messages_size(); i++)
//          msgs->push_back(get_bufpacket_result.messages(i));
//        int n = msgs->size();
//        // HandleMessages(&msgs);
//        if (n > 0) {
//          cb.Reset();
//          cbph_->ClearMessages(MPID_BP,
//                               boost::bind(&CC_CallbackResult::CallbackFunc,
//                                           &cb,
//                                           _1));
//          WaitForResult(cb);
//        }
//      }
    } else {
    }
    return true;
  }
  maidsafe::SessionSingleton::getInstance()->ResetSession();
#ifdef DEBUG
  printf("Invalid password.\n");
#endif
  return false;
}

void ClientController::CloseConnection() {
  CC_CallbackResult cb;
  sm_->Close(boost::bind(&CC_CallbackResult::CallbackFunc, &cb, _1));
  WaitForResult(cb);
  base::GeneralResponse result;
  if ((!result.ParseFromString(cb.result)) ||
      (result.result() == kCallbackFailure)) {
#ifdef DEBUG
    printf("Error leaving network.\n");
#endif
    return;
  } else {
#ifdef DEBUG
    printf("Successfully left kademlia.\n");
#endif
    return;
  }
}

bool ClientController::Logout() {
  packethandler::PacketParams priv_keys, pub_keys;
  std::list<Key_Type> keys;
  boost::scoped_ptr<DataAtlasHandler> dah_(new DataAtlasHandler());
  dah_->GetKeyRing(&keys);

  while (!keys.empty()) {
    Key_Type kt = keys.front();
    keys.pop_front();
    switch (kt.package_type) {
      case ANMID:
        priv_keys["ANMID"] = kt.private_key;
        pub_keys["ANMID"] = kt.public_key;
        break;
      case ANTMID:
        priv_keys["ANTMID"] = kt.private_key;
        pub_keys["ANTMID"] = kt.public_key;
        break;
      case ANSMID:
        priv_keys["ANSMID"] = kt.private_key;
        pub_keys["ANSMID"] = kt.public_key;
        break;
      default: break;
    }
  }

  SerialiseDa();
  exitcode result = auth_->SaveSession(ser_da_, priv_keys, pub_keys);
  int connection_status(0);
  int n = ChangeConnectionStatus(connection_status);
  if (n != 0) {
    // Alert for BP problems
  }
  ss_->SetConnectionStatus(connection_status);

  if (result == OK && !RunDbEncQueue()) {
    fsys_.UnMount();
    ss_->ResetSession();
    delete seh_;
    delete msgh_;
    messages_.clear();
    return true;
  }

  delete seh_;
  delete msgh_;
  return false;
}

bool ClientController::LeaveMaidsafeNetwork() {
  std::list<Key_Type> keys;
  exitcode result;
  std::string dir_ = fsys_.MaidsafeDir();
  {
    boost::scoped_ptr<DataAtlasHandler> dah_(new DataAtlasHandler());
    dah_->GetKeyRing(&keys);
    result = auth_->RemoveMe(keys);
  }
  if (result == OK) {
    delete seh_;
    delete msgh_;
    // if (fs::exists("MaidDataAtlas.db"))
    // fs::remove("MaidDataAtlas.db");
    try {
      fs::remove_all(dir_);
    }
    catch(const std::exception &exception_) {
#ifdef DEBUG
      printf("Error: %s\n", exception_.what());
#endif
    }

    return true;
  }
  return false;
}

bool ClientController::ChangeUsername(std::string new_username) {
  packethandler::PacketParams priv_keys, pub_keys;
  SerialiseDa();
  std::list<Key_Type> keys;
  boost::scoped_ptr<DataAtlasHandler> dah_(new DataAtlasHandler());
  dah_->GetKeyRing(&keys);

  while (!keys.empty()) {
    Key_Type kt = keys.front();
    keys.pop_front();
    switch (kt.package_type) {
      case ANMID:
        priv_keys["ANMID"] = kt.private_key;
        pub_keys["ANMID"] = kt.public_key;
        break;
      case ANTMID:
        priv_keys["ANTMID"] = kt.private_key;
        pub_keys["ANTMID"] = kt.public_key;
        break;
      case ANSMID:
        priv_keys["ANSMID"] = kt.private_key;
        pub_keys["ANSMID"] = kt.public_key;
        break;
      default: {}
    }
  }

  exitcode result = auth_->ChangeUsername(ser_da_,
                                          priv_keys,
                                          pub_keys,
                                          new_username);
#ifdef DEBUG
  // printf("%i\n", result);
#endif
  if (result == OK)
    return true;
  return false;
}

bool ClientController::ChangePin(std::string new_pin) {
  packethandler::PacketParams priv_keys, pub_keys;
  SerialiseDa();
  std::list<Key_Type> keys;
  boost::scoped_ptr<DataAtlasHandler> dah_(new DataAtlasHandler());
  dah_->GetKeyRing(&keys);

  while (!keys.empty()) {
    Key_Type kt = keys.front();
    keys.pop_front();
    switch (kt.package_type) {
      case ANMID:
        priv_keys["ANMID"] = kt.private_key;
        pub_keys["ANMID"] = kt.public_key;
        break;
      case ANTMID:
        priv_keys["ANTMID"] = kt.private_key;
        pub_keys["ANTMID"] = kt.public_key;
        break;
      case ANSMID:
        priv_keys["ANSMID"] = kt.private_key;
        pub_keys["ANSMID"] = kt.public_key;
        break;
      default: {}
    }
  }

  exitcode result = auth_->ChangePin(ser_da_,
                                     priv_keys,
                                     pub_keys,
                                     new_pin);
#ifdef DEBUG
  // printf("%i\n", result);
#endif
  if (result == OK)
    return true;
  return false;
}

bool ClientController::ChangePassword(std::string new_password) {
  packethandler::PacketParams priv_keys, pub_keys;
  SerialiseDa();
  std::list<Key_Type> keys;
  boost::scoped_ptr<DataAtlasHandler> dah_(new DataAtlasHandler());
  dah_->GetKeyRing(&keys);

  while (!keys.empty()) {
    Key_Type kt = keys.front();
    keys.pop_front();
    switch (kt.package_type) {
      case ANMID:
        priv_keys["ANMID"] = kt.private_key;
        pub_keys["ANMID"] = kt.public_key;
        break;
      case ANTMID:
        priv_keys["ANTMID"] = kt.private_key;
        pub_keys["ANTMID"] = kt.public_key;
        break;
      case ANSMID:
        priv_keys["ANSMID"] = kt.private_key;
        pub_keys["ANSMID"] = kt.public_key;
        break;
      default: {}
    }
  }

  exitcode result = auth_->ChangePassword(ser_da_,
                                          priv_keys,
                                          pub_keys,
                                          new_password);
#ifdef DEBUG
  // printf("%i\n", result);
#endif
  if (result == OK)
    return true;
  return false;
}

//////////////////////////////
// Buffer Packet Operations //
//////////////////////////////

bool ClientController::CreatePublicUsername(std::string public_username) {
  if (ss_->PublicUsername() != "") {
#ifdef DEBUG
    printf("Already have public username.\n");
#endif
    return false;
  }
  packethandler::PacketParams keys_result;
  exitcode result = auth_->CreatePublicName(public_username, &keys_result);
  if (result != OK) {
#ifdef DEBUG
    printf("Error in CreatePublicName.\n");
#endif
    return false;
  }

  boost::scoped_ptr<DataAtlasHandler> dah_(new DataAtlasHandler());
  std::stringstream out;
  // if(dah_->AddKeys(ANMPID,
  //                  keys_result["anmpid_name"].string(),
  //                  keys_result["anmpid_private_key"].string(),
  //                  keys_result["anmpid_public_key"].string()));
  out << ANMPID;
  if (dah_->AddKeys(out.str(),
                    boost::any_cast<std::string>(keys_result["anmpid_name"]),
                    boost::any_cast<std::string>(
                      keys_result["anmpid_private_key"]),
                    boost::any_cast<std::string>(
                      keys_result["anmpid_public_key"]))) {
#ifdef DEBUG
    printf("Failed to add ANMPID to key ring\n.");
#endif
    return false;
  }
  // if (dah_->AddKeys(MPID,
  //                   public_username,
  //                   keys_result["mpid_private_key"].string(),
  //                   keys_result["mpid_public_key"].string()));
  out.str("");
  out << MPID;
  if (dah_->AddKeys(out.str(),
                    public_username,
                    boost::any_cast<std::string>(
                      keys_result["mpid_private_key"]),
                    boost::any_cast<std::string>(
                      keys_result["mpid_public_key"]))) {
#ifdef DEBUG
    printf("Failed to add MPID to key ring\n.");
#endif
    return false;
  }

  CC_CallbackResult cb;
  cbph_->CreateBufferPacket(public_username,
                            boost::any_cast<std::string>(
                              keys_result["mpid_public_key"]),
                            boost::any_cast<std::string>(
                              keys_result["mpid_private_key"]),
                            boost::bind(&CC_CallbackResult::CallbackFunc,
                                        &cb,
                                        _1));
  WaitForResult(cb);
  StoreResponse bufpacket_res;
  if ((!bufpacket_res.ParseFromString(cb.result)) ||
      (bufpacket_res.result() == kCallbackFailure)) {
#ifdef DEBUG
    printf("Error creating the buffer packet.\n");
#endif
    return false;
  }
  ss_->SetPublicUsername(public_username);
  ss_->SetPublicKey(boost::any_cast<std::string>(
    keys_result["mpid_public_key"]), MPID_BP);
  ss_->SetPrivateKey(boost::any_cast<std::string>(
    keys_result["mpid_private_key"]), MPID_BP);

  fs::path dbPath(fsys_.MaidsafeHomeDir());
  dbPath /= ".contacts";
  std::string dbName(dbPath.string());

  maidsafe::ContactsHandler ch;
  int n = ch.CreateContactDB(dbName);
  if (n != 0) {
#ifdef DEBUG
    printf("Couldn't create CONTACTS db.\n");
#endif
    return false;
  }

  dbPath = fs::path(fsys_.MaidsafeHomeDir());
  dbPath /= ".shares";
  dbName = dbPath.string();

  maidsafe::PrivateShareHandler psh;
  n = psh.CreatePrivateShareDB(dbName);
  if (n != 0) {
#ifdef DEBUG
    printf("Couldn't create SHARES db.\n");
#endif
    return false;
  }

  return true;
}

bool ClientController::AuthoriseUsers(std::set<std::string> users) {
  if (ss_->PublicUsername() == "" || users.empty())
    return false;

  CC_CallbackResult cb;
  cbph_->AddUsers(users, boost::bind(&CC_CallbackResult::CallbackFunc,
                                     &cb,
                                     _1),
                                     MPID_BP);
  WaitForResult(cb);
  UpdateResponse add_users_res;
  if ((!add_users_res.ParseFromString(cb.result)) ||
      (add_users_res.result() == kCallbackFailure))
    return false;

  return true;
}

bool ClientController::DeauthoriseUsers(std::set<std::string> users) {
  if (ss_->PublicUsername() == "" || users.empty())
    return false;
  CC_CallbackResult cb;
  cbph_->DeleteUsers(users,
                     boost::bind(&CC_CallbackResult::CallbackFunc, &cb, _1),
                     MPID_BP);
  WaitForResult(cb);
  UpdateResponse del_users_res;
  if ((!del_users_res.ParseFromString(cb.result)) ||
      (del_users_res.result() == kCallbackFailure))
    return false;

  return true;
}

int ClientController::ChangeConnectionStatus(int status) {
  if (maidsafe::SessionSingleton::getInstance()->ConnectionStatus() == status)
    return -3;
  CC_CallbackResult cb;
  cbph_->ChangeStatus(status,
                     boost::bind(&CC_CallbackResult::CallbackFunc, &cb, _1),
                     MPID_BP);
  WaitForResult(cb);
  UpdateResponse change_connection_status;
  if (!change_connection_status.ParseFromString(cb.result))
    return -1;
  if (change_connection_status.result() == kCallbackFailure)
    return -2;

  return 0;
}

////////////////////////
// Message Operations //
////////////////////////

bool ClientController::GetMessages() {
  // Only getting MPID buffer packet
  if (ss_->PublicUsername() == "")
    return false;

  CC_CallbackResult cb;
  cbph_->GetMessages(MPID_BP,
                     boost::bind(&CC_CallbackResult::CallbackFunc, &cb, _1));
  WaitForResult(cb);
  GetMessagesResponse result;
  if ((!result.ParseFromString(cb.result)) ||
      (result.result() == kCallbackFailure))
    return false;
  if (result.messages_size() == 0)
    // TODO(Richard): return code for no messages
    return true;
  std::list<std::string> msgs;
  for (int i = 0; i < result.messages_size(); i++)
    msgs.push_back(result.messages(i));
  HandleMessages(&msgs);
  cb.Reset();
  cbph_->ClearMessages(MPID_BP,
                       boost::bind(&CC_CallbackResult::CallbackFunc, &cb, _1));
  WaitForResult(cb);
  DeleteResponse clear_result;
  if ((!clear_result.ParseFromString(cb.result)) ||
       (clear_result.result() == kCallbackFailure)) {
#ifdef DEBUG
    printf("Error clearing messages from buffer packet.");
#endif
  }
  return true;
}

int ClientController::HandleMessages(std::list<std::string> *msgs) {
  int result = 0;
  while (!msgs->empty()) {
    packethandler::ValidatedBufferPacketMessage msg;
    std::string ser_msg = msgs->front();
    msgs->pop_front();
    if (msg.ParseFromString(ser_msg)) {
      switch (msg.type()) {
        case packethandler::ADD_CONTACT_RQST:
//            result += HandleAddContactRequest(msg);
//            SetBufferPacketMessages(true);
//            break;
        case packethandler::INSTANT_MSG:
            result += HandleInstantMessage(msg);
            break;
        default: break;  // TODO(Richard): define other type of messages
      }
    }
  }
  return result;
}

int ClientController::HandleDeleteContactNotification(
    packethandler::ValidatedBufferPacketMessage &vbpm) {
  packethandler::InstantMessage im;
  if (!im.ParseFromString(vbpm.message())) {
#ifdef DEBUG
    printf("Message doesn't parse as an Instant Message.\n");
#endif
    return -40001;
  }

  if (vbpm.sender() != im.sender()) {
#ifdef DEBUG
    printf("Senders do not match.\n");
#endif
    return -40002;
  }

  file_system::FileSystem fsys;
  fs::path newDb(fsys_.MaidsafeHomeDir());
  newDb /= ".contacts";
  std::string dbNameNew(newDb.string());

  maidsafe::Contacts c;
  c.SetPublicName(im.sender());
  c.SetConfirmed('U');
  maidsafe::ContactsHandler ch;
  int n = ch.UpdateContact(dbNameNew, c);
  if (n != 0) {
#ifdef DEBUG
    printf("Status on contact not updated.\n");
#endif
    return -40003;
  }

  return 0;
}

int ClientController::HandleReceivedShare(
    const packethandler::PrivateShareNotification &psn,
    const std::string &name) {
#ifdef DEBUG
  printf("Dir key: %s", psn.dir_db_key().c_str());
  printf("Public key: %s", psn.public_key().c_str());
#endif

  fs::path newDb(fsys_.MaidsafeHomeDir());
  newDb /= ".shares";
  std::string dbNameNew(newDb.string());
  std::vector<std::string> attributes;
  std::list<ShareParticipants> participants;
  attributes.push_back(psn.name());
  attributes.push_back(psn.msid());
  attributes.push_back(psn.public_key());
  attributes.push_back("");
  maidsafe::PrivateShareHandler psh;

  if (!psn.has_private_key()) {
    int n = psh.AddReceivedShare(dbNameNew, attributes);
    if (n != 0)
      return n;
  } else {
    attributes[3] = psn.private_key();

    // Get the public key of the contacts
    fs::path db(fsys_.MaidsafeHomeDir());
    db /= ".contacts";
    std::string dbName(db.string());
    std::vector<maidsafe::Contacts> contact_list;

    for (int n = 0; n < psn.admins_size(); n++) {
      if (psn.admins(n) ==
          maidsafe::SessionSingleton::getInstance()->PublicUsername())
        continue;  // Not to add myself to the share DB
      maidsafe::ShareParticipants sp;
      sp.id = psn.admins(n);
      sp.role = 'A';
      contact_list.clear();
      maidsafe::ContactsHandler ch;
      int r = ch.GetContactList(dbName, contact_list, psn.admins(n), false);
      if (contact_list.size() == 1 && r == 0) {
        sp.public_key = contact_list[0].PublicKey();
      } else {  // search for the public key in kadsafe
        std::string public_key("aaa");
        exitcode result =
          auth_->PublicUsernamePublicKey(sp.id, public_key);
        if (result != OK) {
#ifdef DEBUG
          printf("Couldn't find %s's public key.\n", sp.id.c_str());
#endif
          return -20002;
        }
        sp.public_key = public_key;
      }
      participants.push_back(sp);
    }

    for (int n = 0; n < psn.readonlys_size(); n++) {
      maidsafe::ShareParticipants sp;
      sp.id = psn.readonlys(n);
      sp.role = 'R';
      contact_list.clear();
      maidsafe::ContactsHandler ch;
      int r = ch.GetContactList(dbName, contact_list, psn.readonlys(n), false);
      if (contact_list.size() == 1 && r == 0) {
        sp.public_key = contact_list[0].PublicKey();
      } else {  // search for the public key in kadsafe
        std::string public_key("aaa");
        exitcode result =
          auth_->PublicUsernamePublicKey(sp.id, public_key);
        if (result != OK) {
#ifdef DEBUG
          printf("Couldn't find %s's public key.\n", sp.id.c_str());
#endif
          return -20003;
        }
        sp.public_key = public_key;
      }
      participants.push_back(sp);
    }

    int n = psh.AddPrivateShare(dbNameNew, attributes, &participants);
    if (n != 0)
      return n;
  }

  // Create directory in Shares/Private
  std::string share_path("Shares/Private/" + psn.name());
  DB_TYPE db_type;
  std::string msid("");

  int n = GetDb(share_path, &db_type, &msid);
  if (n != 0) {
#ifdef DEBUG
    printf("Didn't get the DB.\n");
#endif
    return -20004;
  }
  std::string ser_mdm("");
  msid = "";
  PathDistinction(share_path, &msid);
  db_type = GetDbType(share_path);
  if (!seh_->ProcessMetaData(share_path, EMPTY_DIRECTORY, "", 0, &ser_mdm)) {
#ifdef DEBUG
    printf("Didn't process metadata.\n");
#endif
    return -20005;
  }

  boost::scoped_ptr<DataAtlasHandler> dah(new DataAtlasHandler);
  n = dah->AddElement(share_path, ser_mdm, "", psn.dir_db_key(), false);
  if (n != 0) {
#ifdef DEBUG
    printf("Didn't add element to DB.\n");
#endif
    return -20006;
  }
  fs::path pp(share_path);
//  msid = "";
//  PathDistinction(pp.parent_path().string(), &msid);
  db_type = GetDbType(pp.parent_path().string());
#ifdef DEBUG
  printf("CC::HandleReceivedShare, after GetDbType parent(%s): %i.\n",
    share_path.c_str(), static_cast<int>(db_type));
#endif

  if (SaveDb(share_path, db_type, "", false)) {
#ifdef DEBUG
    printf("CC::HandleReceivedShare, SaveDb(%s) failed.\n", share_path.c_str());
#endif
    return -20007;
  }

  return 0;
}

int ClientController::HandleInstantMessage(
    packethandler::ValidatedBufferPacketMessage &vbpm) {
#ifdef DEBUG
  printf("INSTANT MESSAGE received\n");
  printf("Sender: %s\n", vbpm.sender().c_str());
#endif
  packethandler::InstantMessage im;
  if (im.ParseFromString(vbpm.message())) {
//    if
//
//    if (im.type() == packethandler::INSTANT_FILE) {
//      packethandler::InstantFileMessage ifm;
//      if (ifm.ParseFromString(im.message())) {
//        int n = AddInstantFile(ifm);
//#ifdef DEBUG
//        printf("Addition result: %i\n", n);
//#endif
//        if (n != 0)
//          return n;
//        std::string new_msg("You've received file: " +
//          ifm.filename() + ". " + im.sender() + " says: " +
//          ifm.sender_msg() + "\n");
//#ifdef DEBUG
//        printf("%s\n", new_msg.c_str());
//#endif
//        im.set_message(new_msg);
//        messages_.push_back(im);
//#ifdef DEBUG
//        printf("You've got an instant file\n");
//#endif
//      }
//    } else {
      messages_.push_back(im);
#ifdef DEBUG
      printf("%s\n", vbpm.message().c_str());
#endif
//    }
    return 0;
  } else {
    return -1;
  }
}

int ClientController::AddInstantFile(
    const packethandler::InstantFileNotification &ifm,
    const std::string &location) {
  fs::path path(base::TidyPath(kRootSubdir[0][0]));

  maidsafe::MetaDataMap sent_mdm;
  sent_mdm.ParseFromString(ifm.ser_mdm());

  maidsafe::MetaDataMap mdm;
  mdm.set_id(-2);
  mdm.set_display_name(ifm.filename());
  mdm.set_type(sent_mdm.type());
  mdm.set_stats("");
  mdm.set_tag(sent_mdm.tag());
  mdm.set_file_size_high(sent_mdm.file_size_high());
  mdm.set_file_size_low(sent_mdm.file_size_low());
  mdm.set_creation_time(base::get_epoch_time());
  mdm.set_last_modified(base::get_epoch_time());
  mdm.set_last_access(base::get_epoch_time());
  std::string ser_mdm;
  mdm.SerializeToString(&ser_mdm);
  std::string dir_key("");

  boost::scoped_ptr<DataAtlasHandler> dah_(new DataAtlasHandler());

  fs::path path_with_filename(base::TidyPath(kRootSubdir[0][0]));
  path_with_filename /= ifm.filename();
  std::string path_add_element(path_with_filename.string());
  DB_TYPE db_type;
  std::string msid("");
  int n = GetDb(path_add_element, &db_type, &msid);
  n = dah_->AddElement(path_add_element,
    ser_mdm, ifm.ser_dm(), dir_key, false);
  if (n != 0) {
#ifdef DEBUG
    printf("Riata en AddElement\n");
#endif
    return -1111;
  }

  std::string path_save_db(path_with_filename.string());
  if (msid == "") {
    if (SaveDb(path_save_db, db_type, msid, false)) {
#ifdef DEBUG
      printf("\t\tCC::AddInstantFile failed to save the db to queue. %i %s\n",
        db_type, path_save_db.c_str());
#endif
      return -11111;
    }
  } else {
    if (SaveDb(path_save_db, db_type, msid, true)) {
#ifdef DEBUG
      printf("\t\tCC::AddInstantFile failed to save the db immediately.\n");
#endif
      return -111111;
    }
  }

  return 0;
}

int ClientController::HandleAddContactRequest(packethandler::ContactInfo &ci,
    const std::string &sender) {
#ifdef DEBUG
  printf("\n\n\nHandleAddContactRequest\nHandleAddContactRequest\n\n\n");
#endif

//    packethandler::ContactInfo ci;
//    if (!ci.ParseFromString(vbpm.message())) {
//  #ifdef DEBUG
//      printf("Message didn't parse as contact info.\n");
//  #endif
//      return -7;
//    }
//  #ifdef DEBUG
//    printf("Parsed message.\n");
//  #endif
  // TODO(Richard): return choice to the user to accept/reject contact

  // Get contacts public key
  std::string rec_public_key;
  exitcode result = auth_->PublicUsernamePublicKey(sender, rec_public_key);
  if (result != OK) {
#ifdef DEBUG
    printf("Can't get sender's public key.\n");
#endif
    return -77;
  }
#ifdef DEBUG
  printf("Got sender's public key.\n");
#endif

  Contacts c;
  c.SetPublicName(sender);
  c.SetPublicKey(rec_public_key);
  c.SetFullName(ci.name());
  c.SetOfficePhone(ci.office_number());
  c.SetBirthday(ci.birthday());
#ifdef DEBUG
  // printf("Gender: %s\n", ci.gender().c_str());
#endif
  c.SetGender(ci.gender().at(0));
  c.SetLanguage(ci.language());
  c.SetCountry(ci.country());
  c.SetCity(ci.city());
  c.SetConfirmed('C');

  // Add to the contacts DB
  maidsafe::ContactsHandler ch;
  fs::path newDb(fsys_.MaidsafeHomeDir());
  newDb /= ".contacts";
  std::string dbNameNew(newDb.string());

  int n = ch.AddContact(dbNameNew, c);
#ifdef DEBUG
  printf("Result add contact: %i\n", n);
#endif
  if (n != 0) {
#ifdef DEBUG
    printf("Adding contact failed.\n");
#endif
    return -777;
  }
#ifdef DEBUG
  printf("Added Contact.\n");
#endif

  // Add to authorised users in BP
  std::set<std::string> s;
  s.insert(sender);
  if (!AuthoriseUsers(s))
    return -7777;
#ifdef DEBUG
  printf("Authorised Contact to write to BP.\n");
#endif

  // Send message back with own details
  maidsafe::Receivers rec;
  rec.id = sender;
  rec.public_key = rec_public_key;
  std::vector<Receivers> recs;
  recs.push_back(rec);

  packethandler::InstantMessage im;
  packethandler::ContactNotification *cn = im.mutable_contact_notification();
  packethandler::ContactInfo *info = cn->mutable_contact();

  info->set_name("Mock");
  info->set_birthday("Today");
  info->set_office_number("0987456321");
  info->set_gender("F");
  info->set_country(22);
  info->set_city("Troon");
  info->set_language(7);

  cn->set_action(1);

  std::string message("\"");
  message += sender + "\" has confirmed you as a contact.";
  im.set_sender(maidsafe::SessionSingleton::getInstance()->PublicUsername());
  im.set_date(base::get_epoch_time());
  im.set_message(message);
  std::string ser_im;
  im.SerializeToString(&ser_im);

  CC_CallbackResult cb;
  msgh_->SendMessage(ser_im,
                     recs,
                     MPID_BP,
                     packethandler::INSTANT_MSG,
                     boost::bind(&CC_CallbackResult::CallbackFunc,
                     &cb, _1));
  WaitForResult(cb);
  packethandler::StoreMessagesResult res;
  if ((!res.ParseFromString(cb.result)) ||
      (res.result() == kCallbackFailure)) {
#ifdef DEBUG
    printf("Callbackfailure send msg.\n");
#endif
    return -77777;
  }
  if (res.stored_msgs() != 1)
    return -777777;
#ifdef DEBUG
  printf("Sent Contact Addition Response.\n");
#endif
  return 0;
}

int ClientController::HandleAddContactResponse(packethandler::ContactInfo &ci,
  const std::string &sender) {
#ifdef DEBUG
  printf("\n\n\nHandleAddContactResponse\nHandleAddContactResponse\n\n\n");
#endif

  // Check if contact exists in local DB
  Contacts c;
  c.SetPublicName(sender);
  c.SetPublicKey("");
  c.SetFullName(ci.name());
  c.SetOfficePhone(ci.office_number());
  c.SetBirthday(ci.birthday());
  c.SetGender(ci.gender().at(0));
  c.SetLanguage(ci.language());
  c.SetCountry(ci.country());
  c.SetCity(ci.city());
  c.SetConfirmed('C');

  maidsafe::ContactsHandler ch;
  fs::path newDb(fsys_.MaidsafeHomeDir());
  newDb /= ".contacts";
  std::string dbNameNew(newDb.string());
  std::vector<maidsafe::Contacts> list;
  int n = ch.GetContactList(dbNameNew, list, sender);
//#ifdef DEBUG
  printf("GetContactList result: %i\n", n);
//#endif
  if (n != 0) {
#ifdef DEBUG
    printf("Getting contact list failed.\n");
#endif
    return -88;
  }
  if (list.size() != 1) {
#ifdef DEBUG
    printf("List came back empty. No contact.\n");
#endif
    return -888;
  }
  n = ch.UpdateContact(dbNameNew, c);
#ifdef DEBUG
  printf("UpdateContact result: %i\n", n);
#endif
  if (n != 0) {
#ifdef DEBUG
    printf("Could not update contact.\n");
#endif
    return -8888;
  }
  return 0;
}

int ClientController::SendInstantMessage(const std::string &message,
                                         const std::string &contact_name) {
  std::vector<Contacts> list;
  maidsafe::ContactsHandler ch;
  fs::path newDb(fsys_.MaidsafeHomeDir());
  newDb /= ".contacts";
  std::string dbNameNew(newDb.string());
  int n = ch.GetContactList(dbNameNew, list, contact_name);
  if (n != 0) {
#ifdef DEBUG
    printf("Couldn't find contact: %i\n", n);
#endif
    return -9;
  }

  maidsafe::Contacts c = list[0];

  maidsafe::Receivers rec;
  rec.id = contact_name;
  rec.public_key = c.PublicKey();
#ifdef DEBUG
  // printf("Contact's public key: %s\n", rec.public_key.c_str());
#endif
  std::vector<Receivers> recs;
  recs.push_back(rec);

  std::string ser_im;
  packethandler::InstantMessage im;
  im.set_sender(maidsafe::SessionSingleton::getInstance()->PublicUsername());
  im.set_message(message);
  im.set_date(base::get_epoch_time());
//  im.set_type(packethandler::INSTANT_MSG);
  im.SerializeToString(&ser_im);

  CC_CallbackResult cb;
  msgh_->SendMessage(ser_im,
                     recs,
                     MPID_BP,
                     packethandler::INSTANT_MSG,
                     boost::bind(&CC_CallbackResult::CallbackFunc, &cb, _1));
  WaitForResult(cb);
  packethandler::StoreMessagesResult store_res;
  if ((!store_res.ParseFromString(cb.result)) ||
      (store_res.result() == kCallbackFailure)) {
#ifdef DEBUG
    printf("Callback failure sending instant message.\n");
#endif
    return -99;
  }
  if (store_res.stored_msgs() != 1)
    return -999;
  return 0;
}

//unsigned int ClientController::InstantMessageCount() {
//  return messages_.size();
//}
//
int ClientController::GetInstantMessages(
  std::list<packethandler::InstantMessage> *messages) {
  *messages = messages_;
  messages_.clear();
  return 0;
}

int ClientController::SendInstantFile(std::string *filename,
                                      const std::string &msg,
                                      const std::string &contact_name) {
  std::string path = *filename;
  DB_TYPE db_type;
  std::string msid("");
  int n = GetDb(*filename, &db_type, &msid);
  if (n != 0) {
#ifdef DEBUG
    printf("GetDb for file location failed.\n");
#endif
    return -6;
  }

  boost::scoped_ptr<DataAtlasHandler> dah_(new DataAtlasHandler());
  std::string ser_dm("");
  n = dah_->GetDataMap(*filename, &ser_dm);
  if (n != 0) {
#ifdef DEBUG
    printf("GetDataMap for instant file failed.\n");
#endif
    return -66;
  }

  std::string ser_mdm("");
  n = dah_->GetMetaDataMap(*filename, &ser_mdm);
  if (n != 0) {
#ifdef DEBUG
    printf("GetMetaDataMap for instant file failed.\n");
#endif
    return -666;
  }

  fs::path p_filename(*filename);
  packethandler::InstantMessage im;
  packethandler::InstantFileNotification *ifm =
      im.mutable_instantfile_notification();
  ifm->set_ser_mdm(ser_mdm);
  ifm->set_ser_dm(ser_dm);
  ifm->set_filename(p_filename.filename());
  im.set_sender(SessionSingleton::getInstance()->PublicUsername());
  im.set_date(base::get_epoch_time());
  std::string message("\"");
  message += im.sender() + "\" has sent you file " + p_filename.filename();
  im.set_message(message);

  std::string ser_instant_file;
  im.SerializeToString(&ser_instant_file);

  std::vector<Contacts> list;
  maidsafe::ContactsHandler ch;
  fs::path newDb(fsys_.MaidsafeHomeDir());
  newDb /= ".contacts";
  std::string dbNameNew(newDb.string());
  n = ch.GetContactList(dbNameNew, list, contact_name);
  if (n != 0) {
#ifdef DEBUG
    printf("Couldn't find contact: %i\n", n);
#endif
    return -6666;
  }

  maidsafe::Contacts c = list[0];

  maidsafe::Receivers rec;
  rec.id = contact_name;
  rec.public_key = c.PublicKey();
  std::vector<Receivers> recs;
  recs.push_back(rec);

  CC_CallbackResult cb;
  msgh_->SendMessage(ser_instant_file,
                     recs,
                     MPID_BP,
                     packethandler::INSTANT_MSG,
                     boost::bind(&CC_CallbackResult::CallbackFunc, &cb, _1));
  WaitForResult(cb);
  packethandler::StoreMessagesResult res;
  if ((!res.ParseFromString(cb.result)) ||
      (res.result() == kCallbackFailure)) {
#ifdef DEBUG
    printf("Callbackfailure send msg.\n");
#endif
    return -66666;
  }
  if (res.stored_msgs() != 1) {
#ifdef DEBUG
    printf("Messages sent: %i\n", res.stored_msgs());
#endif
    return -666666;
  }

  return 0;
}

////////////////////////
// Contact Operations //
////////////////////////

int ClientController::ContactList(std::vector<maidsafe::Contacts> *c_list,
                                  const std::string &pub_name) {
  maidsafe::ContactsHandler ch;
  fs::path newDb(fsys_.MaidsafeHomeDir());
  newDb /= ".contacts";
  std::string dbNameNew(newDb.string());
  return ch.GetContactList(dbNameNew, *c_list, pub_name);
}

int ClientController::AddContact(const std::string &public_name) {
  std::string public_key("aaa");
  exitcode result = auth_->PublicUsernamePublicKey(public_name, public_key);
  if (result == OK) {
    // Sending the request to add the contact
    // TODO(Richard): the info is empty because there is no way
    // to get the users contact data
    maidsafe::Receivers rec;
    rec.id = public_name;
    rec.public_key = public_key;
    std::vector<Receivers> recs;
    recs.push_back(rec);

    packethandler::InstantMessage im;
    packethandler::ContactNotification *cn = im.mutable_contact_notification();
    packethandler::ContactInfo *info = cn->mutable_contact();

    info->set_name("Mock");
    info->set_birthday("Today");
    info->set_office_number("0987456321");
    info->set_gender("F");
    info->set_country(22);
    info->set_city("Troon");
    info->set_language(7);

    cn->set_action(0);

    im.set_sender(maidsafe::SessionSingleton::getInstance()->PublicUsername());
    im.set_date(base::get_epoch_time());
    std::string message("\"");
    message += im.sender() + "\" has requested to add you as a contact.";
    im.set_message(message);

    std::string ser_im;
    im.SerializeToString(&ser_im);

    CC_CallbackResult cb;
    msgh_->SendMessage(ser_im,
                       recs,
                       MPID_BP,
                       packethandler::ADD_CONTACT_RQST,
                       boost::bind(&CC_CallbackResult::CallbackFunc, &cb, _1));
    WaitForResult(cb);
    packethandler::StoreMessagesResult res;
    if ((!res.ParseFromString(cb.result)) ||
        (res.result() == kCallbackFailure)) {
#ifdef DEBUG
      printf("Callbackfailure send msg.\n");
#endif
      return -22;
    }
    if (res.stored_msgs() != 1)
      return -22;

    std::set<std::string> s;
    s.insert(public_name);

    if (!AuthoriseUsers(s))
      return -22;

    maidsafe::Contacts c;
    maidsafe::ContactsHandler ch;
    fs::path newDb(fsys_.MaidsafeHomeDir());
    newDb /= ".contacts";
    std::string dbNameNew(newDb.string());
    c.SetPublicName(public_name);
    c.SetPublicKey(public_key);
    c.SetConfirmed('U');

    return ch.AddContact(dbNameNew, c);
  } else {
#ifdef DEBUG
    printf("Couldn't find contact's public key.\n");
#endif
    return -221;
  }
}

int ClientController::DeleteContact(const std::string &public_name) {
  // TODO(Richard): Maybe it would be good to send a message for the other
  //                user's GUI to know to change the status of the contact.
  std::set<std::string> s;
  s.insert(public_name);

  // This int receives a bool
  int n = DeauthoriseUsers(s);
  if (n == 0) {
#ifdef DEBUG
    printf("Deauthorisation of user failed.\n");
#endif
    return -501;
  }

  fs::path newDb(fsys_.MaidsafeHomeDir());
  newDb /= ".contacts";
  std::string dbNameNew(newDb.string());

  maidsafe::Contacts c;
  maidsafe::ContactsHandler ch;
  std::vector<Contacts> contact_list;
  n = ch.GetContactList(dbNameNew, contact_list, public_name, false, 0);
  if (n != 0 || contact_list.size() != 1) {
#ifdef DEBUG
    printf("Selection from contacts DB failed: n - %i --- size:%i.\n",
      n, contact_list.size());
#endif
    return -502;
  }

  c = contact_list[0];
  std::string deletion_msg(base::itos(base::get_epoch_nanoseconds()));
  deletion_msg += " deleted " + c.PublicName() + " update " +
    maidsafe::SessionSingleton::getInstance()->PublicUsername();
#ifdef DEBUG
  printf("MSG: %s\n", deletion_msg.c_str());
#endif
  packethandler::InstantMessage im;
  im.set_date(base::get_epoch_milliseconds());
  im.set_message(deletion_msg);
  im.set_sender(maidsafe::SessionSingleton::getInstance()->PublicUsername());
//  im.set_type(packethandler::DELETE_CONTACT_NOTIF);
  std::string ser_im;
  im.SerializeToString(&ser_im);

  std::vector<Receivers> recs;
  Receivers r;
  r.id = c.PublicName();
  r.public_key = c.PublicKey();
  recs.push_back(r);

  CC_CallbackResult cb;
  msgh_->SendMessage(ser_im,
                     recs,
                     MPID_BP,
                     packethandler::INSTANT_MSG,
                     boost::bind(&CC_CallbackResult::CallbackFunc, &cb, _1));
  WaitForResult(cb);
  packethandler::StoreMessagesResult res;
  if ((!res.ParseFromString(cb.result)) ||
      (res.result() == kCallbackFailure) ||
      (res.stored_msgs() != 1)) {
#ifdef DEBUG
    printf("Callbackfailure in sending the deletion notification.\n");
#endif
    return -503;
  }

  n = ch.DeleteContact(dbNameNew, c);
  if (n != 0) {
#ifdef DEBUG
    printf("Deletion of the contact in DB failed.\n");
#endif
    return -504;
  }

  return 0;
}

//////////////////////
// Share Operations //
//////////////////////

int ClientController::GetShareList(std::list<maidsafe::PrivateShare> *ps_list,
                                   const std::string &value) {
  maidsafe::PrivateShareHandler psh;
  fs::path newDb(fsys_.MaidsafeHomeDir());
  newDb /= ".shares";
  std::string dbNameNew(newDb.string());
  return psh.GetPrivateShareList(dbNameNew, ps_list, value, 22);
}

int ClientController::CreateNewShare(const std::string &name,
                      const std::set<std::string> &admins,
                      const std::set<std::string> &readonlys) {
  CC_CallbackResult cbr;
  auth_->CreateMSIDPacket(boost::bind(&CC_CallbackResult::CallbackFunc,
                          &cbr, _1));
  WaitForResult(cbr);
  packethandler::CreateMSIDResult cmsidr;
  if (!cmsidr.ParseFromString(cbr.result)) {
    printf("Result doesn't parse.\n");
    return -30001;
  }
  if (cmsidr.result() == kCallbackFailure) {
    printf("The creation of the MSID failed.\n");
    return -30002;
  }

  maidsafe::PrivateShareHandler psh;
  fs::path newDb(fsys_.MaidsafeHomeDir());
  newDb /= ".shares";
  std::string dbNameNew(newDb.string());

  std::vector<std::string> attributes;
  attributes.push_back(name);

#ifdef DEBUG
  printf("Public key: %s\n", cmsidr.public_key().c_str());
  printf("MSID: %s\n", cmsidr.name().c_str());
#endif
  // MSID & keys are needed here
  attributes.push_back(cmsidr.name());
  attributes.push_back(cmsidr.public_key());
  attributes.push_back(cmsidr.private_key());

  std::list<maidsafe::ShareParticipants> participants;
  std::vector<maidsafe::ShareParticipants> parts;
  std::set<std::string>::iterator it;
  newDb = fs::path(fsys_.MaidsafeHomeDir());
  newDb /= ".contacts";
  dbNameNew = std::string(newDb.string());
  for (it = admins.begin(); it != admins.end(); ++it) {
    maidsafe::ContactsHandler ch;
    std::vector<maidsafe::Contacts> c_list;
    int n = ch.GetContactList(dbNameNew, c_list, *it, false);
    if (n == 0 && c_list.size() == 1) {
      maidsafe::ShareParticipants sp;
      sp.id = *it;
      sp.public_key = c_list[0].PublicKey();
      sp.role = 'A';
      participants.push_back(sp);
      parts.push_back(sp);
    }
  }
  for (it = readonlys.begin(); it != readonlys.end(); ++it) {
    maidsafe::ContactsHandler ch;
    std::vector<maidsafe::Contacts> c_list;
    int n = ch.GetContactList(dbNameNew, c_list, *it, false);
    if (n == 0 && c_list.size() == 1) {
      maidsafe::ShareParticipants sp;
      sp.id = *it;
      sp.public_key = c_list[0].PublicKey();
      sp.role = 'R';
      participants.push_back(sp);
      parts.push_back(sp);
    }
  }

  newDb = fs::path(fsys_.MaidsafeHomeDir());
  newDb /= ".shares";
  dbNameNew = std::string(newDb.string());

  int n = psh.AddPrivateShare(dbNameNew, attributes, &participants);
  if (n != 0)
    return n;

  // Create directory in Shares/Private and get its dir key
  std::string share_path("Shares/Private/" + name);
//  DB_TYPE db_type;
//  std::string msid("");
//  n = GetDb(share_path, &db_type, &msid);
  n = mkdir(share_path);
  if (n != 0)
    return n;
#ifdef DEBUG
  std::cout << "Despues (n=" << n << "): " << std::endl;
#endif
  std::string share_dir_key("");
  boost::scoped_ptr<DataAtlasHandler> dah(new DataAtlasHandler());
  n = dah->GetDirKey(share_path, &share_dir_key);
  if (n != 0 || share_dir_key == "") {
#ifdef DEBUG
    printf("Getting the share dir key failed.\n");
#endif
    return -30007;
  }

  // Send message to all participants
  packethandler::InstantMessage im;
  packethandler::PrivateShareNotification *psn =
      im.mutable_privateshare_notification();
  psn->set_name(name);
  psn->set_msid(cmsidr.name());
  psn->set_public_key(cmsidr.public_key());
  psn->set_dir_db_key(share_dir_key);
  im.set_sender(maidsafe::SessionSingleton::getInstance()->PublicUsername());
  im.set_date(base::get_epoch_time());
  std::string message("\"");
  message += im.sender() + "\" has added you as a Read Only participant to" +
      " share " + name;
  im.set_message(message);
  std::string share_message;
  im.SerializeToString(&share_message);

  // Send to READONLYS
  std::vector<Receivers> recs;
  packethandler::StoreMessagesResult res;
  if (readonlys.size() > 0) {
    for (unsigned int n = 0; n < parts.size(); n++) {
      if (parts[n].role == 'R') {
        Receivers r;
        r.id = parts[n].id;
        r.public_key = parts[n].public_key;
        recs.push_back(r);
        std::string *ro = psn->add_readonlys();
        *ro = parts[n].id;
      } else {
        std::string *admin = psn->add_admins();
        *admin = parts[n].id;
      }
    }
    cbr.Reset();
    msgh_->SendMessage(share_message,
                       recs,
                       MPID_BP,
                       packethandler::INSTANT_MSG,
                       boost::bind(&CC_CallbackResult::CallbackFunc, &cbr, _1));
    WaitForResult(cbr);
    if ((!res.ParseFromString(cbr.result)) ||
        (res.result() == kCallbackFailure)) {
#ifdef DEBUG
      printf("Callback failure send msg to readonlys.\n");
#endif
      return -30003;
    }
    if (static_cast<unsigned int>(res.stored_msgs()) != recs.size())
      return -30004;
  }

  // Send to ADMINS
  if (admins.size() > 0) {
    std::string *me = psn->add_admins();
    *me = maidsafe::SessionSingleton::getInstance()->PublicUsername();
    psn->set_private_key(cmsidr.private_key());
    message = std::string ("\"");
    message += im.sender() +
        "\" has added you as an Administrator participant to" +
        " share " + name;
    im.set_message(message);
    im.SerializeToString(&share_message);
    recs.clear();
    for (unsigned int n = 0; n < parts.size(); n++) {
      if (parts[n].role == 'A') {
        Receivers r;
        r.id = parts[n].id;
        r.public_key = parts[n].public_key;
        recs.push_back(r);
      }
    }
    cbr.Reset();
    msgh_->SendMessage(share_message,
                       recs,
                       MPID_BP,
                       packethandler::INSTANT_MSG,
                       boost::bind(&CC_CallbackResult::CallbackFunc, &cbr, _1));
    WaitForResult(cbr);
    // packethandler::StoreMessagesResult res;
    if ((!res.ParseFromString(cbr.result)) ||
        (res.result() == kCallbackFailure)) {
  #ifdef DEBUG
      printf("Callback failure send msg to admins.\n");
  #endif
      return -30005;
    }
    if (static_cast<unsigned int>(res.stored_msgs()) != recs.size()) {
  #ifdef DEBUG
      printf("Couldn't send message to all participants: %i out of %i.\n",
        res.stored_msgs(), recs.size());
  #endif
      return -30006;
    }
  }
  return 0;
}

///////////////////
// SE Operations //
///////////////////

int ClientController::BackupElement(const std::string &path,
                                    const DB_TYPE db_type,
                                    const std::string &msid) {
  // return seh_->AddJob(path, REGULAR_ENCRYPT);
  return seh_->EncryptFile(path, db_type, msid);
}

int ClientController::RetrieveElement(const std::string &path) {
  int result = seh_->DecryptFile(path);
  return result;
}

int ClientController::RemoveElement(std::string path) {
  boost::scoped_ptr<DataAtlasHandler> dah_(new DataAtlasHandler());
  if (dah_->RemoveElement(path))
    return -1;
  if (fs::exists(fsys_.FullMSPathFromRelPath(path)))
    fs::remove_all(fsys_.FullMSPathFromRelPath(path));
  return 0;
}

DB_TYPE ClientController::GetDbType(const std::string &path_) {
  std::string myfiles = base::TidyPath(kRootSubdir[0][0]);
//  std::string pub_shares = base::TidyPath(kSharesSubdir[1][0]);
  std::string priv_shares = base::TidyPath(kSharesSubdir[0][0]);
  std::string anonymous_shares = base::TidyPath(kSharesSubdir[1][0]);
  if (path_ == "/" || path_ == "\\" ||
      (path_.compare(0, myfiles.size(), myfiles) == 0))
    return PRIVATE;
//  if (path_.compare(0, pub_shares.size(), pub_shares) == 0)
//    return PUBLIC_SHARE;
  if (path_.compare(0, priv_shares.size(), priv_shares) == 0) {
    if (path_.size() == priv_shares.size())
      return PRIVATE;
    else
      return PRIVATE_SHARE;
  }
  if (path_.compare(0, anonymous_shares.size(), anonymous_shares) == 0)
    return ANONYMOUS;
  return PRIVATE;
}

int ClientController::PathDistinction(const std::string &path,
                                      std::string *msid) {
  std::string path_;
  path_ = std::string(path);
#ifdef DEBUG
  printf("Path in PathDistinction: %s\n", path.c_str());
#endif
  std::string search("My Files");
  std::string share("");
  int n = 0;
  // Check if My Files is in the path
  size_t found = path_.find(search);
  // printf("%i", std::string::npos);
  if (found != std::string::npos) {
    n = 1;
  } else {
    search = "Shares/Private";
    found = path_.find(search);
    if (found != std::string::npos) {
      n = 2;
      if (path_.length() == search.length()) {
#ifdef DEBUG
        printf("In Shares/Private only.\n");
#endif
        *msid = "";
        return 0;
      }
      share = path_.substr(search.length() + 1);
      // printf("\n\n\n\t\t\t\t%s\n\n\n", share.c_str());
      std::string share_name("");
      for (unsigned int nn = 0; nn < share.length(); nn++) {
        if (share.at(nn) == '/' || share.at(nn) == '\\')
          nn = share.length();
        else
          share_name += share.at(nn);
      }
      fs::path newDb(fsys_.MaidsafeHomeDir());
      newDb /= ".shares";
      std::string dbNameNew(newDb.string());

      std::list<PrivateShare> shares;
      PrivateShareHandler psh;
      int r = psh.GetPrivateShareList(dbNameNew, &shares, share_name, 0);
      if (shares.size() != 1 || r != 0) {
#ifdef DEBUG
        printf("No MSID for that share name.\n");
#endif
        return -30001;
      }
      maidsafe::PrivateShare ps = shares.front();
      *msid = ps.Msid();
      // printf("\n\n\n\t\t\t\t%s\n\n\n", share_name.c_str());
    } else {
      search = "Shares/Public";
      found = path_.find(search);
      if (found != std::string::npos) {
        n = 3;
      } else {
        search = "Shares/Anonymous";
        found = path_.find(search);
        if (found != std::string::npos)
          n = 4;
      }
    }
  }

#ifdef DEBUG
  printf("\tFound(%i) path(%s) number: %i.\n", found, path.c_str(), n);
#endif

  return n;
}

int ClientController::GetDb(const std::string &orig_path_,
                            DB_TYPE *db_type,
                            std::string *msid) {
  std::string path_ = orig_path_;
  // std::string path_=fsys_.MakeRelativeMSPath(orig_path_);
#ifdef DEBUG
  printf("\t\tCC::GetDb(%s) type(%i)\n", orig_path_.c_str(), *db_type);
#endif
  std::string db_path_, parent_path_, dir_key_;
  if (path_.size() <= 1) {  // i.e. root
    parent_path_ = path_;
  } else {
    fs::path parent_(path_, fs::native);
    parent_path_ = parent_.parent_path().string();
    if (parent_path_ == "")
      parent_path_ = "/";
    // if (parent_path_.size() <= 1 && path_!=base::TidyPath(my_files_)
    //   && path_!=base::TidyPath(public_shares_)
    //   && path_!=base::TidyPath(private_shares_)) {
#ifdef DEBUG
    //   printf("Parent dir is root!\n");
#endif
    //   // return -1;
    // }
    // parent_path_ = base::TidyPath(path_);
  }
  boost::scoped_ptr<DataAtlasHandler> dah_(new DataAtlasHandler());
  dah_->GetDbPath(path_, CONNECT, &db_path_);
  // dah_->GetDbPath(path_, db_path_);
  PathDistinction(parent_path_, msid);
#ifdef DEBUG
  printf("\t\tMSID: %s\n", msid->c_str());
#endif

  if (fs::exists(db_path_) && *msid == "") {
  // if (fs::exists(db_path_)) {
    *db_type = GetDbType(parent_path_);
    return 0;
  }
  if (dah_->GetDirKey(parent_path_, &dir_key_)) {
#ifdef DEBUG
    printf("\t\tGetDirKey failed.\n");
#endif
    return -1;
  }
  bool overwrite = false;
  if (*msid == "") {
    *db_type = GetDbType(parent_path_);
  } else {
    *db_type = GetDbType(path_);
    overwrite = true;
  }

  if (seh_->DecryptDb(parent_path_, *db_type, "", dir_key_,
      *msid, true, overwrite)) {
#ifdef DEBUG
    printf("\t\tFailed trying to decrypt dm of db with dir key: %s\n",
          dir_key_.c_str());
#endif
    return -1;
  }
  return 0;
}

int ClientController::SaveDb(const std::string &db_path,
                             const DB_TYPE db_type,
                             const std::string &msid,
                             const bool &immediate_save) {
#ifdef DEBUG
  printf("\t\tCC::SaveDb %s with MSID = %s\n", db_path.c_str(), msid.c_str());
#endif
  std::string parent_path_(""), dir_key_(""), ser_dm_("");
  fs::path temp_(db_path);
  parent_path_ = temp_.parent_path().string();
  if (parent_path_ == "\\" ||
      parent_path_ == "/" ||
      parent_path_ == base::TidyPath(kRootSubdir[1][0]))
    return 0;
  boost::scoped_ptr<DataAtlasHandler> dah_(new DataAtlasHandler());
  // dah_->GetDbPath(path_, db_path_); // yields db path of parent dir
  if (dah_->GetDirKey(parent_path_, &dir_key_))
    // yields dir key for parent of path_
    return -errno;
  if (!immediate_save) {
    std::pair<std::string, std::string> key_and_msid_(dir_key_, msid);
    db_enc_queue_.insert(std::pair<std::string,
                                   std::pair<std::string, std::string> >
                                       (parent_path_, key_and_msid_));
    if (db_enc_queue_.size() > kSaveUpdatesTrigger)
      RunDbEncQueue();
    return 0;
  } else {
    if (seh_->EncryptDb(parent_path_,
                        db_type,
                        dir_key_,
                        msid,
                        true,
                        &ser_dm_) != 0)
      return -errno;
  }
    return 0;
}

int ClientController::RemoveDb(const std::string &path_) {
#ifdef DEBUG
  printf("\t\tCC::RemoveDb %s\n", path_.c_str());
#endif
  std::string parent_path_, dir_key_;
  fs::path temp_(path_);
  parent_path_ = temp_.parent_path().string();
  if (parent_path_ == "\\"||
      parent_path_ == "/"||
      parent_path_ == base::TidyPath(kRootSubdir[1][0]))
    return 0;
  boost::scoped_ptr<DataAtlasHandler> dah_(new DataAtlasHandler());
  // dah_->GetDbPath(path_, db_path_); // yields db path of parent dir
  std::string dbpath_;
  dah_->GetDbPath(path_, CREATE, &dbpath_);
  try {
    fs::remove_all(dbpath_);
  }
  catch(const std::exception &exception_) {
#ifdef DEBUG
    printf("%s\n", exception_.what());
#endif
  }
  db_enc_queue_.erase(path_);
  return 0;
}

int ClientController::RunDbEncQueue() {
  std::map<std::string, std::pair<std::string, std::string> >::iterator it_;
  int result_ = 0;
  for (it_ = db_enc_queue_.begin(); it_ != db_enc_queue_.end(); ++it_) {
#ifdef DEBUG
    printf("\t\tCC::RunDbEncQueue: first: %s\tsec.first: %s\tsec.second: %s\n",
           (*it_).first.c_str(),
           (*it_).second.first.c_str(),
           (*it_).second.second.c_str());
#endif
    std::string ser_dm_="";
    DB_TYPE db_type_ = GetDbType((*it_).first);
    int int_res_ = seh_->EncryptDb((*it_).first,
                                   db_type_,
                                   (*it_).second.first,
                                   (*it_).second.second,
                                   true,
                                   &ser_dm_);
#ifdef DEBUG
    printf(" with result %i\n", int_res_);
#endif
    if (int_res_ != -2)
      result_ += int_res_;
  }
  db_enc_queue_.clear();
  if (result_)
    return -1;
  else
    return 0;
}

bool ClientController::ReadOnly(const std::string &path, bool gui) {
#ifdef DEBUG
  printf("\n\t\tCC::ReadOnly, path = %s\t%i\t", path.c_str(), gui);
#endif
  std::string parent_path_, dir_key_;
  fs::path path_(path, fs::native);
  fs::path parnt_path_ = path_.parent_path();
#ifdef DEBUG
  printf("and parent_path_ = %s\n", parnt_path_.string().c_str());
#endif
  // if path is a root subdir, but not one of preassigned root subdirs,
  // then readonly = true
  if (parnt_path_.string() == ""||
      parnt_path_.string() == "/"||
      parnt_path_.string() == "\\") {
    for (int i = 0; i < kRootSubdirSize; ++i) {
      fs::path root_subdir_(base::TidyPath(kRootSubdir[i][0]), fs::native);
      if (path_ == root_subdir_) {
#ifdef DEBUG
        printf("Returning false AA.\n");
#endif
        return false;
      }
    }
    if (path_.string() == "/" || path_.string() == "\\") {
#ifdef DEBUG
      printf("Returning false BB.\n");
#endif
      return false;
    } else {
#ifdef DEBUG
    printf("Returning true.\n");
#endif
    return true;
    }
  }

  // if path is a Shares subdir, but not one of preassigned Shares subdirs,
  // then readonly = true.
  fs::path shares_(base::TidyPath(kRootSubdir[1][0]), fs::native);
  if (parnt_path_ == shares_) {
    bool read_only_ = true;
    for (int i = 0; i < kSharesSubdirSize; ++i) {
      fs::path shares_subdir_(base::TidyPath(kSharesSubdir[i][0]), fs::native);
      if (path_ == shares_subdir_)
        read_only_ = false;
    }
#ifdef DEBUG
    printf("Returning %i CC.\n", static_cast<int>(read_only_));
#endif
    return read_only_;
  }
  // if path is a Shares/Private subdir then readonly = true unless request
  // comes from gui setting up a private share.
//  fs::path private_shares_(base::TidyPath(kSharesSubdir[0][0]), fs::native);
//  if (parnt_path_ == private_shares_) {
//    return false
    std::string msid("");
    int n = PathDistinction(path, &msid);
    if (n == 2 && msid != "") {
      PrivateShareHandler psh;
      std::list<PrivateShare> ps;
      fs::path dbPath(fsys_.MaidsafeHomeDir());
      dbPath /= ".shares";
      const std::string dbName(dbPath.string());
      int result = psh.GetPrivateShareList(dbName, &ps, msid, 1);
      if (ps.size() != 1 || result != 0) {
#ifdef DEBUG
        printf("Private share doen't exist.\n");
#endif
        return true;
      }
      if (ps.front().MsidPriKey() == "") {
#ifdef DEBUG
        printf("No priv key. Not admin. Readonly. Feck off.\n");
#endif
        return true;
      }
#ifdef DEBUG
      std::string priv_key = ps.front().MsidPriKey();
      printf("Private key from DB: %s.\n", priv_key.c_str());
#endif
    }
//  } else {
// #ifdef DEBUG
//    printf("Not a private share %s -- %s.\n", parnt_path_.string().c_str(),
//      private_shares_.string().c_str());
// #endif
//  }
#ifdef DEBUG
  printf("Returning false DD.\n");
#endif
  return false;
}

//////////////////////////////
// Here comes FUSE stuff !! //
//////////////////////////////


char ClientController::DriveLetter() {
  for (char drive_ = 'm'; drive_ <= 'z'; ++drive_) {
    std::ostringstream oss_;
    oss_ << drive_;
    std::string dr_ = oss_.str();
    dr_ += ":";
    bool exists_ = true;
    try {
      exists_ = fs::exists(dr_);
    }
    catch(const std::exception &exception_) {
#ifdef DEBUG
      printf("Error: %s\n", exception_.what());
#endif
    }
    if (!exists_) {
      return drive_;
    }
  }
  return '!';
}

int ClientController::mkdir(const std::string &path) {
#ifdef DEBUG
  printf("\t\tCC::mkdir %s\n", path.c_str());
#endif
  DB_TYPE db_type;
  std::string msid("");
  if (GetDb(path, &db_type, &msid)) {
#ifdef DEBUG
    printf("\t\tIn CC::mkdir, GetDb (%s) failed.\n", path.c_str());
#endif
    return -1;
  }
#ifdef DEBUG
  printf("MSID after GetDb: %s\n", msid.c_str());
#endif
  msid = "";
  PathDistinction(path, &msid);
  db_type = GetDbType(path);
  if (!seh_->MakeElement(path, EMPTY_DIRECTORY, db_type, msid, "")) {
#ifdef DEBUG
    printf("\t\tIn CC::mkdir, seh_->MakeElement(%s, EMPTY_DIRECTORY) failed\n",
           path.c_str());
#endif
    return -1;
  }

#ifdef DEBUG
  printf("MSID after MakeElement: %s -- type: %i\n", msid.c_str(), db_type);
#endif
  fs::path pp(path);
  msid = "";
  PathDistinction(pp.parent_path().string(), &msid);
  db_type = GetDbType(pp.parent_path().string());
#ifdef DEBUG
  printf("MSID after PathDis parent: %s. Path: %s -- type: %i\n", msid.c_str(),
    pp.parent_path().string().c_str(), db_type);
#endif
  bool immediate_save = true;
  if (msid == "") {
    immediate_save = false;
//    db_type = maidsafe::PRIVATE;
//  } else {
//    db_type = maidsafe::PRIVATE_SHARE;
  }
  if (SaveDb(path, db_type, msid, immediate_save)) {
#ifdef DEBUG
    printf("\t\tIn CC::mkdir, SaveDb(%s) failed.\n", path.c_str());
#endif
    return -1;
  }

  // need to save newly-created db also - do this by passing path
  // for (non-existant) element within new dir to SaveDb function
  fs::path imaginary_(path);
  imaginary_ /= "a";
  msid = "";
  PathDistinction(imaginary_.string(), &msid);
  db_type = GetDbType(imaginary_.string());
#ifdef DEBUG
  printf("MSID after imaginary string: %s -- type: %i\n", msid.c_str(),
    db_type);
#endif
  immediate_save = true;
  if (msid == "")
    immediate_save = false;
//  else
//    db_type = maidsafe::PRIVATE_SHARE;

  if (SaveDb(imaginary_.string(), db_type, msid, immediate_save)) {
#ifdef DEBUG
    printf("\t\tIn CC::mkdir, SaveDb(%s) failed.\n",
          imaginary_.string().c_str());
#endif
    return -1;
  }

  return 0;
}

int ClientController::rename(const std::string &path,
                             const std::string &path2) {
#ifdef DEBUG
  printf("\t\tCC::rename %s to %s\n", path.c_str(), path2.c_str());
#endif
  DB_TYPE db_type;
  DB_TYPE db_type2;
  std::string msid("");
  std::string msid2("");
  if (GetDb(path, &db_type, &msid) || GetDb(path2, &db_type2, &msid2)) {
#ifdef DEBUG
    printf("\t\tCC::rename failed to get one of the dbs\n");
#endif
    return -1;
  }
  boost::scoped_ptr<DataAtlasHandler> dah_(new DataAtlasHandler());
  if (dah_->RenameElement(path, path2, false)) {
#ifdef DEBUG
    printf("\t\tCC::rename failed to rename in dah\n");
#endif
    return -1;
  }

  // Original dir db
  if (msid == "") {
    if (SaveDb(path, db_type, msid, false)) {
#ifdef DEBUG
      printf("\t\tCC::rename failed to save the original db to queue.\n");
#endif
      return -1;
    }
  } else {
    if (SaveDb(path, db_type, msid, true)) {
#ifdef DEBUG
      printf("\t\tCC::rename failed to save the original db immediately.\n");
#endif
      return -1;
    }
  }

  // Target dir db
  if (msid2 == "") {
    if (SaveDb(path2, db_type2, msid2, false)) {
#ifdef DEBUG
      printf("\t\tCC::rename failed to save the target db to queue.\n");
#endif
      return -1;
    }
  } else {
    fs::path parent_1(path, fs::native);
    std::string parent_path_1 = parent_1.parent_path().string();
    fs::path parent_2(path2, fs::native);
    std::string parent_path_2 = parent_2.parent_path().string();

    if (parent_path_1 != parent_path_2) {
      if (SaveDb(path2, db_type2, msid2, true)) {
  #ifdef DEBUG
        printf("\t\tCC::rename failed to save the target db immediately.\n");
  #endif
        return -1;
      }
    }
  }

  return 0;
}

int ClientController::rmdir(const std::string &path) {
#ifdef DEBUG
  printf("\t\tCC::rmdir %s\n", path.c_str());
#endif
  DB_TYPE db_type;
  std::string msid("");
  if (GetDb(path, &db_type, &msid))
    return -1;
  std::map<std::string, itemtype> children;
  boost::scoped_ptr<DataAtlasHandler> dah_(new DataAtlasHandler());
  dah_->ListFolder(path, &children);
  if (children.size())  // ie the dir is not empty
    return -1;
  if (RemoveElement(path))
    return -1;
  if (msid == "") {
    if (SaveDb(path, db_type, msid, false)) {
#ifdef DEBUG
      printf("\t\tCC::rename failed to save the original db to queue.\n");
#endif
      return -1;
    }
  } else {
    if (SaveDb(path, db_type, msid, true)) {
#ifdef DEBUG
      printf("\t\tCC::rename failed to save the original db immediately.\n");
#endif
      return -1;
    }
  }

  // TODO(team): i ask: do we delete the db and its key value from kad?
  if (RemoveDb(path))
    return -1;
  return 0;
}

int ClientController::getattr(const std::string &path, std::string &ser_mdm) {
#ifdef DEBUG
  printf("\t\tCC::getattr %s\n", path.c_str());
#endif
  DB_TYPE db_type;
  std::string msid("");
  if (GetDb(path, &db_type, &msid))
    return -1;
  boost::scoped_ptr<DataAtlasHandler> dah_(new DataAtlasHandler());
  if (dah_->GetMetaDataMap(path, &ser_mdm))
    return -1;
  MetaDataMap mdm;
  mdm.ParseFromString(ser_mdm);
  return 0;
}

int ClientController::readdir(const std::string &path,  // NOLINT
                              std::map<std::string, itemtype> &children) {
#ifdef DEBUG
  printf("\t\tCC::readdir %s\n", path.c_str());
#endif
  DB_TYPE db_type;
  std::string msid("");
  if (GetDb(path, &db_type, &msid))
    return -1;
  boost::scoped_ptr<DataAtlasHandler> dah_(new DataAtlasHandler());
  if (dah_->ListFolder(path, &children))
    return -1;
  return 0;
}

int ClientController::mknod(const std::string &path) {
#ifdef DEBUG
  printf("\t\tCC::mknod %s\n", path.c_str());
#endif
  DB_TYPE db_type;
  std::string msid("");
  if (GetDb(path, &db_type, &msid))
    return -1;
#ifdef DEBUG
  printf("MSID after GetDb: %s\n", msid.c_str());
#endif

  if (!seh_->MakeElement(path, EMPTY_FILE, db_type, msid, ""))
    return -1;
#ifdef DEBUG
  printf("MSID after MakeElement: %s\n", msid.c_str());
#endif
  if (msid != "") {
    if (SaveDb(path, db_type, msid, true))
      return -1;
  } else {
    if (SaveDb(path, db_type, msid, false))
      return -1;
  }
  return 0;
}

int ClientController::unlink(const std::string &path) {
#ifdef DEBUG
  printf("\t\tCC::unlink %s\n", path.c_str());
#endif
  DB_TYPE db_type;
  std::string msid("");
  if (GetDb(path, &db_type, &msid))
    return -1;
  if (RemoveElement(path))
    return -1;
  if (msid == "") {
    if (SaveDb(path, db_type, msid, false)) {
#ifdef DEBUG
      printf("\t\tCC::rename failed to save the original db to queue.\n");
#endif
      return -1;
    }
  } else {
    if (SaveDb(path, db_type, msid, true)) {
#ifdef DEBUG
      printf("\t\tCC::rename failed to save the original db immediately.\n");
#endif
      return -1;
    }
  }

  return 0;
}

int ClientController::link(const std::string &path, const std::string &path2) {
#ifdef DEBUG
  printf("\t\tCC::link %s to %s\n", path.c_str(), path2.c_str());
#endif
  DB_TYPE db_type;
  DB_TYPE db_type2;
  std::string msid("");
  std::string msid2("");
  if (GetDb(path, &db_type, &msid) || GetDb(path2, &db_type2, &msid2))
    return -1;
  std::string ms_old_rel_entry_ = path;
  std::string ms_new_rel_entry_ = path2;
  fs::path n_path(ms_new_rel_entry_, fs::native);

  std::string new_rel_root_ = n_path.parent_path().string();

  boost::scoped_ptr<DataAtlasHandler> dah_(new DataAtlasHandler());
  if (dah_->CopyElement(ms_old_rel_entry_, ms_new_rel_entry_, "", false))
    return -1;
  if (msid == "") {
    if (SaveDb(path2, db_type2, msid2, false)) {
#ifdef DEBUG
      printf("\t\tCC::rename failed to save the original db to queue.\n");
#endif
      return -1;
    }
  } else {
    if (SaveDb(path2, db_type2, msid2, true)) {
#ifdef DEBUG
      printf("\t\tCC::rename failed to save the original db immediately.\n");
#endif
      return -1;
    }
  }
  return 0;
}

int ClientController::cpdir(const std::string &path,
                            const std::string &path2) {
#ifdef DEBUG
  printf("\t\tCC::cpdir %s to %s\n", path.c_str(), path2.c_str());
#endif
  DB_TYPE db_type;
  DB_TYPE db_type2;
  std::string msid("");
  std::string msid2("");
  if (GetDb(path, &db_type, &msid) || GetDb(path2, &db_type2, &msid2))
    return -1;
  std::string ms_old_rel_entry_ = path;
  std::string ms_new_rel_entry_ = path2;
  fs::path n_path(ms_new_rel_entry_, fs::native);

  std::string new_rel_root_ = n_path.parent_path().string();
  std::string new_dir_key_;
  seh_->GenerateUniqueKey(db_type2, msid2, 0, &new_dir_key_);
  boost::scoped_ptr<DataAtlasHandler> dah_(new DataAtlasHandler());
  if (dah_->CopyElement(ms_old_rel_entry_,
                        ms_new_rel_entry_,
                        new_dir_key_,
                        true))
    return -1;
  if (msid == "") {
    if (SaveDb(path2, db_type2, msid2, false)) {
#ifdef DEBUG
      printf("\t\tCC::rename failed to save the original db to queue.\n");
#endif
      return -1;
    }
  } else {
    if (SaveDb(path2, db_type2, msid2, true)) {
#ifdef DEBUG
      printf("\t\tCC::rename failed to save the original db immediately.\n");
#endif
      return -1;
    }
  }
  // need to save newly-created db also - do this by passing path
  // for (non-existant) element within new dir to SaveDb function
  fs::path imaginary_(path2);
  imaginary_ /= "a";
  if (msid == "") {
    if (SaveDb(imaginary_.string(), db_type2, msid2, false)) {
#ifdef DEBUG
      printf("\t\tCC::rename failed to save the original db to queue.\n");
#endif
      return -1;
    }
  } else {
    if (SaveDb(imaginary_.string(), db_type2, msid2, true)) {
#ifdef DEBUG
      printf("\t\tCC::rename failed to save the original db immediately.\n");
#endif
      return -1;
    }
  }
  return 0;
}

int ClientController::utime(const std::string &path) {
#ifdef DEBUG
  printf("\t\tCC::utime %s\n", path.c_str());
#endif
  DB_TYPE db_type;
  std::string msid("");
  if (GetDb(path, &db_type, &msid))
    return -1;
  std::string thepath = path;
  boost::scoped_ptr<DataAtlasHandler> dah_(new DataAtlasHandler());
  if (dah_->ChangeMtime(thepath))
    return -1;
  if (msid == "") {
    if (SaveDb(path, db_type, msid, false)) {
#ifdef DEBUG
      printf("\t\tCC::rename failed to save the original db to queue.\n");
#endif
      return -1;
    }
  } else {
    if (SaveDb(path, db_type, msid, true)) {
#ifdef DEBUG
      printf("\t\tCC::rename failed to save the original db immediately.\n");
#endif
      return -1;
    }
  }
  return 0;
}

int ClientController::atime(const std::string &path) {
#ifdef DEBUG
  printf("\t\tCC::atime %s\n", path.c_str());
#endif
  DB_TYPE db_type;
  std::string msid("");
  if (GetDb(path, &db_type, &msid))
    return -1;
  std::string thepath = path;
  boost::scoped_ptr<DataAtlasHandler> dah_(new DataAtlasHandler());
  if (dah_->ChangeAtime(thepath))
    return -1;
  // We're not saving the db everytime the access time changes. I said NO!
  // OK, maybe we'll make the following amendments
  if (msid == "") {
    if (SaveDb(path, db_type, msid, false))
      return -1;
  }

  return 0;
}

int ClientController::open(const std::string &path) {
#ifdef DEBUG
  printf("\t\tCC::open %s\n", path.c_str());
#endif
  DB_TYPE db_type;
  std::string msid("");
  if (GetDb(path, &db_type, &msid))
    return -1;
  return RetrieveElement(path);
}

int ClientController::read(const std::string &path) {
#ifdef DEBUG
  printf("\t\tCC::read %s\n", path.c_str());
#endif
  DB_TYPE db_type;
  std::string msid("");
  if (GetDb(path, &db_type, &msid))
    return -1;
  return RetrieveElement(path);
}

int ClientController::write(const std::string &path) {
#ifdef DEBUG
  printf("\t\tCC::write %s\n", path.c_str());
#endif
  DB_TYPE db_type;
  std::string msid("");
  if (GetDb(path, &db_type, &msid)) {
#ifdef DEBUG
    printf("\t\tCC::write GetDb failed.\n");
#endif
    return -1;
  }
  if (BackupElement(path, db_type, msid)) {
#ifdef DEBUG
    printf("\t\tCC::write BackupElement failed.\n");
#endif
    return -1;
  }
  bool immediate = false;
  if (msid != "")
    immediate = true;
  if (SaveDb(path, db_type, msid, immediate)) {
#ifdef DEBUG
    printf("\t\tCC::write SaveDb failed.\n");
#endif
    return -1;
  }
  return 0;
}

int ClientController::create(const std::string &path) {
#ifdef DEBUG
  printf("\t\tCC::create %s\n", path.c_str());
#endif
  return mknod(path);
}

int ClientController::chmod(const std::string &path, int perm) {
#ifdef DEBUG
  printf("\t\tCC::chmod %s to %i\n", path.c_str(), perm);
#endif
  return 0;
}

int ClientController::chown(const std::string &path, std::string &user) {
#ifdef DEBUG
  printf("\t\tCC::chown %s with user %s\n", path.c_str(), user.c_str());
#endif
  return 0;
}

int ClientController::truncate() { return 0; }

int ClientController::flush() { return 0; }

int ClientController::fsync() { return 0; }

int ClientController::opendir(const std::string &path) {
#ifdef DEBUG
  printf("\t\tCC::opendir %s\n", path.c_str());
#endif
  return 0;
}

int ClientController::getdir(const std::string &path) {
#ifdef DEBUG
  printf("\t\tCC::getdir %s\n", path.c_str());
#endif
  return 0;
}

int ClientController::releasedir(const std::string &path) {
#ifdef DEBUG
  printf("\t\tCC::releasedir %s\n", path.c_str());
#endif
  return 0;
}

int ClientController::fsyncdir() { return 0; }

int ClientController::ftruncate() { return 0; }

///////////////////////////////
// Here endeth FUSE stuff !! //
///////////////////////////////

}  // namespace maidsafe
