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
#include <maidsafe/kademlia_service_messages.pb.h>
#include <cstdio>

#include "maidsafe/chunkstore.h"
#include "maidsafe/client/contacts.h"
#include "maidsafe/client/dataatlashandler.h"
#include "maidsafe/client/privateshares.h"
#include "maidsafe/client/selfencryption.h"

#include "maidsafe/client/sessionsingleton.h"
#include "maidsafe/client/storemanager.h"
#include "protobuf/maidsafe_messages.pb.h"
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
      if (cb.result != "")
        return;
    }
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));
  }
}


ClientController *ClientController::single = 0;

ClientController::ClientController() : client_chunkstore_(),
                                       sm_(),
                                       auth_(),
                                       ss_(),
                                       ser_da_(),
                                       ser_dm_(""),
                                       db_enc_queue_(),
                                       seh_(),
                                       messages_(),
                                       fsys_(),
                                       received_messages_(),
                                       rec_msg_mutex_(),
                                       clear_messages_thread_(),
                                       client_store_(),
                                       initialised_(false),
                                       logging_out_(false) {}

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

int ClientController::Init() {
  if (initialised_)
    return 0;
  fs::path client_path(fsys_.ApplicationDataDir(), fs::native);
  try {
    // If main app dir isn't already there, create it
    if (!fs::exists(client_path) && !fs::create_directories(client_path)) {
#ifdef DEBUG
      printf("CC::Init - Couldn't create app path (check permissions?): %s\n",
             client_path.string().c_str());
#endif
      return -2;
    }
    client_path /= "client" + base::RandomString(8);
    while (fs::exists(client_path))
      client_path = fs::path(client_path.string().substr(0,
          client_path.string().size()-8) + base::RandomString(8));
    client_store_ = client_path.string();
    if (!fs::exists(client_path) && !fs::create_directories(client_path)) {
#ifdef DEBUG
      printf("CC::Init -Couldn't create client path (check permissions?): %s\n",
             client_path.string().c_str());
#endif
      return -3;
    }
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("CC::Init - Couldn't create path (check permissions?): %s\n",
           e.what());
#endif
    return -4;
  }
  client_chunkstore_ = boost::shared_ptr<ChunkStore>
      (new ChunkStore(client_path.string(), 0, 0));
  if (!client_chunkstore_->Init()) {
#ifdef DEBUG
    printf("CC::Init - Failed to initialise client chunkstore.\n");
#endif
    return -5;
  }
#ifdef LOCAL_PDVAULT
  sm_.reset(new LocalStoreManager(client_chunkstore_));
#else
  sm_.reset(new MaidsafeStoreManager(client_chunkstore_));
#endif
  if (!JoinKademlia()) {
#ifdef DEBUG
    printf("CC::Init - Couldn't join Kademlia!\n");
#endif
    return -1;
  }
  auth_.Init(sm_);
  ss_ = SessionSingleton::getInstance();
  initialised_ = true;
  return 0;
}

bool ClientController::JoinKademlia() {
  CC_CallbackResult cb;
  sm_->Init(0, boost::bind(&CC_CallbackResult::CallbackFunc, &cb, _1));
  WaitForResult(cb);
  GenericResponse result;
  if ((!result.ParseFromString(cb.result)) ||
      (result.result() == kNack))
    return false;
  else
    return true;
}

int ClientController::ParseDa() {
  if (!initialised_) {
#ifdef DEBUG
    printf("CC::ParseDa - Not initialised.\n");
#endif
    return kClientControllerNotInitialised;
  }
  DataAtlas data_atlas;
  if (ser_da_ == "") {
#ifdef DEBUG
    printf("TMID brought is \"\".\n");
#endif
    return -9000;
  }
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

  if (data_atlas.dms_size() != 2) {
#ifdef DEBUG
    printf("Wrong number of datamaps in the DA.\n");
#endif
    return -9002;
  }

  std::list<Key> keys;
  for (int n = 0; n < data_atlas.keys_size(); ++n) {
    Key k = data_atlas.keys(n);
    keys.push_back(k);
  }
  SessionSingleton::getInstance()->LoadKeys(&keys);

  std::list<PublicContact> contacts;
  for (int n = 0; n < data_atlas.contacts_size(); ++n) {
    PublicContact pc = data_atlas.contacts(n);
    contacts.push_back(pc);
  }
  SessionSingleton::getInstance()->LoadContacts(&contacts);

  std::list<Share> shares;
  for (int n = 0; n < data_atlas.shares_size(); ++n) {
    Share sh = data_atlas.shares(n);
    shares.push_back(sh);
  }
  SessionSingleton::getInstance()->LoadShares(&shares);

  DataMap dm_root, dm_shares;
  dm_root = data_atlas.dms(0);
  dm_shares = data_atlas.dms(1);

  std::string ser_dm_root, ser_dm_shares;
  dm_root.SerializeToString(&ser_dm_root);
  dm_shares.SerializeToString(&ser_dm_shares);
#ifdef DEBUG
  // printf("ser_dm_root_ = %s\n", ser_dm_root_);
#endif
  int i = seh_.DecryptDb(kRoot, PRIVATE, ser_dm_root, "", "", false, false);
#ifdef DEBUG
  printf("result of decrypt root: %i -- (%s)\n", i, ""/*ser_dm_root.c_str()*/);
#endif
  if (i != 0)
    return -1;
  i = seh_.DecryptDb(base::TidyPath(kRootSubdir[1][0]), PRIVATE, ser_dm_shares,
                      "", "", false, false);
#ifdef DEBUG
  printf("result of decrypt %s: %i -- (%s)\n", kRootSubdir[1][0].c_str(), i,
          ""/*ser_dm_shares.c_str()*/);
#endif
  return (i == 0) ? 0 : -1;
}

int ClientController::SerialiseDa() {
  if (!initialised_) {
#ifdef DEBUG
    printf("CC::SerialiseDa - Not initialised.\n");
#endif
    return kClientControllerNotInitialised;
  }
  DataAtlas data_atlas_;
  data_atlas_.set_root_db_key(ss_->RootDbKey());
  DataMap root_dm, shares_dm;
  seh_.EncryptDb(kRoot, PRIVATE, "", "", false, &root_dm);
  seh_.EncryptDb(base::TidyPath(kRootSubdir[1][0]), PRIVATE, "", "", false,
                  &shares_dm);
  DataMap *dm = data_atlas_.add_dms();
  *dm = root_dm;
  dm = data_atlas_.add_dms();
  *dm = shares_dm;
#ifdef DEBUG
  // printf("data_atlas_.dms(0).file_hash(): %s\n",
  //   data_atlas_.dms(0).file_hash().substr(0, 10).c_str());
  // printf("data_atlas_.dms(1).file_hash(): %s\n",
  //   data_atlas_.dms(1).file_hash().substr(0, 10).c_str());
#endif

  std::list<KeyAtlasRow> keyring;
  ss_->GetKeys(&keyring);
  while (!keyring.empty()) {
    KeyAtlasRow kar = keyring.front();
    Key *k = data_atlas_.add_keys();
    k->set_type(maidsafe::PacketType(kar.type_));
    k->set_id(kar.id_);
    k->set_private_key(kar.private_key_);
    k->set_public_key(kar.public_key_);
    k->set_public_key_signature(kar.signed_public_key_);
    keyring.pop_front();
  }
  printf("ClientController::SerialiseDa() - Finished with Keys.\n");

  std::vector<maidsafe::mi_contact> contacts;
  ss_->GetContactList(&contacts);
  for (unsigned int n = 0; n < contacts.size(); ++n) {
    PublicContact *pc = data_atlas_.add_contacts();
    pc->set_pub_name(contacts[n].pub_name_);
    pc->set_pub_key(contacts[n].pub_key_);
    pc->set_full_name(contacts[n].full_name_);
    pc->set_office_phone(contacts[n].office_phone_);
    pc->set_birthday(contacts[n].birthday_);
    std::string g(1, contacts[n].gender_);
    pc->set_gender(g);
    pc->set_language(contacts[n].language_);
    pc->set_country(contacts[n].country_);
    pc->set_city(contacts[n].city_);
    std::string c(1, contacts[n].confirmed_);
    pc->set_confirmed(c);
    pc->set_rank(contacts[n].rank_);
    pc->set_last_contact(contacts[n].last_contact_);
  }
  printf("ClientController::SerialiseDa() - Finished with Contacts.\n");

  std::list<PrivateShare> ps_list;
  ss_->GetFullShareList(ALPHA, kAll, &ps_list);
  while (!ps_list.empty()) {
    PrivateShare this_ps = ps_list.front();
    Share *sh = data_atlas_.add_shares();
    sh->set_name(this_ps.Name());
    sh->set_msid(this_ps.Msid());
    sh->set_msid_pub_key(this_ps.MsidPubKey());
    sh->set_msid_pri_key(this_ps.MsidPriKey());
    sh->set_rank(this_ps.Rank());
    sh->set_last_view(this_ps.LastViewed());
    std::list<ShareParticipants> this_sp_list = this_ps.Participants();
    while (!this_sp_list.empty()) {
      ShareParticipants this_sp = this_sp_list.front();
      ShareParticipant *shp = sh->add_participants();
      shp->set_public_name(this_sp.id);
      shp->set_public_name_pub_key(this_sp.public_key);
      std::string role(1, this_sp.role);
      shp->set_role(role);
      this_sp_list.pop_front();
    }
    ps_list.pop_front();
  }
  printf("ClientController::SerialiseDa() - Finished with Shares.\n");
  ser_da_.clear();
  ser_dm_.clear();
  data_atlas_.SerializeToString(&ser_da_);
  seh_.EncryptString(ser_da_, &ser_dm_);

  printf("ClientController::SerialiseDa() - Serialised.\n");

  return 0;
}

int ClientController::CheckUserExists(const std::string &username,
                                      const std::string &pin,
                                      DefConLevels level) {
  if (!initialised_) {
#ifdef DEBUG
    printf("CC::CheckUserExists - Not initialised.\n");
#endif
    return kClientControllerNotInitialised;
  }
  ss_->ResetSession();
  ss_->SetDefConLevel(level);
  return auth_.GetUserInfo(username, pin);
}

bool ClientController::CreateUser(const std::string &username,
                                  const std::string &pin,
                                  const std::string &password,
                                  const VaultConfigParameters &vcp) {
  if (!initialised_) {
#ifdef DEBUG
    printf("CC::CreateUser - Not initialised.\n");
#endif
    return false;
  }

  ss_->SetConnectionStatus(0);
  int result = auth_.CreateUserSysPackets(username, pin);
  if (result != kSuccess) {
#ifdef DEBUG
    printf("In CC::CreateUser - Failed to create user system packets.\n");
#endif
    ss_->ResetSession();
    return false;
  } else {
#ifdef DEBUG
    printf("In CC::CreateUser - auth_.CreateUserSysPackets DONE - %u.\n",
           ss_->KeyRingSize());
#endif
  }

  OwnLocalVaultResult olvr = SetLocalVaultOwned(vcp.port,
                                                vcp.space * 1024 * 1024,
                                                vcp.directory);
  if (olvr != OWNED_SUCCESS) {
#ifdef DEBUG
    printf("CC::CreateUser +++ OwnLocalVaultResult: %d +++\n", olvr);
#endif
    return false;
  }
                                      boost::this_thread::sleep(boost::posix_time::seconds(60));

  client_chunkstore_->Init();
  seh_.Init(sm_, client_chunkstore_);
  std::string ser_da, ser_dm;
  ss_->SerialisedKeyRing(&ser_da);
  result = seh_.EncryptString(ser_da, &ser_dm);
  if (result != 0) {
#ifdef DEBUG
    printf("In CC::CreateUser - Cannot SelfEncrypt DA - %i.\n", result);
#endif
    ss_->ResetSession();
    return false;
  } else {
#ifdef DEBUG
    printf("In CC::CreateUser - seh_.EncryptString of DA DONE.\n");
#endif
  }

  result = auth_.CreateTmidPacket(username, pin, password, ser_dm);
  if (result != kSuccess) {
#ifdef DEBUG
    printf("In ClientController::CreateUser - Cannot create tmid packet.\n");
#endif
    ss_->ResetSession();
    return false;
  } else {
#ifdef DEBUG
    printf("In CC::CreateUser - auth_.CreateTmidPacket DONE.\n");
#endif
  }

  ss_->SetSessionName(false);
  std::string root_db_key;
  int res = seh_.GenerateUniqueKey(PRIVATE, "", 0, &root_db_key);
  if (res != 0) {
#ifdef DEBUG
    printf("In ClientController::CreateUser - Bombing out, no root_db_key.\n");
#endif
    return false;
  }
  ss_->SetRootDbKey(root_db_key);
  fsys_.Mount();
  fsys_.FuseMountPoint();
  boost::scoped_ptr<DataAtlasHandler> dah(new DataAtlasHandler());
  DataAtlas da;

  res += dah->Init(true);

  // set up root subdirs
  for (int i = 0; i < kRootSubdirSize; ++i) {
    MetaDataMap mdm;
    DataMap dm;
    std::string ser_mdm, key;
    mdm.set_id(-2);
    mdm.set_display_name(base::TidyPath(kRootSubdir[i][0]));
    mdm.set_type(EMPTY_DIRECTORY);
    mdm.set_stats("");
    mdm.set_tag("");
    mdm.set_file_size_high(0);
    mdm.set_file_size_low(0);
    boost::uint32_t current_time = base::get_epoch_time();
    mdm.set_creation_time(current_time);
    mdm.SerializeToString(&ser_mdm);
    if (kRootSubdir[i][1] == "") {
      seh_.GenerateUniqueKey(PRIVATE, "", 0, &key);
    } else {
      key = kRootSubdir[i][1];
    }
    res += dah->AddElement(base::TidyPath(kRootSubdir[i][0]),
                           ser_mdm, "", key, true);
    seh_.EncryptDb(base::TidyPath(kRootSubdir[i][0]),
                    PRIVATE, key, "", true, &dm);
  }

  // set up share subdirs
  for (int i = 0; i < kSharesSubdirSize; ++i) {
    fs::path subdir(kSharesSubdir[i][0], fs::native);
    std::string subdir_name = subdir.filename();
    MetaDataMap mdm;
    DataMap dm;
    std::string ser_mdm, key;
    mdm.set_id(-2);
    mdm.set_display_name(subdir_name);
    mdm.set_type(EMPTY_DIRECTORY);
    mdm.set_stats("");
    mdm.set_tag("");
    mdm.set_file_size_high(0);
    mdm.set_file_size_low(0);
    boost::uint32_t current_time = base::get_epoch_time();
    mdm.set_creation_time(current_time);
    mdm.SerializeToString(&ser_mdm);
    if (kSharesSubdir[i][1] == "") {  // ie no preassigned key so not public
      seh_.GenerateUniqueKey(PRIVATE, "", 0, &key);
      res += dah->AddElement(base::TidyPath(kSharesSubdir[i][0]),
                             ser_mdm, "", key, true);
      seh_.EncryptDb(base::TidyPath(kSharesSubdir[i][0]),
                      PRIVATE, key, "", true, &dm);
    } else {
      key = kSharesSubdir[i][1];
      res += dah->AddElement(base::TidyPath(kSharesSubdir[i][0]),
                             ser_mdm, "", key, true);
      if (seh_.DecryptDb(base::TidyPath(kSharesSubdir[i][0]),
                          ANONYMOUS, "", key, "", true, true)) {
        // ie Public and Anon have never been saved before on the network
        std::string ser_dm;
        seh_.EncryptDb(base::TidyPath(kSharesSubdir[i][0]), ANONYMOUS,
                        kSharesSubdir[i][1], "", true, &dm);
      }
    }
  }

  if (0 != res) {
#ifdef DEBUG
    printf("In ClientController::CreateUser error creating DBs.\n");
#endif
    return false;
  }

  return true;
}

bool ClientController::ValidateUser(const std::string &password) {
  if (!initialised_) {
#ifdef DEBUG
    printf("CC::ValidateUser - Not initialised.\n");
#endif
    return false;
  }
  ser_da_.clear();
  ser_dm_.clear();
  int result = auth_.GetUserData(password, &ser_dm_);

  if (result != kSuccess) {
    // Password validation failed
    ss_->ResetSession();
#ifdef DEBUG
    printf("ClientController::ValidateUser - Invalid password.\n");
#endif
    return false;
  }
  client_chunkstore_->Init();
  seh_.Init(sm_, client_chunkstore_);
  if (seh_.DecryptString(ser_dm_, &ser_da_) != 0) {
    ss_->ResetSession();
#ifdef DEBUG
    printf("ClientController::ValidateUser - Cannot decrypt DA.\n");
#endif
    return false;
  }

  ss_->SetConnectionStatus(0);
  ss_->SetSessionName(false);
  fsys_.Mount();
  boost::scoped_ptr<DataAtlasHandler> dah_(new DataAtlasHandler());
  if (ParseDa() != 0) {
#ifdef DEBUG
    printf("ClientController::ValidateUser - Cannot parse DA.\n");
#endif
    ss_->ResetSession();
    return false;
  }

  if (dah_->Init(false)) {
#ifdef DEBUG
    printf("ClientController::ValidateUser - Cannot initialise DAH.\n");
#endif
    ss_->ResetSession();
    return false;
  }

  // Create the mount point directory
  fsys_.FuseMountPoint();

  // Do BP operations if need be
  if (ss_->PublicUsername() == "") {
    return true;
  }

//  // CHANGE CONNECTION STATUS
//  int connection_status(1);
//  int n = ChangeConnectionStatus(connection_status);
//  if (n != 0) {
//    // Alert for BP problems
//  }
//  ss_->SetConnectionStatus(connection_status);

  clear_messages_thread_ = boost::thread(&ClientController::ClearStaleMessages,
                                         this);
  return true;
}

void ClientController::CloseConnection(bool clean_up_transport) {
  if (!initialised_) {
#ifdef DEBUG
    printf("CC::CloseConnection - Not initialised.\n");
#endif
    return;
  }
  CC_CallbackResult cb;
  sm_->StopRvPing();
  sm_->Close(boost::bind(&CC_CallbackResult::CallbackFunc, &cb, _1), true);
  WaitForResult(cb);
  GenericResponse result;
  if ((!result.ParseFromString(cb.result)) ||
      (result.result() == kNack)) {
#ifdef DEBUG
    printf("ClientController::CloseConnection - Error leaving network.\n");
#endif
    return;
  }

#ifdef DEBUG
  printf("ClientController::CloseConnection - Successfully left kademlia.\n");
#endif
  if (clean_up_transport)
    sm_->CleanUpTransport();
  return;
}

void ClientController::StopRvPing() {
  if (!initialised_) {
#ifdef DEBUG
    printf("CC::StopRvPing - Not initialised.\n");
#endif
    return;
  }
  if (sm_)
    sm_->StopRvPing();
}

bool ClientController::Logout() {
  if (!initialised_) {
#ifdef DEBUG
    printf("CC::Logout - Not initialised.\n");
#endif
    return false;
  }
  logging_out_ = true;

//  int connection_status(0);
//  int n = ChangeConnectionStatus(connection_status);
//  if (n != 0) {
//    // Alert for BP problems
//  }
//  ss_->SetConnectionStatus(connection_status);

  int result = SaveSession();
  if (result != kSuccess) {
#ifdef DEBUG
    printf("ClientController::Logout - Failed to save session %d.\n", result);
#endif
    return false;
  }

  clear_messages_thread_.join();
  while (sm_->NotDoneWithUploading()) {
    boost::this_thread::sleep(boost::posix_time::seconds(1));
  }
#ifdef DEBUG
  printf("ClientController::Logout - After threads done.\n");
#endif

  fsys_.UnMount();
  ss_->ResetSession();
  messages_.clear();
  client_chunkstore_->Clear();
  ser_da_.clear();
  ser_dm_.clear();
  logging_out_ = false;
  return true;
}

int ClientController::SaveSession() {
  if (!initialised_) {
#ifdef DEBUG
    printf("CC::SaveSession - Not initialised.\n");
#endif
    return kClientControllerNotInitialised;
  }

  int n = SerialiseDa();
  if (n != 0) {
#ifdef DEBUG
    printf("ClientController::SaveSession - Failed to serialise DA.\n");
#endif
    return n;
  }
  n = auth_.SaveSession(ser_dm_);
  if (n != 0) {
#ifdef DEBUG
    printf("ClientController::SaveSession - Failed to Save Session.\n");
#endif
    return n;
  }
  return 0;
}

bool ClientController::LeaveMaidsafeNetwork() {
  if (!initialised_) {
#ifdef DEBUG
    printf("CC::LeaveMaidsafeNetwork - Not initialised.\n");
#endif
    return false;
  }
  std::list<KeyAtlasRow> keys;
  int result;
  std::string dir = fsys_.MaidsafeDir();
  {
    ss_->GetKeys(&keys);
    result = auth_.RemoveMe(keys);
  }
  if (result == kSuccess) {
    try {
      fs::remove_all(dir);
    }
    catch(const std::exception &e) {
#ifdef DEBUG
      printf("ClientController::LeaveMaidsafeNetwork - %s\n", e.what());
#endif
    }
    return true;
  }
  return false;
}

bool ClientController::ChangeUsername(const std::string &new_username) {
  if (!initialised_) {
#ifdef DEBUG
    printf("CC::ChangeUsername - Not initialised.\n");
#endif
    return false;
  }
  SerialiseDa();

  int result = auth_.ChangeUsername(ser_dm_, new_username);
  if (result == kSuccess)
    return true;
  return false;
}

bool ClientController::ChangePin(const std::string &new_pin) {
  if (!initialised_) {
#ifdef DEBUG
    printf("CC::ChangePin - Not initialised.\n");
#endif
    return false;
  }
  SerialiseDa();

  int result = auth_.ChangePin(ser_dm_, new_pin);
  if (result == kSuccess)
    return true;
  return false;
}

bool ClientController::ChangePassword(const std::string &new_password) {
  if (!initialised_) {
#ifdef DEBUG
    printf("CC::ChangePassword - Not initialised.\n");
#endif
    return false;
  }
  SerialiseDa();

  int result = auth_.ChangePassword(ser_dm_, new_password);
  if (result == kSuccess)
    return true;
  return false;
}

//////////////////////////////
// Buffer Packet Operations //
//////////////////////////////

bool ClientController::CreatePublicUsername(
    const std::string &public_username) {
  if (!initialised_) {
#ifdef DEBUG
    printf("CC::CreatePublicUsername - Not initialised.\n");
#endif
    return false;
  }
  if (ss_->PublicUsername() != "") {
#ifdef DEBUG
    printf("CC::CreatePublicUsername - Already have public username.\n");
#endif
    return false;
  }

  int result = auth_.CreatePublicName(public_username);
  if (result != kSuccess) {
#ifdef DEBUG
    printf("CC::CreatePublicUsername - Error in CreatePublicName.\n");
#endif
    return false;
  }

  if (sm_->CreateBP() != kSuccess) {
#ifdef DEBUG
    printf("CC::CreatePublicUsername - Failed to create the BP.\n");
#endif
    return false;
  }

  return true;
}

/*
int ClientController::ChangeConnectionStatus(int status) {
  if (ss_->ConnectionStatus() == status)
    return -3;
  CC_CallbackResult cb;
  cbph_->ChangeStatus(status,
                      boost::bind(&CC_CallbackResult::CallbackFunc, &cb, _1),
                      MPID);
  WaitForResult(cb);
  UpdateResponse change_connection_status;
  if (!change_connection_status.ParseFromString(cb.result))
    return -1;
  if (change_connection_status.result() == kNack)
    return -2;

  return 0;
}
*/

////////////////////////
// Message Operations //
////////////////////////

bool ClientController::GetMessages() {
  if (!initialised_) {
#ifdef DEBUG
    printf("CC::GetMessages - Not initialised.\n");
#endif
    return false;
  }
  // Only getting MPID buffer packet
  if (ss_->PublicUsername() == "") {
#ifdef DEBUG
    printf("ClientController::GetMessages - How about the P.U.?\n");
#endif
    return false;
  }

  std::list<ValidatedBufferPacketMessage> valid_messages;
  if (sm_->LoadBPMessages(&valid_messages) != 0) {
#ifdef DEBUG
    printf("ClientController::GetMessages - Muffed the load\n");
#endif
    return false;
  }
  if (valid_messages.empty()) {
    // TODO(Team#5#): return code for no messages
    return true;
  }
  HandleMessages(&valid_messages);
  return true;
}

int ClientController::HandleMessages(
    std::list<ValidatedBufferPacketMessage> *valid_messages) {
  if (!initialised_) {
#ifdef DEBUG
    printf("CC::HandleMessages - Not initialised.\n");
#endif
    return kClientControllerNotInitialised;
  }
  int result = 0;
#ifdef DEBUG
      printf("=========================================\n");
#endif
  while (!valid_messages->empty()) {
    std::map<std::string, boost::uint32_t>::iterator it;
    rec_msg_mutex_.lock();
#ifdef DEBUG
    printf("ClientController::HandleMessages - received_messages_ size: %d\n",
           received_messages_.size());
#endif
    it = received_messages_.find(valid_messages->front().message());
    if (it != received_messages_.end()) {
#ifdef DEBUG
      printf("ClientController::HandleMessages - Previously received message.");
#endif
      rec_msg_mutex_.unlock();
      continue;
    }

    received_messages_.insert(std::pair<std::string, boost::uint32_t>(
                              valid_messages->front().message(),
                              valid_messages->front().timestamp()));
    rec_msg_mutex_.unlock();
#ifdef DEBUG
    printf("ClientController::HandleMessages timestamp: %d\n",
           valid_messages->front().timestamp());
    printf("=========================================\n");
#endif
    switch (valid_messages->front().type()) {
      case ADD_CONTACT_RQST:
      case INSTANT_MSG:
          result += HandleInstantMessage(valid_messages->front());
          break;
      default: break;  // TODO(Team): define other types of message
    }
    valid_messages->pop_front();
  }
  return result;
}

void ClientController::ClearStaleMessages() {
  int recheck_interval = 100;  // milliseconds
  int total_sleep = 10000;  // milliseconds
  while (!logging_out_) {
#ifdef DEBUG
    printf("ClientController::ClearStaleMessages timestamp: %d\n",
           base::get_epoch_time());
#endif
    if (ss_->PublicUsername() == "")
      return;
    boost::mutex::scoped_lock loch(rec_msg_mutex_);
    boost::uint32_t now = base::get_epoch_time() - 10;
    std::map<std::string, boost::uint32_t>::iterator it;
    for (it = received_messages_.begin();
         it != received_messages_.end(); ++it) {
      if (it->second > now)
        break;
    }
    received_messages_.erase(received_messages_.begin(), it);
    int count = 0;
    while (!logging_out_ && count < total_sleep) {
      boost::this_thread::sleep(boost::posix_time::milliseconds(
          recheck_interval));
      count += recheck_interval;
    }
  }
}

int ClientController::HandleDeleteContactNotification(
    const std::string &sender) {
  if (!initialised_) {
#ifdef DEBUG
    printf("CC::HandleDeleteContactNotification - Not initialised.\n");
#endif
    return kClientControllerNotInitialised;
  }
  int n = ss_->UpdateContactConfirmed(sender, 'U');
  if (n != 0) {
#ifdef DEBUG
    printf("Status on contact not updated.\n");
#endif
    return -40003;
  }

  return 0;
}

int ClientController::HandleReceivedShare(
    const PrivateShareNotification &psn,
    const std::string &name) {
  if (!initialised_) {
#ifdef DEBUG
    printf("CC::HandleReceivedShare - Not initialised.\n");
#endif
    return kClientControllerNotInitialised;
  }
#ifdef DEBUG
  printf("Dir key: %s", psn.dir_db_key().c_str());
  printf("Public key: %s", psn.public_key().c_str());
#endif

  std::vector<std::string> attributes;
  std::list<ShareParticipants> participants;
  if (name.empty())
    attributes.push_back(psn.name());
  // TODO(Dan#5#): 2009-06-25 - Make sure name is the correct one
  else
    attributes.push_back(name);
  attributes.push_back(psn.msid());
  attributes.push_back(psn.public_key());
  attributes.push_back("");

  std::vector<boost::uint32_t> share_stats(2, 0);
  if (!psn.has_private_key()) {
    int n = ss_->AddPrivateShare(attributes, share_stats, &participants);
    if (n != 0)
      return n;
  } else {
    attributes[3] = psn.private_key();

    // Get the public key of the contacts
    std::vector<maidsafe::Contact> contact_list;

    for (int n = 0; n < psn.admins_size(); n++) {
      if (psn.admins(n) ==
          ss_->PublicUsername())
        continue;  // Not to add myself to the share DB
      maidsafe::ShareParticipants sp;
      sp.id = psn.admins(n);
      sp.role = 'A';
      contact_list.clear();
      maidsafe::mi_contact mic;
      int r = ss_->GetContactInfo(psn.admins(n), &mic);
      // GetContactList(dbName, contact_list, psn.admins(n), false);
      if (r == 0) {
        sp.public_key = mic.pub_key_;
      } else {  // search for the public key in kadsafe
        std::string public_key;
        int result = auth_.PublicUsernamePublicKey(sp.id, &public_key);
        if (result != kSuccess) {
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
      maidsafe::mi_contact mic;
      int r = ss_->GetContactInfo(psn.admins(n), &mic);
      if (r == 0) {
        sp.public_key = mic.pub_key_;
      } else {  // search for the public key in kadsafe
        std::string public_key;
        int result = auth_.PublicUsernamePublicKey(sp.id, &public_key);
        if (result != kSuccess) {
#ifdef DEBUG
          printf("Couldn't find %s's public key.\n", sp.id.c_str());
#endif
          return -20003;
        }
        sp.public_key = public_key;
      }
      participants.push_back(sp);
    }

    int n = ss_->AddPrivateShare(attributes, share_stats, &participants);
    if (n != 0)
      return n;
  }

  // Create directory in Shares/Private
  std::string share_path("Shares/Private/" + psn.name());
  DirType dir_type;
  std::string msid("");

  int n = GetDb(share_path, &dir_type, &msid);
  if (n != 0) {
#ifdef DEBUG
    printf("Didn't get the DB.\n");
#endif
    return -20004;
  }
  std::string ser_mdm("");
  msid = "";
  PathDistinction(share_path, &msid);
  dir_type = GetDirType(share_path);
  if (!seh_.ProcessMetaData(share_path, EMPTY_DIRECTORY, "", 0, &ser_mdm)) {
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
  dir_type = GetDirType(pp.parent_path().string());
#ifdef DEBUG
  printf("CC::HandleReceivedShare, after GetDirType parent(%s): %i.\n",
    share_path.c_str(), static_cast<int>(dir_type));
#endif

  if (SaveDb(share_path, dir_type, "", false)) {
#ifdef DEBUG
    printf("CC::HandleReceivedShare, SaveDb(%s) failed.\n", share_path.c_str());
#endif
    return -20007;
  }
  return 0;
}

int ClientController::HandleInstantMessage(
    const ValidatedBufferPacketMessage &vbpm) {
  if (!initialised_) {
#ifdef DEBUG
    printf("CC::HandleInstantMessage - Not initialised.\n");
#endif
    return kClientControllerNotInitialised;
  }
#ifdef DEBUG
  printf("INSTANT MESSAGE received\n");
  printf("Sender: %s\n", vbpm.sender().c_str());
#endif
  InstantMessage im;
  if (im.ParseFromString(vbpm.message())) {
      messages_.push_back(im);
#ifdef DEBUG
      printf("%s\n", im.message().c_str());
#endif
    return 0;
  } else {
    return -1;
  }
}

int ClientController::AddInstantFile(
    const InstantFileNotification &ifm,
    const std::string &location) {
  if (!initialised_) {
#ifdef DEBUG
    printf("CC::AddInstantFile - Not initialised.\n");
#endif
    return kClientControllerNotInitialised;
  }
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
  std::string dir_key;

  boost::scoped_ptr<DataAtlasHandler> dah_(new DataAtlasHandler());
  fs::path path_with_filename;
  if (location.empty()) {
    path_with_filename = fs::path(base::TidyPath(kRootSubdir[0][0]));
    path_with_filename /= ifm.filename();
  } else {
    // TODO(Dan#5#): 2009-06-25 - Make sure location is the correct path
    path_with_filename = fs::path(base::TidyPath(location));
    mdm.set_display_name(path_with_filename.filename());
  }
  std::string ser_mdm;
  mdm.SerializeToString(&ser_mdm);
  std::string path_add_element(path_with_filename.string());
  DirType dir_type;
  std::string msid;
  int n = GetDb(path_add_element, &dir_type, &msid);
  if (n != 0) {
#ifdef DEBUG
    printf("MAS - Riata en GetDb - %s\n", path_add_element.c_str());
#endif
    return -8888888;
  }

  n = dah_->AddElement(path_add_element, ser_mdm, ifm.ser_dm(), dir_key, false);
  if (n != 0) {
#ifdef DEBUG
    printf("Riata en AddElement\n");
#endif
    return -1111;
  }

  std::string path_save_db(path_with_filename.string());
  if (msid == "") {
    if (SaveDb(path_save_db, dir_type, msid, false)) {
#ifdef DEBUG
      printf("\t\tCC::AddInstantFile failed to save the db to queue. %i %s\n",
        dir_type, path_save_db.c_str());
#endif
      return -11111;
    }
  } else {
    if (SaveDb(path_save_db, dir_type, msid, true)) {
#ifdef DEBUG
      printf("\t\tCC::AddInstantFile failed to save the db immediately.\n");
#endif
      return -111111;
    }
  }

  return 0;
}

int ClientController::HandleAddContactRequest(
    const ContactInfo &ci, const std::string &sender) {
  if (!initialised_) {
#ifdef DEBUG
    printf("CC::HandleAddContactRequest - Not initialised.\n");
#endif
    return kClientControllerNotInitialised;
  }
  // TODO(Team#5#): return choice to the user to accept/reject contact

  // Check if contact is on the list and has unconfirmed status
  std::string rec_public_key;
  mi_contact mic;
  if (ss_->GetContactInfo(sender, &mic) == 0) {  // Contact exists
    if (mic.confirmed_ == 'C') {
#ifdef DEBUG
      printf("Sender's already confirmed.\n");
#endif
      return -7;
    }
    int n =  ss_->UpdateContactConfirmed(sender, 'C');
    if (n != 0) {
#ifdef DEBUG
      printf("Couldn't update sender's confirmed status.\n");
#endif
      return -77;
    }
    rec_public_key = mic.pub_key_;
  } else {  // Contact didn't exist. Add from scratch.
    // Get contact's public key
    int result = auth_.PublicUsernamePublicKey(sender, &rec_public_key);
    if (result != kSuccess) {
#ifdef DEBUG
      printf("Can't get sender's public key.\n");
#endif
      return -777;
    }

    Contact c;
    c.SetPublicName(sender);
    c.SetPublicKey(rec_public_key);
    c.SetFullName(ci.name());
    c.SetOfficePhone(ci.office_number());
    c.SetBirthday(ci.birthday());
    c.SetGender(ci.gender().at(0));
    c.SetLanguage(ci.language());
    c.SetCountry(ci.country());
    c.SetCity(ci.city());
    c.SetConfirmed('C');

    // Add to the contacts MI
    int n = ss_->AddContact(sender, rec_public_key, ci.name(),
            ci.office_number(), ci.birthday(), ci.gender().at(0), ci.language(),
            ci.country(), ci.city(), 'C', 0, 0);
    if (n != 0) {
#ifdef DEBUG
      printf("ClientController::HandleAddContactRequest - "
             "Adding contact failed.\n");
#endif
      return -7777;
    }

    std::string bpinfo = GenerateBPInfo();
    if (bpinfo.empty()) {
#ifdef DEBUG
      printf("ClientController::HandleAddContactRequest - BPI empty\n");
#endif
      return -77777;
    }
    if (sm_->ModifyBPInfo(bpinfo) != kSuccess) {
#ifdef DEBUG
      printf("ClientController::HandleAddContactRequest - Failed save BPI\n");
#endif
      return -777777;
    }
  }

  InstantMessage im;
  ContactNotification *cn = im.mutable_contact_notification();
  ContactInfo *info = cn->mutable_contact();

  info->set_name("Mock");
  info->set_birthday("Today");
  info->set_office_number("0987456321");
  info->set_gender("F");
  info->set_country(22);
  info->set_city("Troon");
  info->set_language(7);

  cn->set_action(1);

  std::string message("\"");
  message += ss_->PublicUsername() + "\" has confirmed you as a contact.";
  im.set_sender(ss_->PublicUsername());
  im.set_date(base::get_epoch_time());
  im.set_message(message);
  std::string ser_im;
  im.SerializeToString(&ser_im);

  std::vector<std::string> contact_names;
  contact_names.push_back(sender);
  if (sm_->AddBPMessage(contact_names, ser_im, INSTANT_MSG) !=
      kSuccess) {
#ifdef DEBUG
    printf("ClientController::HandleAddContactRequest - Failed send msg\n");
#endif
    return -7777777;
  }

  return 0;
}

int ClientController::HandleAddContactResponse(
    const ContactInfo &ci, const std::string &sender) {
  if (!initialised_) {
#ifdef DEBUG
    printf("CC::HandleAddContactResponse - Not initialised.\n");
#endif
    return kClientControllerNotInitialised;
  }
  // Check if contact exists in local session
  Contact c;
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

  std::vector<maidsafe::Contact> list;
  maidsafe::mi_contact mic;
  int n = ss_->GetContactInfo(sender, &mic);
  if (n != 0) {
#ifdef DEBUG
    printf("ClientController::HandleAddContactResponse - Get list failed.\n");
#endif
    return -8;
  }

  n = ss_->UpdateContactFullName(sender, ci.name());
  n += ss_->UpdateContactOfficePhone(sender, ci.office_number());
  n += ss_->UpdateContactBirthday(sender, ci.birthday());
  n += ss_->UpdateContactGender(sender, ci.gender().at(0));
  n += ss_->UpdateContactLanguage(sender, ci.language());
  n += ss_->UpdateContactCountry(sender, ci.country());
  n += ss_->UpdateContactCity(sender, ci.city());
  n += ss_->UpdateContactConfirmed(sender, 'C');
  if (n != 0) {
#ifdef DEBUG
    printf("ClientController::HandleAddContactResponse - No update contact.\n");
#endif
    return -88;
  }
  return 0;
}

int ClientController::SendInstantMessage(const std::string &message,
    const std::vector<std::string> &contact_names,
    const std::string &conversation) {
  if (!initialised_) {
#ifdef DEBUG
    printf("CC::SendInstantMessage - Not initialised.\n");
#endif
    return kClientControllerNotInitialised;
  }
  if (ss_->ConnectionStatus() == 1) {
#ifdef DEBUG
    printf("Can't send a message while off-line.\n");
#endif
    return -9999;
  }

  std::string ser_im;
  InstantMessage im;
  im.set_sender(ss_->PublicUsername());
  im.set_message(message);
  im.set_date(base::get_epoch_time());
  im.set_conversation(conversation);
  im.SerializeToString(&ser_im);

  if (sm_->AddBPMessage(contact_names, ser_im, INSTANT_MSG) != kSuccess) {
#ifdef DEBUG
    printf("ClientController::SendInstantMessage - Not all recepients got "
           "the message\n");
#endif
    return -999;
  }

  int res = 0;
  for (size_t n = 0; n < contact_names.size(); ++n) {
    res += ss_->SetLastContactRank(contact_names[n]);
  }

  return res;
}

int ClientController::GetInstantMessages(std::list<InstantMessage> *messages) {
  if (!initialised_) {
#ifdef DEBUG
    printf("CC::GetInstantMessages - Not initialised.\n");
#endif
    return kClientControllerNotInitialised;
  }
  *messages = messages_;
  messages_.clear();
  return 0;
}

int ClientController::SendInstantFile(std::string *filename,
    const std::string &msg, const std::vector<std::string> &contact_names,
    const std::string &conversation) {
  if (!initialised_) {
#ifdef DEBUG
    printf("CC::SendInstantFile - Not initialised.\n");
#endif
    return kClientControllerNotInitialised;
  }
  if (ss_->ConnectionStatus() == 1) {
#ifdef DEBUG
    printf("Can't send a message while off-line.\n");
#endif
    return -6666666;
  }

  std::string path = *filename;
  DirType dir_type;
  std::string msid("");
  int n = GetDb(*filename, &dir_type, &msid);
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
  InstantMessage im;
  InstantFileNotification *ifm =
      im.mutable_instantfile_notification();
  ifm->set_ser_mdm(ser_mdm);
  ifm->set_ser_dm(ser_dm);
  ifm->set_filename(p_filename.filename());
  im.set_sender(SessionSingleton::getInstance()->PublicUsername());
  im.set_date(base::get_epoch_time());
  im.set_conversation(conversation);
  std::string message;
  if (msg.empty()) {
    message = "\"";
    message += im.sender() + "\" has sent you file " +
              p_filename.filename();
  } else {
    message = msg + " - Filename: " + p_filename.filename();
  }
  im.set_message(message);

  std::string ser_instant_file;
  im.SerializeToString(&ser_instant_file);

  if (sm_->AddBPMessage(contact_names, ser_instant_file, INSTANT_MSG) !=
      kSuccess) {
#ifdef DEBUG
    printf("ClientController::SendInstantFile - Not all recepients got "
           "the message\n");
#endif
    return -666666;
  }

  int res = 0;
  for (size_t nn = 0; nn < contact_names.size(); ++nn) {
    res += ss_->SetLastContactRank(contact_names[nn]);
  }

  return res;
}

////////////////////////
// Contact Operations //
////////////////////////

int ClientController::ContactList(const std::string &pub_name,
                                  const SortingMode &sm,
                                  std::vector<maidsafe::Contact> *c_list) {
  if (!initialised_) {
#ifdef DEBUG
    printf("CC::ContactList - Not initialised.\n");
#endif
    return kClientControllerNotInitialised;
  }
  std::vector<maidsafe::mi_contact> mic_list;
  if (pub_name.empty()) {
    int n = ss_->GetContactList(&mic_list, sm);
    if (n != 0)
      return n;
  } else {
    maidsafe::mi_contact mic;
    int n = ss_->GetContactInfo(pub_name, &mic);
    if (n != 0)
      return n;
    mic_list.push_back(mic);
  }
  for (unsigned int a = 0; a < mic_list.size(); ++a) {
    Contact c;
    c.SetBirthday(mic_list[a].birthday_);
    c.SetCity(mic_list[a].city_);
    c.SetConfirmed(mic_list[a].confirmed_);
    c.SetCountry(mic_list[a].country_);
    c.SetFullName(mic_list[a].full_name_);
    c.SetGender(mic_list[a].gender_);
    c.SetLanguage(mic_list[a].language_);
    c.SetLastContact(mic_list[a].last_contact_);
    c.SetPublicKey(mic_list[a].pub_key_);
    c.SetOfficePhone(mic_list[a].office_phone_);
    c.SetPublicName(mic_list[a].pub_name_);
    c.SetRank(mic_list[a].rank_);
    c_list->push_back(c);
  }
  return 0;
}

int ClientController::AddContact(const std::string &public_name) {
  if (!initialised_) {
#ifdef DEBUG
    printf("CC::AddContact - Not initialised.\n");
#endif
    return kClientControllerNotInitialised;
  }
  std::string public_key;
  int result = auth_.PublicUsernamePublicKey(public_name, &public_key);
  if (result != kSuccess) {
#ifdef DEBUG
    printf("Couldn't find contact's public key.\n");
#endif
    return -221;
  }

  // Sending the request to add the contact
  // TODO(Richard): the info is empty because there is no way
  // to get the users contact data

  InstantMessage im;
  ContactNotification *cn = im.mutable_contact_notification();
  ContactInfo *info = cn->mutable_contact();

  info->set_name("Mock");
  info->set_birthday("Today");
  info->set_office_number("0987456321");
  info->set_gender("F");
  info->set_country(22);
  info->set_city("Troon");
  info->set_language(7);

  cn->set_action(0);

  im.set_sender(ss_->PublicUsername());
  im.set_date(base::get_epoch_time());
  std::string message("\"");
  message += im.sender() + "\" has requested to add you as a contact.";
  im.set_message(message);

  std::string ser_im;
  im.SerializeToString(&ser_im);

  maidsafe::Contact c;
  c.SetPublicName(public_name);
  c.SetPublicKey(public_key);
  c.SetConfirmed('U');
  if (ss_->AddContact(public_name, public_key, "", "", "", '-', -1,
         -1, "", 'U', 0, 0) != 0) {
#ifdef DEBUG
    printf("ClientController::AddContact - Failed to add contact to session\n");
#endif
    return -2;
  }

  std::string bpinfo = GenerateBPInfo();
  if (bpinfo.empty()) {
#ifdef DEBUG
    printf("ClientController::AddContact - BPInfo is empty\n");
#endif
    return -22;
  }
  if (sm_->ModifyBPInfo(bpinfo) != kSuccess) {
#ifdef DEBUG
    printf("ClientController::AddContact - Failed to modify BPInfo\n");
#endif
    return -222;
  }

  std::vector<std::string> contact_names;
  contact_names.push_back(public_name);
  if (sm_->AddBPMessage(contact_names, ser_im, ADD_CONTACT_RQST) !=
      kSuccess) {
#ifdef DEBUG
    printf("ClientController::AddContact - Failed to send request\n");
#endif
    return -2222;
  }

  return 0;
}

int ClientController::DeleteContact(const std::string &public_name) {
  if (!initialised_) {
#ifdef DEBUG
    printf("CC::DeleteContact - Not initialised.\n");
#endif
    return kClientControllerNotInitialised;
  }
  // TODO(Richard): Maybe it would be good to send a message for the other
  //                user's GUI to know to change the status of the contact.
  std::set<std::string> s;
  s.insert(public_name);

  InstantMessage im;
  ContactNotification *cn = im.mutable_contact_notification();
  cn->set_action(2);

  std::string deletion_msg(base::itos(base::get_epoch_nanoseconds()));
  deletion_msg += " deleted " + public_name + " update " +
    ss_->PublicUsername();
#ifdef DEBUG
  printf("MSG: %s\n", deletion_msg.c_str());
#endif
  im.set_date(base::get_epoch_milliseconds());
  im.set_message(deletion_msg);
  im.set_sender(ss_->PublicUsername());
  std::string ser_im;
  im.SerializeToString(&ser_im);

  std::vector<std::string> contact_names;
  contact_names.push_back(public_name);
  if (sm_->AddBPMessage(contact_names, ser_im, ADD_CONTACT_RQST) !=
      kSuccess) {
#ifdef DEBUG
    printf("ClientController::DeleteContact - Failed to send deletion msg\n");
#endif
    return -504;
  }

  int n = ss_->DeleteContact(public_name);
  if (n != 0) {
#ifdef DEBUG
    printf("ClientController::DeleteContact - Failed session delete.\n");
#endif
    return -504;
  }

  std::string bpinfo = GenerateBPInfo();
  if (bpinfo.empty()) {
#ifdef DEBUG
    printf("ClientController::DeleteContact - BPInfo is empty\n");
#endif
    return -504;
  }
  if (sm_->ModifyBPInfo(bpinfo) != kSuccess) {
#ifdef DEBUG
    printf("ClientController::DeleteContact - Failed to save new BPInfo\n");
#endif
    return -504;
  }

  return 0;
}

std::string ClientController::GenerateBPInfo() {
  std::vector<std::string> contacts;
  if (ss_->GetPublicUsernameList(&contacts) != 0)
    return "";
  BufferPacketInfo bpi;
  bpi.set_owner("a pile of shit");
  bpi.set_ownerpublickey("public key belonging to the pile of shit");
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  for (size_t n = 0; n < contacts.size(); ++n) {
    bpi.add_users(co.Hash(contacts[n], "", crypto::STRING_STRING, false));
  }
  std::string ser_bpi;
  bpi.SerializeToString(&ser_bpi);
  return ser_bpi;
}

//////////////////////
// Share Operations //
//////////////////////

int ClientController::GetShareList(std::list<maidsafe::PrivateShare> *ps_list,
                                   const SortingMode &sm,
                                   const ShareFilter &sf,
                                   const std::string &value) {
  if (!initialised_) {
#ifdef DEBUG
    printf("CC::GetShareList - Not initialised.\n");
#endif
    return kClientControllerNotInitialised;
  }
  int n = 0;
  if (value.empty()) {
    n = ss_->GetFullShareList(sm, sf, ps_list);
  } else {
    PrivateShare ps;
    n = ss_->GetShareInfo(value, 0,  &ps);
    if (n != 0)
      return n;
    ps_list->push_back(ps);
  }
  return n;
}

int ClientController::ShareList(const SortingMode &sm, const ShareFilter &sf,
    std::list<std::string> *share_list) {
  std::list<maidsafe::private_share> ps_list;
  int n = ss_->GetShareList(&ps_list, sm, sf);
  if (n != 0)
    return n;
  while (!ps_list.empty()) {
    share_list->push_back(ps_list.front().name_);
    ps_list.pop_front();
  }
  return 0;
}

int ClientController::GetSortedShareList(
                                  std::list<maidsafe::private_share> *ps_list,
                                  const SortingMode &sm,
                                  const std::string &value) {
  if (!initialised_) {
#ifdef DEBUG
    printf("CC::GetShareList - Not initialised.\n");
#endif
    return kClientControllerNotInitialised;
  }
  int n = 0;
  if (value.empty()) {
    n = ss_->GetShareList(ps_list, sm, kAll);
  }
  return n;
}

int ClientController::CreateNewShare(const std::string &name,
                      const std::set<std::string> &admins,
                      const std::set<std::string> &readonlys) {
  if (!initialised_) {
#ifdef DEBUG
    printf("CC::CreateNewShare - Not initialised.\n");
#endif
    return kClientControllerNotInitialised;
  }
  if (ss_->ConnectionStatus() == 1) {
#ifdef DEBUG
    printf("Can't send a message while off-line.\n");
#endif
    return -30008;
  }
  CC_CallbackResult cbr;
  auth_.CreateMSIDPacket(boost::bind(&CC_CallbackResult::CallbackFunc,
                          &cbr, _1));
  WaitForResult(cbr);
  CreateMSIDResult cmsidr;
  if (!cmsidr.ParseFromString(cbr.result)) {
    printf("Result doesn't parse.\n");
    return -30001;
  }
  if (cmsidr.result() == kNack) {
    printf("The creation of the MSID failed.\n");
    return -30002;
  }

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
  std::vector<std::string> admin_recs;
  std::set<std::string>::iterator it;
  for (it = admins.begin(); it != admins.end(); ++it) {
    std::vector<maidsafe::Contact> c_list;
    maidsafe::mi_contact mic;
    int n = ss_->GetContactInfo(*it, &mic);
    if (n == 0) {
      maidsafe::ShareParticipants sp;
      sp.id = *it;
      sp.public_key = mic.pub_key_;
      sp.role = 'A';
      participants.push_back(sp);
      parts.push_back(sp);
    }
    admin_recs.push_back(*it);
  }
  std::vector<std::string> ro_recs;
  for (it = readonlys.begin(); it != readonlys.end(); ++it) {
    std::vector<maidsafe::Contact> c_list;
    maidsafe::mi_contact mic;
    int n = ss_->GetContactInfo(*it, &mic);
    if (n == 0) {
      maidsafe::ShareParticipants sp;
      sp.id = *it;
      sp.public_key = mic.pub_key_;
      sp.role = 'R';
      participants.push_back(sp);
      parts.push_back(sp);
    }
    ro_recs.push_back(*it);
  }

  std::vector<boost::uint32_t> share_stats(2, 0);
  int n = ss_->AddPrivateShare(attributes, share_stats, &participants);
  if (n != 0)
    return n;

  // Create directory in Shares/Private and get its dir key
  std::string share_path("Shares/Private/" + name);
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
  InstantMessage im;
  PrivateShareNotification *psn =
      im.mutable_privateshare_notification();
  psn->set_name(name);
  psn->set_msid(cmsidr.name());
  psn->set_public_key(cmsidr.public_key());
  psn->set_dir_db_key(share_dir_key);
  im.set_sender(ss_->PublicUsername());
  im.set_date(base::get_epoch_time());
  std::string message("\"");
  message += im.sender() + "\" has added you as a Read Only participant to"
             " share " + name;
  im.set_message(message);
  std::string share_message;
  im.SerializeToString(&share_message);

  if (ro_recs.size() > 0) {
    if (sm_->AddBPMessage(ro_recs, share_message, INSTANT_MSG) !=
        kSuccess) {
  #ifdef DEBUG
      printf("ClientController::CreateNewShare - Not all recepients got "
             "the message\n");
  #endif
      return -22;
    }
  }

  // Send to ADMINS
  if (admin_recs.size() > 0) {
    std::string *me = psn->add_admins();
    *me = ss_->PublicUsername();
    psn->set_private_key(cmsidr.private_key());
    message = std::string("\"");
    message += im.sender() + "\" has added you as an Administrator participant "
               "to share " + name;
    im.set_message(message);
    im.SerializeToString(&share_message);
    if (sm_->AddBPMessage(admin_recs, share_message, INSTANT_MSG) !=
        kSuccess) {
  #ifdef DEBUG
      printf("ClientController::CreateNewShare - Not all recepients got "
             "the message\n");
  #endif
      return -22;
    }
  }

  return 0;
}

//////////////////////
// Vault Operations //
//////////////////////

bool ClientController::PollVaultInfo(std::string *chunkstore,
                                     boost::uint64_t *offered_space,
                                     boost::uint64_t *free_space,
                                     std::string *ip,
                                     boost::uint32_t *port) {
  if (!initialised_) {
#ifdef DEBUG
    printf("CC::PollVaultInfo - Not initialised.\n");
#endif
    return false;
  }
  if (ss_->VaultIP() == "" || ss_->VaultPort() == 0) {
    if (!VaultContactInfo()) {
      return false;
    }
  }

  CC_CallbackResult cb;
  sm_->PollVaultInfo(boost::bind(&CC_CallbackResult::CallbackFunc, &cb, _1));
  WaitForResult(cb);

  if (cb.result == "FAIL") {
#ifdef DEBUG
    printf("ClientController::PollVaultInfo result FAIL.\n");
#endif
    return false;
  }

  VaultCommunication vc;
  if (!vc.ParseFromString(cb.result)) {
#ifdef DEBUG
    printf("ClientController::PollVaultInfo didn't parse.\n");
#endif
    return false;
  }

  *chunkstore = vc.chunkstore();
  *offered_space = vc.offered_space();
  *free_space = vc.free_space();
  *ip = vc.ip();
  *port = vc.port();

  if (!ss_->SetVaultIP(*ip) || !ss_->SetVaultPort(*port)) {
#ifdef DEBUG
    printf("ClientController::PollVaultInfo: putting values into session "
           "failed.\n");
#endif
    return false;
  }
  return true;
}

bool ClientController::VaultContactInfo() {
  if (!initialised_) {
#ifdef DEBUG
    printf("CC::VaultContactInfo - Not initialised.\n");
#endif
    return false;
  }
#ifdef LOCAL_PDVAULT
  ss_->SetVaultIP("192.168.1.7");
  ss_->SetVaultPort(55555);
  return true;
#endif

  CC_CallbackResult cbr;
  sm_->VaultContactInfo(boost::bind(&CC_CallbackResult::CallbackFunc,
                        &cbr, _1));
  WaitForResult(cbr);

  kad::FindNodeResult fnr;
  if (!fnr.ParseFromString(cbr.result) ||
      fnr.result() != kad::kRpcResultSuccess) {
#ifdef DEBUG
    printf("ClientController::VaultContactInfo: failed result.\n");
#endif
    return false;
  }

  kad::ContactInfo ci;
  if (!ci.ParseFromString(fnr.contact())) {
#ifdef DEBUG
    printf("ClientController::VaultContactInfo: failed parsing as contact.\n");
#endif
    return false;
  }

  if (!ss_->SetVaultIP(ci.ip()) || !ss_->SetVaultPort(ci.port())) {
#ifdef DEBUG
    printf("ClientController::VaultContactInfo: putting values into session "
           "failed.\n");
#endif
    return false;
  }
  return true;
}

OwnLocalVaultResult ClientController::SetLocalVaultOwned(
    const boost::uint32_t &port,
    const boost::uint64_t &space,
    const std::string &chunkstore_dir) const {
  bool callback_arrived = false;
  OwnLocalVaultResult result;
  sm_->SetLocalVaultOwned(ss_->PrivateKey(PMID), ss_->PublicKey(PMID),
      ss_->SignedPublicKey(PMID), port, chunkstore_dir, space,
      boost::bind(&ClientController::SetLocalVaultOwnedCallback,
      const_cast<ClientController*>(this), _1, _2, &callback_arrived, &result));
  while (!callback_arrived)
    boost::this_thread::sleep(boost::posix_time::milliseconds(50));
  return result;
}

void ClientController::SetLocalVaultOwnedCallback(
    const OwnLocalVaultResult &result,
    const std::string &pmid_name,
    bool *callback_arrived,
    OwnLocalVaultResult *res) {
  if (result == OWNED_SUCCESS) {
#ifdef DEBUG
    printf("ClientController::SetLocalVaultOwnedCallback %s -- %s\n",
           HexSubstr(ss_->Id(PMID)).c_str(), HexSubstr(pmid_name).c_str());
#endif
    if (pmid_name == ss_->Id(PMID)) {
      *res = result;
    } else {
      // FAILURE -- incorrect pmid name returned by the vault
      *res = INVALID_PMID_NAME;
    }
  } else {
    *res = result;
  }
  *callback_arrived = true;
}

bool ClientController::IsLocalVaultOwned() {
  return (LocalVaultOwned() != NOT_OWNED);
}

VaultStatus ClientController::LocalVaultOwned() const {
  VaultStatus result;
  bool callback_arrived = false;
  sm_->LocalVaultOwned(boost::bind(&ClientController::LocalVaultOwnedCallback,
      const_cast<ClientController*>(this), _1, &callback_arrived, &result));
  while (!callback_arrived)
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  return result;
}

void ClientController::LocalVaultOwnedCallback(const VaultStatus &result,
                                               bool *callback_arrived,
                                               VaultStatus *res) {
  *res = result;
  *callback_arrived = true;
}

///////////////////
// SE Operations //
///////////////////

int ClientController::BackupElement(const std::string &path,
                                    const DirType dir_type,
                                    const std::string &msid) {
  if (!initialised_) {
#ifdef DEBUG
    printf("CC::BackupElement - Not initialised.\n");
#endif
    return kClientControllerNotInitialised;
  }
  return seh_.EncryptFile(path, dir_type, msid);
}

int ClientController::RetrieveElement(const std::string &path) {
  if (!initialised_) {
#ifdef DEBUG
    printf("CC::RetrieveElement - Not initialised.\n");
#endif
    return kClientControllerNotInitialised;
  }
  int result = seh_.DecryptFile(path);
  return result;
}

int ClientController::RemoveElement(std::string path) {
  if (!initialised_) {
#ifdef DEBUG
    printf("CC::RemoveElement - Not initialised.\n");
#endif
    return kClientControllerNotInitialised;
  }
  boost::scoped_ptr<DataAtlasHandler> dah(new DataAtlasHandler());
  if (dah->RemoveElement(path))
    return -1;
  if (fs::exists(fsys_.FullMSPathFromRelPath(path)))
    fs::remove_all(fsys_.FullMSPathFromRelPath(path));
  return 0;
}

DirType ClientController::GetDirType(const std::string &path_) {
  std::string myfiles = base::TidyPath(kRootSubdir[0][0]);
//  std::string pub_shares = base::TidyPath(kSharesSubdir[1][0]);
  std::string priv_shares = base::TidyPath(kSharesSubdir[0][0]);
//  std::string anonymous_shares = base::TidyPath(kSharesSubdir[1][0]);
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
//  if (path_.compare(0, anonymous_shares.size(), anonymous_shares) == 0)
//    return ANONYMOUS;
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

      PrivateShare ps;
      int r = ss_->GetShareInfo(share_name, 0, &ps);
      if (r != 0) {
#ifdef DEBUG
        printf("No MSID for that share name.\n");
#endif
        return -30001;
      }
      *msid = ps.Msid();
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

int ClientController::GetDb(const std::string &orig_path,
                            DirType *dir_type,
                            std::string *msid) {
  std::string path = orig_path;
#ifdef DEBUG
  printf("\t\tCC::GetDb(%s)\n", orig_path.c_str());
#endif
  std::string db_path, parent_path, dir_key;
  if (path.size() <= 1) {  // i.e. root
    parent_path = path;
  } else {
    fs::path parent(path, fs::native);
    parent_path = parent.parent_path().string();
    if (parent_path == "")
      parent_path = "/";
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
  boost::scoped_ptr<DataAtlasHandler> dah(new DataAtlasHandler());
  dah->GetDbPath(path, CONNECT, &db_path);
  PathDistinction(parent_path, msid);
#ifdef DEBUG
  printf("\t\tMSID: %s\n", msid->c_str());
#endif

  if (fs::exists(db_path) && *msid == "") {
    *dir_type = GetDirType(parent_path);
    return 0;
  }
  if (dah->GetDirKey(parent_path, &dir_key)) {
#ifdef DEBUG
    printf("\t\tGetDirKey failed.\n");
#endif
    return -1;
  }
  bool overwrite = false;
  if (*msid == "") {
    *dir_type = GetDirType(parent_path);
  } else {
    *dir_type = GetDirType(path);
    overwrite = true;
  }
  if (seh_.DecryptDb(parent_path, *dir_type, "", dir_key,
      *msid, true, overwrite)) {
#ifdef DEBUG
    printf("\t\tFailed trying to decrypt dm of parent(%s) db - dir key: %s\n",
           parent_path.c_str(), HexSubstr(dir_key).c_str());
#endif
    return -1;
  }
  return 0;
}

int ClientController::SaveDb(const std::string &db_path,
                             const DirType dir_type,
                             const std::string &msid,
                             const bool &immediate_save) {
#ifdef DEBUG
  printf("\t\tCC::SaveDb %s with MSID = %s\n", db_path.c_str(), msid.c_str());
#endif
  std::string parent_path_(""), dir_key_("");
  fs::path temp_(db_path);
  parent_path_ = temp_.parent_path().string();
  if (parent_path_ == "\\" ||
      parent_path_ == "/" ||
      parent_path_ == base::TidyPath(kRootSubdir[1][0]))
    return 0;
  boost::scoped_ptr<DataAtlasHandler> dah_(new DataAtlasHandler());
  if (dah_->GetDirKey(parent_path_, &dir_key_))
    // yields dir key for parent of path_
    return -errno;
  if (!immediate_save) {
    std::pair<std::string, std::string> key_and_msid_(dir_key_, msid);
    db_enc_queue_.insert(std::pair<std::string,
                                   std::pair<std::string, std::string> >
                                       (parent_path_, key_and_msid_));
//    if (db_enc_queue_.size() > kSaveUpdatesTrigger)
    RunDbEncQueue();
    return 0;
  } else {
    DataMap dm;
    if (seh_.EncryptDb(parent_path_, dir_type, dir_key_, msid, true, &dm) != 0)
      return -errno;
  }
    return 0;
}

int ClientController::RemoveDb(const std::string &path) {
#ifdef DEBUG
  printf("\t\tCC::RemoveDb %s\n", path.c_str());
#endif
  std::string parent_path, dir_key;
  fs::path temp(path);
  parent_path = temp.parent_path().string();
  if (parent_path == "\\"||
      parent_path == "/"||
      parent_path == base::TidyPath(kRootSubdir[1][0]))
    return 0;
  boost::scoped_ptr<DataAtlasHandler> dah(new DataAtlasHandler());
  std::string dbpath;
  dah->GetDbPath(path, CREATE, &dbpath);
  try {
    fs::remove_all(dbpath);
  }
  catch(const std::exception &exception) {
#ifdef DEBUG
    printf("%s\n", exception.what());
#endif
  }
  db_enc_queue_.erase(path);
  return 0;
}

int ClientController::RunDbEncQueue() {
  if (!initialised_) {
#ifdef DEBUG
    printf("CC::RunDbEncQueue - Not initialised.\n");
#endif
    return kClientControllerNotInitialised;
  }
  std::map<std::string, std::pair<std::string, std::string> >::iterator it;
  int result = 0;
#ifdef DEBUG
  printf("CC::RunDbEncQueue - before running the whole list %d\n",
          db_enc_queue_.size());
#endif
  for (it = db_enc_queue_.begin(); it != db_enc_queue_.end(); ++it) {
    DataMap dm;
    DirType db_type = GetDirType((*it).first);
#ifdef DEBUG
    printf("\t\tCC::RunDbEncQueue: first: %s\ttype: %i\tsec.first: %s\t",
          HexSubstr((*it).first).c_str(), db_type,
          HexSubstr((*it).second.first).c_str());
    printf("sec.second: %s\n", HexSubstr((*it).second.second).c_str());
#endif
    int int_res = seh_.EncryptDb((*it).first, db_type, (*it).second.first,
                                  (*it).second.second, true, &dm);
#ifdef DEBUG
    printf(" with result %i\n", int_res);
#endif
    if (int_res != -2)
      result += int_res;
  }
  printf("CC::RunDbEncQueue - after running the whole list %d\n", result);
  db_enc_queue_.clear();
  if (result)
    return -1;
  else
    return 0;
}

bool ClientController::ReadOnly(const std::string &path, bool gui) {
  if (!initialised_) {
#ifdef DEBUG
    printf("CC::ReadOnly - Not initialised.\n");
#endif
    return true;
  }
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
      std::string pub_key(""), priv_key("");
      int result = ss_->GetShareKeys(msid, &pub_key, &priv_key);
      if (result != 0) {
#ifdef DEBUG
        printf("Private share doesn't exist.\n");
#endif
        return true;
      }
      if (priv_key == "") {
#ifdef DEBUG
        printf("No priv key. Not admin. Readonly. Feck off.\n");
#endif
        return true;
      }
#ifdef DEBUG
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
  if (!initialised_) {
#ifdef DEBUG
    printf("CC::RunDbEncQueue - Not initialised.\n");
#endif
    return 'c';
  }
  for (char drive = 'm'; drive <= 'z'; ++drive) {
    std::ostringstream oss;
    oss << drive;
    std::string dr = oss.str();
    dr += ":";
    bool exists = true;
    try {
      exists = fs::exists(dr);
    }
    catch(const std::exception &exception) {
#ifdef DEBUG
      printf("Error: %s\n", exception.what());
#endif
    }
    if (!exists) {
      return drive;
    }
  }
  return '!';
}

int ClientController::mkdir(const std::string &path) {
  if (!initialised_) {
#ifdef DEBUG
    printf("CC::mkdir - Not initialised.\n");
#endif
    return kClientControllerNotInitialised;
  }
#ifdef DEBUG
  printf("\t\tCC::mkdir %s\n", path.c_str());
#endif
  DirType dir_type;
  std::string msid("");
  if (GetDb(path, &dir_type, &msid)) {
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
  dir_type = GetDirType(path);
  if (!seh_.MakeElement(path, EMPTY_DIRECTORY, dir_type, msid, "")) {
#ifdef DEBUG
    printf("\t\tIn CC::mkdir, seh_.MakeElement(%s, EMPTY_DIRECTORY) failed\n",
           path.c_str());
#endif
    return -1;
  }

#ifdef DEBUG
  printf("MSID after MakeElement: %s -- type: %i\n", msid.c_str(), dir_type);
#endif
  fs::path pp(path);
  msid = "";
  PathDistinction(pp.parent_path().string(), &msid);
  dir_type = GetDirType(pp.parent_path().string());
#ifdef DEBUG
  printf("MSID after PathDis parent: %s. Path: %s -- type: %i\n", msid.c_str(),
    pp.parent_path().string().c_str(), dir_type);
#endif
  bool immediate_save = true;
  if (msid == "") {
    immediate_save = false;
//    dir_type = maidsafe::PRIVATE;
//  } else {
//    dir_type = maidsafe::PRIVATE_SHARE;
  }
  if (SaveDb(path, dir_type, msid, immediate_save)) {
#ifdef DEBUG
    printf("\t\tIn CC::mkdir, SaveDb(%s) failed.\n", path.c_str());
#endif
    return -1;
  }

  // need to save newly-created db also - do this by passing path
  // for (non-existent) element within new dir to SaveDb function
  fs::path imaginary_(path);
  imaginary_ /= "a";
  msid = "";
  PathDistinction(imaginary_.string(), &msid);
  dir_type = GetDirType(imaginary_.string());
#ifdef DEBUG
  printf("MSID after imaginary string: %s -- type: %i\n", msid.c_str(),
    dir_type);
#endif
  immediate_save = true;
  if (msid == "")
    immediate_save = false;
//  else
//    dir_type = maidsafe::PRIVATE_SHARE;

  if (SaveDb(imaginary_.string(), dir_type, msid, immediate_save)) {
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
  if (!initialised_) {
#ifdef DEBUG
    printf("CC::rename - Not initialised.\n");
#endif
    return kClientControllerNotInitialised;
  }
#ifdef DEBUG
  printf("\t\tCC::rename %s to %s\n", path.c_str(), path2.c_str());
#endif
  DirType dir_type;
  DirType db_type2;
  std::string msid("");
  std::string msid2("");
  if (GetDb(path, &dir_type, &msid) || GetDb(path2, &db_type2, &msid2)) {
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
    if (SaveDb(path, dir_type, msid, false)) {
#ifdef DEBUG
      printf("\t\tCC::rename failed to save the original db to queue.\n");
#endif
      return -1;
    }
  } else {
    if (SaveDb(path, dir_type, msid, true)) {
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
  if (!initialised_) {
#ifdef DEBUG
    printf("CC::rmdir - Not initialised.\n");
#endif
    return kClientControllerNotInitialised;
  }
#ifdef DEBUG
  printf("\t\tCC::rmdir %s\n", path.c_str());
#endif
  DirType dir_type;
  std::string msid("");
  if (GetDb(path, &dir_type, &msid))
    return -1;
  std::map<std::string, ItemType> children;
  boost::scoped_ptr<DataAtlasHandler> dah_(new DataAtlasHandler());
  dah_->ListFolder(path, &children);
  if (children.size())  // ie the dir is not empty
    return -1;
  if (RemoveElement(path))
    return -1;
  if (msid == "") {
    if (SaveDb(path, dir_type, msid, false)) {
#ifdef DEBUG
      printf("\t\tCC::rename failed to save the original db to queue.\n");
#endif
      return -1;
    }
  } else {
    if (SaveDb(path, dir_type, msid, true)) {
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
  if (!initialised_) {
#ifdef DEBUG
    printf("CC::getattr - Not initialised.\n");
#endif
    return kClientControllerNotInitialised;
  }
#ifdef DEBUG
  printf("\t\tCC::getattr %s\n", path.c_str());
#endif
  DirType dir_type;
  std::string msid("");
  if (GetDb(path, &dir_type, &msid))
    return -1;
  boost::scoped_ptr<DataAtlasHandler> dah_(new DataAtlasHandler());
  if (dah_->GetMetaDataMap(path, &ser_mdm))
    return -1;
  MetaDataMap mdm;
  mdm.ParseFromString(ser_mdm);
  return 0;
}

int ClientController::readdir(const std::string &path,  // NOLINT
                              std::map<std::string, ItemType> &children) {
  if (!initialised_) {
#ifdef DEBUG
    printf("CC::readdir - Not initialised.\n");
#endif
    return kClientControllerNotInitialised;
  }
#ifdef DEBUG
  printf("\t\tCC::readdir %s\n", path.c_str());
#endif
  DirType dir_type;
  std::string msid("");
  if (GetDb(path, &dir_type, &msid))
    return -1;
  boost::scoped_ptr<DataAtlasHandler> dah_(new DataAtlasHandler());
  if (dah_->ListFolder(path, &children))
    return -1;
  return 0;
}

int ClientController::mknod(const std::string &path) {
  if (!initialised_) {
#ifdef DEBUG
    printf("CC::mknod - Not initialised.\n");
#endif
    return kClientControllerNotInitialised;
  }
#ifdef DEBUG
  printf("\t\tCC::mknod %s\n", path.c_str());
#endif
  DirType dir_type;
  std::string msid("");
  if (GetDb(path, &dir_type, &msid))
    return -1;
#ifdef DEBUG
  printf("MSID after GetDb: %s\n", msid.c_str());
#endif

  if (!seh_.MakeElement(path, EMPTY_FILE, dir_type, msid, ""))
    return -1;
#ifdef DEBUG
  printf("MSID after MakeElement: %s\n", msid.c_str());
#endif
  if (msid != "") {
    if (SaveDb(path, dir_type, msid, true))
      return -1;
  } else {
    if (SaveDb(path, dir_type, msid, false))
      return -1;
  }
  return 0;
}

int ClientController::unlink(const std::string &path) {
  if (!initialised_) {
#ifdef DEBUG
    printf("CC::unlink - Not initialised.\n");
#endif
    return kClientControllerNotInitialised;
  }
#ifdef DEBUG
  printf("\t\tCC::unlink %s\n", path.c_str());
#endif
  DirType dir_type;
  std::string msid("");
  if (GetDb(path, &dir_type, &msid))
    return -1;
  if (RemoveElement(path))
    return -1;
  if (msid == "") {
    if (SaveDb(path, dir_type, msid, false)) {
#ifdef DEBUG
      printf("\t\tCC::rename failed to save the original db to queue.\n");
#endif
      return -1;
    }
  } else {
    if (SaveDb(path, dir_type, msid, true)) {
#ifdef DEBUG
      printf("\t\tCC::rename failed to save the original db immediately.\n");
#endif
      return -1;
    }
  }

  return 0;
}

int ClientController::link(const std::string &path, const std::string &path2) {
  if (!initialised_) {
#ifdef DEBUG
    printf("CC::link - Not initialised.\n");
#endif
    return kClientControllerNotInitialised;
  }
#ifdef DEBUG
  printf("\t\tCC::link %s to %s\n", path.c_str(), path2.c_str());
#endif
  DirType dir_type;
  DirType db_type2;
  std::string msid("");
  std::string msid2("");
  if (GetDb(path, &dir_type, &msid) || GetDb(path2, &db_type2, &msid2))
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
  if (!initialised_) {
#ifdef DEBUG
    printf("CC::cpdir - Not initialised.\n");
#endif
    return kClientControllerNotInitialised;
  }
#ifdef DEBUG
  printf("\t\tCC::cpdir %s to %s\n", path.c_str(), path2.c_str());
#endif
  DirType dir_type;
  DirType db_type2;
  std::string msid("");
  std::string msid2("");
  if (GetDb(path, &dir_type, &msid) || GetDb(path2, &db_type2, &msid2))
    return -1;
  std::string ms_old_rel_entry_ = path;
  std::string ms_new_rel_entry_ = path2;
  fs::path n_path(ms_new_rel_entry_, fs::native);

  std::string new_rel_root_ = n_path.parent_path().string();
  std::string new_dir_key_;
  seh_.GenerateUniqueKey(db_type2, msid2, 0, &new_dir_key_);
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
  // for (non-existent) element within new dir to SaveDb function
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
  if (!initialised_) {
#ifdef DEBUG
    printf("CC::utime - Not initialised.\n");
#endif
    return kClientControllerNotInitialised;
  }
#ifdef DEBUG
  printf("\t\tCC::utime %s\n", path.c_str());
#endif
  DirType dir_type;
  std::string msid("");
  if (GetDb(path, &dir_type, &msid))
    return -1;
  std::string thepath = path;
  boost::scoped_ptr<DataAtlasHandler> dah_(new DataAtlasHandler());
  if (dah_->ChangeMtime(thepath))
    return -1;
  if (msid == "") {
    if (SaveDb(path, dir_type, msid, false)) {
#ifdef DEBUG
      printf("\t\tCC::rename failed to save the original db to queue.\n");
#endif
      return -1;
    }
  } else {
    if (SaveDb(path, dir_type, msid, true)) {
#ifdef DEBUG
      printf("\t\tCC::rename failed to save the original db immediately.\n");
#endif
      return -1;
    }
  }
  return 0;
}

int ClientController::atime(const std::string &path) {
  if (!initialised_) {
#ifdef DEBUG
    printf("CC::atime - Not initialised.\n");
#endif
    return kClientControllerNotInitialised;
  }
#ifdef DEBUG
  printf("\t\tCC::atime %s\n", path.c_str());
#endif
  DirType dir_type;
  std::string msid("");
  if (GetDb(path, &dir_type, &msid))
    return -1;
  std::string thepath = path;
  boost::scoped_ptr<DataAtlasHandler> dah_(new DataAtlasHandler());
  if (dah_->ChangeAtime(thepath))
    return -1;
  // We're not saving the db everytime the access time changes. I said NO!
  // OK, maybe we'll make the following amendments
  if (msid == "") {
    if (SaveDb(path, dir_type, msid, false))
      return -1;
  }

  return 0;
}

int ClientController::open(const std::string &path) {
  if (!initialised_) {
#ifdef DEBUG
    printf("CC::open - Not initialised.\n");
#endif
    return kClientControllerNotInitialised;
  }
#ifdef DEBUG
  printf("\t\tCC::open %s\n", path.c_str());
#endif
  DirType dir_type;
  std::string msid("");
  if (GetDb(path, &dir_type, &msid))
    return -1;
  return RetrieveElement(path);
}

int ClientController::read(const std::string &path) {
  if (!initialised_) {
#ifdef DEBUG
    printf("CC::read - Not initialised.\n");
#endif
    return kClientControllerNotInitialised;
  }
#ifdef DEBUG
  printf("\t\tCC::read %s\n", path.c_str());
#endif
  DirType dir_type;
  std::string msid("");
  if (GetDb(path, &dir_type, &msid))
    return -1;
  return RetrieveElement(path);
}

int ClientController::write(const std::string &path) {
  if (!initialised_) {
#ifdef DEBUG
    printf("CC::write - Not initialised.\n");
#endif
    return kClientControllerNotInitialised;
  }
#ifdef DEBUG
  printf("\t\tCC::write %s\n", path.c_str());
#endif
  DirType dir_type;
  std::string msid("");
  if (GetDb(path, &dir_type, &msid)) {
#ifdef DEBUG
    printf("\t\tCC::write GetDb failed.\n");
#endif
    return -1;
  }
  if (BackupElement(path, dir_type, msid)) {
#ifdef DEBUG
    printf("\t\tCC::write BackupElement failed.\n");
#endif
    return -1;
  }
  bool immediate = false;
  if (msid != "")
    immediate = true;
  if (SaveDb(path, dir_type, msid, immediate)) {
#ifdef DEBUG
    printf("\t\tCC::write SaveDb failed.\n");
#endif
    return -1;
  }
  return 0;
}

int ClientController::create(const std::string &path) {
  if (!initialised_) {
#ifdef DEBUG
    printf("CC::create - Not initialised.\n");
#endif
    return kClientControllerNotInitialised;
  }
#ifdef DEBUG
  printf("\t\tCC::create %s\n", path.c_str());
#endif
  return mknod(path);
}

///////////////////////////////
// Here endeth FUSE stuff !! //
///////////////////////////////

}  // namespace maidsafe
