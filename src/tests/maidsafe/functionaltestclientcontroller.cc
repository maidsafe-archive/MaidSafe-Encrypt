/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Functional tests for Client Controller operations
* Version:      1.0
* Created:      2009-01-29-02.29.46
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

#include <list>
#include <map>
#include <vector>

#include "boost/bind.hpp"
#include "boost/filesystem/fstream.hpp"
#include "boost/progress.hpp"
#include "boost/thread/thread.hpp"
#include "gtest/gtest.h"

#include "maidsafe/crypto.h"
#include "maidsafe/utils.h"
#include "fs/filesystem.h"
#include "maidsafe/client/clientcontroller.h"
#include "maidsafe/client/selfencryption.h"
#include "maidsafe/vault/pdvault.h"
#include "protobuf/datamaps.pb.h"
#include "protobuf/general_messages.pb.h"
#include "protobuf/maidsafe_service_messages.pb.h"


namespace fs = boost::filesystem;

namespace maidsafe_vault {

void GeneratePmidStuff(std::string *public_key,
                       std::string *private_key,
                       std::string *signed_key,
                       std::string *pmid) {
  crypto::Crypto co_;
  co_.set_hash_algorithm(crypto::SHA_512);
  crypto::RsaKeyPair keys;
  keys.GenerateKeys(packethandler::kRsaKeySize);
  *signed_key = co_.AsymSign(keys.public_key(), "", keys.private_key(),
    crypto::STRING_STRING);
  *public_key = keys.public_key();
  *private_key = keys.private_key();
  *pmid = co_.Hash(*signed_key, "", crypto::STRING_STRING, true);
};

class RunPDVaults {
 public:
  RunPDVaults(const int &no_of_vaults,
              const std::string &test_dir)
//              const std::string &bootstrap_id,
//              const std::string &bootstrap_ip,
//              const boost::uint16_t &bootstrap_port)
      : no_of_vaults_(no_of_vaults),
        test_dir_(test_dir),
//        bootstrap_id_(bootstrap_id),
//        bootstrap_ip_(bootstrap_ip),
//        bootstrap_port_(bootstrap_port),
        kad_config_(),
        chunkstore_dir_(test_dir_+"/Chunkstores"),
        datastore_dir_(test_dir_+"/Datastores"),
//        kad_config_file_(datastore_dir_+"/.kadconfig"),
        kad_config_file_(""),
        chunkstore_dirs_(),
        crypto_(),
        pdvaults_(new std::vector< boost::shared_ptr<PDVault> >),
        current_nodes_created_(0),
        mutex_() {
//        bootstrap_file_prepared_(false) {
    fs::path temp_(test_dir_);
    try {
      if (fs::exists(temp_))
        fs::remove_all(temp_);
      if (fs::exists(".kadconfig"))
        fs::remove(".kadconfig");
    }
    catch(const std::exception &e) {
      printf("%s\n", e.what());
    }
    fs::create_directories(datastore_dir_);
    fs::create_directories(chunkstore_dir_);
    crypto_.set_hash_algorithm(crypto::SHA_512);
    crypto_.set_symm_algorithm(crypto::AES_256);
  }

  ~RunPDVaults() {
    fs::path temp_(test_dir_);
    try {
      if (fs::exists(temp_))
        fs::remove_all(temp_);
    }
    catch(const std::exception &e) {
      printf("%s\n", e.what());
    }
  }

  void SetUp() {
//      bootstrap_file_prepared_ = false;
//      if (bootstrap_id_ != "") {
//        kad_config_.Clear();
//        base::KadConfig::Contact *kad_contact_ = kad_config_.add_contact();
//  //      std::string bin_id_("");
//  //      std::string bin_ip_("");
//  //      base::decode_from_hex(bootstrap_id_, &bin_id_);
//  //      base::decode_from_hex(bootstrap_ip_, &bin_ip_);
//        kad_contact_->set_node_id(bootstrap_id_);
//        kad_contact_->set_ip(bootstrap_ip_);
//        kad_contact_->set_port(bootstrap_port_);
//        // Save kad_config to file
//        std::fstream output_(kad_config_file_.c_str(),
//          std::ios::out | std::ios::trunc | std::ios::binary);
//        ASSERT_TRUE(kad_config_.SerializeToOstream(&output_));
//        output_.close();
//        bootstrap_file_prepared_ = true;
//  //      printf("\nIn bootstrap ip: %s, port: %d\n",
//  //             kad_contact_->ip().c_str(),
//  //             kad_contact_->port());
//      }
    // Construct and start vaults
    for (int i = 0; i < no_of_vaults_; ++i) {
      std::string chunkstore_local_ = chunkstore_dir_+"/Chunkstore"+
          base::itos(64101+i);
      fs::path chunkstore_local_path_(chunkstore_local_, fs::native);
      chunkstore_dirs_.push_back(chunkstore_local_path_);
      std::string datastore_local_ = datastore_dir_+"/Datastore"+
          base::itos(64101+i);
      std::string public_key_(""), private_key_(""), signed_key_("");
      std::string node_id_("");
      GeneratePmidStuff(&public_key_,
                        &private_key_,
                        &signed_key_,
                        &node_id_);
      ASSERT_TRUE(crypto_.AsymCheckSig(public_key_, signed_key_, public_key_,
                                       crypto::STRING_STRING));
      kad_config_file_ = datastore_local_ + "/.kadconfig";
      boost::shared_ptr<PDVault>
          pdvault_local_(new PDVault(public_key_,
                                     private_key_,
                                     signed_key_,
                                     chunkstore_local_,
                                     datastore_local_,
                                     64101+i,
                                     kad_config_file_));
      pdvaults_->push_back(pdvault_local_);
      ++current_nodes_created_;
      bool port_forwarded = false;
      pdvault_local_->Start(port_forwarded);
      printf(".");
//      if (i == 0 && !bootstrap_file_prepared_) {
      if (i == 0) {
        // Make the first vault as bootstrapping node
        kad_config_.Clear();
        base::KadConfig::Contact *kad_contact_ = kad_config_.add_contact();
//        std::string bin_id_("");
//        std::string bin_ip_("");
//        base::decode_from_hex(pdvault_local_->node_id(), &bin_id_);
//        base::decode_from_hex(pdvault_local_->host_ip(), &bin_ip_);
        kad_contact_->set_node_id(pdvault_local_->node_id());
        kad_contact_->set_ip(pdvault_local_->host_ip());
        kad_contact_->set_port(pdvault_local_->host_port());
        kad_contact_->set_local_ip(pdvault_local_->local_host_ip());
        kad_contact_->set_local_port(pdvault_local_->local_host_port());
//        printf("In kadcontact host ip: %s, host port: %d\n",
//          kad_contact_->ip().c_str(),
//          kad_contact_->port());
        // Save kad_config to files
        for (int k = 1; k < no_of_vaults_; ++k) {
          std::string dir = datastore_dir_+"/Datastore"+ base::itos(64101+k);
          fs::create_directories(dir);
          kad_config_file_ = datastore_dir_+"/Datastore"+ base::itos(64101+k) +
              "/.kadconfig";
          std::fstream output_(kad_config_file_.c_str(),
            std::ios::out | std::ios::trunc | std::ios::binary);
          ASSERT_TRUE(kad_config_.SerializeToOstream(&output_));
          output_.close();
        }
        kad_config_file_ = ".kadconfig";
        std::fstream output_(kad_config_file_.c_str(),
          std::ios::out | std::ios::trunc | std::ios::binary);
        ASSERT_TRUE(kad_config_.SerializeToOstream(&output_));
        output_.close();
      }
    }
    printf("\n");
  }

  void TearDown() {
    bool success_(false);
    for (int i = 0; i < no_of_vaults_; ++i) {
      success_ = false;
      (*(pdvaults_))[i]->Stop();
      for (int j = 0; j < 6000; ++j) {
        if (!(*(pdvaults_))[i]->vault_started()) {
          success_ = true;
          break;
        }
        boost::this_thread::sleep(boost::posix_time::milliseconds(10));
      }
      if (success_)
        printf("\tVault %i stopped.\n", i+1);
      else
        printf("\tVault %i failed to stop correctly.\n", i+1);
      (*(pdvaults_))[i].reset();
    }
  }

 private:
  RunPDVaults(const RunPDVaults&);
  RunPDVaults &operator=(const RunPDVaults&);
  const int no_of_vaults_;
  std::string test_dir_;
//  std::string bootstrap_id_;
//  std::string bootstrap_ip_;
//  boost::uint16_t bootstrap_port_;
  base::KadConfig kad_config_;
  std::string chunkstore_dir_, datastore_dir_, kad_config_file_;
  std::vector<fs::path> chunkstore_dirs_;
  crypto::Crypto crypto_;
  boost::shared_ptr< std::vector< boost::shared_ptr<PDVault> > > pdvaults_;
  int current_nodes_created_;
  boost::mutex mutex_;
//  bool bootstrap_file_prepared_;
};

}  // namespace maidsafe_vault

namespace maidsafe {

class FakeCallback {
 public:
  FakeCallback() : result("") {}
  void CallbackFunc(const std::string &res) {
    result = res;
  }
  void Reset() {
    result = "";
  }
  std::string result;
};

class FunctionalMaidsafeClientControllerTest : public testing::Test {
 protected:
  FunctionalMaidsafeClientControllerTest() : cc(),
                                             authentication(),
                                             ss(),
                                             se(),
                                             dir1_(""),
                                             dir2_(""),
                                             final_dir_(),
                                             cb() {}

  static void SetUpTestCase() {
    shared_vaults_ = new maidsafe_vault::RunPDVaults(10, "CCTest"
                     /*, "", "", 0*/);
    shared_vaults_->SetUp();
  }

  static void TearDownTestCase() {
    shared_vaults_->TearDown();
    delete shared_vaults_;
    shared_vaults_ = 0;
  }

  void SetUp() {
    try {
      if (fs::exists("KademilaDb.db"))
        fs::remove(fs::path("KademilaDb.db"));
      if (fs::exists("StoreChunks"))
        fs::remove_all("StoreChunks");
      if (fs::exists("KademilaDb.db"))
        printf("Kademila.db still there\n");
      if (fs::exists("StoreChunks"))
        printf("StoreChunks still there\n");
    }
    catch(const std::exception &e) {
      printf("Error: %s\n", e.what());
    }
    cc = ClientController::getInstance();
    ASSERT_TRUE(cc->JoinKademlia());
    ASSERT_TRUE(cc->Init());
  }

  void TearDown() {
    boost::this_thread::sleep(boost::posix_time::seconds(10));
    cc->CloseConnection();
    try {
      if (fs::exists("KademilaDb.db"))
        fs::remove(fs::path("KademilaDb.db"));
      if (fs::exists("StoreChunks"))
        fs::remove_all("StoreChunks");
      if (fs::exists("KademilaDb.db"))
        printf("Kademila.db still there\n");
      if (fs::exists("StoreChunks"))
        printf("StoreChunks still there\n");
      if (fs::exists(dir1_)) {
        // printf("Removing maidsafe directories.");
        fs::remove_all(dir1_);
      }
      if (fs::exists(dir2_))
        fs::remove_all(dir2_);
      if (final_dir_ != "" && fs::exists(final_dir_))
        fs::remove_all(final_dir_);
      if (fs::exists(dir1_))
        printf("dir1_ still there\n");
      if (fs::exists(dir2_))
        printf("dir2_ still there\n");
    }
    catch(const std::exception &e) {
      printf("Error: %s\n", e.what());
    }
  }

  ClientController *cc;
  Authentication *authentication;
  SessionSingleton *ss;
  SelfEncryption se;
  std::string dir1_, dir2_, final_dir_;
  FakeCallback cb;

  static maidsafe_vault::RunPDVaults *shared_vaults_;

 private:
  FunctionalMaidsafeClientControllerTest
      (const FunctionalMaidsafeClientControllerTest&);
  FunctionalMaidsafeClientControllerTest &operator=
      (const FunctionalMaidsafeClientControllerTest&);
};

maidsafe_vault::RunPDVaults
    *FunctionalMaidsafeClientControllerTest::shared_vaults_ = 0;

TEST_F(FunctionalMaidsafeClientControllerTest,
       FUNC_MAID_ControllerLoginSequence) {
  std::string username = "User1";
  std::string pin = "1234";
  std::string password = "The beagle has landed.";
  ss = SessionSingleton::getInstance();
  ASSERT_EQ("", ss->Username());
  ASSERT_EQ("", ss->Pin());
  ASSERT_EQ("", ss->Password());
  printf("Preconditions fulfilled.\n");

  exitcode result = cc->CheckUserExists(username,
                                        pin,
                                        boost::bind(
                                            &FakeCallback::CallbackFunc,
                                            &cb,
                                            _1),
                                        DEFCON3);
  ASSERT_EQ(NON_EXISTING_USER, result);
  ASSERT_TRUE(cc->CreateUser(username, pin, password));
  ASSERT_EQ(username, ss->Username());
  ASSERT_EQ(pin, ss->Pin());
  ASSERT_EQ(password, ss->Password());
  printf("User created.\n");

  ASSERT_TRUE(cc->Logout());
  ASSERT_EQ("", ss->Username());
  ASSERT_EQ("", ss->Pin());
  ASSERT_EQ("", ss->Password());
  printf("Logged out.\n");

  result = cc->CheckUserExists(username,
                               pin,
                               boost::bind(&FakeCallback::CallbackFunc,
                                           &cb,
                                           _1),
                               DEFCON3);
  ASSERT_EQ(USER_EXISTS, result);
  boost::this_thread::sleep(boost::posix_time::seconds(10));
  GetResponse load_res;
  ASSERT_TRUE(load_res.ParseFromString(cb.result));
  ASSERT_EQ(kCallbackSuccess, load_res.result());
  ASSERT_TRUE(cc->ValidateUser(password));
  ASSERT_EQ(username, ss->Username());
  ASSERT_EQ(pin, ss->Pin());
  ASSERT_EQ(password, ss->Password());
  printf("Logged in.\n");

  ASSERT_TRUE(cc->Logout());
  ASSERT_EQ("", ss->Username());
  ASSERT_EQ("", ss->Pin());
  ASSERT_EQ("", ss->Password());
  printf("Logged out.\n");

  cb.Reset();
  result = cc->CheckUserExists("juan.smer",
                               pin,
                               boost::bind(&FakeCallback::CallbackFunc,
                                           &cb,
                                           _1),
                               DEFCON3);
  ASSERT_EQ(NON_EXISTING_USER, result);
  printf("Can't log in with fake details.\n");
}

TEST_F(FunctionalMaidsafeClientControllerTest,
       FUNC_MAID_ControllerChangeDetails) {
  std::string username = "User2";
  std::string pin = "2345";
  std::string password = "The axolotl has landed.";
  ss = SessionSingleton::getInstance();
  ASSERT_EQ("", ss->Username());
  ASSERT_EQ("", ss->Pin());
  ASSERT_EQ("", ss->Password());
  printf("Preconditions fulfilled.\n");

  exitcode result = cc->CheckUserExists(username,
                                        pin,
                                        boost::bind(
                                            &FakeCallback::CallbackFunc,
                                            &cb,
                                            _1),
                                        DEFCON3);
  ASSERT_EQ(NON_EXISTING_USER, result);
  ASSERT_TRUE(cc->CreateUser(username, pin, password));
  ASSERT_EQ(username, ss->Username());
  ASSERT_EQ(pin, ss->Pin());
  ASSERT_EQ(password, ss->Password());
  printf("User created.\n");

//  ASSERT_TRUE(cc->Logout());
//  ASSERT_EQ("", ss->Username());
//  ASSERT_EQ("", ss->Pin());
//  ASSERT_EQ("", ss->Password());
//  printf("Logged out.\n");
//
//  exitcode result = cc->CheckUserExists(username,
//                                        pin,
//                                      boost::bind(&FakeCallback::CallbackFunc,
//                                                    &cb,
//                                                    _1),
//                                        DEFCON3);
//  ASSERT_EQ(USER_EXISTS, result);
//  boost::this_thread::sleep(boost::posix_time::seconds(10));
//  GetResponse load_res;
//  ASSERT_TRUE(load_res.ParseFromString(cb.result));
//  ASSERT_EQ(kCallbackSuccess, load_res.result());
//  std::list<std::string> list;
//  ASSERT_TRUE(cc->ValidateUser(password, &list));
//  ASSERT_EQ(username, ss->Username());
//  ASSERT_EQ(pin, ss->Pin());
//  ASSERT_EQ(password, ss->Password());
//  printf("Logged in.\n");

  ASSERT_TRUE(cc->ChangeUsername("juan.smer"));
  ASSERT_EQ("juan.smer", ss->Username());
  ASSERT_EQ(pin, ss->Pin());
  ASSERT_EQ(password, ss->Password());
  printf("Changed username.\n");

  ASSERT_TRUE(cc->Logout());
  ASSERT_EQ("", ss->Username());
  ASSERT_EQ("", ss->Pin());
  ASSERT_EQ("", ss->Password());
  printf("Logged out.\n");

  result = cc->CheckUserExists("juan.smer",
                               pin,
                               boost::bind(&FakeCallback::CallbackFunc,
                                           &cb,
                                           _1),
                               DEFCON3);
  ASSERT_EQ(USER_EXISTS, result);
  boost::this_thread::sleep(boost::posix_time::seconds(10));
  GetResponse load_res;
  ASSERT_TRUE(load_res.ParseFromString(cb.result));
  ASSERT_EQ(kCallbackSuccess, load_res.result());
  ASSERT_TRUE(cc->ValidateUser(password));
  ASSERT_EQ("juan.smer", ss->Username());
  ASSERT_EQ(pin, ss->Pin());
  ASSERT_EQ(password, ss->Password());
  printf("Logged in.\n");
  file_system::FileSystem fsys_;
  dir1_ = fsys_.MaidsafeDir();

  ASSERT_TRUE(cc->ChangePin("2207"));
  ASSERT_EQ("juan.smer", ss->Username());
  ASSERT_EQ("2207", ss->Pin());
  ASSERT_EQ(password, ss->Password());
  printf("Changed pin.\n");

  ASSERT_TRUE(cc->Logout());
  ASSERT_EQ("", ss->Username());
  ASSERT_EQ("", ss->Pin());
  ASSERT_EQ("", ss->Password());
  printf("Logged out.\n");

  result = cc->CheckUserExists("juan.smer",
                               "2207",
                               boost::bind(&FakeCallback::CallbackFunc,
                                           &cb,
                                           _1),
                               DEFCON3);
  ASSERT_EQ(USER_EXISTS, result);
  boost::this_thread::sleep(boost::posix_time::seconds(10));
  load_res.Clear();
  ASSERT_TRUE(load_res.ParseFromString(cb.result));
  ASSERT_EQ(kCallbackSuccess, load_res.result());
  ASSERT_TRUE(cc->ValidateUser(password));
  ASSERT_EQ("juan.smer", ss->Username());
  ASSERT_EQ("2207", ss->Pin());
  ASSERT_EQ(password, ss->Password());
  printf("Logged in.\n");
  dir2_ = fsys_.MaidsafeDir();

  ASSERT_TRUE(cc->ChangePassword("elpasguor"));
  ASSERT_EQ("juan.smer", ss->Username());
  ASSERT_EQ("2207", ss->Pin());
  ASSERT_EQ("elpasguor", ss->Password());
  printf("Changed password.\n");

  ASSERT_TRUE(cc->Logout());
  ASSERT_EQ("", ss->Username());
  ASSERT_EQ("", ss->Pin());
  ASSERT_EQ("", ss->Password());
  printf("Logged out.\n");

  result = cc->CheckUserExists("juan.smer",
                               "2207",
                               boost::bind(&FakeCallback::CallbackFunc,
                                           &cb,
                                           _1),
                               DEFCON3);
  ASSERT_EQ(USER_EXISTS, result);
  boost::this_thread::sleep(boost::posix_time::seconds(10));
  load_res.Clear();
  ASSERT_TRUE(load_res.ParseFromString(cb.result));
  ASSERT_EQ(kCallbackSuccess, load_res.result());
  std::string new_pwd("elpasguor");
  ASSERT_TRUE(cc->ValidateUser(new_pwd));
  ASSERT_EQ("juan.smer", ss->Username());
  ASSERT_EQ("2207", ss->Pin());
  ASSERT_EQ("elpasguor", ss->Password());
  printf("Logged in. New u/p/w.\n");

  ASSERT_TRUE(cc->Logout());
  ASSERT_EQ("", ss->Username());
  ASSERT_EQ("", ss->Pin());
  ASSERT_EQ("", ss->Password());
  printf("Logged out.\n");

  result = cc->CheckUserExists(username,
                               pin,
                               boost::bind(&FakeCallback::CallbackFunc,
                                           &cb,
                                           _1),
                               DEFCON3);
  ASSERT_EQ(NON_EXISTING_USER, result);

  result = cc->CheckUserExists("juan.smer",
                               "2207",
                               boost::bind(&FakeCallback::CallbackFunc,
                                           &cb,
                                           _1),
                               DEFCON3);
  ASSERT_EQ(USER_EXISTS, result);
  boost::this_thread::sleep(boost::posix_time::seconds(10));
  load_res.Clear();
  ASSERT_TRUE(load_res.ParseFromString(cb.result));
  ASSERT_EQ(kCallbackSuccess, load_res.result());
  ASSERT_FALSE(cc->ValidateUser(password))
    << "old details still work, damn it, damn the devil to hell";
  ss->ResetSession();
  ASSERT_EQ("", ss->Username());
  ASSERT_EQ("", ss->Pin());
  ASSERT_EQ("", ss->Password());
  printf("Can't log in with old u/p/w.\n");
}

TEST_F(FunctionalMaidsafeClientControllerTest,
       FUNC_MAID_ControllerCreatePublicUsername) {
  std::string username = "User3";
  std::string pin = "3456";
  std::string password = "The fanjeeta has landed.";
  ss = SessionSingleton::getInstance();
  ASSERT_EQ("", ss->Username());
  ASSERT_EQ("", ss->Pin());
  ASSERT_EQ("", ss->Password());
  printf("Preconditions fulfilled.\n");

  exitcode result = cc->CheckUserExists(username,
                                        pin,
                                        boost::bind(
                                            &FakeCallback::CallbackFunc,
                                            &cb,
                                            _1),
                                        DEFCON3);
  ASSERT_EQ(NON_EXISTING_USER, result);
  ASSERT_TRUE(cc->CreateUser(username, pin, password));
  ASSERT_EQ(username, ss->Username());
  ASSERT_EQ(pin, ss->Pin());
  ASSERT_EQ(password, ss->Password());
  printf("User created.\n");

//  ASSERT_TRUE(cc->Logout());
//  ASSERT_EQ("", ss->Username());
//  ASSERT_EQ("", ss->Pin());
//  ASSERT_EQ("", ss->Password());
//  printf("Logged out.\n");
//
//  exitcode result = cc->CheckUserExists(username,
//                                        pin,
//                                      boost::bind(&FakeCallback::CallbackFunc,
//                                                    &cb,
//                                                    _1),
//                                        DEFCON3);
//  ASSERT_EQ(USER_EXISTS, result);
//  boost::this_thread::sleep(boost::posix_time::seconds(10));
//  GetResponse load_res;
//  ASSERT_TRUE(load_res.ParseFromString(cb.result));
//  ASSERT_EQ(kCallbackSuccess, load_res.result());
//  std::list<std::string> list;
//  ASSERT_TRUE(cc->ValidateUser(password, &list));
//  ASSERT_EQ(username, ss->Username());
//  ASSERT_EQ(pin, ss->Pin());
//  ASSERT_EQ(password, ss->Password());
//  ASSERT_EQ("el.mambo.tonnnnnto", ss->PublicUsername());
//  printf("Logged in.\n");

  ASSERT_TRUE(cc->CreatePublicUsername("el.mambo.tonnnnnto"));
  ASSERT_EQ("el.mambo.tonnnnnto", ss->PublicUsername());
  printf("Public Username created.\n");

  ASSERT_FALSE(cc->CreatePublicUsername("el.mambo.tonnnnnto"));
  ASSERT_EQ("el.mambo.tonnnnnto", ss->PublicUsername());
  printf("Public Username already created.\n");

  ASSERT_TRUE(cc->Logout());
  ASSERT_EQ("", ss->Username());
  ASSERT_EQ("", ss->Pin());
  ASSERT_EQ("", ss->Password());
  printf("Logged out.\n");
}

TEST_F(FunctionalMaidsafeClientControllerTest,
       FUNC_MAID_ControllerLeaveNetwork) {
  std::string username = "User4";
  std::string pin = "4567";
  std::string password = "The chubster has landed.";
  ss = SessionSingleton::getInstance();
  ASSERT_EQ("", ss->Username());
  ASSERT_EQ("", ss->Pin());
  ASSERT_EQ("", ss->Password());
  printf("Preconditions fulfilled.\n");

  exitcode result = cc->CheckUserExists(username,
                                        pin,
                                        boost::bind(
                                            &FakeCallback::CallbackFunc,
                                            &cb,
                                            _1),
                                        DEFCON3);
  ASSERT_EQ(NON_EXISTING_USER, result);
  ASSERT_TRUE(cc->CreateUser(username, pin, password));
  ASSERT_EQ(username, ss->Username());
  ASSERT_EQ(pin, ss->Pin());
  ASSERT_EQ(password, ss->Password());
  printf("User created.\n");

  result = cc->CheckUserExists(username,
                               pin,
                               boost::bind(&FakeCallback::CallbackFunc,
                                           &cb,
                                           _1),
                               DEFCON3);
  ASSERT_EQ(USER_EXISTS, result);
  boost::this_thread::sleep(boost::posix_time::seconds(10));
  GetResponse load_res;
  ASSERT_TRUE(load_res.ParseFromString(cb.result));
  ASSERT_EQ(kCallbackSuccess, load_res.result());
  ASSERT_TRUE(cc->ValidateUser(password));
  ASSERT_EQ(username, ss->Username());
  ASSERT_EQ(pin, ss->Pin());
  ASSERT_EQ(password, ss->Password());
//  ASSERT_EQ("el.mambo.tonnnnnto", ss->PublicUsername());
  printf("Logged in.\n");

  ASSERT_TRUE(cc->LeaveMaidsafeNetwork());
  printf("Left maidsafe ='(.\n");

  result = cc->CheckUserExists(username,
                               pin,
                               boost::bind(&FakeCallback::CallbackFunc,
                                           &cb,
                                           _1),
                               DEFCON3);
  ASSERT_EQ(NON_EXISTING_USER, result);
  printf("User no longer exists.\n");

  result = cc->CheckUserExists(username,
                               pin,
                               boost::bind(&FakeCallback::CallbackFunc,
                                           &cb,
                                           _1),
                               DEFCON3);
  ASSERT_EQ(NON_EXISTING_USER, result);
  ASSERT_TRUE(cc->CreateUser(username, pin, password));
  ASSERT_EQ(username, ss->Username());
  ASSERT_EQ(pin, ss->Pin());
  ASSERT_EQ(password, ss->Password());
  printf("User created again.\n");

  ASSERT_TRUE(cc->Logout());
  ASSERT_EQ("", ss->Username());
  ASSERT_EQ("", ss->Pin());
  ASSERT_EQ("", ss->Password());
  printf("Logged out.\n");
}

TEST_F(FunctionalMaidsafeClientControllerTest,
       FUNC_MAID_ControllerBackupFile) {
  std::string username = "User5";
  std::string pin = "5678";
  std::string password = "The limping dog has landed.";
  ss = SessionSingleton::getInstance();
  ASSERT_EQ("", ss->Username());
  ASSERT_EQ("", ss->Pin());
  ASSERT_EQ("", ss->Password());
  printf("Preconditions fulfilled.\n");

  exitcode result = cc->CheckUserExists(username,
                                        pin,
                                        boost::bind(
                                            &FakeCallback::CallbackFunc,
                                            &cb,
                                            _1),
                                        DEFCON3);
  ASSERT_EQ(NON_EXISTING_USER, result);
  ASSERT_TRUE(cc->CreateUser(username, pin, password));
  ASSERT_EQ(username, ss->Username());
  ASSERT_EQ(pin, ss->Pin());
  ASSERT_EQ(password, ss->Password());
  printf("User created.\n");

//  exitcode result = cc->CheckUserExists(username,
//                                        pin,
//                                      boost::bind(&FakeCallback::CallbackFunc,
//                                                    &cb,
//                                                    _1),
//                                        DEFCON3);
//  ASSERT_EQ(USER_EXISTS, result);
//  boost::this_thread::sleep(boost::posix_time::seconds(10));
//  GetResponse load_res;
//  ASSERT_TRUE(load_res.ParseFromString(cb.result));
//  ASSERT_EQ(kCallbackSuccess, load_res.result());
//  std::list<std::string> list;
//  ASSERT_TRUE(cc->ValidateUser(password, &list));
//  ASSERT_EQ(username, ss->Username());
//  ASSERT_EQ(pin, ss->Pin());
//  ASSERT_EQ(password, ss->Password());
//  ASSERT_EQ("el.mambo.tonnnnnto", ss->PublicUsername());
//  printf("Logged in.\n");

  file_system::FileSystem fsys_;
  fs::create_directories(fsys_.MaidsafeHomeDir()+kRootSubdir[0][0]);
  fs::path rel_path_(kRootSubdir[0][0]);
  rel_path_ /= "testencryption.txt";
  std::string rel_str_ = base::TidyPath(rel_path_.string());

  fs::path full_path_(fsys_.MaidsafeHomeDir());
  full_path_ /= rel_path_;
  fs::ofstream testfile(full_path_.string().c_str());
  testfile << base::RandomString(1024*1024);
  testfile.close();
  std::string hash_original_file = se.SHA512(full_path_);
  {
    boost::progress_timer t;
    ASSERT_EQ(0, cc->write(rel_str_));
    printf("File backed up in ");
  }

  ASSERT_TRUE(cc->Logout());
  ASSERT_EQ("", ss->Username());
  ASSERT_EQ("", ss->Pin());
  ASSERT_EQ("", ss->Password());
  printf("Logged out user.\n");

  if (fs::exists(full_path_))
      fs::remove(full_path_);

  result = cc->CheckUserExists(username,
                               pin,
                               boost::bind(&FakeCallback::CallbackFunc,
                                           &cb,
                                           _1),
                               DEFCON3);
  ASSERT_EQ(USER_EXISTS, result);
  boost::this_thread::sleep(boost::posix_time::seconds(10));
  GetResponse load_res;
  ASSERT_TRUE(load_res.ParseFromString(cb.result));
  ASSERT_EQ(kCallbackSuccess, load_res.result());
  ASSERT_TRUE(cc->ValidateUser(password));
  ASSERT_EQ(username, ss->Username());
  ASSERT_EQ(pin, ss->Pin());
  ASSERT_EQ(password, ss->Password());
  printf("User logged in.\n");
  fs::create_directories(fsys_.MaidsafeHomeDir()+kRootSubdir[0][0]);

  {
    boost::progress_timer t;
    ASSERT_EQ(0, cc->read(rel_str_));
    printf("Self decrypted file in ");
  }
  std::string hash_dec_file = se.SHA512(full_path_);
  ASSERT_EQ(hash_original_file, hash_dec_file);

  ASSERT_TRUE(cc->Logout());
  ASSERT_EQ("", ss->Username());
  ASSERT_EQ("", ss->Pin());
  ASSERT_EQ("", ss->Password());
  printf("Logged out user.\n");
}

TEST_F(FunctionalMaidsafeClientControllerTest,
       FUNC_MAID_ControllerUserAuthorisation) {
  std::string username = "User6";
  std::string pin = "6789";
  std::string password = "The deleted folder has landed.";
  ss = SessionSingleton::getInstance();
  ASSERT_EQ("", ss->Username());
  ASSERT_EQ("", ss->Pin());
  ASSERT_EQ("", ss->Password());
  printf("Preconditions fulfilled.\n");

  exitcode result = cc->CheckUserExists(username,
                                        pin,
                                        boost::bind(
                                            &FakeCallback::CallbackFunc,
                                            &cb,
                                            _1),
                                        DEFCON3);
  ASSERT_EQ(NON_EXISTING_USER, result);
  ASSERT_TRUE(cc->CreateUser(username, pin, password));
  ASSERT_EQ(username, ss->Username());
  ASSERT_EQ(pin, ss->Pin());
  ASSERT_EQ(password, ss->Password());
  printf("User created.\n");

//  exitcode result = cc->CheckUserExists(username,
//                                        pin,
//                                      boost::bind(&FakeCallback::CallbackFunc,
//                                                    &cb,
//                                                    _1),
//                                        DEFCON3);
//  ASSERT_EQ(USER_EXISTS, result);
//  boost::this_thread::sleep(boost::posix_time::seconds(10));
//  GetResponse load_res;
//  ASSERT_TRUE(load_res.ParseFromString(cb.result));
//  ASSERT_EQ(kCallbackSuccess, load_res.result());
//  std::list<std::string> list;
//  ASSERT_TRUE(cc->ValidateUser(password, &list));
//  ASSERT_EQ(username, ss->Username());
//  ASSERT_EQ(pin, ss->Pin());
//  ASSERT_EQ(password, ss->Password());
//  ASSERT_EQ("el.mambo.tonnnnnto", ss->PublicUsername());
//  printf("Logged in.\n");

  ASSERT_TRUE(cc->CreatePublicUsername("el.mambo.tonnnnnto"));
  ASSERT_EQ("el.mambo.tonnnnnto", ss->PublicUsername());
  printf("Public Username created.\n");

  ASSERT_TRUE(cc->Logout());
  ASSERT_EQ("", ss->Username());
  ASSERT_EQ("", ss->Pin());
  ASSERT_EQ("", ss->Password());
  printf("Logged out.\n");

  result = cc->CheckUserExists(username,
                               pin,
                               boost::bind(&FakeCallback::CallbackFunc,
                                           &cb,
                                           _1),
                               DEFCON3);
  ASSERT_EQ(USER_EXISTS, result);
  boost::this_thread::sleep(boost::posix_time::seconds(10));
  GetResponse load_res;
  ASSERT_TRUE(load_res.ParseFromString(cb.result));
  ASSERT_EQ(kCallbackSuccess, load_res.result());
  ASSERT_TRUE(cc->ValidateUser(password));
  ASSERT_EQ(username, ss->Username());
  ASSERT_EQ(pin, ss->Pin());
  ASSERT_EQ(password, ss->Password());
  ASSERT_EQ("el.mambo.tonnnnnto", ss->PublicUsername());
  printf("Logged in.\n");

  std::set<std::string> auth_users;
  std::string users[3] = {"esssmer", "es tu", "padre"};
  for (int n = 0; n < 3 ; ++n)
    auth_users.insert(users[n]);

  ASSERT_TRUE(cc->AuthoriseUsers(auth_users));
  std::set<std::string> local_set = ss->AuthorisedUsers();
  for (std::set<std::string>::iterator p = local_set.begin();
       p != local_set.end();
       ++p)
    ASSERT_TRUE(*p == users[0] || *p == users[1] || *p == users[2])
      << "User missing";
  printf("Authorised 3 users.\n");

  ASSERT_TRUE(cc->Logout());
  ASSERT_EQ("", ss->Username());
  ASSERT_EQ("", ss->Pin());
  ASSERT_EQ("", ss->Password());
  printf("Logged out.\n");

  result = cc->CheckUserExists(username,
                               pin,
                               boost::bind(&FakeCallback::CallbackFunc,
                                           &cb,
                                           _1),
                               DEFCON3);
  ASSERT_EQ(USER_EXISTS, result);
  boost::this_thread::sleep(boost::posix_time::seconds(10));
  load_res.Clear();
  ASSERT_TRUE(load_res.ParseFromString(cb.result));
  ASSERT_EQ(kCallbackSuccess, load_res.result());
  ASSERT_TRUE(cc->ValidateUser(password));
  ASSERT_EQ(username, ss->Username());
  ASSERT_EQ(pin, ss->Pin());
  ASSERT_EQ(password, ss->Password());
  ASSERT_EQ("el.mambo.tonnnnnto", ss->PublicUsername());
  printf("Logged in.\n");

  ASSERT_TRUE(cc->AuthoriseUsers(auth_users));
  local_set.clear();
  local_set = ss->AuthorisedUsers();
  for (std::set<std::string>::iterator p = local_set.begin();
       p != local_set.end();
       ++p)
    ASSERT_TRUE(*p == users[0] || *p == users[1] || *p == users[2])
      << "User missing";
  printf("Authorised users still there.\n");

  std::set<std::string> deauth_users;
  deauth_users.insert(users[0]);
  ASSERT_TRUE(cc->DeauthoriseUsers(deauth_users));
  local_set.clear();
  local_set = ss->AuthorisedUsers();
  for (std::set<std::string>::iterator p = local_set.begin();
       p != local_set.end();
       ++p)
    ASSERT_TRUE(*p == users[1] || *p == users[2]) << "User missing";
  printf("Deauthorised a user.\n");

  ASSERT_TRUE(cc->Logout());
  ASSERT_EQ("", ss->Username());
  ASSERT_EQ("", ss->Pin());
  ASSERT_EQ("", ss->Password());
  printf("Logged out.\n");

  result = cc->CheckUserExists(username,
                               pin,
                               boost::bind(&FakeCallback::CallbackFunc,
                                           &cb,
                                           _1),
                               DEFCON3);
  ASSERT_EQ(USER_EXISTS, result);
  boost::this_thread::sleep(boost::posix_time::seconds(10));
  load_res.Clear();
  ASSERT_TRUE(load_res.ParseFromString(cb.result));
  ASSERT_EQ(kCallbackSuccess, load_res.result());
  ASSERT_TRUE(cc->ValidateUser(password));
  ASSERT_EQ(username, ss->Username());
  ASSERT_EQ(pin, ss->Pin());
  ASSERT_EQ(password, ss->Password());
  ASSERT_EQ("el.mambo.tonnnnnto", ss->PublicUsername());
  printf("Logged in.\n");

  local_set.clear();
  local_set = ss->AuthorisedUsers();
  for (std::set<std::string>::iterator p = local_set.begin();
       p != local_set.end();
       ++p) {
    bool b_ = (*p == users[1] || *p == users[2]);
    ASSERT_TRUE(b_) << "User missing";
  }
  printf("2 authorised users.\n");

  ASSERT_TRUE(cc->Logout());
  ASSERT_EQ("", ss->Username());
  ASSERT_EQ("", ss->Pin());
  ASSERT_EQ("", ss->Password());
  printf("Logged out.\n");
}

//  TEST_F(FunctionalMaidsafeClientControllerTest,
//         FUNC_MAID_ControllerShares) {
//    ss = SessionSingleton::getInstance();
//    ASSERT_EQ("", ss->Username());
//    ASSERT_EQ("", ss->Pin());
//    ASSERT_EQ("", ss->Password());
//    printf("Preconditions fulfilled.\n");
//
//    ASSERT_TRUE(cc->CreateUser(username, pin, password));
//    ASSERT_EQ(username, ss->Username());
//    ASSERT_EQ(pin, ss->Pin());
//    ASSERT_EQ(password, ss->Password());
//    printf("User created.\n");
//
//    ASSERT_TRUE(cc->CreatePublicUsername("el.mambo.tonnnnnto"));
//    ASSERT_EQ("el.mambo.tonnnnnto", ss->PublicUsername());
//    printf("Public Username created.\n");
//
//    std::set<std::string> auth_users;
//    std::string users[3] = {"el.dan.liiiiiisto", "es tu", "padre"};
//    for (int n=0; n<3 ; n++)
//      auth_users.insert(users[n]);
//
//    ASSERT_TRUE(cc->AuthoriseUsers(auth_users));
//    std::set<std::string> local_set = ss->AuthorisedUsers();
//    for (std::set<std::string>::iterator p = local_set.begin();
//         p != local_set.end();
//         ++p)
//      ASSERT_TRUE(*p==users[0] || *p==users[1] || *p==users[2])
//        << "User missing";
//    printf("Authorised 3 users.\n");
//
//    ASSERT_TRUE(cc->Logout());
//    ASSERT_EQ("", ss->Username());
//    ASSERT_EQ("", ss->Pin());
//    ASSERT_EQ("", ss->Password());
//    printf("Logged out.\n");
//
//    ASSERT_TRUE(cc->CreateUser("smer","7777","palofeo"));
//    ASSERT_TRUE(ss->Username() == "smer");
//    ASSERT_TRUE(ss->Pin() == "7777");
//    ASSERT_TRUE(ss->Password() == "palofeo");
//    printf("User created.\n");
//
//    ASSERT_TRUE(cc->CreatePublicUsername("el.dan.liiiiiisto"));
//    ASSERT_TRUE(ss->PublicUsername() == "el.dan.liiiiiisto");
//    printf("Public Username created.\n");
//
//    std::string path = file_system::FileSystem::getInstance()->HomeDir() +
//                       "/testencryption.txt";
//    fs::path path_(path);
//    fs::ofstream testfile(path.c_str());
//    testfile << base::RandomString(1024*1024);
//    testfile.close();
//    std::string hash_original_file = se.SHA512(path_);
//    ASSERT_TRUE(cc->BackupElement(path));
//    while(ss->SelfEncrypting())
//      boost::this_thread::sleep(boost::posix_time::milliseconds(100));
//    OutputProcessedJobs(cc);
//    printf("File backed up.\n");
//
//    std::vector<std::string> paths, share_users;
//    std::string ms_path = path;
//    ms_path.erase(0,
//                  file_system::FileSystem::getInstance()->HomeDir().size());
//    paths.push_back(ms_path);
//    share_users.push_back("el.mambo.tonnnnnto");
//    ASSERT_TRUE(cc->CreateShare(paths,share_users,"fotos puercas"));
//    printf("Created share.\n");
//
//    ASSERT_TRUE(cc->Logout());
//    ASSERT_EQ("", ss->Username());
//    ASSERT_EQ("", ss->Pin());
//    ASSERT_EQ("", ss->Password());
//    printf("Logged out.\n");
//
//    ASSERT_TRUE(cc->Start(username, pin, password));
//    ASSERT_EQ(username, ss->Username());
//    ASSERT_EQ(pin, ss->Pin());
//    ASSERT_EQ(password, ss->Password());
//    printf("User logged in.\n");
//
//    ASSERT_TRUE(cc->Logout());
//    ASSERT_EQ("", ss->Username());
//    ASSERT_EQ("", ss->Pin());
//    ASSERT_EQ("", ss->Password());
//    printf("Logged out.\n");
//
//    if (fs::exists(path))
//      fs::remove(fs::path(path));
//  }

TEST_F(FunctionalMaidsafeClientControllerTest,
      FUNC_MAID_ControllerFuseFunctions) {
  std::string username = "User7";
  std::string pin = "7890";
  std::string password = "The pint of lager has landed on the floor.";
  ss = SessionSingleton::getInstance();
  ASSERT_EQ("", ss->Username());
  ASSERT_EQ("", ss->Pin());
  ASSERT_EQ("", ss->Password());
  printf("Preconditions fulfilled.\n");

//  exitcode result = cc->CheckUserExists(username,
//                                        pin,
//                                        boost::bind(
//                                            &FakeCallback::CallbackFunc,
//                                            &cb,
//                                            _1),
//                                        DEFCON3);
//  ASSERT_EQ(NON_EXISTING_USER, result);
//  ASSERT_TRUE(cc->CreateUser(username, pin, password));
//  ASSERT_EQ(username, ss->Username());
//  ASSERT_EQ(pin, ss->Pin());
//  ASSERT_EQ(password, ss->Password());
//  printf("User created.\n");
//

  exitcode result = cc->CheckUserExists(username,
                                        pin,
                                        boost::bind(&FakeCallback::CallbackFunc,
                                                    &cb,
                                                    _1),
                                        DEFCON3);
  ASSERT_EQ(USER_EXISTS, result);
  boost::this_thread::sleep(boost::posix_time::seconds(10));
  GetResponse load_res;
  ASSERT_TRUE(load_res.ParseFromString(cb.result));
  ASSERT_EQ(kCallbackSuccess, load_res.result());
  ASSERT_TRUE(cc->ValidateUser(password));
  ASSERT_EQ(username, ss->Username());
  ASSERT_EQ(pin, ss->Pin());
  ASSERT_EQ(password, ss->Password());
  printf("Logged in.\n");

  file_system::FileSystem fsys_;
  fs::create_directories(fsys_.MaidsafeHomeDir()+kRootSubdir[0][0]);
  fs::path rel_path_(kRootSubdir[0][0]);
  fs::path testfile[15];
  fs::path homedir(fsys_.HomeDir());
  fs::path mshomedir(fsys_.MaidsafeHomeDir());
  // fs::path newdir = homedir / "NewDir";
  // fs::path msnewdir = mshomedir / "NewDir";
  fs::path my_files(base::TidyPath(kRootSubdir[0][0]));
  fs::path startdir = my_files / "NewDir";

  testfile[0] = startdir;
  testfile[1] = startdir / "file0";
  testfile[2] = startdir / "file1";
  testfile[3] = startdir / "file2";
  testfile[4] = startdir / "file3";

  fs::path insidenewdir = startdir / "insidenewdir";
  testfile[5] = insidenewdir;
  testfile[6] = insidenewdir / "file4";
  testfile[7] = insidenewdir / "file5";
  testfile[8] = insidenewdir / "file6";

  fs::path quitedeepinsidenewdir = insidenewdir / "quitedeepinsidenewdir";
  testfile[9] = quitedeepinsidenewdir;
  fs::path deepinsidenewdir = quitedeepinsidenewdir / "deepinsidenewdir";
  testfile[10] = deepinsidenewdir;
  testfile[11] = deepinsidenewdir / "file7";
  testfile[12] = deepinsidenewdir / "file8";

  fs::path reallydeepinsidenewdir = deepinsidenewdir / "reallydeepinsidenewdir";
  testfile[13] = reallydeepinsidenewdir;
  testfile[14] = reallydeepinsidenewdir / "file9";

  std::string temp_path, temp_path1;

  printf("Creating directories and files.\n");
  for (int n = 0; n < 15; ++n) {
    temp_path = testfile[n].string();
    if (n == 0 || n == 5 || n == 9 || n == 10 || n == 13) {
      fs::create_directory(mshomedir.string()+"/"+temp_path);
      ASSERT_EQ(0, cc->mkdir(temp_path));
    } else {
      std::string full_ = mshomedir.string()+"/"+temp_path;
      fs::ofstream testfile(full_.c_str());
      testfile.close();
      ASSERT_EQ(0, cc->mknod(temp_path));
    }
    // printf("Creating element [%i]: %s\n", i, temp_path);
  }

  fs::path newdirtest2_ = insidenewdir / "testdir1/dansdir";
  temp_path = newdirtest2_.string();
  ASSERT_NE(0, cc->mkdir(temp_path)) << "making impossible dir failed";
  printf("Doesn't create impossible directory.\n");
  fs::path newfiletest3_ = insidenewdir / "testdir/lapuercota.jpg";
  temp_path = newfiletest3_.string();
  ASSERT_NE(0, cc->mknod(temp_path)) << "making impossible dir failed";
  printf("Doesn't create impossible file.\n");

  temp_path = testfile[1].string();
  fs::path temp_b_path = insidenewdir / "renamedfile0";
  temp_path1 = temp_b_path.string();
  ASSERT_EQ(0, cc->rename(temp_path, temp_path1)) << "file rename failed";
  // printf("Renamed file " << temp_path << " to " << temp_path1 << std::endl;
  printf("Renamed file.\n");

  temp_path = testfile[10].string();
  temp_b_path = quitedeepinsidenewdir / "renamed_deepinsidenewdir";
  temp_path1 = temp_b_path.string();
  ASSERT_EQ(0, cc->rename(temp_path, temp_path1)) << "directory rename failed";
  // printf("Renamed dir %s to %s\n", temp_path.c_str(), temp_path1.c_str());
  printf("Renamed directory.\n");
  testfile[10] = temp_b_path.string();

  temp_path = testfile[2].string();
  temp_b_path = insidenewdir / "nonexistant" / "renamedfile0";
  temp_path1 = temp_b_path.string();
  ASSERT_NE(0, cc->rename(temp_path, temp_path1))
    << "impossible file rename failed";
  printf("Didn't rename existant file to impossible one.\n");

  temp_path = testfile[13].string();
  temp_b_path = deepinsidenewdir /
                "nonexistant" /
                "renamed_reallydeepinsidenewdir";
  temp_path1 = temp_b_path.string();
  ASSERT_NE(0, cc->rename(temp_path, temp_path1))
    << "impossible directory rename failed";
  printf("Didn't rename existant directory to impossible one.\n");

  temp_path = testfile[13].string();
  ASSERT_NE(0, cc->rmdir(temp_path)) << "remove non-empty directory failed";
  printf("Doesn't remove non-empty directory.\n");

  temp_b_path = quitedeepinsidenewdir /
                "renamed_deepinsidenewdir" /
                "reallydeepinsidenewdir" /
                "file9";
  temp_path = temp_b_path.string();
  ASSERT_EQ(0, cc->unlink(temp_path)) << "remove file failed";
  // printf("Removed file " << temp_path << std::endl;
  printf("Removed file.\n");

  temp_b_path = temp_b_path.parent_path();
  temp_path = temp_b_path.string();
  ASSERT_EQ(0, cc->rmdir(temp_path)) << "remove directory failed";
  // printf("Removed directory " << temp_path << std::endl;
  printf("Removed directory.\n");

  temp_b_path = quitedeepinsidenewdir / "renamed_deepinsidenewdir" / "file8";
  temp_path = temp_b_path.string();
  ASSERT_EQ(0, cc->unlink(temp_path)) << "remove file failed";
  temp_b_path = quitedeepinsidenewdir / "renamed_deepinsidenewdir" / "file7";
  temp_path = temp_b_path.string();
  ASSERT_EQ(0, cc->unlink(temp_path)) << "remove file failed";
  temp_b_path = quitedeepinsidenewdir / "renamed_deepinsidenewdir";
  temp_path = temp_b_path.string();
  ASSERT_EQ(0, cc->unlink(temp_path)) << "remove stupid dir failed";
  // printf("Recursively removed directory %s and its content.\n",
  //        temp_path.c_str());
  printf("Recursively removed directory and its content.\n");

  std::string o_path = testfile[8].string();
  fs::path ppp = startdir / "file6";
  std::string n_path = ppp.string();
  ASSERT_EQ(0, cc->link(o_path, n_path));
  printf("\nCopied file %s to %s\n", o_path.c_str(), n_path.c_str());
  o_path = testfile[9].string();
  fs::path ppp1 = startdir / "dirA";
  n_path = ppp1.string();
  ASSERT_EQ(0, cc->cpdir(o_path, n_path));
  // printf("Copied directory %s to %s\n", o_path, n_path);
  printf("Copied directory.\n");

  temp_b_path = startdir;
  temp_path = temp_b_path.string();
  ASSERT_EQ(0, cc->utime(temp_path));
  // printf("\nChanged the last modification time to directory %s\n",
  //        temp_path);
  printf("Changed the last modification time to directory.\n");

  // ASSERT_EQ(0, cc->statfs());
  // printf("Got the FS stats.\n\n");

  final_dir_ = fsys_.MaidsafeDir();

  ASSERT_TRUE(cc->Logout());
  ASSERT_EQ("", ss->Username());
  ASSERT_EQ("", ss->Pin());
  ASSERT_EQ("", ss->Password());
  printf("Logged out user.\n");
}

}  // namespace maidsafe

int main() {
return 0;
}
