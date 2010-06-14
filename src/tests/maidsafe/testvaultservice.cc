/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Version:      1.0
* Created:      2009-08-20
* Revision:     none
* Compiler:     gcc
* Author:       Team www.maidsafe.net
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

#include <boost/shared_ptr.hpp>
#include <boost/lexical_cast.hpp>
#include <google/protobuf/descriptor.h>
#include <gtest/gtest.h>
#include <maidsafe/base/crypto.h>
#include <maidsafe/protobuf/kademlia_service_messages.pb.h>
#include <maidsafe/transport/transportudt.h>

#include "fs/filesystem.h"
#include "maidsafe/vault/chunkinfohandler.h"
#include "maidsafe/vault/vaultchunkstore.h"
#include "maidsafe/vault/vaultdaemon.h"
#include "maidsafe/vault/vaultrpc.h"
#include "maidsafe/vault/vaultservice.h"
#include "maidsafe/vault/vaultservicelogic.h"
#include "tests/maidsafe/cached_keys.h"
#include "tests/maidsafe/mockvaultservicelogic.h"

namespace fs = boost::filesystem;

const boost::uint64_t kAvailableSpace = 1073741824;

inline void CreateRSAKeys(std::string *pub_key, std::string *priv_key) {
  crypto::RsaKeyPair kp;
  kp.GenerateKeys(maidsafe_vault::kRsaKeySize);
  *pub_key =  kp.public_key();
  *priv_key = kp.private_key();
}

inline void CreateSignedRequest(const std::string &pub_key,
                                const std::string &priv_key,
                                const std::string &key,
                                std::string *pmid,
                                std::string *sig_pub_key,
                                std::string *sig_req) {
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);
  *sig_pub_key = co.AsymSign(pub_key, "", priv_key, crypto::STRING_STRING);
  *pmid = co.Hash(pub_key + *sig_pub_key, "", crypto::STRING_STRING, false);
  *sig_req = co.AsymSign(co.Hash(pub_key + *sig_pub_key + key, "",
       crypto::STRING_STRING, false), "", priv_key, crypto::STRING_STRING);
  // TODO(Team#) use new request signature method from the validator
}

namespace test_vault_service {
static const boost::uint8_t K(4);
}  // namespace test_vault_service

namespace maidsafe_vault {

typedef std::map<std::string, maidsafe::StoreContract> PrepsReceivedMap;

class TestCallback {
 public:
  void CallbackFunction() {}
};

class VaultServicesTest : public testing::Test {
 protected:
  VaultServicesTest()
      : chunkstore_dir_(file_system::TempDir() /
            ("maidsafe_TestVaultServices_" + base::RandomString(6))),
        vault_pmid_(),
        vault_public_key_(),
        vault_private_key_(),
        vault_public_key_signature_(),
        udt_transport_(),
        transport_handler_(),
        channel_manager_(&transport_handler_),
        kad_ops_(),
        vault_chunkstore_(),
        vault_rpcs_(new VaultRpcs(&transport_handler_, &channel_manager_)),
        vault_service_logic_(),
        vault_service_(),
        svc_channel_(),
        keys_() {}

  virtual void SetUp() {
    CreateRSAKeys(&vault_public_key_, &vault_private_key_);
    {
      crypto::Crypto co;
      co.set_symm_algorithm(crypto::AES_256);
      co.set_hash_algorithm(crypto::SHA_512);
      vault_public_key_signature_ = co.AsymSign(vault_public_key_, "",
                                                vault_private_key_,
                                                crypto::STRING_STRING);
      vault_pmid_ = co.Hash(vault_public_key_ + vault_public_key_signature_,
                            "", crypto::STRING_STRING, false);
    }

    try {
      fs::remove_all(chunkstore_dir_);
    }
    catch(const std::exception &e) {
      printf("%s\n", e.what());
    }
    boost::int16_t transport_id;
    transport_handler_.Register(&udt_transport_, &transport_id);
    vault_chunkstore_.reset(new VaultChunkStore(chunkstore_dir_.string(),
                                                kAvailableSpace, 0));
    ASSERT_TRUE(vault_chunkstore_->Init());
    kad_ops_.reset(new maidsafe::KadOps(&transport_handler_,
        &channel_manager_, kad::VAULT, vault_private_key_, vault_public_key_,
        false, false, vault_chunkstore_));
    kad_ops_->set_transport_id(transport_id);

    vault_service_logic_ = new VaultServiceLogic(vault_rpcs_, kad_ops_);
    vault_service_ = new VaultService(vault_pmid_, vault_public_key_,
                                      vault_private_key_,
                                      vault_public_key_signature_,
                                      vault_chunkstore_, vault_service_logic_,
                                      transport_id, kad_ops_);

    maidsafe::GetSyncDataResponse get_sync_data_response;
    vault_service_->AddStartupSyncData(get_sync_data_response);

    vault_service_logic_->Init(vault_pmid_,
                               vault_public_key_,
                               vault_public_key_signature_,
                               vault_private_key_);

    svc_channel_ = new rpcprotocol::Channel(&channel_manager_,
                                            &transport_handler_);
    svc_channel_->SetService(vault_service_);
    channel_manager_.RegisterChannel(vault_service_->GetDescriptor()->name(),
                                     svc_channel_);
  }

  virtual void TearDown() {
    channel_manager_.UnRegisterChannel(
        vault_service_->GetDescriptor()->name());
    transport_handler_.StopAll();
    channel_manager_.Stop();
    transport::TransportUDT::CleanUp();
    delete svc_channel_;
    delete vault_service_;
    delete vault_service_logic_;

    try {
      fs::remove_all(chunkstore_dir_);
    }
    catch(const std::exception &e) {
      printf("%s\n", e.what());
    }
  }

  fs::path chunkstore_dir_;
  std::string vault_pmid_, vault_public_key_, vault_private_key_;
  std::string vault_public_key_signature_;
  transport::TransportUDT udt_transport_;
  transport::TransportHandler transport_handler_;
  rpcprotocol::ChannelManager channel_manager_;
  boost::shared_ptr<maidsafe::KadOps> kad_ops_;
  boost::shared_ptr<VaultChunkStore> vault_chunkstore_;
  boost::shared_ptr<VaultRpcs> vault_rpcs_;
  VaultServiceLogic *vault_service_logic_;
  VaultService *vault_service_;
  rpcprotocol::Channel *svc_channel_;
  std::vector<crypto::RsaKeyPair> keys_;

 private:
  VaultServicesTest(const VaultServicesTest&);
  VaultServicesTest& operator=(const VaultServicesTest&);
};

class MockVaultServicesTest : public VaultServicesTest {
 protected:
  MockVaultServicesTest()
      : mock_vault_service_logic_(boost::shared_ptr<VaultRpcs>(),
                                  boost::shared_ptr<maidsafe::KadOps>()) {}
  void SetUp() {
    VaultServicesTest::SetUp();
    // Initialise mock_vault_service_logic
    mock_vault_service_logic_.pmid_ = vault_pmid_;
    mock_vault_service_logic_.pmid_public_signature_ =
        vault_public_key_signature_;
    mock_vault_service_logic_.pmid_private_ = vault_private_key_;
    kad::Contact our_details(kad_ops_->contact_info());
    mock_vault_service_logic_.our_details_ = our_details;
    mock_vault_service_logic_.SetOnlineStatus(true);
  }
  MockVsl mock_vault_service_logic_;
 private:
  MockVaultServicesTest(const MockVaultServicesTest&);
  MockVaultServicesTest &operator=(const MockVaultServicesTest&);
};

TEST_F(VaultServicesTest, BEH_MAID_ServicesValidateSignedSize) {
  maidsafe::SignedSize sz;
  ASSERT_FALSE(vault_service_->ValidateSignedSize(sz));

  boost::uint64_t size(123);
  std::string pub_key, priv_key, pub_key_sig, size_sig, pmid;
  CreateRSAKeys(&pub_key, &priv_key);
  crypto::Crypto co;
  pub_key_sig = co.AsymSign(pub_key, "", priv_key, crypto::STRING_STRING);
  pmid = co.Hash(pub_key + pub_key_sig, "", crypto::STRING_STRING, false);
  size_sig = co.AsymSign(boost::lexical_cast<std::string>(size), "", priv_key,
                         crypto::STRING_STRING);

  sz.set_data_size(size);
  sz.set_signature(size_sig);
  sz.set_pmid("moo");
  sz.set_public_key(pub_key);
  sz.set_public_key_signature(pub_key_sig);
  ASSERT_FALSE(vault_service_->ValidateSignedSize(sz));
  sz.set_pmid(pmid);
  sz.set_data_size(321);
  ASSERT_FALSE(vault_service_->ValidateSignedSize(sz));
  sz.set_data_size(size);
  ASSERT_TRUE(vault_service_->ValidateSignedSize(sz));
}

TEST_F(VaultServicesTest, BEH_MAID_ServicesValidateStoreContract) {
  maidsafe::StoreContract sc;
  ASSERT_FALSE(vault_service_->ValidateStoreContract(sc));

  std::string pub_key, priv_key, pub_key_sig, pmid;
  CreateRSAKeys(&pub_key, &priv_key);
  crypto::Crypto co;
  pub_key_sig = co.AsymSign(pub_key, "", priv_key, crypto::STRING_STRING);
  pmid = co.Hash(pub_key + pub_key_sig, "", crypto::STRING_STRING, false);

  sc.set_signature("moo");
  sc.set_pmid(pmid);
  sc.set_public_key(pub_key);
  sc.set_public_key_signature(pub_key_sig);
  ASSERT_FALSE(vault_service_->ValidateStoreContract(sc));

  maidsafe::StoreContract::InnerContract *ic = sc.mutable_inner_contract();
  maidsafe::SignedSize *sz = ic->mutable_signed_size();
  ic->set_result(kAck);
  ASSERT_FALSE(vault_service_->ValidateStoreContract(sc));

  std::string pub_key2, priv_key2, pub_key_sig2, size_sig, pmid2;
  CreateRSAKeys(&pub_key2, &priv_key2);
  pub_key_sig2 = co.AsymSign(pub_key2, "", priv_key2, crypto::STRING_STRING);
  pmid2 = co.Hash(pub_key2 + pub_key_sig2, "", crypto::STRING_STRING, false);
  size_sig = co.AsymSign("123", "", priv_key2, crypto::STRING_STRING);

  sz->set_data_size(123);
  sz->set_signature(size_sig);
  sz->set_pmid(pmid2);
  sz->set_public_key(pub_key2);
  sz->set_public_key_signature(pub_key_sig2);
  sc.set_pmid(pmid2);
  sc.set_public_key(pub_key2);
  sc.set_public_key_signature(pub_key_sig2);
  sc.set_signature(co.AsymSign(ic->SerializeAsString(), "", priv_key2,
                               crypto::STRING_STRING));
  ASSERT_FALSE(vault_service_->ValidateStoreContract(sc));

  ic->set_result(kAck);
  sc.set_pmid(pmid);
  sc.set_public_key_signature(pub_key_sig);
  sc.set_signature(co.AsymSign(ic->SerializeAsString(), "", priv_key,
                               crypto::STRING_STRING));
  ASSERT_FALSE(vault_service_->ValidateStoreContract(sc));

  sc.set_public_key(pub_key);
  ic->set_result(kNack);
  sc.set_signature(co.AsymSign(ic->SerializeAsString(), "", priv_key,
                               crypto::STRING_STRING));
  ASSERT_FALSE(vault_service_->ValidateStoreContract(sc));

  ic->set_result(kAck);
  sc.set_signature(co.AsymSign(ic->SerializeAsString(), "", priv_key,
                               crypto::STRING_STRING));
  ASSERT_TRUE(vault_service_->ValidateStoreContract(sc));
}

TEST_F(VaultServicesTest, BEH_MAID_ServicesValidateAmendRequest) {
  maidsafe::AmendAccountRequest req;
  boost::uint64_t account_delta;
  std::string returned_pmid;
  ASSERT_FALSE(vault_service_->ValidateAmendRequest(&req, &account_delta,
                                                    &returned_pmid));

  std::string pub_key, priv_key, pub_key_sig, pmid, size_sig;
  CreateRSAKeys(&pub_key, &priv_key);
  crypto::Crypto co;
  pub_key_sig = co.AsymSign(pub_key, "", priv_key, crypto::STRING_STRING);
  pmid = co.Hash(pub_key + pub_key_sig, "", crypto::STRING_STRING, false);
  size_sig = co.AsymSign("123", "", priv_key, crypto::STRING_STRING);

  req.set_amendment_type(maidsafe::AmendAccountRequest::kSpaceOffered);
  req.set_account_pmid(pmid);
  ASSERT_FALSE(vault_service_->ValidateAmendRequest(&req, &account_delta,
                                                    &returned_pmid));

  maidsafe::SignedSize *sz = req.mutable_signed_size();
  sz->set_data_size(123);
  sz->set_signature(size_sig);
  sz->set_pmid(pmid);
  sz->set_public_key(pub_key);
  sz->set_public_key_signature(pub_key_sig);
  req.set_account_pmid(vault_service_->pmid_);
  ASSERT_FALSE(vault_service_->ValidateAmendRequest(&req, &account_delta,
                                                    &returned_pmid));
  req.set_account_pmid("moo");
  ASSERT_FALSE(vault_service_->ValidateAmendRequest(&req, &account_delta,
                                                    &returned_pmid));

  req.set_amendment_type(maidsafe::AmendAccountRequest::kSpaceGivenInc);
  ASSERT_FALSE(vault_service_->ValidateAmendRequest(&req, &account_delta,
                                                    &returned_pmid));

  req.set_chunkname("chunk name");
  ASSERT_TRUE(vault_service_->ValidateAmendRequest(&req, &account_delta,
                                                   &returned_pmid));
  ASSERT_EQ(boost::uint64_t(123), account_delta);
  ASSERT_EQ("moo", returned_pmid);

  req.set_amendment_type(maidsafe::AmendAccountRequest::kSpaceOffered);
  req.clear_chunkname();
  req.set_account_pmid(pmid);
  ASSERT_TRUE(vault_service_->ValidateAmendRequest(&req, &account_delta,
                                                   &returned_pmid));
  ASSERT_EQ(boost::uint64_t(123), account_delta);
  ASSERT_EQ(pmid, returned_pmid);
}

TEST_F(VaultServicesTest, BEH_MAID_ServicesValidateIdAndRequest) {
  std::string pub_key, priv_key, key("xyz"), pmid, sig_pub_key, sig_req;
  CreateRSAKeys(&pub_key, &priv_key);

  EXPECT_TRUE(vault_service_->ValidateIdAndRequest("abc", "def",
                                                   kAnonymousRequestSignature,
                                                   key, ""));

  CreateSignedRequest(pub_key, priv_key, key, &pmid, &sig_pub_key, &sig_req);
  EXPECT_TRUE(vault_service_->ValidateIdAndRequest(pub_key, sig_pub_key,
                                                   sig_req, key, pmid));

  EXPECT_FALSE(vault_service_->ValidateIdAndRequest(pub_key, sig_pub_key,
                                                    sig_req, key, "abcdef"));

  CreateSignedRequest("123", "456", key, &pmid, &sig_pub_key, &sig_req);
  EXPECT_FALSE(vault_service_->ValidateIdAndRequest("123", sig_pub_key,
                                                    sig_req, key, pmid));
  EXPECT_FALSE(vault_service_->ValidateIdAndRequest("abc", "def", "ghi", key,
                                                    pmid));
}

TEST_F(VaultServicesTest, BEH_MAID_ServicesValidateRequestSignature) {
  std::string pub_key, priv_key, key("xyz"), pmid, sig_pub_key, sig_req;
  CreateRSAKeys(&pub_key, &priv_key);
  CreateSignedRequest(pub_key, priv_key, key, &pmid, &sig_pub_key, &sig_req);
  ASSERT_TRUE(vault_service_->ValidateRequestSignature(pub_key, sig_pub_key,
                                                       sig_req, key));
  ASSERT_FALSE(vault_service_->ValidateRequestSignature("123", sig_pub_key,
                                                        sig_req, key));
  ASSERT_FALSE(vault_service_->ValidateRequestSignature(pub_key, "def", sig_req,
                                                        key));
  ASSERT_FALSE(vault_service_->ValidateRequestSignature(pub_key, sig_pub_key,
                                                        "hijklm", key));
  ASSERT_FALSE(vault_service_->ValidateRequestSignature(pub_key, sig_pub_key,
                                                        sig_req, "abcdef"));
}

TEST_F(VaultServicesTest, BEH_MAID_ServicesValidateIdentity) {
  std::string pub_key, priv_key, sig_pub_key;
  CreateRSAKeys(&pub_key, &priv_key);
  crypto::Crypto co;
  sig_pub_key = co.AsymSign(pub_key, "", priv_key, crypto::STRING_STRING);
  std::string pmid = co.Hash(pub_key + sig_pub_key, "", crypto::STRING_STRING,
                     false);

  ASSERT_FALSE(vault_service_->ValidateIdentity("", pub_key, sig_pub_key));
  ASSERT_FALSE(vault_service_->ValidateIdentity(pmid, "", sig_pub_key));
  ASSERT_FALSE(vault_service_->ValidateIdentity(pmid, pub_key, ""));
  ASSERT_FALSE(vault_service_->ValidateIdentity("AAA", pub_key, sig_pub_key));
  ASSERT_TRUE(vault_service_->ValidateIdentity(pmid, pub_key, sig_pub_key));
}

TEST_F(VaultServicesTest, BEH_MAID_ServicesValidateSystemPacket) {
  std::string pub_key, priv_key;
  CreateRSAKeys(&pub_key, &priv_key);

  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);

  maidsafe::GenericPacket gp;
  gp.set_data("Generic System Packet Data");
  gp.set_signature(co.AsymSign(gp.data(), "", priv_key,
                   crypto::STRING_STRING));

  EXPECT_TRUE(vault_service_->ValidateSystemPacket(gp.SerializeAsString(),
                                                   pub_key));
  EXPECT_FALSE(vault_service_->ValidateSystemPacket("abc",
                                                    pub_key));
  EXPECT_FALSE(vault_service_->ValidateSystemPacket(gp.SerializeAsString(),
                                                    "123"));
  gp.set_signature("abcdef");
  EXPECT_FALSE(vault_service_->ValidateSystemPacket(gp.SerializeAsString(),
                                                    pub_key));
}

TEST_F(VaultServicesTest, BEH_MAID_ServicesValidateDataChunk) {
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  std::string content("This is a data chunk");
  std::string chunkname(co.Hash(content, "", crypto::STRING_STRING, false));
  EXPECT_TRUE(vault_service_->ValidateDataChunk(chunkname, content));
  EXPECT_FALSE(vault_service_->ValidateDataChunk("123", content));
  EXPECT_FALSE(vault_service_->ValidateDataChunk(chunkname, "abc"));
  EXPECT_FALSE(vault_service_->ValidateDataChunk("", ""));
  chunkname = co.Hash(content + "X", "", crypto::STRING_STRING, false);
  EXPECT_FALSE(vault_service_->ValidateDataChunk(chunkname, content));
}

TEST_F(VaultServicesTest, BEH_MAID_ServicesStorable) {
  EXPECT_EQ(0, vault_service_->Storable(12345));
  EXPECT_EQ(0, vault_service_->Storable(kAvailableSpace));
  EXPECT_NE(0, vault_service_->Storable(kAvailableSpace + 1));
  EXPECT_NE(0, vault_service_->Storable(0));
}

TEST_F(VaultServicesTest, BEH_MAID_ServicesLocalStorage) {
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  std::string content("This is a data chunk"), test_content;
  std::string chunkname(co.Hash(content, "", crypto::STRING_STRING, false));
  std::string fake_chunkname(co.Hash("moo", "", crypto::STRING_STRING, false));
  EXPECT_FALSE(vault_service_->HasChunkLocal(chunkname));
  EXPECT_EQ(boost::uint64_t(0), vault_service_->GetChunkSizeLocal(chunkname));
  EXPECT_TRUE(vault_service_->StoreChunkLocal(chunkname, content));
  EXPECT_TRUE(vault_service_->HasChunkLocal(chunkname));
  EXPECT_EQ(content.size(), vault_service_->GetChunkSizeLocal(chunkname));
  EXPECT_TRUE(vault_service_->LoadChunkLocal(chunkname, &test_content));
  EXPECT_EQ(content, test_content);
  // EXPECT_FALSE(vault_service_->StoreChunkLocal(chunkname, content));
  // EXPECT_FALSE(vault_service_->StoreChunkLocal(chunkname, new_content));
  EXPECT_FALSE(vault_service_->LoadChunkLocal(fake_chunkname, &test_content));
  EXPECT_TRUE(vault_service_->DeleteChunkLocal(chunkname));
  EXPECT_FALSE(vault_service_->HasChunkLocal(chunkname));
  EXPECT_EQ(boost::uint64_t(0), vault_service_->GetChunkSizeLocal(chunkname));
  EXPECT_FALSE(vault_service_->LoadChunkLocal(chunkname, &test_content));
}

TEST_F(VaultServicesTest, BEH_MAID_ServicesNodeWithinClosest) {
  vault_service_->pmid_ = std::string(kKeySize, 0);
  for (int i = 0; i < 5; ++i) {
    base::PublicRoutingTableTuple entry(std::string(kKeySize, i + 1),
                                    "127.0.0.1", 123 + i, "127.0.0.1", 456 + i,
                                    "pubkey", 10, 1, 1234);
    ASSERT_EQ(kSuccess, vault_service_->routing_table_->AddTuple(entry));
  }

  ASSERT_FALSE(vault_service_->NodeWithinClosest(std::string(kKeySize, 6), 10));
  ASSERT_FALSE(vault_service_->NodeWithinClosest(std::string(kKeySize, 4), 3));
  ASSERT_TRUE(vault_service_->NodeWithinClosest(std::string(kKeySize, 1), 0));
  ASSERT_TRUE(vault_service_->NodeWithinClosest(std::string(kKeySize, 2), 0));
  ASSERT_TRUE(vault_service_->NodeWithinClosest(std::string(kKeySize, 3), 0));
  ASSERT_TRUE(vault_service_->NodeWithinClosest(std::string(kKeySize, 4), 0));
  ASSERT_TRUE(vault_service_->NodeWithinClosest(std::string(kKeySize, 5), 0));

  vault_service_->routing_table_->Clear();
}

// -----------------------------------------------------------------------------

TEST_F(VaultServicesTest, BEH_MAID_ServicesStorePrep) {
  rpcprotocol::Controller controller;
  maidsafe::StorePrepRequest request;
  maidsafe::StorePrepResponse response;

  maidsafe::SignedSize *signed_size = NULL;
  maidsafe::StoreContract *store_contract = NULL;
  maidsafe::StoreContract::InnerContract *inner_contract = NULL;

  std::string pub_key, priv_key, pmid, pub_key_sig, req_sig, size_sig;
  CreateRSAKeys(&pub_key, &priv_key);
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);

  std::string chunk_data("This is a data chunk");
  std::string chunk_name(co.Hash(chunk_data, "", crypto::STRING_STRING, false));
  boost::uint64_t chunk_size(chunk_data.size());

  pub_key_sig = co.AsymSign(pub_key, "", priv_key, crypto::STRING_STRING);
  pmid = co.Hash(pub_key + pub_key_sig, "", crypto::STRING_STRING, false);

  size_sig = co.AsymSign(boost::lexical_cast<std::string>(chunk_size), "",
                         priv_key, crypto::STRING_STRING);

  req_sig = co.AsymSign(co.Hash(pub_key_sig + chunk_name + vault_pmid_, "",
                        crypto::STRING_STRING, false), "", priv_key,
                        crypto::STRING_STRING);

  TestCallback cb_obj;

  for (int i = 0; i < 8; ++i) {
    printf("--- CASE #%i --- \n", i);
    switch (i) {
      case 0:  // empty request
        break;
      case 1:  // unsigned request
        signed_size = request.mutable_signed_size();
        signed_size->set_data_size(chunk_size);
        signed_size->set_signature(size_sig);
        signed_size->set_pmid(pmid);
        signed_size->set_public_key(pub_key);
        signed_size->set_public_key_signature(pub_key_sig);
        request.set_chunkname(chunk_name);
        request.set_request_signature("fail");
        break;
      case 2:  // empty signed_size
        request.clear_signed_size();
        request.set_request_signature(req_sig);
        break;
      case 3:  // unsigned signed_size
        signed_size = request.mutable_signed_size();
        signed_size->set_data_size(chunk_size);
        signed_size->set_signature("fail");
        signed_size->set_pmid(pmid);
        signed_size->set_public_key(pub_key);
        signed_size->set_public_key_signature(pub_key_sig);
        break;
      case 4:  // invalid chunk name
        request.set_chunkname("fail");
        request.set_request_signature(co.AsymSign(co.Hash(pub_key_sig + "fail"
            + vault_pmid_, "", crypto::STRING_STRING, false), "", priv_key,
            crypto::STRING_STRING));
        break;
      case 5:  // size too big
        request.set_chunkname(chunk_name);
        request.set_request_signature(req_sig);
        signed_size->set_data_size(kAvailableSpace + 1);
        signed_size->set_signature(co.AsymSign(
            boost::lexical_cast<std::string>(kAvailableSpace + 1), "",
            priv_key, crypto::STRING_STRING));
        break;
      case 6:  // zero size
        signed_size->set_data_size(0);
        signed_size->set_signature(co.AsymSign("0", "", priv_key,
                                   crypto::STRING_STRING));
        break;
      case 7:  // store to self
        signed_size->set_data_size(chunk_size);
        signed_size->set_signature(
            co.AsymSign(boost::lexical_cast<std::string>(chunk_size), "",
            vault_private_key_, crypto::STRING_STRING));
        signed_size->set_pmid(vault_pmid_);
        signed_size->set_public_key(vault_public_key_);
        signed_size->set_public_key_signature(vault_public_key_signature_);
        request.set_request_signature(co.AsymSign(co.Hash(
            vault_public_key_signature_ + chunk_name + vault_pmid_, "",
            crypto::STRING_STRING, false), "", priv_key,
            crypto::STRING_STRING));
        break;
    }

    google::protobuf::Closure *done =
        google::protobuf::NewCallback<TestCallback>(&cb_obj,
        &TestCallback::CallbackFunction);
    vault_service_->StorePrep(&controller, &request, &response, done);
    ASSERT_TRUE(response.IsInitialized());
    store_contract = response.mutable_store_contract();
    inner_contract = store_contract->mutable_inner_contract();
    std::string inner_cont_sig = co.AsymSign(
        inner_contract->SerializeAsString(), "", vault_private_key_,
        crypto::STRING_STRING);
    EXPECT_EQ(inner_cont_sig, store_contract->signature());
    std::string cont_sig = co.AsymSign(store_contract->SerializeAsString(), "",
        vault_private_key_, crypto::STRING_STRING);
    EXPECT_EQ(cont_sig, response.response_signature());
    EXPECT_NE(kAck, static_cast<int>(inner_contract->result()));
    response.Clear();
  }

  signed_size->set_signature(size_sig);
  signed_size->set_pmid(pmid);
  signed_size->set_public_key(pub_key);
  signed_size->set_public_key_signature(pub_key_sig);
  request.set_request_signature(req_sig);

  // proper request
  {
    google::protobuf::Closure *done =
        google::protobuf::NewCallback<TestCallback>(&cb_obj,
        &TestCallback::CallbackFunction);
    vault_service_->StorePrep(&controller, &request, &response, done);
    ASSERT_TRUE(response.IsInitialized());
    store_contract = response.mutable_store_contract();
    inner_contract = store_contract->mutable_inner_contract();
    signed_size = inner_contract->mutable_signed_size();
    std::string inner_cont_sig = co.AsymSign(
        inner_contract->SerializeAsString(), "", vault_private_key_,
        crypto::STRING_STRING);
    EXPECT_EQ(inner_cont_sig, store_contract->signature());
    EXPECT_EQ(vault_pmid_, store_contract->pmid());
    EXPECT_EQ(vault_public_key_, store_contract->public_key());
    EXPECT_EQ(vault_public_key_signature_,
              store_contract->public_key_signature());
    EXPECT_EQ(chunk_size, signed_size->data_size());
    EXPECT_EQ(size_sig, signed_size->signature());
    EXPECT_EQ(pmid, signed_size->pmid());
    EXPECT_EQ(pub_key, signed_size->public_key());
    EXPECT_EQ(pub_key_sig, signed_size->public_key_signature());
    std::string cont_sig = co.AsymSign(store_contract->SerializeAsString(), "",
        vault_private_key_, crypto::STRING_STRING);
    EXPECT_EQ(cont_sig, response.response_signature());
    EXPECT_EQ(kAck, static_cast<int>(inner_contract->result()));
    response.Clear();
  }
}

TEST_F(MockVaultServicesTest, BEH_MAID_ServicesStoreChunk) {
  delete vault_service_;
  vault_service_ = new VaultService(vault_pmid_, vault_public_key_,
                                    vault_private_key_,
                                    vault_public_key_signature_,
                                    vault_chunkstore_,
                                    &mock_vault_service_logic_,
                                    udt_transport_.transport_id(), kad_ops_);

  maidsafe::GetSyncDataResponse get_sync_data_response;
  vault_service_->AddStartupSyncData(get_sync_data_response);

  rpcprotocol::Controller controller;
  maidsafe::StoreChunkRequest request;
  maidsafe::StoreChunkResponse response;

  std::string pub_key, priv_key, pmid, pub_key_sig, req_sig, size_sig;
  CreateRSAKeys(&pub_key, &priv_key);
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);

  std::string chunk_data("This is a data chunk");
  std::string chunk_name(co.Hash(chunk_data, "", crypto::STRING_STRING, false));
  boost::uint64_t chunk_size(chunk_data.size());

  CreateSignedRequest(pub_key, priv_key, chunk_name, &pmid, &pub_key_sig,
                      &req_sig);  // TODO(Team#) create new request signature

  size_sig = co.AsymSign(boost::lexical_cast<std::string>(chunk_size), "",
                         priv_key, crypto::STRING_STRING);

  req_sig = co.AsymSign(co.Hash(pub_key_sig + chunk_name + vault_pmid_, "",
                        crypto::STRING_STRING, false), "", priv_key,
                        crypto::STRING_STRING);

  EXPECT_CALL(mock_vault_service_logic_,
              AddToRemoteRefList(testing::_, testing::_, testing::_,
                                 testing::_))
      .Times(testing::Exactly(1));
  EXPECT_CALL(mock_vault_service_logic_,
              AmendRemoteAccount(testing::_, testing::_, testing::_,
                                 testing::_));

  TestCallback cb_obj;

  for (int i = 0; i < 3; ++i) {
    printf("--- CASE #%i --- \n", i);
    switch (i) {
      case 0:  // uninitialized request
        break;
      case 1:  // unsigned request
        request.set_chunkname(chunk_name);
        request.set_data(chunk_data);
        request.set_pmid(pmid);
        request.set_public_key(pub_key);
        request.set_public_key_signature(pub_key_sig);
        request.set_request_signature("fail");
        request.set_data_type(maidsafe::DATA);
        // request.set_offset(  );
        // request.set_chunklet_size(  );
        break;
      case 2:  // store without prep
        request.set_chunkname(chunk_name);
        request.set_request_signature(req_sig);
        break;
    }

    google::protobuf::Closure *done =
        google::protobuf::NewCallback<TestCallback>(&cb_obj,
        &TestCallback::CallbackFunction);
    vault_service_->StoreChunk(&controller, &request, &response, done);
    ASSERT_TRUE(response.IsInitialized());
    EXPECT_NE(kAck, static_cast<int>(response.result()));
    response.Clear();
  }

  // simulate prep by adding contract
  /* {
    maidsafe::StoreContract store_contract;
    std::pair<std::string, maidsafe::StoreContract>
        p(chunk_name, store_contract);
    std::pair<PrepsReceivedMap::iterator, bool> result =
        vault_service_->prm_.insert(p);
    EXPECT_TRUE(result.second);
  } */

  // prepare storing, get proper contract
  maidsafe::StorePrepResponse sp_rsp;
  {
    maidsafe::StorePrepRequest sp_req;
    maidsafe::SignedSize *signed_size;
    signed_size = sp_req.mutable_signed_size();
    signed_size->set_data_size(chunk_size);
    signed_size->set_signature(size_sig);
    signed_size->set_pmid(pmid);
    signed_size->set_public_key(pub_key);
    signed_size->set_public_key_signature(pub_key_sig);
    sp_req.set_chunkname(chunk_name);
    sp_req.set_request_signature(req_sig);
    google::protobuf::Closure *done =
        google::protobuf::NewCallback<TestCallback>(&cb_obj,
        &TestCallback::CallbackFunction);
    vault_service_->StorePrep(&controller, &sp_req, &sp_rsp, done);
    ASSERT_TRUE(sp_rsp.IsInitialized());
  }
  const maidsafe::StoreContract &contract = sp_rsp.store_contract();
  EXPECT_EQ(kAck, static_cast<int>(contract.inner_contract().result()));

  // simulate AddToWatchList
  {
    int req_references, req_payments;
    vault_service_->cih_.PrepareAddToWatchList(chunk_name, pmid, chunk_size,
                                               &req_references, &req_payments);
    vault_service_->cih_.SetPaymentsDone(chunk_name, pmid);
  }

  ChunkInfo &ci = vault_service_->cih_.chunk_infos_[chunk_name];
  EXPECT_EQ(size_t(1), ci.waiting_list.size());
  EXPECT_EQ(size_t(0), ci.watch_list.size());
  EXPECT_EQ(size_t(0), ci.reference_list.size());

  // try to store, should succeed
  {
    google::protobuf::Closure *done =
        google::protobuf::NewCallback<TestCallback>(&cb_obj,
        &TestCallback::CallbackFunction);
    vault_service_->StoreChunk(&controller, &request, &response, done);
    ASSERT_TRUE(response.IsInitialized());
    EXPECT_EQ(kAck, static_cast<int>(response.result()));
    response.Clear();
  }

  vault_service_->HasChunkLocal(chunk_name);

  // process outstanding tasks
  vault_service_->thread_pool_.waitForDone();

  // we should have a reference list entry now
  EXPECT_EQ(size_t(0), ci.waiting_list.size());
  EXPECT_NE(size_t(0), ci.watch_list.size());
  EXPECT_EQ(size_t(1), ci.reference_list.size());
}

TEST_F(VaultServicesTest, BEH_MAID_ServicesGetCheckChunk) {
  rpcprotocol::Controller controller;
  maidsafe::GetChunkRequest request;
  maidsafe::GetChunkResponse response;
  maidsafe::CheckChunkRequest check_request;
  maidsafe::CheckChunkResponse check_response;

  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);
  std::string content("This is a data chunk");
  std::string chunkname(co.Hash(content, "", crypto::STRING_STRING, false));

  TestCallback cb_obj;

  // test Get()'s error handling
  for (boost::uint32_t i = 0; i <= 1; ++i) {
    switch (i) {
      case 0:  // uninitialized request
        break;
      case 1:  // make LoadChunkLocal() fail
        request.set_chunkname(chunkname);
        break;
    }

    google::protobuf::Closure *done =
        google::protobuf::NewCallback<TestCallback>(&cb_obj,
        &TestCallback::CallbackFunction);
    vault_service_->GetChunk(&controller, &request, &response, done);
    ASSERT_TRUE(response.IsInitialized());
    EXPECT_NE(kAck, static_cast<int>(response.result()));
    response.Clear();
  }

  // test CheckChunk()'s error handling
  for (boost::uint32_t i = 0; i <= 1; ++i) {
    switch (i) {
      case 0:  // uninitialized request
        break;
      case 1:  // make HasChunkLocal() fail
        check_request.set_chunkname(chunkname);
        break;
    }
    google::protobuf::Closure *done =
        google::protobuf::NewCallback<TestCallback>(&cb_obj,
        &TestCallback::CallbackFunction);
    vault_service_->CheckChunk(&controller, &check_request, &check_response,
                               done);
    ASSERT_TRUE(check_response.IsInitialized());
    EXPECT_NE(kAck, static_cast<int>(check_response.result()));
    response.Clear();
  }

  // test both for success
  {
    EXPECT_TRUE(vault_service_->StoreChunkLocal(chunkname, content));

    google::protobuf::Closure *done1 =
        google::protobuf::NewCallback<TestCallback>(&cb_obj,
        &TestCallback::CallbackFunction);
    vault_service_->CheckChunk(&controller, &check_request, &check_response,
                               done1);
    ASSERT_TRUE(check_response.IsInitialized());
    EXPECT_EQ(kAck, static_cast<int>(check_response.result()));
    response.Clear();

    google::protobuf::Closure *done2 =
        google::protobuf::NewCallback<TestCallback>(&cb_obj,
        &TestCallback::CallbackFunction);
    vault_service_->GetChunk(&controller, &request, &response, done2);
    ASSERT_TRUE(response.IsInitialized());
    EXPECT_EQ(kAck, static_cast<int>(response.result()));
    EXPECT_EQ(content, response.content());
    response.Clear();
  }
}

TEST_F(VaultServicesTest, BEH_MAID_ServicesDeleteChunk) {
  rpcprotocol::Controller controller;
  maidsafe::DeleteChunkRequest request;
  maidsafe::DeleteChunkResponse response;

  maidsafe::SignedSize *signed_size = NULL;

  std::string pub_key, priv_key, pmid, pub_key_sig, req_sig, size_sig;
  CreateRSAKeys(&pub_key, &priv_key);
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);

  maidsafe::GenericPacket gp;
  gp.set_data("Generic System Packet Data");
  gp.set_signature(co.AsymSign(gp.data(), "", priv_key, crypto::STRING_STRING));

  std::string chunk_data(gp.SerializeAsString());
  std::string chunk_name(co.Hash(chunk_data, "", crypto::STRING_STRING, false));
  boost::uint64_t chunk_size(chunk_data.size());

  pub_key_sig = co.AsymSign(pub_key, "", priv_key, crypto::STRING_STRING);
  pmid = co.Hash(pub_key + pub_key_sig, "", crypto::STRING_STRING, false);

  size_sig = co.AsymSign(boost::lexical_cast<std::string>(chunk_size), "",
                         priv_key, crypto::STRING_STRING);

  req_sig = co.AsymSign(co.Hash(pub_key_sig + chunk_name + vault_pmid_, "",
                        crypto::STRING_STRING, false), "", priv_key,
                        crypto::STRING_STRING);

  TestCallback cb_obj;

  EXPECT_TRUE(vault_service_->StoreChunkLocal(chunk_name, chunk_data));
  EXPECT_TRUE(vault_service_->HasChunkLocal(chunk_name));

  for (int i = 0; i <= 4; ++i) {
    printf("--- CASE #%i --- \n", i);
    switch (i) {
      case 0:  // empty request
        break;
      case 1:  // unsigned request
        signed_size = request.mutable_signed_size();
        signed_size->set_data_size(chunk_size);
        signed_size->set_signature(size_sig);
        signed_size->set_pmid(pmid);
        signed_size->set_public_key(pub_key);
        signed_size->set_public_key_signature(pub_key_sig);
        request.set_chunkname(chunk_name);
        request.set_request_signature("fail");
        request.set_data_type(maidsafe::SYSTEM_PACKET);
        break;
      case 2:  // unsigned signed_size
        request.set_request_signature(req_sig);
        signed_size->set_signature("fail");
        break;
      case 3:  // wrong size
        signed_size->set_data_size(123);
        signed_size->set_signature(co.AsymSign("123", "", priv_key,
                                               crypto::STRING_STRING));
        break;
      case 4:  // invalid chunk name
        signed_size->set_data_size(chunk_size);
        signed_size->set_signature(size_sig);
        request.set_chunkname("fail");
        request.set_request_signature(co.AsymSign(co.Hash(pub_key_sig + "fail"
            + vault_pmid_, "", crypto::STRING_STRING, false), "", priv_key,
            crypto::STRING_STRING));
        break;
    }

    google::protobuf::Closure *done =
        google::protobuf::NewCallback<TestCallback>(&cb_obj,
        &TestCallback::CallbackFunction);
    vault_service_->DeleteChunk(&controller, &request, &response, done);
    ASSERT_TRUE(response.IsInitialized());
    EXPECT_NE(kAck, static_cast<int>(response.result()));
    response.Clear();
  }

  request.set_chunkname(co.Hash("abc", "", crypto::STRING_STRING, false));
  request.set_request_signature(co.AsymSign(co.Hash(pub_key_sig +
      request.chunkname() + vault_pmid_, "",
      crypto::STRING_STRING, false), "", priv_key,
      crypto::STRING_STRING));

  // test success for non-existing chunk
  {
    google::protobuf::Closure *done =
        google::protobuf::NewCallback<TestCallback>(&cb_obj,
        &TestCallback::CallbackFunction);
    vault_service_->DeleteChunk(&controller, &request, &response, done);
    ASSERT_TRUE(response.IsInitialized());
    EXPECT_EQ(kAck, static_cast<int>(response.result()));
    response.Clear();
  }

  request.set_chunkname(chunk_name);
  request.set_request_signature(req_sig);

  // test success for existing chunk
  {
    google::protobuf::Closure *done =
        google::protobuf::NewCallback<TestCallback>(&cb_obj,
        &TestCallback::CallbackFunction);
    vault_service_->DeleteChunk(&controller, &request, &response, done);
    ASSERT_TRUE(response.IsInitialized());
    EXPECT_EQ(kAck, static_cast<int>(response.result()));
    response.Clear();
  }

  EXPECT_FALSE(vault_service_->HasChunkLocal(chunk_name));
}

TEST_F(VaultServicesTest, BEH_MAID_ServicesValidityCheck) {
  rpcprotocol::Controller controller;
  maidsafe::ValidityCheckRequest request;
  maidsafe::ValidityCheckResponse response;

  std::string pub_key, priv_key, pmid, sig_pub_key, sig_req;
  CreateRSAKeys(&pub_key, &priv_key);
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);
  std::string content("This is a data chunk");
  std::string rnd_data(base::RandomString(20));
  std::string chunkname(co.Hash(content, "", crypto::STRING_STRING, false));
  std::string vc_hash(co.Hash(content + rnd_data, "", crypto::STRING_STRING,
                              false));
  CreateSignedRequest(pub_key, priv_key, chunkname, &pmid, &sig_pub_key,
                      &sig_req);

  TestCallback cb_obj;

  for (boost::uint32_t i = 0; i <= 1; ++i) {
    switch (i) {
      case 0:  // uninitialized request
        break;
      case 1:  // make LoadChunkLocal() fail
        request.set_chunkname(chunkname);
        request.set_random_data(rnd_data);
        break;
    }

    google::protobuf::Closure *done =
        google::protobuf::NewCallback<TestCallback>(&cb_obj,
        &TestCallback::CallbackFunction);
    vault_service_->ValidityCheck(&controller, &request, &response, done);
    ASSERT_TRUE(response.IsInitialized());
    EXPECT_NE(kAck, static_cast<int>(response.result()));
    response.Clear();
  }

  EXPECT_TRUE(vault_service_->StoreChunkLocal(chunkname, content));

  // test success
  {
    google::protobuf::Closure *done =
        google::protobuf::NewCallback<TestCallback>(&cb_obj,
        &TestCallback::CallbackFunction);
    vault_service_->ValidityCheck(&controller, &request, &response, done);
    ASSERT_TRUE(response.IsInitialized());
    EXPECT_EQ(kAck, static_cast<int>(response.result()));
    EXPECT_EQ(vc_hash, response.hash_content());
  }
}

TEST_F(VaultServicesTest, DISABLED_BEH_MAID_ServicesSwapChunk) {
  // TODO(Team#) test SwapChunk
  ASSERT_TRUE(false) << "NOT IMPLEMENTED";
}

TEST_F(VaultServicesTest, BEH_MAID_ServicesCacheChunk) {
  rpcprotocol::Controller controller;
  maidsafe::CacheChunkRequest request;
  maidsafe::CacheChunkResponse response;

  std::string pub_key, priv_key, pmid, sig_pub_key, sig_req;
  CreateRSAKeys(&pub_key, &priv_key);
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);
  std::string content("This is a data chunk");
  std::string chunkname(co.Hash(content, "", crypto::STRING_STRING, false));
  CreateSignedRequest(pub_key, priv_key, chunkname, &pmid, &sig_pub_key,
                      &sig_req);

  // Not initialised
  TestCallback cb_obj;
  google::protobuf::Closure *done = google::protobuf::NewCallback<TestCallback>
                                    (&cb_obj, &TestCallback::CallbackFunction);
  vault_service_->CacheChunk(&controller, &request, &response, done);
  ASSERT_TRUE(response.IsInitialized());
  EXPECT_EQ(kNack, static_cast<int>(response.result()));
  EXPECT_FALSE(vault_service_->vault_chunkstore_->Has(chunkname));
  response.Clear();

  // Wrong parameters
  request.set_chunkname("aaaaaaaaaaaaa");
  request.set_chunkcontent(content);
  request.set_pmid(pmid);
  request.set_public_key(pub_key);
  request.set_public_key_signature(sig_pub_key);
  request.set_request_signature(sig_req);
  done = google::protobuf::NewCallback<TestCallback>
         (&cb_obj, &TestCallback::CallbackFunction);
  vault_service_->CacheChunk(&controller, &request, &response, done);
  ASSERT_TRUE(response.IsInitialized());
  EXPECT_EQ(kNack, static_cast<int>(response.result()));
  EXPECT_FALSE(vault_service_->vault_chunkstore_->Has(chunkname));
  response.Clear();

  request.set_chunkname(chunkname);
  request.set_pmid("aaaaaaaaaaaaaa");
  done = google::protobuf::NewCallback<TestCallback>
         (&cb_obj, &TestCallback::CallbackFunction);
  vault_service_->CacheChunk(&controller, &request, &response, done);
  ASSERT_TRUE(response.IsInitialized());
  EXPECT_EQ(kNack, static_cast<int>(response.result()));
  EXPECT_FALSE(vault_service_->vault_chunkstore_->Has(chunkname));
  EXPECT_FALSE(fs::exists(vault_service_->vault_chunkstore_->GetChunkPath(
               chunkname, (maidsafe::kHashable | maidsafe::kCache), false)));
  response.Clear();

  request.set_pmid(pmid);
  done = google::protobuf::NewCallback<TestCallback>
         (&cb_obj, &TestCallback::CallbackFunction);
  vault_service_->CacheChunk(&controller, &request, &response, done);
  ASSERT_TRUE(response.IsInitialized());
  EXPECT_EQ(kAck, static_cast<int>(response.result()));
  EXPECT_TRUE(vault_service_->vault_chunkstore_->Has(chunkname));
  EXPECT_EQ(maidsafe::kHashable|maidsafe::kCache,
            vault_service_->vault_chunkstore_->chunk_type(chunkname));
  EXPECT_TRUE(fs::exists(vault_service_->vault_chunkstore_->GetChunkPath(
              chunkname, (maidsafe::kHashable | maidsafe::kCache), false)));
}

TEST_F(VaultServicesTest, BEH_MAID_ServicesGetChunkReferences) {
  rpcprotocol::Controller controller;
  maidsafe::GetChunkReferencesRequest request;
  maidsafe::GetChunkReferencesResponse response;

  std::string pub_key, priv_key, pmid, sig_pub_key, sig_req;
  CreateRSAKeys(&pub_key, &priv_key);
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);
  std::string content("This is a data chunk");
  std::string chunk_name(co.Hash(content, "", crypto::STRING_STRING, false));
  CreateSignedRequest(pub_key, priv_key, chunk_name, &pmid, &sig_pub_key,
                      &sig_req);

  TestCallback cb_obj;

  for (int i = 0; i <= 2; ++i) {
    switch (i) {
      case 0:  // empty request
        break;
      case 1:  // non-existant chunk info
        request.set_chunkname(chunk_name);
        break;
      case 2:  // no active watchers
        int required_references, required_payments;
        vault_service_->cih_.PrepareAddToWatchList(chunk_name, pmid, 9,
                                                   &required_references,
                                                   &required_payments);
        break;
    }
    google::protobuf::Closure *done =
        google::protobuf::NewCallback<TestCallback>
        (&cb_obj, &TestCallback::CallbackFunction);
    vault_service_->GetChunkReferences(&controller, &request, &response, done);
    ASSERT_TRUE(response.IsInitialized());
    EXPECT_EQ(kNack, static_cast<int>(response.result()));
    response.Clear();
  }

  // watchers, but no refs
  vault_service_->cih_.SetStoringDone(chunk_name, pmid);
  vault_service_->cih_.SetPaymentsDone(chunk_name, pmid);
  std::string creditor;
  int refunds;
  EXPECT_TRUE(vault_service_->cih_.TryCommitToWatchList(chunk_name, pmid,
                                                        &creditor, &refunds));
  {
    google::protobuf::Closure *done =
        google::protobuf::NewCallback<TestCallback>
        (&cb_obj, &TestCallback::CallbackFunction);
    vault_service_->GetChunkReferences(&controller, &request, &response, done);
    ASSERT_TRUE(response.IsInitialized());
    EXPECT_EQ(kAck, static_cast<int>(response.result()));
    EXPECT_EQ(0, response.references_size());
    response.Clear();
  }

  // now we have a reference
  vault_service_->cih_.AddToReferenceList(chunk_name, vault_service_->pmid_, 9);
  {
    google::protobuf::Closure *done =
        google::protobuf::NewCallback<TestCallback>
        (&cb_obj, &TestCallback::CallbackFunction);
    vault_service_->GetChunkReferences(&controller, &request, &response, done);
    ASSERT_TRUE(response.IsInitialized());
    EXPECT_EQ(kAck, static_cast<int>(response.result()));
    EXPECT_EQ(1, response.references_size());
    EXPECT_EQ(vault_service_->pmid_, response.references(0));
  }
}

TEST_F(MockVaultServicesTest, BEH_MAID_ServicesAddToWatchList) {
  delete vault_service_;
  vault_service_ = new VaultService(vault_pmid_, vault_public_key_,
                                    vault_private_key_,
                                    vault_public_key_signature_,
                                    vault_chunkstore_,
                                    &mock_vault_service_logic_,
                                    udt_transport_.transport_id(), kad_ops_);

  maidsafe::GetSyncDataResponse get_sync_data_response;
  vault_service_->AddStartupSyncData(get_sync_data_response);

  rpcprotocol::Controller controller;
  maidsafe::AddToWatchListRequest request;
  maidsafe::AddToWatchListResponse response;

  // client = node requesting to store a chunk
  // vlt = Vault storing the chunk
  // vault_service_ = this vault, i.e. the Chunk Info and Account Holder

  std::string client_pub_key, client_priv_key, client_pmid, client_pub_key_sig;
  std::string vlt_pub_key, vlt_priv_key, vlt_pmid, vlt_pub_key_sig;
  std::string size_sig;

  CreateRSAKeys(&client_pub_key, &client_priv_key);
  CreateRSAKeys(&vlt_pub_key, &vlt_priv_key);
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);

  client_pub_key_sig = co.AsymSign(client_pub_key, "", client_priv_key,
                                   crypto::STRING_STRING);
  client_pmid = co.Hash(client_pub_key + client_pub_key_sig, "",
                        crypto::STRING_STRING, false);
  vlt_pub_key_sig = co.AsymSign(vlt_pub_key, "", vlt_priv_key,
                                crypto::STRING_STRING);
  vlt_pmid = co.Hash(vlt_pub_key + vlt_pub_key_sig, "", crypto::STRING_STRING,
                     false);

  EXPECT_CALL(mock_vault_service_logic_,
              AmendRemoteAccount(testing::_, testing::_, testing::_,
                                 testing::_))
      .Times(testing::AtLeast(2))
      .WillRepeatedly(testing::WithArg<2>(testing::Invoke(
          boost::bind(&mock_vsl::RunVaultCallback, kSuccess, _1))));

  std::string chunk_data("This is a data chunk");
  std::string chunk_name(co.Hash(chunk_data, "", crypto::STRING_STRING, false));
  boost::uint64_t chunk_size(chunk_data.size());

  size_sig = co.AsymSign(boost::lexical_cast<std::string>(chunk_size), "",
                         client_priv_key, crypto::STRING_STRING);

  TestCallback cb_obj;

  boost::uint64_t space_offered = chunk_size * 3 / 2;

  maidsafe::SignedSize *signed_size;

  maidsafe::AmendAccountRequest amend_req;
  maidsafe::AmendAccountResponse amend_resp;
  signed_size = amend_req.mutable_signed_size();
  signed_size->set_data_size(space_offered);
  signed_size->set_signature(
      co.AsymSign(boost::lexical_cast<std::string>(space_offered), "",
                  client_priv_key, crypto::STRING_STRING));
  signed_size->set_pmid(client_pmid);
  signed_size->set_public_key(client_pub_key);
  signed_size->set_public_key_signature(client_pub_key_sig);
  amend_req.set_amendment_type(maidsafe::AmendAccountRequest::kSpaceOffered);
  amend_req.set_account_pmid(client_pmid);
  amend_req.set_chunkname(chunk_name);

  // Create the account first
  {
    google::protobuf::Closure *done =
        google::protobuf::NewCallback<TestCallback>
        (&cb_obj, &TestCallback::CallbackFunction);
    vault_service_->AmendAccount(&controller, &amend_req, &amend_resp, done);
    ASSERT_TRUE(amend_resp.IsInitialized());
    EXPECT_EQ(kAck, static_cast<int>(amend_resp.result()));
    amend_resp.Clear();
  }

  for (int i = 0; i <= 3; ++i) {
    switch (i) {
      case 0:  // empty request
        break;
      case 1:  // unsigned request
        signed_size = request.mutable_signed_size();
        signed_size->set_data_size(chunk_size);
        signed_size->set_signature(size_sig);
        signed_size->set_pmid(client_pmid);
        signed_size->set_public_key(client_pub_key);
        signed_size->set_public_key_signature(client_pub_key_sig);
        request.set_chunkname(chunk_name);
        request.set_request_signature("fail");
        break;
      case 2:  // unsigned size
        request.set_request_signature(co.AsymSign(co.Hash(client_pub_key_sig +
            chunk_name + vault_pmid_, "", crypto::STRING_STRING, false),
            "", client_priv_key, crypto::STRING_STRING));
        signed_size->set_signature("fail");
        break;
      case 3:  // zero size
        signed_size->set_data_size(0);
        signed_size->set_signature(co.AsymSign("0", "", client_priv_key,
                                   crypto::STRING_STRING));
        break;
    }

    google::protobuf::Closure *done =
        google::protobuf::NewCallback<TestCallback>(&cb_obj,
        &TestCallback::CallbackFunction);
    vault_service_->AddToWatchList(&controller, &request, &response, done);
    ASSERT_TRUE(response.IsInitialized());
    EXPECT_NE(kAck, static_cast<int>(response.result()));
    response.Clear();
  }

  signed_size->set_data_size(chunk_size);
  signed_size->set_signature(size_sig);

  maidsafe::AccountStatusRequest asreq;
  asreq.set_account_pmid(client_pmid);
  asreq.set_public_key(client_pub_key);
  asreq.set_public_key_signature(client_pub_key_sig);
  asreq.set_request_signature(co.AsymSign(co.Hash(client_pub_key_sig +
      co.Hash(client_pmid + kAccount, "", crypto::STRING_STRING, false) +
      vault_pmid_, "", crypto::STRING_STRING, false), "", client_priv_key,
      crypto::STRING_STRING));

  // SpaceTaken should be 0
  {
    maidsafe::AccountStatusResponse asrsp;
    google::protobuf::Closure *done =
        google::protobuf::NewCallback<TestCallback>(&cb_obj,
        &TestCallback::CallbackFunction);
    vault_service_->AccountStatus(&controller, &asreq, &asrsp, done);
    ASSERT_TRUE(asrsp.IsInitialized());
    EXPECT_EQ(boost::uint64_t(0), asrsp.space_taken());
  }

  // add to watch list as first
  {
    google::protobuf::Closure *done =
        google::protobuf::NewCallback<TestCallback>(&cb_obj,
        &TestCallback::CallbackFunction);
    vault_service_->AddToWatchList(&controller, &request, &response, done);
    ASSERT_TRUE(response.IsInitialized());
    EXPECT_EQ(kAck, static_cast<int>(response.result()));
    response.Clear();
  }

  // wait for amendments by the chunk info holder
  vault_service_->thread_pool_.waitForDone();

  // SpaceTaken should be none, because we don't have credits
  {
    maidsafe::AccountStatusResponse asrsp;
    google::protobuf::Closure *done =
        google::protobuf::NewCallback<TestCallback>(&cb_obj,
        &TestCallback::CallbackFunction);
    vault_service_->AccountStatus(&controller, &asreq, &asrsp, done);
    ASSERT_TRUE(asrsp.IsInitialized());
    EXPECT_EQ(boost::uint64_t(0), asrsp.space_taken());
  }

  // create the account
  {
    maidsafe::AmendAccountRequest aa_req;
    maidsafe::AmendAccountResponse aa_rsp;
    google::protobuf::Closure *done =
        google::protobuf::NewCallback<TestCallback>(&cb_obj,
        &TestCallback::CallbackFunction);
    signed_size = aa_req.mutable_signed_size();
    signed_size->set_data_size(chunk_size * kMinChunkCopies * 2);
    std::string ser_size(boost::lexical_cast<std::string>
                         (signed_size->data_size()));
    signed_size->set_signature(co.AsymSign(ser_size, "", client_priv_key,
                               crypto::STRING_STRING));
    signed_size->set_pmid(client_pmid);
    signed_size->set_public_key(client_pub_key);
    signed_size->set_public_key_signature(client_pub_key_sig);
    aa_req.set_amendment_type(maidsafe::AmendAccountRequest::kSpaceOffered);
    aa_req.set_account_pmid(client_pmid);
    vault_service_->AmendAccount(&controller, &aa_req, &aa_rsp, done);
    ASSERT_TRUE(aa_rsp.IsInitialized());
    EXPECT_EQ(kAck, static_cast<int>(aa_rsp.result()));
  }

  // add to watch list as first, second try
  {
    google::protobuf::Closure *done =
        google::protobuf::NewCallback<TestCallback>(&cb_obj,
        &TestCallback::CallbackFunction);
    vault_service_->AddToWatchList(&controller, &request, &response, done);
    ASSERT_TRUE(response.IsInitialized());
    EXPECT_EQ(kAck, static_cast<int>(response.result()));
    response.Clear();
  }

  // wait for amendments by the chunk info holder
  vault_service_->thread_pool_.waitForDone();

  // SpaceTaken should be four times the chunk size
  {
    maidsafe::AccountStatusResponse asrsp;
    google::protobuf::Closure *done =
        google::protobuf::NewCallback<TestCallback>(&cb_obj,
        &TestCallback::CallbackFunction);
    vault_service_->AccountStatus(&controller, &asreq, &asrsp, done);
    ASSERT_TRUE(asrsp.IsInitialized());
    EXPECT_EQ(kMinChunkCopies * chunk_size, asrsp.space_taken());
  }
}

TEST_F(MockVaultServicesTest, FUNC_MAID_ServicesRemoveFromWatchList) {
  delete vault_service_;
  vault_service_ = new VaultService(vault_pmid_, vault_public_key_,
                                    vault_private_key_,
                                    vault_public_key_signature_,
                                    vault_chunkstore_,
                                    &mock_vault_service_logic_,
                                    udt_transport_.transport_id(), kad_ops_);

  maidsafe::GetSyncDataResponse get_sync_data_response;
  vault_service_->AddStartupSyncData(get_sync_data_response);

  rpcprotocol::Controller controller;
  maidsafe::AddToWatchListRequest add_request;
  maidsafe::AddToWatchListResponse add_response;
  maidsafe::RemoveFromWatchListRequest rem_request;
  maidsafe::RemoveFromWatchListResponse rem_response;

  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);

  EXPECT_CALL(mock_vault_service_logic_,
              AmendRemoteAccount(testing::_, testing::_, testing::_,
                                 testing::_))
      .Times(testing::AtLeast(kMinChunkCopies + 1))
      .WillRepeatedly(testing::WithArg<2>(testing::Invoke(
          boost::bind(&mock_vsl::RunVaultCallback, kSuccess, _1))));

  std::string chunk_data("This is a data chunk");
  std::string chunk_name(co.Hash(chunk_data, "", crypto::STRING_STRING, false));
  boost::uint64_t chunk_size(chunk_data.size());

  std::string client_pub_key[kMinChunkCopies + 1];
  std::string client_priv_key[kMinChunkCopies + 1];
  std::string client_pmid[kMinChunkCopies + 1];
  std::string client_pub_key_sig[kMinChunkCopies + 1];
  maidsafe::AccountStatusRequest client_asreq[kMinChunkCopies + 1];

  maidsafe::SignedSize *signed_size;
  TestCallback cb_obj;

  // initialise 5 clients and add them to the Watch List
  for (int i = 0; i < kMinChunkCopies + 1; ++i) {
    printf("Initialising client %d of %d...\n", i + 1, kMinChunkCopies + 1);
    CreateRSAKeys(&client_pub_key[i], &client_priv_key[i]);
    client_pub_key_sig[i] = co.AsymSign(client_pub_key[i], "",
                                        client_priv_key[i],
                                        crypto::STRING_STRING);
    client_pmid[i] = co.Hash(client_pub_key[i] + client_pub_key_sig[i], "",
                             crypto::STRING_STRING, false);

    signed_size = add_request.mutable_signed_size();
    signed_size->set_data_size(chunk_size);
    signed_size->set_signature(co.AsymSign(boost::lexical_cast<std::string>
        (chunk_size), "", client_priv_key[i], crypto::STRING_STRING));
    signed_size->set_pmid(client_pmid[i]);
    signed_size->set_public_key(client_pub_key[i]);
    signed_size->set_public_key_signature(client_pub_key_sig[i]);

    add_request.set_chunkname(chunk_name);
    add_request.set_request_signature(co.AsymSign(co.Hash(client_pub_key_sig[i]
        + chunk_name + vault_pmid_, "", crypto::STRING_STRING, false), "",
        client_priv_key[i], crypto::STRING_STRING));

    client_asreq[i].set_account_pmid(client_pmid[i]);
    client_asreq[i].set_public_key(client_pub_key[i]);
    client_asreq[i].set_public_key_signature(client_pub_key_sig[i]);
    client_asreq[i].set_request_signature(co.AsymSign(co.Hash(
        client_pub_key_sig[i] + co.Hash(client_pmid[i] + kAccount, "",
        crypto::STRING_STRING, false) + vault_pmid_, "", crypto::STRING_STRING,
        false), "", client_priv_key[i], crypto::STRING_STRING));

    // create #i's account
    {
      maidsafe::AmendAccountRequest aa_req;
      maidsafe::AmendAccountResponse aa_rsp;
      google::protobuf::Closure *done =
          google::protobuf::NewCallback<TestCallback>(&cb_obj,
          &TestCallback::CallbackFunction);
      signed_size = aa_req.mutable_signed_size();
      signed_size->set_data_size(chunk_size * kMinChunkCopies * 2);
      std::string ser_size(boost::lexical_cast<std::string>
                           (signed_size->data_size()));
      signed_size->set_signature(co.AsymSign(ser_size, "", client_priv_key[i],
                                 crypto::STRING_STRING));
      signed_size->set_pmid(client_pmid[i]);
      signed_size->set_public_key(client_pub_key[i]);
      signed_size->set_public_key_signature(client_pub_key_sig[i]);
      aa_req.set_amendment_type(maidsafe::AmendAccountRequest::kSpaceOffered);
      aa_req.set_account_pmid(client_pmid[i]);
      vault_service_->AmendAccount(&controller, &aa_req, &aa_rsp, done);
      ASSERT_TRUE(aa_rsp.IsInitialized());
      EXPECT_EQ(kAck, static_cast<int>(aa_rsp.result()));
    }

    // add #i to Watch List
    {
      google::protobuf::Closure *done =
          google::protobuf::NewCallback<TestCallback>(&cb_obj,
          &TestCallback::CallbackFunction);
      add_response.Clear();
      vault_service_->AddToWatchList(&controller, &add_request, &add_response,
                                     done);
      ASSERT_TRUE(add_response.IsInitialized());
      EXPECT_EQ(kAck, static_cast<int>(add_response.result()));
    }

    // wait for amendments by the chunk info holder
    vault_service_->thread_pool_.waitForDone();

    // simulate uploaded chunk for #i
    if (add_response.upload_count() > 0) {
      maidsafe::AddToReferenceListRequest add_ref_request;
      maidsafe::AddToReferenceListResponse add_ref_response;

      maidsafe::StoreContract *sc = add_ref_request.mutable_store_contract();
      maidsafe::StoreContract::InnerContract *ic = sc->mutable_inner_contract();
      maidsafe::SignedSize *sz = ic->mutable_signed_size();

      sz->set_data_size(chunk_size);
      sz->set_signature(co.AsymSign(boost::lexical_cast<std::string>
          (chunk_size), "", client_priv_key[i], crypto::STRING_STRING));
      sz->set_pmid(client_pmid[i]);
      sz->set_public_key(client_pub_key[i]);
      sz->set_public_key_signature(client_pub_key_sig[i]);

      ic->set_result(kAck);

      sc->set_signature(co.AsymSign(ic->SerializeAsString(), "",
                                    vault_private_key_, crypto::STRING_STRING));
      sc->set_pmid(vault_pmid_);
      sc->set_public_key(vault_public_key_);
      sc->set_public_key_signature(vault_public_key_signature_);

      add_ref_request.set_chunkname(chunk_name);
      add_ref_request.set_request_signature(co.AsymSign(co.Hash(
          vault_public_key_signature_+ chunk_name + vault_pmid_, "",
          crypto::STRING_STRING, false), "", vault_private_key_,
          crypto::STRING_STRING));

      google::protobuf::Closure *done =
          google::protobuf::NewCallback<TestCallback>(&cb_obj,
          &TestCallback::CallbackFunction);
      vault_service_->AddToReferenceList(&controller, &add_ref_request,
                                         &add_ref_response, done);
      ASSERT_TRUE(add_ref_response.IsInitialized());
      EXPECT_EQ(kAck, static_cast<int>(add_ref_response.result()));
    }

    // wait for amendments by the chunk info holder
    vault_service_->thread_pool_.waitForDone();

    // check SpaceTaken for #i except #0
    if (i > 0) {
      maidsafe::AccountStatusResponse asrsp;
      google::protobuf::Closure *done =
          google::protobuf::NewCallback<TestCallback>(&cb_obj,
          &TestCallback::CallbackFunction);
      vault_service_->AccountStatus(&controller, &client_asreq[i], &asrsp,
                                    done);
      ASSERT_TRUE(asrsp.IsInitialized());
      EXPECT_EQ(chunk_size, asrsp.space_taken());
    }

    // check SpaceTaken for #0
    {
      maidsafe::AccountStatusResponse asrsp;
      google::protobuf::Closure *done =
          google::protobuf::NewCallback<TestCallback>(&cb_obj,
          &TestCallback::CallbackFunction);
      vault_service_->AccountStatus(&controller, &client_asreq[0], &asrsp,
                                    done);
      EXPECT_TRUE(asrsp.IsInitialized());
      if (i <= kMinChunkCopies - 1)
        EXPECT_EQ((kMinChunkCopies - i) * chunk_size, asrsp.space_taken());
      else
        EXPECT_EQ(chunk_size, asrsp.space_taken());
    }
  }

  rem_request.set_chunkname(chunk_name);
  rem_request.set_pmid(client_pmid[0]);
  rem_request.set_public_key(client_pub_key[0]);
  rem_request.set_public_key_signature(client_pub_key_sig[0]);
  rem_request.set_request_signature("fail");

  // invalid removal request only for the first client
  {
    google::protobuf::Closure *done =
        google::protobuf::NewCallback<TestCallback>(&cb_obj,
        &TestCallback::CallbackFunction);
    vault_service_->RemoveFromWatchList(&controller, &rem_request,
                                        &rem_response, done);
    ASSERT_TRUE(rem_response.IsInitialized());
    EXPECT_NE(kAck, static_cast<int>(rem_response.result()));
    rem_response.Clear();
  }

  // now remove all, from last to first
  for (int i = kMinChunkCopies; i >= 0; --i) {
    rem_request.set_pmid(client_pmid[i]);
    rem_request.set_public_key(client_pub_key[i]);
    rem_request.set_public_key_signature(client_pub_key_sig[i]);
    rem_request.set_request_signature(co.AsymSign(co.Hash(client_pub_key_sig[i]
        + chunk_name + vault_pmid_, "", crypto::STRING_STRING, false), "",
        client_priv_key[i], crypto::STRING_STRING));

    // remove #i from Watch List
    {
      google::protobuf::Closure *done =
          google::protobuf::NewCallback<TestCallback>(&cb_obj,
          &TestCallback::CallbackFunction);
      vault_service_->RemoveFromWatchList(&controller, &rem_request,
                                          &rem_response, done);
      ASSERT_TRUE(rem_response.IsInitialized());
      EXPECT_EQ(kAck, static_cast<int>(rem_response.result()));
      rem_response.Clear();
    }

    // wait for amendments by the chunk info holder
    vault_service_->thread_pool_.waitForDone();

    // check SpaceTaken for #i
    {
      maidsafe::AccountStatusResponse asrsp;
      google::protobuf::Closure *done =
          google::protobuf::NewCallback<TestCallback>(&cb_obj,
          &TestCallback::CallbackFunction);
      vault_service_->AccountStatus(&controller, &client_asreq[i], &asrsp,
                                    done);
      ASSERT_TRUE(asrsp.IsInitialized());
      if (i == 0 || i == kMinChunkCopies)
        EXPECT_EQ(boost::uint64_t(0), asrsp.space_taken());
      else
        EXPECT_EQ(chunk_size, asrsp.space_taken());
    }
  }
}

TEST_F(MockVaultServicesTest, BEH_MAID_ServicesAddToReferenceList) {
  delete vault_service_;
  vault_service_ = new VaultService(vault_pmid_, vault_public_key_,
                                    vault_private_key_,
                                    vault_public_key_signature_,
                                    vault_chunkstore_,
                                    &mock_vault_service_logic_,
                                    udt_transport_.transport_id(), kad_ops_);

  maidsafe::GetSyncDataResponse get_sync_data_response;
  vault_service_->AddStartupSyncData(get_sync_data_response);

  rpcprotocol::Controller controller;
  maidsafe::AddToReferenceListRequest request;
  maidsafe::AddToReferenceListResponse response;

  maidsafe::SignedSize *signed_size = NULL;
  maidsafe::StoreContract *store_contract = NULL;
  maidsafe::StoreContract::InnerContract *inner_contract = NULL;

  // client = node requesting to store a chunk
  // vlt = Vault storing the chunk
  // vault_service_ = this vault, i.e. the Chunk Info and Account Holder

  std::string client_pub_key, client_priv_key, client_pmid, client_pub_key_sig;
  std::string vlt_pub_key, vlt_priv_key, vlt_pmid, vlt_pub_key_sig;
  std::string size_sig;

  CreateRSAKeys(&client_pub_key, &client_priv_key);
  CreateRSAKeys(&vlt_pub_key, &vlt_priv_key);
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);

  client_pub_key_sig = co.AsymSign(client_pub_key, "", client_priv_key,
                                   crypto::STRING_STRING);
  client_pmid = co.Hash(client_pub_key + client_pub_key_sig, "",
                        crypto::STRING_STRING, false);
  vlt_pub_key_sig = co.AsymSign(vlt_pub_key, "", vlt_priv_key,
                                crypto::STRING_STRING);
  vlt_pmid = co.Hash(vlt_pub_key + vlt_pub_key_sig, "", crypto::STRING_STRING,
                     false);

  EXPECT_CALL(mock_vault_service_logic_,
              AmendRemoteAccount(testing::_, testing::_, testing::_,
                                 testing::_))
      .Times(testing::AtLeast(2))
      .WillRepeatedly(testing::WithArg<2>(testing::Invoke(
          boost::bind(&mock_vsl::RunVaultCallback, kSuccess, _1))));

  std::string chunk_data("This is a data chunk");
  std::string chunk_name(co.Hash(chunk_data, "", crypto::STRING_STRING, false));
  boost::uint64_t chunk_size(chunk_data.size());

  size_sig = co.AsymSign(boost::lexical_cast<std::string>(chunk_size), "",
                         client_priv_key, crypto::STRING_STRING);

  TestCallback cb_obj;

  for (int i = 0; i <= 7; ++i) {
    printf("\n--- CASE #%i --- \n", i);
    switch (i) {
      case 0:  // empty request
        break;
      case 1:  // unsigned request
        store_contract = request.mutable_store_contract();
        inner_contract = store_contract->mutable_inner_contract();
        signed_size = inner_contract->mutable_signed_size();
        signed_size->set_data_size(chunk_size);
        signed_size->set_signature(size_sig);
        signed_size->set_pmid(client_pmid);
        signed_size->set_public_key(client_pub_key);
        signed_size->set_public_key_signature(client_pub_key_sig);
        inner_contract->set_result(kAck);
        store_contract->set_signature(co.AsymSign(
            inner_contract->SerializeAsString(), "", vlt_priv_key,
            crypto::STRING_STRING));
        store_contract->set_pmid(vlt_pmid);
        store_contract->set_public_key(vlt_pub_key);
        store_contract->set_public_key_signature(vlt_pub_key_sig);

        request.set_chunkname(chunk_name);
        request.set_request_signature("fail");
        break;
      case 2:  // unsigned contract
        store_contract->set_signature("fail");
        request.set_request_signature(co.AsymSign(co.Hash(vlt_pub_key_sig +
            chunk_name + vault_pmid_, "", crypto::STRING_STRING, false),
            "", vlt_priv_key, crypto::STRING_STRING));
        break;
      case 3:  // unsigned size
        signed_size->set_signature("fail");
        store_contract->set_signature(co.AsymSign(
            inner_contract->SerializeAsString(), "", vlt_priv_key,
            crypto::STRING_STRING));
        break;
      case 4:  // zero size
        signed_size->set_data_size(0);
        signed_size->set_signature(co.AsymSign("0", "", client_priv_key,
                                   crypto::STRING_STRING));
        store_contract->set_signature(co.AsymSign(
            inner_contract->SerializeAsString(), "", vlt_priv_key,
            crypto::STRING_STRING));
        break;
      case 5:  // rejected contract
        signed_size->set_data_size(chunk_size);
        signed_size->set_signature(size_sig);
        inner_contract->set_result(kNack);
        store_contract->set_signature(co.AsymSign(
            inner_contract->SerializeAsString(), "", vlt_priv_key,
            crypto::STRING_STRING));
        break;
      case 6:  // invalid chunk name
        inner_contract->set_result(kAck);
        store_contract->set_signature(co.AsymSign(
            inner_contract->SerializeAsString(), "", vlt_priv_key,
            crypto::STRING_STRING));
        request.set_chunkname("fail");
        request.set_request_signature(co.AsymSign(co.Hash(vlt_pub_key_sig +
            "fail" + vault_pmid_, "", crypto::STRING_STRING, false), "",
            vlt_priv_key, crypto::STRING_STRING));
        break;
      case 7:  // non-existing watchlist
        request.set_chunkname(chunk_name);
        request.set_request_signature(co.AsymSign(co.Hash(vlt_pub_key_sig +
            chunk_name + vault_pmid_, "", crypto::STRING_STRING, false), "",
            vlt_priv_key, crypto::STRING_STRING));
        break;
    }

    google::protobuf::Closure *done =
        google::protobuf::NewCallback<TestCallback>(&cb_obj,
        &TestCallback::CallbackFunction);
    vault_service_->AddToReferenceList(&controller, &request, &response, done);
    ASSERT_TRUE(response.IsInitialized());
    EXPECT_NE(kAck, static_cast<int>(response.result()));
    response.Clear();
  }

  maidsafe::AccountStatusRequest asreq;
  asreq.set_account_pmid(vlt_pmid);
  asreq.set_public_key(vlt_pub_key);
  asreq.set_public_key_signature(vlt_pub_key_sig);
  asreq.set_request_signature(co.AsymSign(co.Hash(vlt_pub_key_sig +
      co.Hash(vlt_pmid + kAccount, "", crypto::STRING_STRING, false) +
      vault_pmid_, "", crypto::STRING_STRING, false), "", vlt_priv_key,
      crypto::STRING_STRING));

  // SpaceGiven should be 0
  {
    maidsafe::AccountStatusResponse asrsp;
    google::protobuf::Closure *done =
        google::protobuf::NewCallback<TestCallback>(&cb_obj,
        &TestCallback::CallbackFunction);
    vault_service_->AccountStatus(&controller, &asreq, &asrsp, done);
    ASSERT_TRUE(asrsp.IsInitialized());
    EXPECT_EQ(boost::uint64_t(0), asrsp.space_given());
  }

  // create client's account
  {
    maidsafe::AmendAccountRequest aa_req;
    maidsafe::AmendAccountResponse aa_rsp;
    google::protobuf::Closure *done =
        google::protobuf::NewCallback<TestCallback>(&cb_obj,
        &TestCallback::CallbackFunction);
    signed_size = aa_req.mutable_signed_size();
    signed_size->set_data_size(chunk_size * kMinChunkCopies);
    std::string ser_size(boost::lexical_cast<std::string>
                         (signed_size->data_size()));
    signed_size->set_signature(co.AsymSign(ser_size, "", client_priv_key,
                               crypto::STRING_STRING));
    signed_size->set_pmid(client_pmid);
    signed_size->set_public_key(client_pub_key);
    signed_size->set_public_key_signature(client_pub_key_sig);
    aa_req.set_amendment_type(maidsafe::AmendAccountRequest::kSpaceOffered);
    aa_req.set_account_pmid(client_pmid);
    vault_service_->AmendAccount(&controller, &aa_req, &aa_rsp, done);
    ASSERT_TRUE(aa_rsp.IsInitialized());
    EXPECT_EQ(kAck, static_cast<int>(aa_rsp.result()));
  }

  // create vault's account
  {
    maidsafe::AmendAccountRequest aa_req;
    maidsafe::AmendAccountResponse aa_rsp;
    google::protobuf::Closure *done =
        google::protobuf::NewCallback<TestCallback>(&cb_obj,
        &TestCallback::CallbackFunction);
    signed_size = aa_req.mutable_signed_size();
    signed_size->set_data_size(chunk_size * kMinChunkCopies);
    std::string ser_size(boost::lexical_cast<std::string>
                         (signed_size->data_size()));
    signed_size->set_signature(co.AsymSign(ser_size, "", vlt_priv_key,
                               crypto::STRING_STRING));
    signed_size->set_pmid(vlt_pmid);
    signed_size->set_public_key(vlt_pub_key);
    signed_size->set_public_key_signature(vlt_pub_key_sig);
    aa_req.set_amendment_type(maidsafe::AmendAccountRequest::kSpaceOffered);
    aa_req.set_account_pmid(vlt_pmid);
    vault_service_->AmendAccount(&controller, &aa_req, &aa_rsp, done);
    ASSERT_TRUE(aa_rsp.IsInitialized());
    EXPECT_EQ(kAck, static_cast<int>(aa_rsp.result()));
  }

  // add client to Watch List
  {
    maidsafe::AddToWatchListRequest add_request;
    maidsafe::AddToWatchListResponse add_response;

    signed_size = add_request.mutable_signed_size();
    signed_size->set_data_size(chunk_size);
    signed_size->set_signature(co.AsymSign(boost::lexical_cast<std::string>
        (chunk_size), "", client_priv_key, crypto::STRING_STRING));
    signed_size->set_pmid(client_pmid);
    signed_size->set_public_key(client_pub_key);
    signed_size->set_public_key_signature(client_pub_key_sig);

    add_request.set_chunkname(chunk_name);
    add_request.set_request_signature(co.AsymSign(co.Hash(client_pub_key_sig
        + chunk_name + vault_pmid_, "", crypto::STRING_STRING, false), "",
        client_priv_key, crypto::STRING_STRING));

    google::protobuf::Closure *done =
        google::protobuf::NewCallback<TestCallback>(&cb_obj,
        &TestCallback::CallbackFunction);
    vault_service_->AddToWatchList(&controller, &add_request, &add_response,
                                   done);
    ASSERT_TRUE(add_response.IsInitialized());
    EXPECT_EQ(kAck, static_cast<int>(add_response.result()));
  }

  // add vault to Reference List
  {
    google::protobuf::Closure *done =
        google::protobuf::NewCallback<TestCallback>(&cb_obj,
        &TestCallback::CallbackFunction);
    vault_service_->AddToReferenceList(&controller, &request, &response, done);
    ASSERT_TRUE(response.IsInitialized());
    EXPECT_EQ(kAck, static_cast<int>(response.result()));
    response.Clear();
  }

  // wait for amendments by the chunk info holder
  vault_service_->thread_pool_.waitForDone();

  // SpaceGiven should be the chunk size
  {
    maidsafe::AccountStatusResponse asrsp;
    google::protobuf::Closure *done =
        google::protobuf::NewCallback<TestCallback>(&cb_obj,
        &TestCallback::CallbackFunction);
    vault_service_->AccountStatus(&controller, &asreq, &asrsp, done);
    ASSERT_TRUE(asrsp.IsInitialized());
    EXPECT_EQ(chunk_size, asrsp.space_given());
  }
}

TEST_F(MockVaultServicesTest, FUNC_MAID_ServicesAmendAccount) {
  boost::shared_ptr<VaultRpcs> vault_rpcs;
  boost::shared_ptr<kad::KNode> knode;
  MockVsl mock_vault_service_logic(vault_rpcs, kad_ops_);
  delete vault_service_;
  vault_service_ = new VaultService(vault_pmid_, vault_public_key_,
                                    vault_private_key_,
                                    vault_public_key_signature_,
                                    vault_chunkstore_,
                                    &mock_vault_service_logic_,
                                    udt_transport_.transport_id(), kad_ops_);

  maidsafe::GetSyncDataResponse get_sync_data_response;
  vault_service_->AddStartupSyncData(get_sync_data_response);

  rpcprotocol::Controller controller;
  maidsafe::AmendAccountRequest request;
  maidsafe::AmendAccountResponse response;

  mock_vsl::KGroup k_group(test_vault_service::K);

  std::string client_pub_key, client_priv_key, client_pmid, client_pub_key_sig;
  std::string size_sig;

  CreateRSAKeys(&client_pub_key, &client_priv_key);
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);

  client_pub_key_sig = co.AsymSign(client_pub_key, "", client_priv_key,
                                   crypto::STRING_STRING);
  client_pmid = co.Hash(client_pub_key + client_pub_key_sig, "",
                        crypto::STRING_STRING, false);
  std::string client_account_name = co.Hash(client_pmid + kAccount, "",
                                            crypto::STRING_STRING, false);

  std::string chunk_data("This is a data chunk");
  std::string chunk_name(co.Hash(chunk_data, "", crypto::STRING_STRING, false));
  boost::uint64_t chunk_size(chunk_data.size());

  EXPECT_CALL(*mock_vault_service_logic.kadops(),
              FindKClosestNodes(chunk_name,
                                testing::An<kad::VoidFunctorOneString>()))
      .Times(testing::AtLeast(6))
      .WillRepeatedly(testing::WithArg<1>(testing::Invoke(
          boost::bind(&mock_kadops::RunCallback,
          k_group.serialised_find_nodes_response(), _1))));

  size_sig = co.AsymSign(boost::lexical_cast<std::string>(chunk_size), "",
                         client_priv_key, crypto::STRING_STRING);

  TestCallback cb_obj;

  boost::uint64_t space_offered = chunk_size * 3 / 2;

  request.Clear();
  {
    maidsafe::SignedSize *signed_size = request.mutable_signed_size();
    signed_size->set_data_size(space_offered);
    signed_size->set_signature(
        co.AsymSign(boost::lexical_cast<std::string>(space_offered), "",
                    client_priv_key, crypto::STRING_STRING));
    signed_size->set_pmid(client_pmid);
    signed_size->set_public_key(client_pub_key);
    signed_size->set_public_key_signature(client_pub_key_sig);
  }
  request.set_amendment_type(maidsafe::AmendAccountRequest::kSpaceOffered);
  request.set_account_pmid(client_pmid);
  request.set_chunkname(chunk_name);

  // Create the account first
  google::protobuf::Closure *done =
      google::protobuf::NewCallback<TestCallback>
      (&cb_obj, &TestCallback::CallbackFunction);
  {
    vault_service_->AmendAccount(&controller, &request, &response, done);
    ASSERT_TRUE(response.IsInitialized());
    EXPECT_EQ(kAck, static_cast<int>(response.result()));
    response.Clear();
  }

  // Create an amendment awaiting a single further request to succeed
  std::vector<maidsafe::AmendAccountRequest> requests;
  std::vector<maidsafe::AmendAccountResponse> responses;
  std::vector<google::protobuf::Closure*> callbacks;
  int success_count(0);

  for (int i = 0; i <= 3; ++i) {
    printf("--- CASE #%i ---\n", i);
    maidsafe::SignedSize *signed_size;
    k_group.MakeAmendAccountRequests(
      maidsafe::AmendAccountRequest::kSpaceGivenInc, client_pmid, chunk_size,
      chunk_name, &requests);
    switch (i) {
      case 0:  // empty request
        for (int i = 0; i < test_vault_service::K; ++i)
          requests.at(i).Clear();
        break;
      case 1:  // unsigned size
        for (int i = 0; i < test_vault_service::K; ++i) {
          signed_size = requests.at(i).mutable_signed_size();
          signed_size->set_signature("fail");
        }
        break;
      case 2:  // zero size
        for (int i = 0; i < test_vault_service::K; ++i) {
          signed_size = requests.at(i).mutable_signed_size();
          signed_size->set_data_size(0);
          signed_size->set_signature(
              co.AsymSign(boost::lexical_cast<std::string>(0), "",
                          client_priv_key, crypto::STRING_STRING));
        }
        break;
      case 3:  // missing chunk name
        for (int i = 0; i < test_vault_service::K; ++i) {
          requests.at(i).clear_chunkname();
        }
        break;
    }

    for (int i = 0; i < test_vault_service::K; ++i) {
      maidsafe::AmendAccountResponse response;
      responses.push_back(response);
      google::protobuf::Closure *done = google::protobuf::NewCallback(&cb_obj,
          &TestCallback::CallbackFunction);
      callbacks.push_back(done);
    }
    for (int i = 0; i < test_vault_service::K; ++i) {
      printf("REQ %02d/%02d - ", i+1, test_vault_service::K);
      vault_service_->AmendAccount(&controller, &requests.at(i),
          &responses.at(i), callbacks.at(i));
    }
    success_count = 0;
    for (int i = 0; i < test_vault_service::K; ++i) {
      ASSERT_TRUE(responses.at(i).IsInitialized());
      if (static_cast<int>(responses.at(i).result()) == kAck)
        ++success_count;
    }
    EXPECT_EQ(success_count, 0);
    responses.clear();
    callbacks.clear();
    vault_service_->aah_.amendments_.clear();
  }

  maidsafe::AccountStatusRequest asreq;
  asreq.set_account_pmid(client_pmid);
  asreq.set_space_requested(chunk_size);

  // should have enough space to store chunk
  {
    maidsafe::AccountStatusResponse asrsp;
    google::protobuf::Closure *done =
        google::protobuf::NewCallback<TestCallback>(&cb_obj,
        &TestCallback::CallbackFunction);
    vault_service_->AccountStatus(&controller, &asreq, &asrsp, done);
    ASSERT_TRUE(asrsp.IsInitialized());
    EXPECT_EQ(kAck, static_cast<int>(asrsp.result()));
  }

  asreq.clear_space_requested();
  asreq.set_public_key(client_pub_key);
  asreq.set_public_key_signature(client_pub_key_sig);
  asreq.set_request_signature(co.AsymSign(co.Hash(client_pub_key_sig +
      co.Hash(client_pmid + kAccount, "", crypto::STRING_STRING, false) +
      vault_pmid_, "", crypto::STRING_STRING, false), "", client_priv_key,
      crypto::STRING_STRING));

  // current SpaceTaken should be 0
  {
    maidsafe::AccountStatusResponse asrsp;
    google::protobuf::Closure *done =
        google::protobuf::NewCallback<TestCallback>(&cb_obj,
        &TestCallback::CallbackFunction);
    vault_service_->AccountStatus(&controller, &asreq, &asrsp, done);
    ASSERT_TRUE(asrsp.IsInitialized());
    EXPECT_EQ(kAck, static_cast<int>(asrsp.result()));
    EXPECT_EQ(space_offered, asrsp.space_offered());
    EXPECT_EQ(boost::uint64_t(0), asrsp.space_taken());
    EXPECT_EQ(boost::uint64_t(0), asrsp.space_given());
    printf("Passed getting status with 0 space taken.\n");
  }

  // increase SpaceTaken
  k_group.MakeAmendAccountRequests(
    maidsafe::AmendAccountRequest::kSpaceTakenInc, client_pmid, chunk_size,
    chunk_name, &requests);
  responses.clear();
  callbacks.clear();
  for (int i = 0; i < test_vault_service::K; ++i) {
    maidsafe::AmendAccountResponse response;
    responses.push_back(response);
    google::protobuf::Closure *done = google::protobuf::NewCallback(&cb_obj,
        &TestCallback::CallbackFunction);
    callbacks.push_back(done);
  }
  for (int i = 0; i < test_vault_service::K; ++i) {
    vault_service_->AmendAccount(&controller, &requests.at(i), &responses.at(i),
        callbacks.at(i));
  }
  success_count = 0;
  for (int i = 0; i < test_vault_service::K; ++i) {
    ASSERT_TRUE(responses.at(i).IsInitialized());
    if (static_cast<int>(responses.at(i).result()) == kAck)
      ++success_count;
  }
  EXPECT_GE(success_count, test_vault_service::K - 1);
  printf("Completed incrementing space taken.\n");

  // current SpaceTaken should be chunk_size
  {
    maidsafe::AccountStatusResponse asrsp;
    google::protobuf::Closure *done =
        google::protobuf::NewCallback<TestCallback>(&cb_obj,
        &TestCallback::CallbackFunction);
    vault_service_->AccountStatus(&controller, &asreq, &asrsp, done);
    ASSERT_TRUE(asrsp.IsInitialized());
    EXPECT_EQ(space_offered, asrsp.space_offered());
    EXPECT_EQ(chunk_size, asrsp.space_taken());
    EXPECT_EQ(boost::uint64_t(0), asrsp.space_given());
    printf("Completed getting status with appropriate space taken.\n");
  }

  asreq.set_space_requested(chunk_size);

  // shouldn't have enough space to store chunk
  {
    maidsafe::AccountStatusResponse asrsp;
    google::protobuf::Closure *done =
        google::protobuf::NewCallback<TestCallback>(&cb_obj,
        &TestCallback::CallbackFunction);
    vault_service_->AccountStatus(&controller, &asreq, &asrsp, done);
    ASSERT_TRUE(asrsp.IsInitialized());
    EXPECT_NE(kAck, static_cast<int>(asrsp.result()));
  }

  asreq.clear_space_requested();

  // decrease SpaceTaken
  k_group.MakeAmendAccountRequests(
    maidsafe::AmendAccountRequest::kSpaceTakenDec, client_pmid, chunk_size,
    chunk_name, &requests);
  responses.clear();
  callbacks.clear();
  for (int i = 0; i < test_vault_service::K; ++i) {
    maidsafe::AmendAccountResponse response;
    responses.push_back(response);
    google::protobuf::Closure *done = google::protobuf::NewCallback(&cb_obj,
        &TestCallback::CallbackFunction);
    callbacks.push_back(done);
  }
  for (int i = 0; i < test_vault_service::K; ++i) {
    vault_service_->AmendAccount(&controller, &requests.at(i), &responses.at(i),
        callbacks.at(i));
  }
  success_count = 0;
  for (int i = 0; i < test_vault_service::K; ++i) {
    ASSERT_TRUE(responses.at(i).IsInitialized());
    if (static_cast<int>(responses.at(i).result()) == kAck)
      ++success_count;
  }
  EXPECT_GE(success_count, test_vault_service::K - 1);
  printf("Completed decrementing space taken.\n");

  // current SpaceTaken should be 0
  {
    maidsafe::AccountStatusResponse asrsp;
    google::protobuf::Closure *done =
        google::protobuf::NewCallback<TestCallback>(&cb_obj,
        &TestCallback::CallbackFunction);
    vault_service_->AccountStatus(&controller, &asreq, &asrsp, done);
    ASSERT_TRUE(asrsp.IsInitialized());
    EXPECT_EQ(space_offered, asrsp.space_offered());
    EXPECT_EQ(boost::uint64_t(0), asrsp.space_taken());
    EXPECT_EQ(boost::uint64_t(0), asrsp.space_given());
    printf("Completed getting status with 0 space taken.\n");
  }

  // decrease SpaceTaken again, should fail
  responses.clear();
  callbacks.clear();
  for (int i = 0; i < test_vault_service::K; ++i) {
    maidsafe::AmendAccountResponse response;
    responses.push_back(response);
    google::protobuf::Closure *done = google::protobuf::NewCallback(&cb_obj,
        &TestCallback::CallbackFunction);
    callbacks.push_back(done);
  }
  for (int i = 0; i < test_vault_service::K; ++i) {
    vault_service_->AmendAccount(&controller, &requests.at(i), &responses.at(i),
        callbacks.at(i));
  }
  success_count = 0;
  for (int i = 0; i < test_vault_service::K; ++i) {
    ASSERT_TRUE(responses.at(i).IsInitialized());
    if (static_cast<int>(responses.at(i).result()) == kAck)
      ++success_count;
  }
  EXPECT_EQ(0, success_count);
  printf("Completed invalid attempt to decrement space taken.\n");

  // current SpaceTaken should still be 0
  {
    maidsafe::AccountStatusResponse asrsp;
    google::protobuf::Closure *done =
        google::protobuf::NewCallback<TestCallback>(&cb_obj,
        &TestCallback::CallbackFunction);
    vault_service_->AccountStatus(&controller, &asreq, &asrsp, done);
    ASSERT_TRUE(asrsp.IsInitialized());
    EXPECT_EQ(space_offered, asrsp.space_offered());
    EXPECT_EQ(boost::uint64_t(0), asrsp.space_taken());
    EXPECT_EQ(boost::uint64_t(0), asrsp.space_given());
    printf("Completed getting status with 0 space taken.\n");
  }

  // increase SpaceGiven
  k_group.MakeAmendAccountRequests(
    maidsafe::AmendAccountRequest::kSpaceGivenInc, client_pmid, chunk_size,
    chunk_name, &requests);
  responses.clear();
  callbacks.clear();
  for (int i = 0; i < test_vault_service::K; ++i) {
    maidsafe::AmendAccountResponse response;
    responses.push_back(response);
    google::protobuf::Closure *done = google::protobuf::NewCallback(&cb_obj,
        &TestCallback::CallbackFunction);
    callbacks.push_back(done);
  }
  for (int i = 0; i < test_vault_service::K; ++i) {
    vault_service_->AmendAccount(&controller, &requests.at(i), &responses.at(i),
        callbacks.at(i));
  }
  success_count = 0;
  for (int i = 0; i < test_vault_service::K; ++i) {
    ASSERT_TRUE(responses.at(i).IsInitialized());
    if (static_cast<int>(responses.at(i).result()) == kAck)
      ++success_count;
  }
  EXPECT_GE(success_count, test_vault_service::K - 1);
  printf("Completed incrementing space given.\n");

  // current SpaceGiven should be chunk_size
  {
    maidsafe::AccountStatusResponse asrsp;
    google::protobuf::Closure *done =
        google::protobuf::NewCallback<TestCallback>(&cb_obj,
        &TestCallback::CallbackFunction);
    vault_service_->AccountStatus(&controller, &asreq, &asrsp, done);
    ASSERT_TRUE(asrsp.IsInitialized());
    EXPECT_EQ(space_offered, asrsp.space_offered());
    EXPECT_EQ(boost::uint64_t(0), asrsp.space_taken());
    EXPECT_EQ(chunk_size, asrsp.space_given());
    printf("Completed getting status with appropriate space given.\n");
  }

  // decrease SpaceGiven
  k_group.MakeAmendAccountRequests(
    maidsafe::AmendAccountRequest::kSpaceGivenDec, client_pmid, chunk_size,
    chunk_name, &requests);
  responses.clear();
  callbacks.clear();
  for (int i = 0; i < test_vault_service::K; ++i) {
    maidsafe::AmendAccountResponse response;
    responses.push_back(response);
    google::protobuf::Closure *done = google::protobuf::NewCallback(&cb_obj,
        &TestCallback::CallbackFunction);
    callbacks.push_back(done);
  }
  for (int i = 0; i < test_vault_service::K; ++i) {
    vault_service_->AmendAccount(&controller, &requests.at(i), &responses.at(i),
        callbacks.at(i));
  }
  success_count = 0;
  for (int i = 0; i < test_vault_service::K; ++i) {
    ASSERT_TRUE(responses.at(i).IsInitialized());
    if (static_cast<int>(responses.at(i).result()) == kAck)
      ++success_count;
  }
  EXPECT_GE(success_count, test_vault_service::K - 1);
  printf("Completed decrementing space given.\n");

  // current SpaceGiven should still be 0
  {
    maidsafe::AccountStatusResponse asrsp;
    google::protobuf::Closure *done =
        google::protobuf::NewCallback<TestCallback>(&cb_obj,
        &TestCallback::CallbackFunction);
    vault_service_->AccountStatus(&controller, &asreq, &asrsp, done);
    ASSERT_TRUE(asrsp.IsInitialized());
    EXPECT_EQ(space_offered, asrsp.space_offered());
    EXPECT_EQ(boost::uint64_t(0), asrsp.space_taken());
    EXPECT_EQ(boost::uint64_t(0), asrsp.space_given());
    printf("Completed getting status with 0 space given.\n");
  }

  // decrease SpaceGiven again, should fail
  k_group.MakeAmendAccountRequests(
    maidsafe::AmendAccountRequest::kSpaceGivenDec, client_pmid, chunk_size,
    chunk_name, &requests);
  responses.clear();
  callbacks.clear();
  for (int i = 0; i < test_vault_service::K; ++i) {
    maidsafe::AmendAccountResponse response;
    responses.push_back(response);
    google::protobuf::Closure *done = google::protobuf::NewCallback(&cb_obj,
        &TestCallback::CallbackFunction);
    callbacks.push_back(done);
  }
  for (int i = 0; i < test_vault_service::K; ++i) {
    vault_service_->AmendAccount(&controller, &requests.at(i), &responses.at(i),
        callbacks.at(i));
  }
  success_count = 0;
  for (int i = 0; i < test_vault_service::K; ++i) {
    ASSERT_TRUE(responses.at(i).IsInitialized());
    if (static_cast<int>(responses.at(i).result()) == kAck)
      ++success_count;
  }
  EXPECT_EQ(0, success_count);
  printf("Completed invalid attempt to decrement space given.\n");

  // current SpaceGiven should still be 0
  {
    maidsafe::AccountStatusResponse asrsp;
    google::protobuf::Closure *done =
        google::protobuf::NewCallback<TestCallback>(&cb_obj,
        &TestCallback::CallbackFunction);
    vault_service_->AccountStatus(&controller, &asreq, &asrsp, done);
    ASSERT_TRUE(asrsp.IsInitialized());
    EXPECT_EQ(space_offered, asrsp.space_offered());
    EXPECT_EQ(boost::uint64_t(0), asrsp.space_taken());
    EXPECT_EQ(boost::uint64_t(0), asrsp.space_given());
    printf("Completed getting status with 0 space given.\n");
  }
}

TEST_F(VaultServicesTest, BEH_MAID_ServicesExpectAmendment) {
  rpcprotocol::Controller controller;
  maidsafe::ExpectAmendmentRequest request;
  maidsafe::ExpectAmendmentResponse response;

  std::string pub_key, priv_key, pmid, pub_key_sig, req_sig;
  CreateRSAKeys(&pub_key, &priv_key);
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);
  std::string content("This is a data chunk");
  std::string chunk_name(co.Hash(content, "", crypto::STRING_STRING, false));
  pub_key_sig = co.AsymSign(pub_key, "", priv_key, crypto::STRING_STRING);
  pmid = co.Hash(pub_key + pub_key_sig, "", crypto::STRING_STRING, false);
  req_sig = co.AsymSign(co.Hash(pub_key_sig + chunk_name + vault_pmid_, "",
                        crypto::STRING_STRING, false), "", priv_key,
                        crypto::STRING_STRING);
  std::string account_pmid(pmid);

  request.set_amendment_type(maidsafe::AmendAccountRequest::kSpaceTakenInc);
  request.set_chunkname(chunk_name);
  request.set_account_pmid(account_pmid);
  request.set_public_key(pub_key);
  request.set_public_key_signature(pub_key_sig);
  std::vector<std::string> amender_pmids;
  for (boost::uint16_t i = 0; i < kad::K; ++i) {
    amender_pmids.push_back(co.Hash(base::RandomString(100), "",
                                    crypto::STRING_STRING, false));
    request.add_amender_pmids(amender_pmids.at(i));
  }

  TestCallback cb_obj;

  for (int i = 0; i <= 2; ++i) {
    switch (i) {
      case 0:  // uninitialized request
        break;
      case 1:  // anonymous request
        request.set_request_signature(kAnonymousRequestSignature);
        break;
      case 2:  // invalid request
        request.set_request_signature("Bunkum");
        break;
    }

    google::protobuf::Closure *done =
        google::protobuf::NewCallback<TestCallback>(&cb_obj,
        &TestCallback::CallbackFunction);
    vault_service_->ExpectAmendment(&controller, &request, &response, done);
    ASSERT_TRUE(response.IsInitialized());
    EXPECT_EQ(kNack, static_cast<int>(response.result()));
    response.Clear();
  }

  request.set_request_signature(req_sig);
  google::protobuf::Closure *done =
      google::protobuf::NewCallback<TestCallback>(&cb_obj,
      &TestCallback::CallbackFunction);
  vault_service_->ExpectAmendment(&controller, &request, &response, done);
  ASSERT_TRUE(response.IsInitialized());
  EXPECT_EQ(kAck, static_cast<int>(response.result()));
  response.Clear();

  // Retrieve and check expectation
  maidsafe::AmendAccountRequest amend_account_request;
  amend_account_request.set_amendment_type(request.amendment_type());
  amend_account_request.set_chunkname(request.chunkname());
  amend_account_request.set_account_pmid(request.account_pmid());
  std::vector<std::string> result_ids = vault_service_->
      request_expectation_handler_.GetExpectedCallersIds(amend_account_request);
  bool result = amender_pmids == result_ids;
  ASSERT_TRUE(result);
}

TEST_F(VaultServicesTest, BEH_MAID_ServicesGetSyncData) {
  rpcprotocol::Controller controller;
  maidsafe::GetSyncDataRequest request;
  maidsafe::GetSyncDataResponse response;

  std::string pub_key, priv_key, pmid, pub_key_sig, req_sig;
  CreateRSAKeys(&pub_key, &priv_key);
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);
  std::string content("This is a data chunk");
  std::string chunk_name(co.Hash(content, "", crypto::STRING_STRING, false));
  std::string bp_name(co.Hash("testBUFFER", "", crypto::STRING_STRING, false));
  CreateSignedRequest(pub_key, priv_key, "", &pmid, &pub_key_sig, &req_sig);

  TestCallback cb_obj;

  for (int i = 0; i <= 2; ++i) {
    switch (i) {
      case 0:  // uninitialized request
        break;
      case 1:  // invalid request
        request.set_pmid(pmid);
        request.set_public_key(pub_key);
        request.set_public_key_signature(pub_key_sig);
        request.set_request_signature("fail");
        break;
      case 2:  // not in local routing table
        request.set_request_signature(req_sig);
        break;
    }

    google::protobuf::Closure *done =
        google::protobuf::NewCallback<TestCallback>(&cb_obj,
        &TestCallback::CallbackFunction);
    vault_service_->GetSyncData(&controller, &request, &response, done);
    ASSERT_TRUE(response.IsInitialized());
    EXPECT_EQ(kNack, static_cast<int>(response.result()));
    response.Clear();
  }

  // valid request, but no data to sync
  base::PublicRoutingTableTuple entry(pmid, "127.0.0.1", 123, "127.0.0.1", 456,
                                  pub_key, 10, 1, 1234);
  EXPECT_EQ(kSuccess, vault_service_->routing_table_->AddTuple(entry));
  {
    google::protobuf::Closure *done =
        google::protobuf::NewCallback<TestCallback>(&cb_obj,
        &TestCallback::CallbackFunction);
    vault_service_->GetSyncData(&controller, &request, &response, done);
    ASSERT_TRUE(response.IsInitialized());
    EXPECT_EQ(kAck, static_cast<int>(response.result()));
    if (response.has_vault_account_set())
      EXPECT_EQ(0, response.vault_account_set().vault_account_size());
    if (response.has_chunk_info_map())
      EXPECT_EQ(0, response.chunk_info_map().vault_chunk_info_size());
    if (response.has_vault_buffer_packet_map())
      EXPECT_EQ(0,
                response.vault_buffer_packet_map().vault_buffer_packet_size());
    response.Clear();
  }

  // add and retrieve accounts, chunk info and buffer packet
  {
    EXPECT_EQ(kSuccess, vault_service_->AddAccount(pmid, 1234));
    EXPECT_EQ(kSuccess, vault_service_->AddAccount("other pmid", 1234));
    int req_references, req_payments, refunds;
    std::string creditor;
    vault_service_->cih_.PrepareAddToWatchList(chunk_name, pmid, 123,
                                               &req_references, &req_payments);
    vault_service_->cih_.SetStoringDone(chunk_name, pmid);
    vault_service_->cih_.SetPaymentsDone(chunk_name, pmid);
    EXPECT_TRUE(vault_service_->cih_.TryCommitToWatchList(chunk_name, pmid,
                                                          &creditor, &refunds));
    maidsafe::BufferPacket bp;
    maidsafe::GenericPacket *gp = bp.add_owner_info();
    gp->set_data("bp owner data");
    gp->set_signature("bp owner sig");
    EXPECT_TRUE(vault_service_->bps_.StoreBP(bp_name, bp.SerializeAsString()));

    google::protobuf::Closure *done =
        google::protobuf::NewCallback<TestCallback>(&cb_obj,
        &TestCallback::CallbackFunction);
    vault_service_->GetSyncData(&controller, &request, &response, done);
    ASSERT_TRUE(response.IsInitialized());
    EXPECT_EQ(kAck, static_cast<int>(response.result()));

    ASSERT_TRUE(response.has_vault_account_set());
    // only one account, because sender's account should be excluded
    ASSERT_EQ(1, response.vault_account_set().vault_account_size());
    ASSERT_TRUE(response.vault_account_set().vault_account(0).has_pmid());
    EXPECT_EQ("other pmid",
              response.vault_account_set().vault_account(0).pmid());

    ASSERT_TRUE(response.has_chunk_info_map());
    ASSERT_EQ(1, response.chunk_info_map().vault_chunk_info_size());
    ASSERT_LE(1, response.chunk_info_map().vault_chunk_info(0).
                     watch_list_entry_size());
    ASSERT_TRUE(response.chunk_info_map().vault_chunk_info(0).
                    watch_list_entry(0).has_pmid());
    EXPECT_EQ(pmid, response.chunk_info_map().vault_chunk_info(0).
                        watch_list_entry(0).pmid());

    ASSERT_TRUE(response.has_vault_buffer_packet_map());
    ASSERT_EQ(1, response.vault_buffer_packet_map().vault_buffer_packet_size());
    ASSERT_EQ(1, response.vault_buffer_packet_map().vault_buffer_packet(0).
                     owner_info_size());
    ASSERT_TRUE(response.vault_buffer_packet_map().vault_buffer_packet(0).
                    owner_info(0).has_data());
    EXPECT_EQ(gp->data(), response.vault_buffer_packet_map().
                              vault_buffer_packet(0).owner_info(0).data());
  }
  vault_service_->routing_table_->Clear();
}

TEST_F(VaultServicesTest, BEH_MAID_ServicesGetAccount) {
  rpcprotocol::Controller controller;
  maidsafe::GetAccountRequest request;
  maidsafe::GetAccountResponse response;

  std::string pub_key, priv_key, pmid, pub_key_sig, req_sig;
  CreateRSAKeys(&pub_key, &priv_key);
  CreateSignedRequest(pub_key, priv_key, "account pmid", &pmid, &pub_key_sig,
                      &req_sig);

  TestCallback cb_obj;

  for (int i = 0; i <= 3; ++i) {
    switch (i) {
      case 0:  // uninitialized request
        break;
      case 1:  // invalid request
        request.set_account_pmid("account pmid");
        request.set_pmid(pmid);
        request.set_public_key(pub_key);
        request.set_public_key_signature(pub_key_sig);
        request.set_request_signature("fail");
        break;
      case 2:  // not in local routing table
        request.set_request_signature(req_sig);
        break;
      case 3:  // no account
        base::PublicRoutingTableTuple entry(pmid, "127.0.0.1", 123, "127.0.0.1",
                                        456, pub_key, 10, 1, 1234);
        EXPECT_EQ(kSuccess, vault_service_->routing_table_->AddTuple(entry));
        break;
    }

    google::protobuf::Closure *done =
        google::protobuf::NewCallback<TestCallback>(&cb_obj,
        &TestCallback::CallbackFunction);
    vault_service_->GetAccount(&controller, &request, &response, done);
    ASSERT_TRUE(response.IsInitialized());
    EXPECT_EQ(kNack, static_cast<int>(response.result()));
    response.Clear();
  }

  // add and retrieve account
  {
    ASSERT_EQ(kSuccess, vault_service_->AddAccount("account pmid", 1234));

    google::protobuf::Closure *done =
        google::protobuf::NewCallback<TestCallback>(&cb_obj,
        &TestCallback::CallbackFunction);
    vault_service_->GetAccount(&controller, &request, &response, done);
    ASSERT_TRUE(response.IsInitialized());
    EXPECT_EQ(kAck, static_cast<int>(response.result()));

    ASSERT_TRUE(response.has_vault_account());
    ASSERT_TRUE(response.vault_account().has_pmid());
    EXPECT_EQ("account pmid", response.vault_account().pmid());
  }
  vault_service_->routing_table_->Clear();
}

TEST_F(VaultServicesTest, BEH_MAID_ServicesGetChunkInfo) {
  rpcprotocol::Controller controller;
  maidsafe::GetChunkInfoRequest request;
  maidsafe::GetChunkInfoResponse response;

  std::string pub_key, priv_key, pmid, pub_key_sig, req_sig;
  CreateRSAKeys(&pub_key, &priv_key);
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);
  std::string content("This is a data chunk");
  std::string chunk_name(co.Hash(content, "", crypto::STRING_STRING, false));
  CreateSignedRequest(pub_key, priv_key, chunk_name, &pmid, &pub_key_sig,
                      &req_sig);

  TestCallback cb_obj;

  for (int i = 0; i <= 3; ++i) {
    switch (i) {
      case 0:  // uninitialized request
        break;
      case 1:  // invalid request
        request.set_chunkname(chunk_name);
        request.set_pmid(pmid);
        request.set_public_key(pub_key);
        request.set_public_key_signature(pub_key_sig);
        request.set_request_signature("fail");
        break;
      case 2:  // not in local routing table
        request.set_request_signature(req_sig);
        break;
      case 3:  // no account
        base::PublicRoutingTableTuple entry(pmid, "127.0.0.1", 123, "127.0.0.1",
                                        456, pub_key, 10, 1, 1234);
        EXPECT_EQ(kSuccess, vault_service_->routing_table_->AddTuple(entry));
        break;
    }

    google::protobuf::Closure *done =
        google::protobuf::NewCallback<TestCallback>(&cb_obj,
        &TestCallback::CallbackFunction);
    vault_service_->GetChunkInfo(&controller, &request, &response, done);
    ASSERT_TRUE(response.IsInitialized());
    EXPECT_EQ(kNack, static_cast<int>(response.result()));
    response.Clear();
  }

  // add and retrieve chunk info
  {
    int req_references, req_payments, refunds;
    std::string creditor;
    vault_service_->cih_.PrepareAddToWatchList(chunk_name, pmid, 123,
                                               &req_references, &req_payments);
    vault_service_->cih_.SetStoringDone(chunk_name, pmid);
    vault_service_->cih_.SetPaymentsDone(chunk_name, pmid);
    EXPECT_TRUE(vault_service_->cih_.TryCommitToWatchList(chunk_name, pmid,
                                                          &creditor, &refunds));

    google::protobuf::Closure *done =
        google::protobuf::NewCallback<TestCallback>(&cb_obj,
        &TestCallback::CallbackFunction);
    vault_service_->GetChunkInfo(&controller, &request, &response, done);
    ASSERT_TRUE(response.IsInitialized());
    EXPECT_EQ(kAck, static_cast<int>(response.result()));

    ASSERT_TRUE(response.has_vault_chunk_info());
    ASSERT_LE(1, response.vault_chunk_info().watch_list_entry_size());
    ASSERT_TRUE(response.vault_chunk_info().watch_list_entry(0).has_pmid());
    EXPECT_EQ(pmid, response.vault_chunk_info().watch_list_entry(0).pmid());
  }
  vault_service_->routing_table_->Clear();
}

TEST_F(VaultServicesTest, BEH_MAID_ServicesGetBufferPacket) {
  rpcprotocol::Controller controller;
  maidsafe::GetBufferPacketRequest request;
  maidsafe::GetBufferPacketResponse response;

  std::string pub_key, priv_key, pmid, pub_key_sig, req_sig;
  CreateRSAKeys(&pub_key, &priv_key);
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);
  std::string bp_name(co.Hash("testBUFFER", "", crypto::STRING_STRING, false));
  CreateSignedRequest(pub_key, priv_key, bp_name, &pmid, &pub_key_sig,
                      &req_sig);

  TestCallback cb_obj;

  for (int i = 0; i <= 3; ++i) {
    switch (i) {
      case 0:  // uninitialized request
        break;
      case 1:  // invalid request
        request.set_bufferpacket_name(bp_name);
        request.set_pmid(pmid);
        request.set_public_key(pub_key);
        request.set_public_key_signature(pub_key_sig);
        request.set_request_signature("fail");
        break;
      case 2:  // not in local routing table
        request.set_request_signature(req_sig);
        break;
      case 3:  // no buffer packet
        base::PublicRoutingTableTuple entry(pmid, "127.0.0.1", 123, "127.0.0.1",
                                        456, pub_key, 10, 1, 1234);
        EXPECT_EQ(kSuccess, vault_service_->routing_table_->AddTuple(entry));
        break;
    }

    google::protobuf::Closure *done =
        google::protobuf::NewCallback<TestCallback>(&cb_obj,
        &TestCallback::CallbackFunction);
    vault_service_->GetBufferPacket(&controller, &request, &response, done);
    ASSERT_TRUE(response.IsInitialized());
    EXPECT_EQ(kNack, static_cast<int>(response.result()));
    response.Clear();
  }

  // add and retrieve bp
  {
    maidsafe::BufferPacket bp;
    maidsafe::GenericPacket *gp = bp.add_owner_info();
    gp->set_data("bp owner data");
    gp->set_signature("bp owner sig");
    ASSERT_TRUE(vault_service_->bps_.StoreBP(bp_name, bp.SerializeAsString()));

    google::protobuf::Closure *done =
        google::protobuf::NewCallback<TestCallback>(&cb_obj,
        &TestCallback::CallbackFunction);
    vault_service_->GetBufferPacket(&controller, &request, &response, done);
    ASSERT_TRUE(response.IsInitialized());
    EXPECT_EQ(kAck, static_cast<int>(response.result()));

    ASSERT_TRUE(response.has_vault_buffer_packet());
    ASSERT_EQ(1, response.vault_buffer_packet().owner_info_size());
    const maidsafe::GenericPacket &owner_info =
        response.vault_buffer_packet().owner_info(0);
    EXPECT_EQ(gp->data(), owner_info.data());
    EXPECT_EQ(gp->signature(), owner_info.signature());
  }
  vault_service_->routing_table_->Clear();
}

TEST_F(VaultServicesTest, BEH_MAID_ServicesVaultStatus) {
  rpcprotocol::Controller controller;
  maidsafe::VaultStatusRequest request;
  maidsafe::VaultStatusResponse response;

  std::string pub_key, priv_key, pmid, sig_pub_key, sig_req;
  CreateRSAKeys(&pub_key, &priv_key);
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);
  std::string content("This is a data chunk");
  std::string chunkname(co.Hash(content, "", crypto::STRING_STRING, false));
  CreateSignedRequest(pub_key, priv_key, chunkname, &pmid, &sig_pub_key,
                      &sig_req);

  TestCallback cb_obj;

  for (boost::uint32_t i = 0; i <= 1; ++i) {
    switch (i) {
      case 0:  // uninitialized request
        break;
      case 1:  // invalid request
        request.set_encrypted_request("fail");
        break;
    }

    google::protobuf::Closure *done =
        google::protobuf::NewCallback<TestCallback>(&cb_obj,
        &TestCallback::CallbackFunction);
    vault_service_->VaultStatus(&controller, &request, &response, done);
    ASSERT_TRUE(response.IsInitialized());
    EXPECT_NE(kAck, static_cast<int>(response.result()));
    response.Clear();
  }

  // test success
  {
    maidsafe::VaultCommunication vc;
    vc.set_timestamp(0);
    std::string enc_req = co.AsymEncrypt(vc.SerializeAsString(), "",
                                         vault_public_key_,
                                         crypto::STRING_STRING);
    request.set_encrypted_request(enc_req);

    google::protobuf::Closure *done =
        google::protobuf::NewCallback<TestCallback>(&cb_obj,
        &TestCallback::CallbackFunction);
    vault_service_->VaultStatus(&controller, &request, &response, done);
    ASSERT_TRUE(response.IsInitialized());
    EXPECT_EQ(kAck, static_cast<int>(response.result()));

    std::string dec_rsp = co.AsymDecrypt(response.encrypted_response(), "",
                                         vault_private_key_,
                                         crypto::STRING_STRING);
    EXPECT_TRUE(vc.ParseFromString(dec_rsp));
    EXPECT_EQ(vault_chunkstore_->ChunkStoreDir(), vc.chunkstore());
    EXPECT_EQ(vault_chunkstore_->available_space(), vc.offered_space());
    EXPECT_EQ(vault_chunkstore_->FreeSpace(), vc.free_space());
  }
}

TEST_F(VaultServicesTest, BEH_MAID_ServicesCreateBP) {
  VaultService service(vault_pmid_, vault_public_key_, vault_private_key_,
                       vault_public_key_signature_, vault_chunkstore_,
                       vault_service_logic_, udt_transport_.transport_id(),
                       boost::shared_ptr<maidsafe::KadOps>());
  rpcprotocol::Controller controller;
  maidsafe::CreateBPRequest request;
  maidsafe::CreateBPResponse response;

  // Not initialised
  TestCallback cb_obj;
  google::protobuf::Closure *done = google::protobuf::NewCallback<TestCallback>
                                    (&cb_obj, &TestCallback::CallbackFunction);
  service.CreateBP(&controller, &request, &response, done);
  ASSERT_TRUE(response.IsInitialized());
  ASSERT_EQ(kNack, static_cast<int>(response.result()));
  ASSERT_EQ(vault_pmid_, response.pmid_id());
  ASSERT_EQ(vault_public_key_, response.public_key());
  ASSERT_EQ(vault_public_key_signature_, response.signed_public_key());

  std::string pub_key, priv_key, pmid, sig_pub_key, sig_req;
  CreateRSAKeys(&pub_key, &priv_key);
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);

  maidsafe::BufferPacketInfo bpi;
  bpi.set_owner("Dan");
  bpi.set_owner_publickey(pub_key);
  bpi.add_users("newuser");
  maidsafe::BufferPacket bp;
  maidsafe::GenericPacket *info = bp.add_owner_info();
  std::string ser_bpi;
  bpi.SerializeToString(&ser_bpi);
  info->set_data(ser_bpi);
  info->set_signature(co.AsymSign(ser_bpi, "", priv_key,
                                  crypto::STRING_STRING));
  std::string ser_gp;
  info->SerializeToString(&ser_gp);
  std::string ser_bp;
  bp.SerializeToString(&ser_bp);

  std::string bufferpacket_name(co.Hash("DanBUFFER", "", crypto::STRING_STRING,
                                        false));
  CreateSignedRequest(pub_key, priv_key, bufferpacket_name, &pmid, &sig_pub_key,
                      &sig_req);
  request.set_bufferpacket_name(bufferpacket_name);
  request.set_data(ser_bp);
  request.set_pmid("Dan");
  request.set_public_key(pub_key);
  request.set_signed_public_key(sig_pub_key);
  request.set_signed_request(sig_req);

  response.Clear();
  done = google::protobuf::NewCallback<TestCallback>
         (&cb_obj, &TestCallback::CallbackFunction);
  service.CreateBP(&controller, &request, &response, done);
  ASSERT_TRUE(response.IsInitialized());
  EXPECT_EQ(kAck, static_cast<int>(response.result()));
  EXPECT_EQ(response.pmid_id(), co.Hash(response.public_key() +
                                        response.signed_public_key(), "",
                                        crypto::STRING_STRING, false));

  // Load the stored BP
  std::string test_content;
  EXPECT_TRUE(service.bps_.HasBP(bufferpacket_name));
  EXPECT_TRUE(service.bps_.LoadBP(bufferpacket_name, &test_content));
  EXPECT_EQ(ser_bp, test_content);
}

TEST_F(VaultServicesTest, BEH_MAID_ServicesModifyBPInfo) {
  VaultService service(vault_pmid_, vault_public_key_, vault_private_key_,
                       vault_public_key_signature_, vault_chunkstore_,
                       vault_service_logic_, udt_transport_.transport_id(),
                       boost::shared_ptr<maidsafe::KadOps>());
  rpcprotocol::Controller controller;
  maidsafe::CreateBPRequest create_request;
  maidsafe::CreateBPResponse create_response;

  // Not initialised
  TestCallback cb_obj;
  google::protobuf::Closure *done = google::protobuf::NewCallback<TestCallback>
                                    (&cb_obj, &TestCallback::CallbackFunction);
  std::string pub_key, priv_key, pmid, sig_pub_key, sig_req;
  CreateRSAKeys(&pub_key, &priv_key);
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);


  maidsafe::BufferPacketInfo bpi;
  bpi.set_owner("Dan");
  bpi.set_owner_publickey(pub_key);
  bpi.add_users("newuser");
  maidsafe::BufferPacket bp;
  maidsafe::GenericPacket *info = bp.add_owner_info();
  std::string ser_bpi;
  bpi.SerializeToString(&ser_bpi);
  info->set_data(ser_bpi);
  info->set_signature(co.AsymSign(ser_bpi, "", priv_key,
                                  crypto::STRING_STRING));
  std::string ser_gp;
  info->SerializeToString(&ser_gp);
  std::string ser_bp;
  bp.SerializeToString(&ser_bp);

  std::string bufferpacket_name(co.Hash("DanBUFFER", "", crypto::STRING_STRING,
                                        false));
  CreateSignedRequest(pub_key, priv_key, bufferpacket_name, &pmid, &sig_pub_key,
                      &sig_req);
  create_request.set_bufferpacket_name(bufferpacket_name);
  create_request.set_data(ser_bp);
  create_request.set_pmid("Dan");
  create_request.set_public_key(pub_key);
  create_request.set_signed_public_key(sig_pub_key);
  create_request.set_signed_request(sig_req);

  done = google::protobuf::NewCallback<TestCallback>
         (&cb_obj, &TestCallback::CallbackFunction);
  service.CreateBP(&controller, &create_request, &create_response, done);
  ASSERT_TRUE(create_response.IsInitialized());
  EXPECT_EQ(kAck, static_cast<int>(create_response.result()));
  EXPECT_EQ(create_response.pmid_id(),
            co.Hash(create_response.public_key() +
                    create_response.signed_public_key(), "",
                    crypto::STRING_STRING, false));

  // Load the stored BP
  std::string test_content;
  EXPECT_TRUE(service.bps_.HasBP(bufferpacket_name));
  EXPECT_TRUE(service.bps_.LoadBP(bufferpacket_name, &test_content));
  EXPECT_EQ(ser_bp, test_content);

  // Wrong data: not a Generic Packet
  maidsafe::ModifyBPInfoRequest modify_request;
  maidsafe::ModifyBPInfoResponse modify_response;
  modify_request.set_bufferpacket_name(bufferpacket_name);
  modify_request.set_data("some bollocks that doesn't serialise or parse");
  modify_request.set_pmid(pmid);
  modify_request.set_public_key(pub_key);
  modify_request.set_signed_public_key(sig_pub_key);
  modify_request.set_signed_request(sig_req);
  done = google::protobuf::NewCallback<TestCallback>
         (&cb_obj, &TestCallback::CallbackFunction);
  service.ModifyBPInfo(&controller, &modify_request, &modify_response, done);
  ASSERT_TRUE(modify_response.IsInitialized());
  EXPECT_EQ(kNack, static_cast<int>(modify_response.result()));
  EXPECT_EQ(vault_pmid_, modify_response.pmid_id());
  EXPECT_EQ(vault_public_key_, modify_response.public_key());
  EXPECT_EQ(vault_public_key_signature_, modify_response.signed_public_key());

  // Wrong data: not a BufferPacketInfo inside the GP
  modify_request.Clear();
  modify_response.Clear();
  maidsafe::GenericPacket gp;
  gp.set_data("some bollocks that doesn't serialise or parse");
  gp.set_signature(co.AsymSign(gp.data(), "", priv_key, crypto::STRING_STRING));
  gp.SerializeToString(&ser_gp);

  modify_request.set_bufferpacket_name(bufferpacket_name);
  modify_request.set_data(ser_gp);
  modify_request.set_pmid(pmid);
  modify_request.set_public_key(pub_key);
  modify_request.set_signed_public_key(sig_pub_key);
  modify_request.set_signed_request(sig_req);
  done = google::protobuf::NewCallback<TestCallback>
         (&cb_obj, &TestCallback::CallbackFunction);
  service.ModifyBPInfo(&controller, &modify_request, &modify_response, done);
  ASSERT_TRUE(modify_response.IsInitialized());
  EXPECT_EQ(kNack, static_cast<int>(modify_response.result()));
  EXPECT_EQ(vault_pmid_, modify_response.pmid_id());
  EXPECT_EQ(vault_public_key_, modify_response.public_key());
  EXPECT_EQ(vault_public_key_signature_, modify_response.signed_public_key());

  // Wrong bufferpacket name
  modify_request.Clear();
  modify_response.Clear();
  bpi.Clear();
  bpi.set_owner("Dan");
  bpi.set_owner_publickey(pub_key);
  bpi.add_users("newuser0");
  bpi.add_users("newuser1");
  bpi.add_users("newuser2");
  bpi.SerializeToString(&ser_bpi);
  gp.set_data(ser_bpi);
  gp.set_signature(co.AsymSign(gp.data(), "", priv_key, crypto::STRING_STRING));
  gp.SerializeToString(&ser_gp);
  modify_request.set_bufferpacket_name("some bp that doesn't exist");
  modify_request.set_data(ser_gp);
  modify_request.set_pmid("Dan");
  modify_request.set_public_key(pub_key);
  modify_request.set_signed_public_key(sig_pub_key);
  modify_request.set_signed_request(co.AsymSign(co.Hash(pub_key + sig_pub_key +
                                    modify_request.bufferpacket_name(), "",
                                    crypto::STRING_STRING, false), "",
                                    priv_key, crypto::STRING_STRING));
  done = google::protobuf::NewCallback<TestCallback>
         (&cb_obj, &TestCallback::CallbackFunction);
  service.ModifyBPInfo(&controller, &modify_request, &modify_response, done);
  ASSERT_TRUE(modify_response.IsInitialized());
  EXPECT_EQ(kNack, static_cast<int>(modify_response.result()));
  EXPECT_EQ(vault_pmid_, modify_response.pmid_id());
  EXPECT_EQ(vault_public_key_, modify_response.public_key());
  EXPECT_EQ(vault_public_key_signature_, modify_response.signed_public_key());

  // Correct change
  modify_request.Clear();
  modify_response.Clear();
  modify_request.set_bufferpacket_name(bufferpacket_name);
  modify_request.set_data(ser_gp);
  modify_request.set_pmid("Dan");
  modify_request.set_public_key(pub_key);
  modify_request.set_signed_public_key(sig_pub_key);
  modify_request.set_signed_request(sig_req);
  done = google::protobuf::NewCallback<TestCallback>
         (&cb_obj, &TestCallback::CallbackFunction);
  service.ModifyBPInfo(&controller, &modify_request, &modify_response, done);
  ASSERT_TRUE(modify_response.IsInitialized());
  EXPECT_EQ(kAck, static_cast<int>(modify_response.result()));
  EXPECT_EQ(vault_pmid_, modify_response.pmid_id());
  EXPECT_EQ(vault_public_key_, modify_response.public_key());
  EXPECT_EQ(vault_public_key_signature_, modify_response.signed_public_key());

  EXPECT_TRUE(service.bps_.HasBP(bufferpacket_name));
  EXPECT_TRUE(service.bps_.LoadBP(bufferpacket_name, &test_content));
  ASSERT_TRUE(bp.ParseFromString(test_content));
  ASSERT_TRUE(bpi.ParseFromString(bp.owner_info(0).data()));
  EXPECT_EQ("Dan", bpi.owner());
  EXPECT_EQ(pub_key, bpi.owner_publickey());
  EXPECT_EQ(3, bpi.users_size());
  for (int n = 0; n < bpi.users_size(); ++n)
    EXPECT_EQ("newuser" + base::IntToString(n), bpi.users(n));
}

TEST_F(VaultServicesTest, BEH_MAID_ServicesGetBPMessages) {
  VaultService service(vault_pmid_, vault_public_key_, vault_private_key_,
                       vault_public_key_signature_, vault_chunkstore_,
                       vault_service_logic_, udt_transport_.transport_id(),
                       boost::shared_ptr<maidsafe::KadOps>());
  rpcprotocol::Controller controller;
  maidsafe::CreateBPRequest request;
  maidsafe::CreateBPResponse response;

  // Not initialised
  TestCallback cb_obj;
  google::protobuf::Closure *done = google::protobuf::NewCallback<TestCallback>
                                    (&cb_obj, &TestCallback::CallbackFunction);
  std::string pub_key, priv_key, pmid, sig_pub_key, sig_req;
  CreateRSAKeys(&pub_key, &priv_key);
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);

  maidsafe::BufferPacketInfo bpi;
  bpi.set_owner("Dan");
  bpi.set_owner_publickey(pub_key);
  bpi.add_users("newuser");
  maidsafe::BufferPacket bp;
  maidsafe::GenericPacket *info = bp.add_owner_info();
  std::string ser_bpi;
  bpi.SerializeToString(&ser_bpi);
  info->set_data(ser_bpi);
  info->set_signature(co.AsymSign(ser_bpi, "", priv_key,
                      crypto::STRING_STRING));
  std::string ser_gp;
  info->SerializeToString(&ser_gp);
  std::string ser_bp;
  bp.SerializeToString(&ser_bp);

  std::string bufferpacket_name(co.Hash("DanBUFFER", "", crypto::STRING_STRING,
                                        false));
  CreateSignedRequest(pub_key, priv_key, bufferpacket_name, &pmid, &sig_pub_key,
                      &sig_req);
  request.set_bufferpacket_name(bufferpacket_name);
  request.set_data(ser_bp);
  request.set_pmid("Dan");
  request.set_public_key(pub_key);
  request.set_signed_public_key(sig_pub_key);
  request.set_signed_request(sig_req);

  service.CreateBP(&controller, &request, &response, done);
  ASSERT_TRUE(response.IsInitialized());
  EXPECT_EQ(kAck, static_cast<int>(response.result()));
  EXPECT_EQ(response.pmid_id(), co.Hash(response.public_key() +
                                        response.signed_public_key(), "",
                                        crypto::STRING_STRING, false));

  // Load the stored BP to check it
  std::string test_content;
  EXPECT_TRUE(service.bps_.HasBP(bufferpacket_name));
  EXPECT_TRUE(service.bps_.LoadBP(bufferpacket_name, &test_content));
  EXPECT_EQ(ser_bp, test_content);

  // Get the messages
  maidsafe::GetBPMessagesRequest get_msg_request;
  maidsafe::GetBPMessagesResponse get_msg_response;
  get_msg_request.set_bufferpacket_name(bufferpacket_name);
  get_msg_request.set_pmid("Dan");
  get_msg_request.set_public_key(pub_key);
  get_msg_request.set_signed_public_key(sig_pub_key);
  get_msg_request.set_signed_request(sig_req);
  done = google::protobuf::NewCallback<TestCallback>
         (&cb_obj, &TestCallback::CallbackFunction);
  service.GetBPMessages(&controller, &get_msg_request, &get_msg_response, done);
  ASSERT_TRUE(get_msg_response.IsInitialized());
  EXPECT_EQ(kAck, static_cast<int>(get_msg_response.result()));
  EXPECT_EQ(get_msg_response.pmid_id(),
            co.Hash(get_msg_response.public_key() +
                    get_msg_response.signed_public_key(), "",
                    crypto::STRING_STRING, false));
  EXPECT_EQ(0, get_msg_response.messages_size());
}

TEST_F(VaultServicesTest, BEH_MAID_ServicesAddBPMessages) {
  VaultService service(vault_pmid_, vault_public_key_, vault_private_key_,
                       vault_public_key_signature_, vault_chunkstore_,
                       vault_service_logic_, udt_transport_.transport_id(),
                       boost::shared_ptr<maidsafe::KadOps>());
  rpcprotocol::Controller controller;
  maidsafe::CreateBPRequest request;
  maidsafe::CreateBPResponse response;

  // Not initialised
  TestCallback cb_obj;
  google::protobuf::Closure *done = google::protobuf::NewCallback<TestCallback>
                                    (&cb_obj, &TestCallback::CallbackFunction);
  std::string pub_key, priv_key, pmid, sig_pub_key, sig_req;
  CreateRSAKeys(&pub_key, &priv_key);
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);

  maidsafe::BufferPacketInfo bpi;
  bpi.set_owner("Dan");
  bpi.set_owner_publickey(pub_key);
  bpi.add_users(co.Hash("newuser", "", crypto::STRING_STRING, false));
  maidsafe::BufferPacket bp;
  maidsafe::GenericPacket *info = bp.add_owner_info();
  std::string ser_bpi;
  bpi.SerializeToString(&ser_bpi);
  info->set_data(ser_bpi);
  info->set_signature(co.AsymSign(ser_bpi, "", priv_key,
                                  crypto::STRING_STRING));
  std::string ser_gp;
  info->SerializeToString(&ser_gp);
  std::string ser_bp;
  bp.SerializeToString(&ser_bp);

  std::string bufferpacket_name(co.Hash("DanBUFFER", "", crypto::STRING_STRING,
                                        false));
  CreateSignedRequest(pub_key, priv_key, bufferpacket_name, &pmid, &sig_pub_key,
                      &sig_req);
  request.set_bufferpacket_name(bufferpacket_name);
  request.set_data(ser_bp);
  request.set_pmid("Dan");
  request.set_public_key(pub_key);
  request.set_signed_public_key(sig_pub_key);
  request.set_signed_request(sig_req);

  service.CreateBP(&controller, &request, &response, done);
  ASSERT_TRUE(response.IsInitialized());
  EXPECT_EQ(kAck, static_cast<int>(response.result()));
  EXPECT_EQ(response.pmid_id(), co.Hash(response.public_key() +
                                        response.signed_public_key(), "",
                                        crypto::STRING_STRING, false));

  // Load the stored BP to check it
  std::string test_content;
  EXPECT_TRUE(service.bps_.HasBP(bufferpacket_name));
  EXPECT_TRUE(service.bps_.LoadBP(bufferpacket_name, &test_content));
  EXPECT_EQ(ser_bp, test_content);

  // Get the messages
  maidsafe::GetBPMessagesRequest get_msg_request;
  maidsafe::GetBPMessagesResponse get_msg_response;
  get_msg_request.set_bufferpacket_name(bufferpacket_name);
  get_msg_request.set_pmid("Dan");
  get_msg_request.set_public_key(pub_key);
  get_msg_request.set_signed_public_key(sig_pub_key);
  get_msg_request.set_signed_request(sig_req);
  done = google::protobuf::NewCallback<TestCallback>
         (&cb_obj, &TestCallback::CallbackFunction);
  service.GetBPMessages(&controller, &get_msg_request, &get_msg_response, done);
  ASSERT_TRUE(get_msg_response.IsInitialized());
  EXPECT_EQ(kAck, static_cast<int>(get_msg_response.result()));
  EXPECT_EQ(get_msg_response.pmid_id(),
            co.Hash(get_msg_response.public_key() +
                    get_msg_response.signed_public_key(), "",
                    crypto::STRING_STRING, false));
  EXPECT_EQ(0, get_msg_response.messages_size());

  // Creation of newuser's credentials
  std::string newuser_pub_key, newuser_priv_key, newuser_pmid,
              newuser_sig_pub_key, newuser_sig_req;
  CreateRSAKeys(&newuser_pub_key, &newuser_priv_key);
  CreateSignedRequest(newuser_pub_key, newuser_priv_key, bufferpacket_name,
                      &newuser_pmid, &newuser_sig_pub_key, &newuser_sig_req);

  // Sending wrong message
  maidsafe::AddBPMessageRequest add_msg_request;
  maidsafe::AddBPMessageResponse add_msg_response;
  add_msg_request.set_bufferpacket_name(bufferpacket_name);
  add_msg_request.set_data("Something that's not a correct message");
  add_msg_request.set_pmid("newuser_pmid");
  add_msg_request.set_public_key(newuser_pub_key);
  add_msg_request.set_signed_public_key(newuser_sig_pub_key);
  add_msg_request.set_signed_request(newuser_sig_req);
  done = google::protobuf::NewCallback<TestCallback>
         (&cb_obj, &TestCallback::CallbackFunction);
  service.AddBPMessage(&controller, &add_msg_request, &add_msg_response, done);
  ASSERT_TRUE(add_msg_response.IsInitialized());
  EXPECT_EQ(kNack, static_cast<int>(add_msg_response.result()));
  EXPECT_EQ(add_msg_response.pmid_id(),
            co.Hash(add_msg_response.public_key() +
                    add_msg_response.signed_public_key(), "",
                    crypto::STRING_STRING, false));

  // Creating the message
  maidsafe::BufferPacketMessage bpm;
  maidsafe::GenericPacket gp;
  std::string msg("Don't switch doors!!");
  bpm.set_sender_id("newuser");
  bpm.set_sender_public_key(newuser_pub_key);
  bpm.set_type(maidsafe::INSTANT_MSG);
  boost::uint32_t iter = base::RandomUint32() % 1000 +1;
  std::string aes_key = co.SecurePassword(co.Hash(msg, "",
                                          crypto::STRING_STRING, false), iter);
  bpm.set_rsaenc_key(co.AsymEncrypt(aes_key, "", pub_key,
                                    crypto::STRING_STRING));
  bpm.set_aesenc_message(co.SymmEncrypt(msg, "", crypto::STRING_STRING,
                                        aes_key));
  bpm.set_timestamp(base::GetEpochTime());
  std::string ser_bpm;
  bpm.SerializeToString(&ser_bpm);
  gp.set_data(ser_bpm);
  gp.set_signature(co.AsymSign(gp.data(), "", newuser_priv_key,
                   crypto::STRING_STRING));
  gp.SerializeToString(&ser_gp);

  // Sending the message
  add_msg_request.Clear();
  add_msg_response.Clear();
  add_msg_request.set_bufferpacket_name(bufferpacket_name);
  add_msg_request.set_data(ser_gp);
  add_msg_request.set_pmid("newuser_pmid");
  add_msg_request.set_public_key(newuser_pub_key);
  add_msg_request.set_signed_public_key(newuser_sig_pub_key);
  add_msg_request.set_signed_request(newuser_sig_req);
  done = google::protobuf::NewCallback<TestCallback>
         (&cb_obj, &TestCallback::CallbackFunction);
  service.AddBPMessage(&controller, &add_msg_request, &add_msg_response, done);
  ASSERT_TRUE(add_msg_response.IsInitialized());
  EXPECT_EQ(kAck, static_cast<int>(add_msg_response.result()));
  EXPECT_EQ(add_msg_response.pmid_id(),
            co.Hash(add_msg_response.public_key() +
                    add_msg_response.signed_public_key(), "",
                    crypto::STRING_STRING, false));

  // Get the messages again
  get_msg_request.Clear();
  get_msg_response.Clear();
  get_msg_request.set_bufferpacket_name(bufferpacket_name);
  get_msg_request.set_pmid("Dan");
  get_msg_request.set_public_key(pub_key);
  get_msg_request.set_signed_public_key(sig_pub_key);
  get_msg_request.set_signed_request(sig_req);
  done = google::protobuf::NewCallback<TestCallback>
         (&cb_obj, &TestCallback::CallbackFunction);
  service.GetBPMessages(&controller, &get_msg_request, &get_msg_response, done);
  ASSERT_TRUE(get_msg_response.IsInitialized());
  EXPECT_EQ(kAck, static_cast<int>(get_msg_response.result()));
  EXPECT_EQ(get_msg_response.pmid_id(),
            co.Hash(get_msg_response.public_key() +
                    get_msg_response.signed_public_key(), "",
                    crypto::STRING_STRING, false));
  ASSERT_EQ(1, get_msg_response.messages_size());
  maidsafe::ValidatedBufferPacketMessage vbpm;
  ASSERT_TRUE(vbpm.ParseFromString(get_msg_response.messages(0)));
  EXPECT_EQ(bpm.sender_id(), vbpm.sender());
  EXPECT_EQ(bpm.aesenc_message(), vbpm.message());
  EXPECT_EQ(bpm.rsaenc_key(), vbpm.index());
  EXPECT_EQ(bpm.type(), vbpm.type());

  // Get the messages again
  get_msg_request.Clear();
  get_msg_response.Clear();
  get_msg_request.set_bufferpacket_name(bufferpacket_name);
  get_msg_request.set_pmid("Dan");
  get_msg_request.set_public_key(pub_key);
  get_msg_request.set_signed_public_key(sig_pub_key);
  get_msg_request.set_signed_request(sig_req);
  done = google::protobuf::NewCallback<TestCallback>
         (&cb_obj, &TestCallback::CallbackFunction);
  service.GetBPMessages(&controller, &get_msg_request, &get_msg_response, done);
  ASSERT_TRUE(get_msg_response.IsInitialized());
  EXPECT_EQ(kAck, static_cast<int>(get_msg_response.result()));
  EXPECT_EQ(get_msg_response.pmid_id(),
            co.Hash(get_msg_response.public_key() +
                    get_msg_response.signed_public_key(), "",
                    crypto::STRING_STRING, false));
  EXPECT_EQ(0, get_msg_response.messages_size());
}

TEST_F(VaultServicesTest, BEH_MAID_ServicesGetBPPresence) {
  VaultService service(vault_pmid_, vault_public_key_, vault_private_key_,
                       vault_public_key_signature_, vault_chunkstore_,
                       vault_service_logic_, udt_transport_.transport_id(),
                       boost::shared_ptr<maidsafe::KadOps>());
  rpcprotocol::Controller controller;
  maidsafe::CreateBPRequest request;
  maidsafe::CreateBPResponse response;

  // Not initialised
  TestCallback cb_obj;
  google::protobuf::Closure *done = google::protobuf::NewCallback<TestCallback>
                                    (&cb_obj, &TestCallback::CallbackFunction);
  std::string pub_key, priv_key, pmid, sig_pub_key, sig_req;
  CreateRSAKeys(&pub_key, &priv_key);
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);

  maidsafe::BufferPacketInfo bpi;
  bpi.set_owner("Dan");
  bpi.set_owner_publickey(pub_key);
  bpi.add_users("newuser");
  maidsafe::BufferPacket bp;
  maidsafe::GenericPacket *info = bp.add_owner_info();
  std::string ser_bpi;
  bpi.SerializeToString(&ser_bpi);
  info->set_data(ser_bpi);
  info->set_signature(co.AsymSign(ser_bpi, "", priv_key,
                                  crypto::STRING_STRING));
  std::string ser_gp;
  info->SerializeToString(&ser_gp);
  std::string ser_bp;
  bp.SerializeToString(&ser_bp);

  std::string bufferpacket_name(co.Hash("DanBUFFER", "", crypto::STRING_STRING,
                                false));
  CreateSignedRequest(pub_key, priv_key, bufferpacket_name, &pmid, &sig_pub_key,
                      &sig_req);
  request.set_bufferpacket_name(bufferpacket_name);
  request.set_data(ser_bp);
  request.set_pmid("Dan");
  request.set_public_key(pub_key);
  request.set_signed_public_key(sig_pub_key);
  request.set_signed_request(sig_req);

  service.CreateBP(&controller, &request, &response, done);
  ASSERT_TRUE(response.IsInitialized());
  EXPECT_EQ(kAck, static_cast<int>(response.result()));
  EXPECT_EQ(response.pmid_id(), co.Hash(response.public_key() +
                                        response.signed_public_key(), "",
                                        crypto::STRING_STRING, false));

  // Load the stored BP to check it
  std::string test_content;
  EXPECT_TRUE(service.bps_.HasBP(bufferpacket_name));
  EXPECT_TRUE(service.bps_.LoadBP(bufferpacket_name, &test_content));
  EXPECT_EQ(ser_bp, test_content);

  // Get the messages
  maidsafe::GetBPPresenceRequest get_presence_request;
  maidsafe::GetBPPresenceResponse get_presence_response;
  get_presence_request.set_bufferpacket_name(bufferpacket_name);
  get_presence_request.set_pmid("Dan");
  get_presence_request.set_public_key(pub_key);
  get_presence_request.set_signed_public_key(sig_pub_key);
  get_presence_request.set_signed_request(sig_req);
  done = google::protobuf::NewCallback<TestCallback>
         (&cb_obj, &TestCallback::CallbackFunction);
  service.GetBPPresence(&controller, &get_presence_request,
                        &get_presence_response, done);
  ASSERT_TRUE(get_presence_response.IsInitialized());
  EXPECT_EQ(kAck, static_cast<int>(get_presence_response.result()));
  EXPECT_EQ(get_presence_response.pmid_id(),
            co.Hash(get_presence_response.public_key() +
                    get_presence_response.signed_public_key(), "",
                    crypto::STRING_STRING, false));
  EXPECT_EQ(0, get_presence_response.messages_size());
  EXPECT_TRUE(service.bps_.HasBP(bufferpacket_name));
  EXPECT_TRUE(service.bps_.LoadBP(bufferpacket_name, &test_content));
  EXPECT_EQ(ser_bp, test_content);

  maidsafe::BufferPacket mod_bp;
  bp.ParseFromString(test_content);
  maidsafe::LivePresence lp;
  lp.set_contact_id("newuser");
  maidsafe::EndPoint ep;
  for (int n = 0; n < 3; ++n) {
    ep.add_ip(base::IntToString(n));
    ep.add_port(n);
  }
  lp.set_end_point(ep.SerializeAsString());
  maidsafe::GenericPacket lp_gp;
  lp_gp.set_data(lp.SerializeAsString());
  lp_gp.set_signature("");
  maidsafe::GenericPacket *mod_gp = mod_bp.add_presence_notifications();
  *mod_gp = lp_gp;
  EXPECT_TRUE(service.bps_.UpdateBP(bufferpacket_name,
                                    mod_bp.SerializeAsString()));

  done = google::protobuf::NewCallback<TestCallback>
         (&cb_obj, &TestCallback::CallbackFunction);
  service.GetBPPresence(&controller, &get_presence_request,
                        &get_presence_response, done);
  ASSERT_TRUE(get_presence_response.IsInitialized());
  EXPECT_EQ(kAck, static_cast<int>(get_presence_response.result()));
  EXPECT_EQ(get_presence_response.pmid_id(),
            co.Hash(get_presence_response.public_key() +
                    get_presence_response.signed_public_key(), "",
                    crypto::STRING_STRING, false));
  EXPECT_EQ(1, get_presence_response.messages_size());
  ASSERT_EQ(lp_gp.SerializeAsString(), get_presence_response.messages(0));

  get_presence_response.Clear();
  done = google::protobuf::NewCallback<TestCallback>
         (&cb_obj, &TestCallback::CallbackFunction);
  service.GetBPPresence(&controller, &get_presence_request,
                        &get_presence_response, done);
  ASSERT_TRUE(get_presence_response.IsInitialized());
  EXPECT_EQ(kAck, static_cast<int>(get_presence_response.result()));
  EXPECT_EQ(get_presence_response.pmid_id(),
            co.Hash(get_presence_response.public_key() +
                    get_presence_response.signed_public_key(), "",
                    crypto::STRING_STRING, false));
  EXPECT_EQ(0, get_presence_response.messages_size());
}

TEST_F(VaultServicesTest, BEH_MAID_ServicesAddBPPresence) {
  VaultService service(vault_pmid_, vault_public_key_, vault_private_key_,
                       vault_public_key_signature_, vault_chunkstore_,
                       vault_service_logic_, udt_transport_.transport_id(),
                       boost::shared_ptr<maidsafe::KadOps>());
  rpcprotocol::Controller controller;
  maidsafe::CreateBPRequest request;
  maidsafe::CreateBPResponse response;

  // Not initialised
  TestCallback cb_obj;
  google::protobuf::Closure *done = google::protobuf::NewCallback<TestCallback>
                                    (&cb_obj, &TestCallback::CallbackFunction);
  std::string pub_key, priv_key, pmid, sig_pub_key, sig_req;
  CreateRSAKeys(&pub_key, &priv_key);
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);

  maidsafe::BufferPacketInfo bpi;
  bpi.set_owner("Dan");
  bpi.set_owner_publickey(pub_key);
  bpi.add_users(co.Hash("newuser", "", crypto::STRING_STRING, false));
  maidsafe::BufferPacket bp;
  maidsafe::GenericPacket *info = bp.add_owner_info();
  std::string ser_bpi;
  bpi.SerializeToString(&ser_bpi);
  info->set_data(ser_bpi);
  info->set_signature(co.AsymSign(ser_bpi, "", priv_key,
                                  crypto::STRING_STRING));
  std::string ser_gp;
  info->SerializeToString(&ser_gp);
  std::string ser_bp;
  bp.SerializeToString(&ser_bp);

  std::string bufferpacket_name(co.Hash("DanBUFFER", "", crypto::STRING_STRING,
                                false));
  CreateSignedRequest(pub_key, priv_key, bufferpacket_name, &pmid, &sig_pub_key,
                      &sig_req);
  request.set_bufferpacket_name(bufferpacket_name);
  request.set_data(ser_bp);
  request.set_pmid("Dan");
  request.set_public_key(pub_key);
  request.set_signed_public_key(sig_pub_key);
  request.set_signed_request(sig_req);

  service.CreateBP(&controller, &request, &response, done);
  ASSERT_TRUE(response.IsInitialized());
  EXPECT_EQ(kAck, static_cast<int>(response.result()));
  EXPECT_EQ(response.pmid_id(), co.Hash(response.public_key() +
                                        response.signed_public_key(), "",
                                        crypto::STRING_STRING, false));

  // Load the stored BP to check it
  std::string test_content;
  EXPECT_TRUE(service.bps_.HasBP(bufferpacket_name));
  EXPECT_TRUE(service.bps_.LoadBP(bufferpacket_name, &test_content));
  EXPECT_EQ(ser_bp, test_content);

  // Get the messages
  maidsafe::GetBPPresenceRequest get_presence_request;
  maidsafe::GetBPPresenceResponse get_presence_response;
  get_presence_request.set_bufferpacket_name(bufferpacket_name);
  get_presence_request.set_pmid("Dan");
  get_presence_request.set_public_key(pub_key);
  get_presence_request.set_signed_public_key(sig_pub_key);
  get_presence_request.set_signed_request(sig_req);
  done = google::protobuf::NewCallback<TestCallback>
         (&cb_obj, &TestCallback::CallbackFunction);
  service.GetBPPresence(&controller, &get_presence_request,
                        &get_presence_response, done);
  ASSERT_TRUE(get_presence_response.IsInitialized());
  EXPECT_EQ(kAck, static_cast<int>(get_presence_response.result()));
  EXPECT_EQ(get_presence_response.pmid_id(),
            co.Hash(get_presence_response.public_key() +
                    get_presence_response.signed_public_key(), "",
                    crypto::STRING_STRING, false));
  EXPECT_EQ(0, get_presence_response.messages_size());

  // Creation of newuser's credentials
  std::string newuser_pub_key, newuser_priv_key, newuser_pmid,
              newuser_sig_pub_key, newuser_sig_req;
  CreateRSAKeys(&newuser_pub_key, &newuser_priv_key);
  CreateSignedRequest(newuser_pub_key, newuser_priv_key, bufferpacket_name,
                      &newuser_pmid, &newuser_sig_pub_key, &newuser_sig_req);

  // Sending wrong message
  maidsafe::AddBPPresenceRequest add_presence_request;
  maidsafe::AddBPPresenceResponse add_presence_response;
  add_presence_request.set_bufferpacket_name(bufferpacket_name);
  add_presence_request.set_data("Something that's not a correct message");
  add_presence_request.set_pmid("newuser_pmid");
  add_presence_request.set_public_key(newuser_pub_key);
  add_presence_request.set_signed_public_key(newuser_sig_pub_key);
  add_presence_request.set_signed_request(newuser_sig_req);
  done = google::protobuf::NewCallback<TestCallback>
         (&cb_obj, &TestCallback::CallbackFunction);
  service.AddBPPresence(&controller, &add_presence_request,
                        &add_presence_response, done);
  ASSERT_TRUE(add_presence_response.IsInitialized());
  EXPECT_EQ(kNack, static_cast<int>(add_presence_response.result()));
  EXPECT_EQ(add_presence_response.pmid_id(),
            co.Hash(add_presence_response.public_key() +
                    add_presence_response.signed_public_key(), "",
                    crypto::STRING_STRING, false));

  // Creating the message
  maidsafe::LivePresence lp;
  lp.set_contact_id("newuser");
  maidsafe::EndPoint ep;
  for (int n = 0; n < 3; ++n) {
    ep.add_ip(base::IntToString(n));
    ep.add_port(n);
  }
  lp.set_end_point(ep.SerializeAsString());
  maidsafe::GenericPacket lp_gp;
  lp_gp.set_data(lp.SerializeAsString());
  lp_gp.set_signature("");
  ser_gp = "";
  lp_gp.SerializeToString(&ser_gp);

  // Sending the message
  add_presence_request.Clear();
  add_presence_response.Clear();
  add_presence_request.set_bufferpacket_name(bufferpacket_name);
  add_presence_request.set_data(ser_gp);
  add_presence_request.set_pmid("newuser_pmid");
  add_presence_request.set_public_key(newuser_pub_key);
  add_presence_request.set_signed_public_key(newuser_sig_pub_key);
  add_presence_request.set_signed_request(newuser_sig_req);
  done = google::protobuf::NewCallback<TestCallback>
         (&cb_obj, &TestCallback::CallbackFunction);
  service.AddBPPresence(&controller, &add_presence_request,
                        &add_presence_response, done);
  ASSERT_TRUE(add_presence_response.IsInitialized());
  EXPECT_EQ(kAck, static_cast<int>(add_presence_response.result()));
  EXPECT_EQ(add_presence_response.pmid_id(),
            co.Hash(add_presence_response.public_key() +
                    add_presence_response.signed_public_key(), "",
                    crypto::STRING_STRING, false));

  // Get the messages again
  get_presence_request.Clear();
  get_presence_response.Clear();
  get_presence_request.set_bufferpacket_name(bufferpacket_name);
  get_presence_request.set_pmid("Dan");
  get_presence_request.set_public_key(pub_key);
  get_presence_request.set_signed_public_key(sig_pub_key);
  get_presence_request.set_signed_request(sig_req);
  done = google::protobuf::NewCallback<TestCallback>
         (&cb_obj, &TestCallback::CallbackFunction);
  service.GetBPPresence(&controller, &get_presence_request,
                        &get_presence_response, done);
  ASSERT_TRUE(get_presence_response.IsInitialized());
  EXPECT_EQ(kAck, static_cast<int>(get_presence_response.result()));
  EXPECT_EQ(get_presence_response.pmid_id(),
            co.Hash(get_presence_response.public_key() +
                    get_presence_response.signed_public_key(), "",
                    crypto::STRING_STRING, false));
  ASSERT_EQ(1, get_presence_response.messages_size());
  ASSERT_EQ(lp_gp.SerializeAsString(), get_presence_response.messages(0));

  // Get the messages again
  get_presence_request.Clear();
  get_presence_response.Clear();
  get_presence_request.set_bufferpacket_name(bufferpacket_name);
  get_presence_request.set_pmid("Dan");
  get_presence_request.set_public_key(pub_key);
  get_presence_request.set_signed_public_key(sig_pub_key);
  get_presence_request.set_signed_request(sig_req);
  done = google::protobuf::NewCallback<TestCallback>
         (&cb_obj, &TestCallback::CallbackFunction);
  service.GetBPPresence(&controller, &get_presence_request,
                        &get_presence_response, done);
  ASSERT_TRUE(get_presence_response.IsInitialized());
  EXPECT_EQ(kAck, static_cast<int>(get_presence_response.result()));
  EXPECT_EQ(get_presence_response.pmid_id(),
            co.Hash(get_presence_response.public_key() +
                    get_presence_response.signed_public_key(), "",
                    crypto::STRING_STRING, false));
  EXPECT_EQ(0, get_presence_response.messages_size());
}

}  // namespace maidsafe_vault
