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
#include <gtest/gtest.h>
#include <google/protobuf/descriptor.h>
#include <maidsafe/kademlia_service_messages.pb.h>
#include "maidsafe/vault/vaultservice.h"
#include "maidsafe/vault/vaultchunkstore.h"
#include "maidsafe/vault/vaultbufferpackethandler.h"

namespace fs = boost::filesystem;

const boost::uint64_t kAvailableSpace = 1073741824;

inline void CreateRSAKeys(std::string *pub_key, std::string *priv_key) {
  crypto::RsaKeyPair kp;
  kp.GenerateKeys(4096);
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
}

namespace maidsafe_vault {

class Callback {
 public:
  void CallbackFunction() {}
};

class VaultServicesTest : public testing::Test {
  protected:
    VaultServicesTest()
        : chunkstore_dir_("./TESTSTORAGE" +
                          base::itos(base::random_32bit_integer()),
                          fs::native),
          pmid_public_(),
          pmid_private_(),
          pmid_public_signature_(),
          pmid_(),
          non_hex_pmid_(),
          transport_(),
          channel_manager_(&transport_),
          knode_(),
          vault_chunkstore_(),
          vault_service_(),
          svc_channel_(),
          poh_() {}

    virtual void SetUp() {
      CreateRSAKeys(&pmid_public_, &pmid_private_);
      {
        crypto::Crypto co;
        co.set_symm_algorithm(crypto::AES_256);
        co.set_hash_algorithm(crypto::SHA_512);
        pmid_public_signature_ = co.AsymSign(pmid_public_, "", pmid_private_,
                                             crypto::STRING_STRING);
        pmid_ = co.Hash(pmid_public_ + pmid_public_signature_, "",
                        crypto::STRING_STRING, true);
        non_hex_pmid_ = base::DecodeFromHex(pmid_);
      }

      try {
        fs::remove_all(chunkstore_dir_);
      }
      catch(const std::exception &e) {
        printf("%s\n", e.what());
      }
      knode_ = new kad::KNode(&channel_manager_, &transport_, kad::VAULT,
                              pmid_private_, pmid_public_, false, false);
      vault_chunkstore_ = new VaultChunkStore(chunkstore_dir_.string(),
                                              kAvailableSpace, 0);
      ASSERT_TRUE(vault_chunkstore_->Init());

      vault_service_ = new VaultService(pmid_public_, pmid_private_,
                                        pmid_public_signature_,
                                        vault_chunkstore_, knode_, &poh_);

      svc_channel_ = new rpcprotocol::Channel(&channel_manager_, &transport_);
      svc_channel_->SetService(vault_service_);
      channel_manager_.RegisterChannel(vault_service_->GetDescriptor()->name(),
                                       svc_channel_);
    }

    virtual void TearDown() {
      channel_manager_.UnRegisterChannel(
          vault_service_->GetDescriptor()->name());
      transport_.Stop();
      channel_manager_.Stop();
      transport::CleanUp();
      delete svc_channel_;
      delete vault_service_;
      delete vault_chunkstore_;
      delete knode_;

      try {
        fs::remove_all(chunkstore_dir_);
      }
      catch(const std::exception &e) {
        printf("%s\n", e.what());
      }
    }

    fs::path chunkstore_dir_;
    std::string pmid_public_, pmid_private_, pmid_public_signature_;
    std::string pmid_, non_hex_pmid_;
    transport::Transport transport_;
    rpcprotocol::ChannelManager channel_manager_;
    kad::KNode *knode_;
    VaultChunkStore *vault_chunkstore_;
    VaultService *vault_service_;
    rpcprotocol::Channel *svc_channel_;
    PendingOperationsHandler poh_;

  private:
    VaultServicesTest(const VaultServicesTest&);
    VaultServicesTest& operator=(const VaultServicesTest&);
};

TEST_F(VaultServicesTest, BEH_MAID_ServicesValidateSignedRequest) {
  std::string pub_key, priv_key, key("xyz"), pmid, sig_pub_key, sig_req;
  CreateRSAKeys(&pub_key, &priv_key);

  EXPECT_TRUE(vault_service_->ValidateSignedRequest("abc", "def",
                                                    kAnonymousSignedRequest,
                                                    key, ""));

  CreateSignedRequest(pub_key, priv_key, key, &pmid, &sig_pub_key, &sig_req);
  EXPECT_TRUE(vault_service_->ValidateSignedRequest(pub_key, sig_pub_key,
                                                    sig_req, key, pmid));

  EXPECT_FALSE(vault_service_->ValidateSignedRequest(pub_key, sig_pub_key,
                                                     sig_req, key, "abcdef"));

  CreateSignedRequest("123", "456", key, &pmid, &sig_pub_key, &sig_req);
  EXPECT_FALSE(vault_service_->ValidateSignedRequest("123", sig_pub_key,
                                                     sig_req, key, pmid));
  EXPECT_FALSE(vault_service_->ValidateSignedRequest("abc", "def",
                                                     "ghi", key, pmid));
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
  ASSERT_EQ(0, vault_service_->Storable(12345));
  ASSERT_EQ(0, vault_service_->Storable(kAvailableSpace));
  ASSERT_NE(0, vault_service_->Storable(kAvailableSpace + 1));
}

TEST_F(VaultServicesTest, BEH_MAID_ServicesLocalStorage) {
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  std::string content("This is a data chunk");
  std::string chunkname(co.Hash(content, "", crypto::STRING_STRING, false));
  std::string test_content, new_content("This is another data chunk");
  EXPECT_FALSE(vault_service_->HasChunkLocal(chunkname));
  EXPECT_TRUE(vault_service_->StoreChunkLocal(chunkname, content));
  EXPECT_TRUE(vault_service_->HasChunkLocal(chunkname));
  EXPECT_TRUE(vault_service_->LoadChunkLocal(chunkname, &test_content));
  EXPECT_EQ(content, test_content);
  EXPECT_FALSE(vault_service_->LoadChunkLocal(chunkname + "X", &test_content));
  EXPECT_TRUE(vault_service_->UpdateChunkLocal(chunkname, new_content));
  EXPECT_TRUE(vault_service_->LoadChunkLocal(chunkname, &test_content));
  EXPECT_EQ(new_content, test_content);
  EXPECT_TRUE(vault_service_->DeleteChunkLocal(chunkname));
  EXPECT_FALSE(vault_service_->HasChunkLocal(chunkname));
  EXPECT_FALSE(vault_service_->LoadChunkLocal(chunkname, &test_content));
}

TEST_F(VaultServicesTest, BEH_MAID_ServicesStoreChunkPrep) {
/*  rpcprotocol::Controller controller;
  maidsafe::StorePrepRequest request;
  maidsafe::StorePrepResponse response;

  std::string pub_key, priv_key, pmid, sig_pub_key, sig_req;
  CreateRSAKeys(&pub_key, &priv_key);
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);
  std::string content("This is a data chunk");
  std::string chunkname(co.Hash(content, "", crypto::STRING_STRING, false));
  CreateSignedRequest(pub_key, priv_key, chunkname, &pmid, &sig_pub_key,
                      &sig_req);

  Callback cb_obj;

  // uninitialized request
  {
    google::protobuf::Closure *done = google::protobuf::NewCallback<Callback>
        (&cb_obj, &Callback::CallbackFunction);
    vault_service_->StorePrep(&controller, &request, &response, done);
    EXPECT_TRUE(response.IsInitialized());
    EXPECT_NE(kAck, static_cast<int>(response.result()));
    EXPECT_EQ(non_hex_pmid_, response.pmid());
    response.Clear();
  }

  request.set_chunkname(chunkname);
  request.set_data_size(kAvailableSpace + 1);
  request.set_pmid(pmid);
  request.set_public_key(pub_key);
  request.set_public_key_signature(sig_pub_key);
  request.set_request_signature(sig_req);

  // too much data
  {
    google::protobuf::Closure *done = google::protobuf::NewCallback<Callback>
        (&cb_obj, &Callback::CallbackFunction);
    vault_service_->StoreChunkPrep(&controller, &request, &response, done);
    EXPECT_TRUE(response.IsInitialized());
    EXPECT_NE(kAck, static_cast<int>(response.result()));
    EXPECT_EQ(non_hex_pmid_, response.pmid());
    response.Clear();
  }

  request.set_data_size(content.size());
  request.set_public_key("fail");

  // invalid request
  {
    google::protobuf::Closure *done = google::protobuf::NewCallback<Callback>
        (&cb_obj, &Callback::CallbackFunction);
    vault_service_->StoreChunkPrep(&controller, &request, &response, done);
    EXPECT_TRUE(response.IsInitialized());
    EXPECT_NE(kAck, static_cast<int>(response.result()));
    EXPECT_EQ(non_hex_pmid_, response.pmid());
    response.Clear();
  }

  request.set_public_key(pub_key);
  request.set_data_size(0);

  // make PendingOperationsHandler::AddPendingOperation() fail
  {
    google::protobuf::Closure *done = google::protobuf::NewCallback<Callback>
        (&cb_obj, &Callback::CallbackFunction);
    vault_service_->StoreChunkPrep(&controller, &request, &response, done);
    EXPECT_TRUE(response.IsInitialized());
    EXPECT_NE(kAck, static_cast<int>(response.result()));
    EXPECT_EQ(non_hex_pmid_, response.pmid());
    response.Clear();
  }

  request.set_data_size(content.size());
  std::string sig_req_to_self;
  CreateSignedRequest(pmid_public_, pmid_private_, chunkname, &pmid_,
                      &pmid_public_signature_, &sig_req_to_self);
  request.set_pmid(pmid_);
  request.set_public_key(pmid_public_);
  request.set_3(pmid_public_signature_);
  request.set_request_signature(sig_req_to_self);

  // request to store ourself
  {
    google::protobuf::Closure *done = google::protobuf::NewCallback<Callback>
        (&cb_obj, &Callback::CallbackFunction);
    vault_service_->StoreChunkPrep(&controller, &request, &response, done);
    EXPECT_TRUE(response.IsInitialized());
    EXPECT_NE(kAck, static_cast<int>(response.result()));
    EXPECT_EQ(non_hex_pmid_, response.pmid());
    response.Clear();
  }

  request.set_pmid(pmid);
  request.set_public_key(pub_key);
  request.set_public_key_signature(sig_pub_key);
  request.set_request_signature(sig_req);

  // proper request
  {
    google::protobuf::Closure *done = google::protobuf::NewCallback<Callback>
        (&cb_obj, &Callback::CallbackFunction);
    vault_service_->StoreChunkPrep(&controller, &request, &response, done);
    EXPECT_TRUE(response.IsInitialized());
    EXPECT_EQ(kAck, static_cast<int>(response.result()));
    EXPECT_EQ(non_hex_pmid_, response.pmid());
  }

  maidsafe::IOUAuthority iou_authority;
  iou_authority.set_data_size(content.size());
  iou_authority.set_pmid(non_hex_pmid_);
  std::string iou_authority_str;
  iou_authority.SerializeToString(&iou_authority_str);
  EXPECT_EQ(iou_authority_str, response.iou_authority());
  std::string signed_iou_authority(co.AsymSign(iou_authority_str, "",
      pmid_private_, crypto::STRING_STRING));
  EXPECT_EQ(signed_iou_authority, response.signed_iou_authority());*/
}

TEST_F(VaultServicesTest, BEH_MAID_ServicesStoreChunks) {
  rpcprotocol::Controller controller;
  maidsafe::StoreChunkRequest request;
  maidsafe::StoreChunkResponse response;

  std::string pub_key, priv_key, pmid, sig_pub_key, sig_req;
  CreateRSAKeys(&pub_key, &priv_key);
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);
  std::string content("This is a data chunk");
  std::string chunkname(co.Hash(content, "", crypto::STRING_STRING, false));
  CreateSignedRequest(pub_key, priv_key, chunkname, &pmid, &sig_pub_key,
                      &sig_req);

  Callback cb_obj;

  for (boost::uint32_t i = 0; i <= 1; ++i) {
    switch (i) {
      case 0:  // uninitialized request
        break;
      case 1:  // invalid request
        request.set_chunkname(chunkname);
        request.set_data(content);
        request.set_pmid(pmid);
        request.set_public_key("fail");  // !
        request.set_public_key_signature(sig_pub_key);
        request.set_request_signature(sig_req);
        request.set_data_type(maidsafe::DATA);
        // request.set_offset(  );
        // request.set_chunklet_size(  );
        break;
    }

    google::protobuf::Closure *done = google::protobuf::NewCallback<Callback>
        (&cb_obj, &Callback::CallbackFunction);
    vault_service_->StoreChunk(&controller, &request, &response, done);
    EXPECT_TRUE(response.IsInitialized());
    EXPECT_NE(kAck, static_cast<int>(response.result()));
    response.Clear();
  }

  request.set_public_key(pub_key);
  request.set_data("abcdef");

  // TODO(anyone) add more data types
  int data_type[] = { maidsafe::PDDIR_SIGNED, maidsafe::DATA };

  // invalid data for all data types
  for (size_t i = 0; i < sizeof(data_type)/sizeof(data_type[0]); ++i) {
    request.set_data_type(data_type[i]);
    google::protobuf::Closure *done = google::protobuf::NewCallback<Callback>
        (&cb_obj, &Callback::CallbackFunction);
    vault_service_->StoreChunk(&controller, &request, &response, done);
    EXPECT_TRUE(response.IsInitialized());
    EXPECT_NE(kAck, static_cast<int>(response.result()));
    response.Clear();
  }

  request.set_data(content);
  request.set_data_type(maidsafe::DATA);

  // #1 make PendingOperationsHandler::FindOperation() fail
  // #2 actually store the chunk
  // #3 try storing again, will make StoreChunkLocal() fail, but service wiil
  //    return overall success
  for (int i = 0; i < 3; ++i) {
    if (i > 0) {
      EXPECT_EQ(0, poh_.AddPendingOperation(pmid, chunkname, content.size(), "",
                                            "", 0, pub_key, STORE_ACCEPTED));
    }
    google::protobuf::Closure *done = google::protobuf::NewCallback<Callback>
        (&cb_obj, &Callback::CallbackFunction);
    vault_service_->StoreChunk(&controller, &request, &response, done);
    EXPECT_TRUE(response.IsInitialized());
    if (i > 0) {
      EXPECT_EQ(kAck, static_cast<int>(response.result()));
    } else {
      EXPECT_NE(kAck, static_cast<int>(response.result()));
    }
    response.Clear();
  }

  // TODO(Steve) make PendingOperationsHandler::AdvanceStatus() fail (?)

  // check success for all remaining data types
  for (size_t i = 0; i < sizeof(data_type)/sizeof(data_type[0]); ++i) {
    if (data_type[i] == maidsafe::DATA) continue;
    request.set_data_type(data_type[i]);

    if (data_type[i] == maidsafe::PDDIR_SIGNED) {
      maidsafe::GenericPacket gp;
      gp.set_data("Generic System Packet Data " + base::itos(i));
      gp.set_signature(co.AsymSign(gp.data(), "", priv_key,
                                   crypto::STRING_STRING));
      content = gp.SerializeAsString();
    }

    chunkname = co.Hash(content, "", crypto::STRING_STRING, false);
    CreateSignedRequest(pub_key, priv_key, chunkname, &pmid, &sig_pub_key,
                        &sig_req);
    request.set_chunkname(chunkname);
    request.set_data(content);
    request.set_pmid(pmid);
    request.set_public_key_signature(sig_pub_key);
    request.set_request_signature(sig_req);

    EXPECT_EQ(0, poh_.AddPendingOperation(pmid, chunkname, content.size(), "",
                                          "", 0, pub_key, STORE_ACCEPTED));

    google::protobuf::Closure *done = google::protobuf::NewCallback<Callback>
        (&cb_obj, &Callback::CallbackFunction);
    vault_service_->StoreChunk(&controller, &request, &response, done);
    EXPECT_TRUE(response.IsInitialized());
    EXPECT_EQ(kAck, static_cast<int>(response.result()));
    response.Clear();
  }
}

/*TEST_F(VaultServicesTest, BEH_MAID_ServicesIOUDone) {
  rpcprotocol::Controller controller;
  maidsafe::IOUDoneRequest request;
  maidsafe::IOUDoneResponse response;

  std::string pub_key, priv_key, pmid, sig_pub_key, sig_req;
  CreateRSAKeys(&pub_key, &priv_key);
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);
  std::string content("This is a data chunk");
  std::string chunkname(co.Hash(content, "", crypto::STRING_STRING, false));
  CreateSignedRequest(pub_key, priv_key, chunkname, &pmid, &sig_pub_key,
                      &sig_req);

  Callback cb_obj;

  for (boost::uint32_t i = 0; i <= 2; ++i) {
    switch (i) {
      case 0:  // uninitialized request
        break;
      case 1:  // invalid request
        request.set_chunkname(chunkname);
        request.set_own_pmid(pmid);
        request.set_public_key("fail");  // !
        request.set_public_key_signature(sig_pub_key);
        request.set_request_signature(sig_req);
        break;
      case 2:  // make PendingOperationsHandler::AdvanceStatus() fail
        request.set_public_key(pub_key);
        break;
    }

    google::protobuf::Closure *done = google::protobuf::NewCallback<Callback>
        (&cb_obj, &Callback::CallbackFunction);
    vault_service_->IOUDone(&controller, &request, &response, done);
    EXPECT_TRUE(response.IsInitialized());
    EXPECT_NE(kAck, static_cast<int>(response.result()));
    response.Clear();
  }

  // proper request
  {
    ASSERT_EQ(0, poh_.AddPendingOperation("pmid", chunkname, 1, "", "", 0, "",
                                          STORE_DONE));

    google::protobuf::Closure *done = google::protobuf::NewCallback<Callback>
        (&cb_obj, &Callback::CallbackFunction);
    vault_service_->IOUDone(&controller, &request, &response, done);
    EXPECT_TRUE(response.IsInitialized());
    EXPECT_EQ(kAck, static_cast<int>(response.result()));
    response.Clear();
  }
}

TEST_F(VaultServicesTest, BEH_MAID_ServicesStoreIOU) {
  rpcprotocol::Controller controller;
  maidsafe::StoreIOURequest request;
  maidsafe::StoreIOUResponse response;

  std::string pub_key, priv_key, pmid, sig_pub_key, sig_req;
  CreateRSAKeys(&pub_key, &priv_key);
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);
  std::string content("This is a data chunk");
  std::string chunkname(co.Hash(content, "", crypto::STRING_STRING, false));
  CreateSignedRequest(pub_key, priv_key, chunkname, &pmid, &sig_pub_key,
                      &sig_req);

  Callback cb_obj;

  for (boost::uint32_t i = 0; i <= 4; ++i) {
    switch (i) {
      case 0:  // uninitialized request
        break;
      case 1:  // invalid request
        request.set_chunkname(chunkname);
        request.set_data_size(content.size());
        request.set_collector_pmid("pmid");
        request.set_iou("iou");
        request.set_own_pmid(pmid);
        request.set_public_key("fail");  // !
        request.set_public_key_signature(sig_pub_key);
        request.set_request_signature(sig_req);
        break;
      case 2:  // invalid data size
        request.set_public_key(pub_key);
        request.set_data_size(0);
        break;
      case 3:  // no IOU
        request.set_data_size(content.size());
        request.set_iou("");
        break;
      case 4:  // make PendingOperationsHandler::AddPendingOperation() fail
        request.set_iou("iou");
        ASSERT_EQ(0, poh_.AddPendingOperation("pmid", chunkname, content.size(),
                                              "iou", "", 0, "", IOU_RECEIVED));
        break;
    }

    google::protobuf::Closure *done = google::protobuf::NewCallback<Callback>
        (&cb_obj, &Callback::CallbackFunction);
    vault_service_->StoreIOU(&controller, &request, &response, done);
    EXPECT_TRUE(response.IsInitialized());
    EXPECT_NE(kAck, static_cast<int>(response.result()));
    response.Clear();
  }

  poh_.ClearPendingOperations();

  // proper request
  {
    google::protobuf::Closure *done = google::protobuf::NewCallback<Callback>
        (&cb_obj, &Callback::CallbackFunction);
    vault_service_->StoreIOU(&controller, &request, &response, done);
    EXPECT_TRUE(response.IsInitialized());
    EXPECT_EQ(kAck, static_cast<int>(response.result()));
    response.Clear();
  }
}
*/
TEST_F(VaultServicesTest, BEH_MAID_ServicesStoreChunkReference) {
  rpcprotocol::Controller controller;
  maidsafe::AddToReferenceListRequest request;
  maidsafe::AddToReferenceListResponse response;

  std::string pub_key, priv_key, pmid, sig_pub_key, sig_req;
  CreateRSAKeys(&pub_key, &priv_key);
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);
  std::string content("This is a data chunk");
  std::string chunkname(co.Hash(content, "", crypto::STRING_STRING, false));
  CreateSignedRequest(pub_key, priv_key, chunkname, &pmid, &sig_pub_key,
                      &sig_req);

  Callback cb_obj;

  for (boost::uint32_t i = 0; i <= 2; ++i) {
    switch (i) {
      case 0:  // uninitialized request
        break;
      case 1:  // invalid request
        request.set_chunkname(chunkname);
/*        request.set_pmid(pmid);
        request.set_signed_pmid("signed pmid");
        request.set_public_key("fail");  // !
        request.set_public_key_signature(sig_pub_key);*/
        request.set_request_signature(sig_req);
        break;
      case 2:  // make PendingOperationsHandler::GetSizeAndIOU() fail
/*        request.set_public_key(pub_key);*/
        break;
      // TODO(Steve) make PendingOperationsHandler::AdvanceStatus() fail (?)
      // TODO(Steve) make KNode::StoreValueLocal() fail (?)
    }

    google::protobuf::Closure *done = google::protobuf::NewCallback<Callback>
        (&cb_obj, &Callback::CallbackFunction);
    vault_service_->StoreChunkReference(&controller, &request, &response, done);
    EXPECT_TRUE(response.IsInitialized());
    EXPECT_NE(kAck, static_cast<int>(response.result()));
    response.Clear();
  }

  poh_.ClearPendingOperations();
  ASSERT_EQ(0, poh_.AddPendingOperation(pmid, chunkname, content.size(),
                                        "iou", "", 0, "", IOU_RECEIVED));

  // proper request
  {
    google::protobuf::Closure *done = google::protobuf::NewCallback<Callback>
        (&cb_obj, &Callback::CallbackFunction);
    vault_service_->StoreChunkReference(&controller, &request, &response, done);
    EXPECT_TRUE(response.IsInitialized());
    EXPECT_EQ(kAck, static_cast<int>(response.result()));
    response.Clear();

    kad::SignedValue signed_value;
    signed_value.set_value(pmid);
/*    signed_value.set_value_signature(request.signed_pmid());*/
    std::string ser_signed_value = signed_value.SerializeAsString();

    std::vector<std::string> values;
    ASSERT_TRUE(knode_->FindValueLocal(chunkname, &values));
    ASSERT_EQ(size_t(1), values.size());
    ASSERT_EQ(ser_signed_value, values[0]);
  }
}

TEST_F(VaultServicesTest, BEH_MAID_ServicesGetCheck) {
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

  Callback cb_obj;

  // test Get()'s error handling
  for (boost::uint32_t i = 0; i <= 1; ++i) {
    switch (i) {
      case 0:  // uninitialized request
        break;
      case 1:  // make LoadChunkLocal() fail
        request.set_chunkname(chunkname);
        break;
    }

    google::protobuf::Closure *done = google::protobuf::NewCallback<Callback>
        (&cb_obj, &Callback::CallbackFunction);
    vault_service_->GetChunk(&controller, &request, &response, done);
    EXPECT_TRUE(response.IsInitialized());
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
    google::protobuf::Closure *done = google::protobuf::NewCallback<Callback>
        (&cb_obj, &Callback::CallbackFunction);
    vault_service_->CheckChunk(&controller, &check_request, &check_response,
                               done);
    EXPECT_TRUE(check_response.IsInitialized());
    EXPECT_NE(kAck, static_cast<int>(check_response.result()));
    response.Clear();
  }

  // test both for success
  {
    ASSERT_TRUE(vault_service_->StoreChunkLocal(chunkname, content));

    google::protobuf::Closure *done1 = google::protobuf::NewCallback<Callback>
        (&cb_obj, &Callback::CallbackFunction);
    vault_service_->CheckChunk(&controller, &check_request, &check_response,
                               done1);
    EXPECT_TRUE(check_response.IsInitialized());
    EXPECT_EQ(kAck, static_cast<int>(check_response.result()));
    response.Clear();

    google::protobuf::Closure *done2 = google::protobuf::NewCallback<Callback>
        (&cb_obj, &Callback::CallbackFunction);
    vault_service_->GetChunk(&controller, &request, &response, done2);
    EXPECT_TRUE(response.IsInitialized());
    EXPECT_EQ(kAck, static_cast<int>(response.result()));
    EXPECT_EQ(content, response.content());
    response.Clear();
  }
}

TEST_F(VaultServicesTest, BEH_MAID_ServicesUpdate) {
  rpcprotocol::Controller controller;
  maidsafe::UpdateChunkRequest request;
  maidsafe::UpdateChunkResponse response;

  std::string pub_key, priv_key, pmid, sig_pub_key, sig_req;
  CreateRSAKeys(&pub_key, &priv_key);
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);
  std::string content("This is a data chunk"), prev_content("");
  std::string chunkname(co.Hash(content, "", crypto::STRING_STRING, false));
  CreateSignedRequest(pub_key, priv_key, chunkname, &pmid, &sig_pub_key,
                      &sig_req);

  Callback cb_obj;

  for (boost::uint32_t i = 0; i <= 2; ++i) {
    switch (i) {
      case 0:  // uninitialized request
        break;
      case 1:  // invalid request
        request.set_chunkname(chunkname);
        request.set_data(content);
        request.set_pmid(pmid);
        request.set_public_key("fail");  // !
        request.set_public_key_signature(sig_pub_key);
        request.set_request_signature(sig_req);
        request.set_data_type(maidsafe::SYSTEM_PACKET);
        break;
      case 2:  // make LoadChunkLocal() fail
        request.set_public_key(pub_key);
        break;
    }

    google::protobuf::Closure *done = google::protobuf::NewCallback<Callback>
        (&cb_obj, &Callback::CallbackFunction);
    vault_service_->UpdateChunk(&controller, &request, &response, done);
    EXPECT_TRUE(response.IsInitialized());
    EXPECT_NE(kAck, static_cast<int>(response.result()));
    response.Clear();
  }

  ASSERT_TRUE(vault_service_->StoreChunkLocal(chunkname, content));
  request.set_data("abcdef");

  // TODO(anyone) add more data types
  int data_type[] = { maidsafe::SYSTEM_PACKET, maidsafe::PDDIR_SIGNED };

  // invalid data for all data types
  for (size_t i = 0; i < sizeof(data_type)/sizeof(data_type[0]); ++i) {
    request.set_data_type(data_type[i]);
    google::protobuf::Closure *done = google::protobuf::NewCallback<Callback>
        (&cb_obj, &Callback::CallbackFunction);
    vault_service_->UpdateChunk(&controller, &request, &response, done);
    EXPECT_TRUE(response.IsInitialized());
    EXPECT_NE(kAck, static_cast<int>(response.result()));
    response.Clear();
  }

  // valid data for all data types
  for (size_t i = 0; i < sizeof(data_type)/sizeof(data_type[0]); ++i) {
    request.set_data_type(data_type[i]);
    prev_content = "";

    switch (data_type[i]) {
      case maidsafe::SYSTEM_PACKET:
      case maidsafe::PDDIR_SIGNED: {
        maidsafe::GenericPacket gp;
        gp.set_data("Generic System Packet Data " + base::itos(i));
        gp.set_signature(co.AsymSign(gp.data(), "", priv_key,
                                     crypto::STRING_STRING));
        content = gp.SerializeAsString();
        break;
      }
    }

    if (prev_content.empty())
      prev_content = content;

    chunkname = co.Hash(prev_content, "", crypto::STRING_STRING, false);
    CreateSignedRequest(pub_key, priv_key, chunkname, &pmid, &sig_pub_key,
                        &sig_req);
    request.set_chunkname(chunkname);
    request.set_pmid(pmid);
    request.set_data(content);
    request.set_public_key_signature(sig_pub_key);
    request.set_request_signature(sig_req);

    ASSERT_TRUE(vault_service_->StoreChunkLocal(chunkname, prev_content));

    google::protobuf::Closure *done = google::protobuf::NewCallback<Callback>
        (&cb_obj, &Callback::CallbackFunction);
    vault_service_->UpdateChunk(&controller, &request, &response, done);
    EXPECT_TRUE(response.IsInitialized());
    EXPECT_EQ(kAck, static_cast<int>(response.result()));
    response.Clear();
  }
}

TEST_F(VaultServicesTest, BEH_MAID_ServicesDelete) {
  rpcprotocol::Controller controller;
  maidsafe::DeleteChunkRequest request;
  maidsafe::DeleteChunkResponse response;

  std::string pub_key, priv_key, pmid, sig_pub_key, sig_req;
  CreateRSAKeys(&pub_key, &priv_key);
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);
  std::string content("This is a data chunk"), prev_content("");
  std::string chunkname(co.Hash(content, "", crypto::STRING_STRING, false));
  CreateSignedRequest(pub_key, priv_key, chunkname, &pmid, &sig_pub_key,
                      &sig_req);

  Callback cb_obj;

  for (boost::uint32_t i = 0; i <= 2; ++i) {
    switch (i) {
      case 0:  // uninitialized request
        break;
      case 1:  // invalid request
        request.set_chunkname(chunkname);
/*        request.set_pmid(pmid);
        request.set_public_key("fail");  // !
        request.set_public_key_signature(sig_pub_key);*/
        request.set_request_signature(sig_req);
        request.set_data_type(maidsafe::SYSTEM_PACKET);
        break;
      case 2:  // make LoadChunkLocal() fail
/*        request.set_public_key(pub_key);*/
        break;
    }

    google::protobuf::Closure *done = google::protobuf::NewCallback<Callback>
        (&cb_obj, &Callback::CallbackFunction);
    vault_service_->DeleteChunk(&controller, &request, &response, done);
    EXPECT_TRUE(response.IsInitialized());
    EXPECT_NE(kAck, static_cast<int>(response.result()));
    response.Clear();
  }

  ASSERT_TRUE(vault_service_->StoreChunkLocal(chunkname, "abcde"));

  // TODO(anyone) add more data types
  int data_type[] = {maidsafe::SYSTEM_PACKET, maidsafe::PDDIR_SIGNED};

  // invalid data for all data types
  for (size_t i = 0; i < sizeof(data_type)/sizeof(data_type[0]); ++i) {
    request.set_data_type(data_type[i]);
    google::protobuf::Closure *done = google::protobuf::NewCallback<Callback>
        (&cb_obj, &Callback::CallbackFunction);
    vault_service_->DeleteChunk(&controller, &request, &response, done);
    EXPECT_TRUE(response.IsInitialized());
    EXPECT_NE(kAck, static_cast<int>(response.result()));
    response.Clear();
  }

  // test success
  for (size_t i = 0; i < sizeof(data_type)/sizeof(data_type[0]); ++i) {
    request.set_data_type(data_type[i]);

    switch (data_type[i]) {
      case maidsafe::SYSTEM_PACKET:
      case maidsafe::PDDIR_SIGNED: {
        maidsafe::GenericPacket gp;
        gp.set_data("Generic System Packet Data " + base::itos(i));
        gp.set_signature(co.AsymSign(gp.data(), "", priv_key,
                                     crypto::STRING_STRING));
        content = gp.SerializeAsString();
        break;
      }
    }

    chunkname = co.Hash(content, "", crypto::STRING_STRING, false);
    CreateSignedRequest(pub_key, priv_key, chunkname, &pmid, &sig_pub_key,
                        &sig_req);
    request.set_chunkname(chunkname);
/*    request.set_pmid(pmid);
    request.set_public_key_signature(sig_pub_key);*/
    request.set_request_signature(sig_req);

    ASSERT_TRUE(vault_service_->StoreChunkLocal(chunkname, content));
    ASSERT_TRUE(vault_service_->HasChunkLocal(chunkname));

    google::protobuf::Closure *done = google::protobuf::NewCallback<Callback>
        (&cb_obj, &Callback::CallbackFunction);
    vault_service_->DeleteChunk(&controller, &request, &response, done);
    EXPECT_TRUE(response.IsInitialized());
    EXPECT_EQ(kAck, static_cast<int>(response.result()));
    ASSERT_FALSE(vault_service_->HasChunkLocal(chunkname));
    response.Clear();
  }
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

  Callback cb_obj;

  for (boost::uint32_t i = 0; i <= 1; ++i) {
    switch (i) {
      case 0:  // uninitialized request
        break;
      case 1:  // make LoadChunkLocal() fail
        request.set_chunkname(chunkname);
        request.set_random_data(rnd_data);
        break;
    }

    google::protobuf::Closure *done = google::protobuf::NewCallback<Callback>
        (&cb_obj, &Callback::CallbackFunction);
    vault_service_->ValidityCheck(&controller, &request, &response, done);
    EXPECT_TRUE(response.IsInitialized());
    EXPECT_NE(kAck, static_cast<int>(response.result()));
    response.Clear();
  }

  ASSERT_TRUE(vault_service_->StoreChunkLocal(chunkname, content));

  // test success
  {
    google::protobuf::Closure *done = google::protobuf::NewCallback<Callback>
        (&cb_obj, &Callback::CallbackFunction);
    vault_service_->ValidityCheck(&controller, &request, &response, done);
    EXPECT_TRUE(response.IsInitialized());
    EXPECT_EQ(kAck, static_cast<int>(response.result()));
    EXPECT_EQ(vc_hash, response.hash_content());
  }
}

// TODO(Steve) test VaultService::SwapChunk() -- waiting for implementation
/* TEST_F(VaultServicesTest, BEH_MAID_ServicesSwapChunk) {
  rpcprotocol::Controller controller;
  maidsafe::SwapChunkRequest request;
  maidsafe::SwapChunkResponse response;

  std::string pub_key, priv_key, pmid, sig_pub_key, sig_req;
  CreateRSAKeys(&pub_key, &priv_key);
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);
  std::string content("This is a data chunk");
  std::string chunkname(co.Hash(content, "", crypto::STRING_STRING, false));
  CreateSignedRequest(pub_key, priv_key, chunkname, &pmid, &sig_pub_key,
                      &sig_req);

  Callback cb_obj;

  for (boost::uint32_t i = 0; i <= 2; ++i) {
    switch (i) {
      case 0:  // uninitialized request
        break;
      case 1:  // invalid request type
        request.set_request_type(2);
        request.set_chunkname1(chunkname);
        request.set_chunkcontent1(content);  // opt
        request.set_size1(content.size());  // opt
        // request.set_chunkcontent2( );  // opt
        break;
      case 2:  // make HasChunkLocal() fail
        request.set_request_type(0);
        break;
      // ...
    }

    google::protobuf::Closure *done = google::protobuf::NewCallback<Callback>
        (&cb_obj, &Callback::CallbackFunction);
    vault_service_->SwapChunk(&controller, &request, &response, done);
    EXPECT_TRUE(response.IsInitialized());
    EXPECT_NE(kAck, static_cast<int>(response.result()));
    response.Clear();
  }

  // ...
} */

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

  Callback cb_obj;

  for (boost::uint32_t i = 0; i <= 1; ++i) {
    switch (i) {
      case 0:  // uninitialized request
        break;
      case 1:  // invalid request
        request.set_encrypted_request("fail");
        break;
    }

    google::protobuf::Closure *done = google::protobuf::NewCallback<Callback>
        (&cb_obj, &Callback::CallbackFunction);
    vault_service_->VaultStatus(&controller, &request, &response, done);
    EXPECT_TRUE(response.IsInitialized());
    EXPECT_NE(kAck, static_cast<int>(response.result()));
    response.Clear();
  }

  // test success
  {
    maidsafe::VaultCommunication vc;
    vc.set_timestamp(0);
    std::string enc_req = co.AsymEncrypt(vc.SerializeAsString(), "",
                                         pmid_public_,
                                         crypto::STRING_STRING);
    request.set_encrypted_request(enc_req);

    google::protobuf::Closure *done = google::protobuf::NewCallback<Callback>
        (&cb_obj, &Callback::CallbackFunction);
    vault_service_->VaultStatus(&controller, &request, &response, done);
    EXPECT_TRUE(response.IsInitialized());
    EXPECT_EQ(kAck, static_cast<int>(response.result()));

    std::string dec_rsp = co.AsymDecrypt(response.encrypted_response(), "",
                                         pmid_private_,
                                         crypto::STRING_STRING);
    EXPECT_TRUE(vc.ParseFromString(dec_rsp));
    EXPECT_EQ(vault_chunkstore_->ChunkStoreDir(), vc.chunkstore());
    EXPECT_EQ(vault_chunkstore_->available_space(), vc.offered_space());
    EXPECT_EQ(vault_chunkstore_->FreeSpace(), vc.free_space());

    response.Clear();
  }
}

TEST_F(VaultServicesTest, BEH_MAID_ServicesCreateBP) {
  VaultService service(pmid_public_, pmid_private_, pmid_public_signature_,
    vault_chunkstore_, NULL, &poh_);
  rpcprotocol::Controller controller;
  maidsafe::CreateBPRequest request;
  maidsafe::CreateBPResponse response;

  // Not initialised
  Callback cb_obj;
  google::protobuf::Closure *done = google::protobuf::NewCallback<Callback>
    (&cb_obj, &Callback::CallbackFunction);
  service.CreateBP(&controller, &request, &response, done);
  ASSERT_EQ(kNack, static_cast<int>(response.result()));
  ASSERT_EQ(non_hex_pmid_, response.pmid_id());
  ASSERT_EQ(pmid_public_, response.public_key());
  ASSERT_EQ(pmid_public_signature_, response.signed_public_key());

  std::string pub_key, priv_key, pmid, sig_pub_key, sig_req;
  CreateRSAKeys(&pub_key, &priv_key);
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);

  maidsafe::BufferPacketInfo bpi;
  bpi.set_owner("Dan");
  bpi.set_ownerpublickey(pub_key);
  bpi.set_online(1);
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
  request.set_pmid(pmid);
  request.set_public_key(pub_key);
  request.set_signed_public_key(sig_pub_key);
  request.set_signed_request(sig_req);

  done = google::protobuf::NewCallback<Callback>
         (&cb_obj, &Callback::CallbackFunction);
  service.CreateBP(&controller, &request, &response, done);
  ASSERT_TRUE(response.IsInitialized());
  ASSERT_EQ(kAck, static_cast<int>(response.result()));
  ASSERT_EQ(response.pmid_id(), co.Hash(response.public_key() +
    response.signed_public_key(), "", crypto::STRING_STRING, false));

  // Load the stored BP
  std::string test_content;
  ASSERT_TRUE(service.HasChunkLocal(bufferpacket_name));
  ASSERT_TRUE(service.LoadChunkLocal(bufferpacket_name, &test_content));
  ASSERT_EQ(ser_bp, test_content);
}

TEST_F(VaultServicesTest, BEH_MAID_ServicesModifyBPInfo) {
  VaultService service(pmid_public_, pmid_private_, pmid_public_signature_,
    vault_chunkstore_, NULL, &poh_);
  rpcprotocol::Controller controller;
  maidsafe::CreateBPRequest create_request;
  maidsafe::CreateBPResponse create_response;

  // Not initialised
  Callback cb_obj;
  google::protobuf::Closure *done = google::protobuf::NewCallback<Callback>
    (&cb_obj, &Callback::CallbackFunction);
  std::string pub_key, priv_key, pmid, sig_pub_key, sig_req;
  CreateRSAKeys(&pub_key, &priv_key);
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);


  maidsafe::BufferPacketInfo bpi;
  bpi.set_owner("Dan");
  bpi.set_ownerpublickey(pub_key);
  bpi.set_online(1);
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
  create_request.set_pmid(pmid);
  create_request.set_public_key(pub_key);
  create_request.set_signed_public_key(sig_pub_key);
  create_request.set_signed_request(sig_req);

  done = google::protobuf::NewCallback<Callback> (&cb_obj,
    &Callback::CallbackFunction);
  service.CreateBP(&controller, &create_request, &create_response,
    done);
  ASSERT_TRUE(create_response.IsInitialized());
  ASSERT_EQ(kAck, static_cast<int>(create_response.result()));
  ASSERT_EQ(create_response.pmid_id(), co.Hash(create_response.public_key() +
    create_response.signed_public_key(), "", crypto::STRING_STRING, false));

  // Load the stored BP
  std::string test_content;
  ASSERT_TRUE(service.HasChunkLocal(bufferpacket_name));
  ASSERT_TRUE(service.LoadChunkLocal(bufferpacket_name, &test_content));
  ASSERT_EQ(ser_bp, test_content);

  // Wrong data: not a Generic Packet
  maidsafe::ModifyBPInfoRequest modify_request;
  maidsafe::ModifyBPInfoResponse modify_response;
  modify_request.set_bufferpacket_name(bufferpacket_name);
  modify_request.set_data("some bollocks that doesn't serialise or parse");
  modify_request.set_pmid(pmid);
  modify_request.set_public_key(pub_key);
  modify_request.set_signed_public_key(sig_pub_key);
  modify_request.set_signed_request(sig_req);
  done = google::protobuf::NewCallback<Callback> (&cb_obj,
    &Callback::CallbackFunction);
  service.ModifyBPInfo(&controller, &modify_request, &modify_response, done);
  ASSERT_EQ(kNack, static_cast<int>(modify_response.result()));
  ASSERT_EQ(non_hex_pmid_, modify_response.pmid_id());
  ASSERT_EQ(pmid_public_, modify_response.public_key());
  ASSERT_EQ(pmid_public_signature_, modify_response.signed_public_key());

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
  done = google::protobuf::NewCallback<Callback> (&cb_obj,
    &Callback::CallbackFunction);
  service.ModifyBPInfo(&controller, &modify_request, &modify_response, done);
  ASSERT_EQ(kNack, static_cast<int>(modify_response.result()));
  ASSERT_EQ(non_hex_pmid_, modify_response.pmid_id());
  ASSERT_EQ(pmid_public_, modify_response.public_key());
  ASSERT_EQ(pmid_public_signature_, modify_response.signed_public_key());

  // Wrong bufferpacket name
  modify_request.Clear();
  modify_response.Clear();
  bpi.Clear();
  bpi.set_owner("Dan");
  bpi.set_ownerpublickey(pub_key);
  bpi.set_online(0);
  bpi.add_users("newuser0");
  bpi.add_users("newuser1");
  bpi.add_users("newuser2");
  bpi.SerializeToString(&ser_bpi);
  gp.set_data(ser_bpi);
  gp.set_signature(co.AsymSign(gp.data(), "", priv_key, crypto::STRING_STRING));
  gp.SerializeToString(&ser_gp);
  modify_request.set_bufferpacket_name("some bp that doesn't exist");
  modify_request.set_data(ser_gp);
  modify_request.set_pmid(pmid);
  modify_request.set_public_key(pub_key);
  modify_request.set_signed_public_key(sig_pub_key);
  modify_request.set_signed_request(co.AsymSign(co.Hash(pub_key + sig_pub_key +
    modify_request.bufferpacket_name(), "", crypto::STRING_STRING, false), "",
    priv_key, crypto::STRING_STRING));
  done = google::protobuf::NewCallback<Callback> (&cb_obj,
    &Callback::CallbackFunction);
  service.ModifyBPInfo(&controller, &modify_request, &modify_response, done);
  ASSERT_EQ(kNack, static_cast<int>(modify_response.result()));
  ASSERT_EQ(non_hex_pmid_, modify_response.pmid_id());
  ASSERT_EQ(pmid_public_, modify_response.public_key());
  ASSERT_EQ(pmid_public_signature_, modify_response.signed_public_key());

  // Correct change
  modify_request.Clear();
  modify_response.Clear();
  modify_request.set_bufferpacket_name(bufferpacket_name);
  modify_request.set_data(ser_gp);
  modify_request.set_pmid(pmid);
  modify_request.set_public_key(pub_key);
  modify_request.set_signed_public_key(sig_pub_key);
  modify_request.set_signed_request(sig_req);
  done = google::protobuf::NewCallback<Callback> (&cb_obj,
    &Callback::CallbackFunction);
  service.ModifyBPInfo(&controller, &modify_request, &modify_response, done);
  ASSERT_EQ(kAck, static_cast<int>(modify_response.result()));
  ASSERT_EQ(non_hex_pmid_, modify_response.pmid_id());
  ASSERT_EQ(pmid_public_, modify_response.public_key());
  ASSERT_EQ(pmid_public_signature_, modify_response.signed_public_key());

  ASSERT_TRUE(service.HasChunkLocal(bufferpacket_name));
  ASSERT_TRUE(service.LoadChunkLocal(bufferpacket_name, &test_content));
  ASSERT_TRUE(bp.ParseFromString(test_content));
  ASSERT_TRUE(bpi.ParseFromString(bp.owner_info(0).data()));
  ASSERT_EQ("Dan", bpi.owner());
  ASSERT_EQ(pub_key, bpi.ownerpublickey());
  ASSERT_EQ(0, bpi.online());
  ASSERT_EQ(3, bpi.users_size());
  for (int n = 0; n < bpi.users_size(); ++n)
    ASSERT_EQ("newuser" + base::itos(n), bpi.users(n));
}

TEST_F(VaultServicesTest, BEH_MAID_ServicesGetBPMessages) {
  VaultService service(pmid_public_, pmid_private_, pmid_public_signature_,
    vault_chunkstore_, NULL, &poh_);
  rpcprotocol::Controller controller;
  maidsafe::CreateBPRequest request;
  maidsafe::CreateBPResponse response;

  // Not initialised
  Callback cb_obj;
  google::protobuf::Closure *done = google::protobuf::NewCallback<Callback>
    (&cb_obj, &Callback::CallbackFunction);
  std::string pub_key, priv_key, pmid, sig_pub_key, sig_req;
  CreateRSAKeys(&pub_key, &priv_key);
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);

  maidsafe::BufferPacketInfo bpi;
  bpi.set_owner("Dan");
  bpi.set_ownerpublickey(pub_key);
  bpi.set_online(1);
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
  request.set_pmid(pmid);
  request.set_public_key(pub_key);
  request.set_signed_public_key(sig_pub_key);
  request.set_signed_request(sig_req);

  service.CreateBP(&controller, &request, &response, done);
  ASSERT_TRUE(response.IsInitialized());
  ASSERT_EQ(kAck, static_cast<int>(response.result()));
  ASSERT_EQ(response.pmid_id(), co.Hash(response.public_key() +
    response.signed_public_key(), "", crypto::STRING_STRING, false));

  // Load the stored BP to check it
  std::string test_content;
  ASSERT_TRUE(service.HasChunkLocal(bufferpacket_name));
  ASSERT_TRUE(service.LoadChunkLocal(bufferpacket_name, &test_content));
  ASSERT_EQ(ser_bp, test_content);

  // Get the messages
  maidsafe::GetBPMessagesRequest get_msg_request;
  maidsafe::GetBPMessagesResponse get_msg_response;
  get_msg_request.set_bufferpacket_name(bufferpacket_name);
  get_msg_request.set_pmid(pmid);
  get_msg_request.set_public_key(pub_key);
  get_msg_request.set_signed_public_key(sig_pub_key);
  get_msg_request.set_signed_request(sig_req);
  done = google::protobuf::NewCallback<Callback> (&cb_obj,
    &Callback::CallbackFunction);
  service.GetBPMessages(&controller, &get_msg_request, &get_msg_response, done);
  ASSERT_TRUE(get_msg_response.IsInitialized());
  ASSERT_EQ(kAck, static_cast<int>(get_msg_response.result()));
  ASSERT_EQ(get_msg_response.pmid_id(), co.Hash(get_msg_response.public_key() +
    get_msg_response.signed_public_key(), "", crypto::STRING_STRING, false));
  ASSERT_EQ(0, get_msg_response.messages_size());
}

TEST_F(VaultServicesTest, BEH_MAID_ServicesAddBPMessages) {
  VaultService service(pmid_public_, pmid_private_, pmid_public_signature_,
    vault_chunkstore_, NULL, &poh_);
  rpcprotocol::Controller controller;
  maidsafe::CreateBPRequest request;
  maidsafe::CreateBPResponse response;

  // Not initialised
  Callback cb_obj;
  google::protobuf::Closure *done = google::protobuf::NewCallback<Callback>
    (&cb_obj, &Callback::CallbackFunction);
  std::string pub_key, priv_key, pmid, sig_pub_key, sig_req;
  CreateRSAKeys(&pub_key, &priv_key);
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);

  maidsafe::BufferPacketInfo bpi;
  bpi.set_owner("Dan");
  bpi.set_ownerpublickey(pub_key);
  bpi.set_online(1);
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
  request.set_pmid(pmid);
  request.set_public_key(pub_key);
  request.set_signed_public_key(sig_pub_key);
  request.set_signed_request(sig_req);

  service.CreateBP(&controller, &request, &response, done);
  ASSERT_TRUE(response.IsInitialized());
  ASSERT_EQ(kAck, static_cast<int>(response.result()));
  ASSERT_EQ(response.pmid_id(), co.Hash(response.public_key() +
    response.signed_public_key(), "", crypto::STRING_STRING, false));

  // Load the stored BP to check it
  std::string test_content;
  ASSERT_TRUE(service.HasChunkLocal(bufferpacket_name));
  ASSERT_TRUE(service.LoadChunkLocal(bufferpacket_name, &test_content));
  ASSERT_EQ(ser_bp, test_content);

  // Get the messages
  maidsafe::GetBPMessagesRequest get_msg_request;
  maidsafe::GetBPMessagesResponse get_msg_response;
  get_msg_request.set_bufferpacket_name(bufferpacket_name);
  get_msg_request.set_pmid(pmid);
  get_msg_request.set_public_key(pub_key);
  get_msg_request.set_signed_public_key(sig_pub_key);
  get_msg_request.set_signed_request(sig_req);
  done = google::protobuf::NewCallback<Callback> (&cb_obj,
    &Callback::CallbackFunction);
  service.GetBPMessages(&controller, &get_msg_request, &get_msg_response, done);
  ASSERT_TRUE(get_msg_response.IsInitialized());
  ASSERT_EQ(kAck, static_cast<int>(get_msg_response.result()));
  ASSERT_EQ(get_msg_response.pmid_id(), co.Hash(get_msg_response.public_key() +
    get_msg_response.signed_public_key(), "", crypto::STRING_STRING, false));
  ASSERT_EQ(0, get_msg_response.messages_size());

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
  add_msg_request.set_pmid(newuser_pmid);
  add_msg_request.set_public_key(newuser_pub_key);
  add_msg_request.set_signed_public_key(newuser_sig_pub_key);
  add_msg_request.set_signed_request(newuser_sig_req);
  done = google::protobuf::NewCallback<Callback> (&cb_obj,
    &Callback::CallbackFunction);
  service.AddBPMessage(&controller, &add_msg_request, &add_msg_response, done);
  ASSERT_TRUE(add_msg_response.IsInitialized());
  ASSERT_EQ(kNack, static_cast<int>(add_msg_response.result()));
  ASSERT_EQ(add_msg_response.pmid_id(), co.Hash(add_msg_response.public_key() +
    add_msg_response.signed_public_key(), "", crypto::STRING_STRING, false));

  // Creating the message
  maidsafe::BufferPacketMessage bpm;
  maidsafe::GenericPacket gp;
  std::string msg("Don't switch doors!!");
  bpm.set_sender_id("newuser");
  bpm.set_sender_public_key(newuser_pub_key);
  bpm.set_type(maidsafe::INSTANT_MSG);
  int iter = base::random_32bit_uinteger() % 1000 +1;
  std::string aes_key = co.SecurePassword(co.Hash(msg, "",
    crypto::STRING_STRING, true), iter);
  bpm.set_rsaenc_key(co.AsymEncrypt(aes_key, "", pub_key,
    crypto::STRING_STRING));
  bpm.set_aesenc_message(co.SymmEncrypt(msg, "", crypto::STRING_STRING,
    aes_key));
  bpm.set_timestamp(base::get_epoch_time());
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
  add_msg_request.set_pmid(newuser_pmid);
  add_msg_request.set_public_key(newuser_pub_key);
  add_msg_request.set_signed_public_key(newuser_sig_pub_key);
  add_msg_request.set_signed_request(newuser_sig_req);
  done = google::protobuf::NewCallback<Callback> (&cb_obj,
    &Callback::CallbackFunction);
  service.AddBPMessage(&controller, &add_msg_request, &add_msg_response, done);
  ASSERT_TRUE(add_msg_response.IsInitialized());
  ASSERT_EQ(kAck, static_cast<int>(add_msg_response.result()));
  ASSERT_EQ(add_msg_response.pmid_id(), co.Hash(add_msg_response.public_key() +
    add_msg_response.signed_public_key(), "", crypto::STRING_STRING, false));

  // Get the messages again
  get_msg_request.Clear();
  get_msg_response.Clear();
  get_msg_request.set_bufferpacket_name(bufferpacket_name);
  get_msg_request.set_pmid(pmid);
  get_msg_request.set_public_key(pub_key);
  get_msg_request.set_signed_public_key(sig_pub_key);
  get_msg_request.set_signed_request(sig_req);
  done = google::protobuf::NewCallback<Callback> (&cb_obj,
    &Callback::CallbackFunction);
  service.GetBPMessages(&controller, &get_msg_request, &get_msg_response, done);
  ASSERT_TRUE(get_msg_response.IsInitialized());
  ASSERT_EQ(kAck, static_cast<int>(get_msg_response.result()));
  ASSERT_EQ(get_msg_response.pmid_id(), co.Hash(get_msg_response.public_key() +
    get_msg_response.signed_public_key(), "", crypto::STRING_STRING, false));
  ASSERT_EQ(1, get_msg_response.messages_size());
  maidsafe::ValidatedBufferPacketMessage vbpm;
  ASSERT_TRUE(vbpm.ParseFromString(get_msg_response.messages(0)));
  ASSERT_EQ(bpm.sender_id(), vbpm.sender());
  ASSERT_EQ(bpm.aesenc_message(), vbpm.message());
  ASSERT_EQ(bpm.rsaenc_key(), vbpm.index());
  ASSERT_EQ(bpm.type(), vbpm.type());

  // Get the messages again
  get_msg_request.Clear();
  get_msg_response.Clear();
  get_msg_request.set_bufferpacket_name(bufferpacket_name);
  get_msg_request.set_pmid(pmid);
  get_msg_request.set_public_key(pub_key);
  get_msg_request.set_signed_public_key(sig_pub_key);
  get_msg_request.set_signed_request(sig_req);
  done = google::protobuf::NewCallback<Callback> (&cb_obj,
    &Callback::CallbackFunction);
  service.GetBPMessages(&controller, &get_msg_request, &get_msg_response, done);
  ASSERT_TRUE(get_msg_response.IsInitialized());
  ASSERT_EQ(kAck, static_cast<int>(get_msg_response.result()));
  ASSERT_EQ(get_msg_response.pmid_id(), co.Hash(get_msg_response.public_key() +
    get_msg_response.signed_public_key(), "", crypto::STRING_STRING, false));
  ASSERT_EQ(0, get_msg_response.messages_size());
}

TEST_F(VaultServicesTest, BEH_MAID_ServicesGetPacket) {
  rpcprotocol::Controller controller;
  maidsafe::GetPacketRequest request;
  maidsafe::GetPacketResponse response;
  maidsafe::GenericPacket *random_gp = response.add_content();
  random_gp->set_data("petting the one-eyed snake");

  // Not initialised
  Callback cb_obj;
  google::protobuf::Closure *done = google::protobuf::NewCallback<Callback>
                                    (&cb_obj, &Callback::CallbackFunction);
  vault_service_->GetPacket(&controller, &request, &response, done);
  ASSERT_TRUE(response.IsInitialized());
  ASSERT_EQ(kNack, static_cast<int>(response.result()));
  ASSERT_EQ(0, response.content_size());
  ASSERT_EQ(non_hex_pmid_, response.pmid());

  // Generate packet and signatures
  std::string pub_key, priv_key, key_id, sig_pub_key, sig_req;
  CreateRSAKeys(&pub_key, &priv_key);
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);

  std::string packetname = co.Hash("packetname", "", crypto::STRING_STRING,
                           false);
  CreateSignedRequest(pub_key, priv_key, packetname, &key_id, &sig_pub_key,
                      &sig_req);

  request.set_key_id(key_id);
  done = google::protobuf::NewCallback<Callback>
         (&cb_obj, &Callback::CallbackFunction);
  vault_service_->GetPacket(&controller, &request, &response, done);
  ASSERT_TRUE(response.IsInitialized());
  ASSERT_EQ(kNack, static_cast<int>(response.result()));
  ASSERT_EQ(0, response.content_size());
  ASSERT_EQ(non_hex_pmid_, response.pmid());

  request.set_public_key(pub_key);
  request.set_public_key_signature(sig_pub_key);
  request.set_request_signature(sig_req);
  request.set_packetname(packetname);
  done = google::protobuf::NewCallback<Callback>
         (&cb_obj, &Callback::CallbackFunction);
  vault_service_->GetPacket(&controller, &request, &response, done);
  ASSERT_TRUE(response.IsInitialized());
  ASSERT_EQ(kNack, static_cast<int>(response.result()));
  ASSERT_EQ(0, response.content_size());
  ASSERT_EQ(non_hex_pmid_, response.pmid());

  // single value
  maidsafe::GenericPacket injection_gp;
  injection_gp.set_data("some random data, not to do with chickens or snakes");
  injection_gp.set_signature(co.AsymSign(injection_gp.data(), "", priv_key,
                             crypto::STRING_STRING));
  ASSERT_EQ(kSuccess, vault_service_->vault_chunkstore_->StorePacket(packetname,
            injection_gp));
  done = google::protobuf::NewCallback<Callback>
         (&cb_obj, &Callback::CallbackFunction);
  vault_service_->GetPacket(&controller, &request, &response, done);
  ASSERT_TRUE(response.IsInitialized());
  ASSERT_EQ(kAck, static_cast<int>(response.result()));
  ASSERT_EQ(1, response.content_size());
  ASSERT_EQ(non_hex_pmid_, response.pmid());
  ASSERT_EQ(injection_gp.data(), response.content(0).data());
  ASSERT_EQ(injection_gp.signature(), response.content(0).signature());

  // multiple values
  size_t kNumTestPackets(46);
  std::vector<maidsafe::GenericPacket> injection_gps;
  for (size_t i = 0; i < kNumTestPackets; ++i) {
    maidsafe::GenericPacket injection_gp;
    injection_gp.set_data(base::itos(i));
    injection_gp.set_signature(co.AsymSign(injection_gp.data(), "", priv_key,
                               crypto::STRING_STRING));
    injection_gps.push_back(injection_gp);
  }
  // as single value has already been stored then overwrite with multiple values
  ASSERT_EQ(kSuccess, vault_service_->vault_chunkstore_->OverwritePacket(
            packetname, injection_gps, pub_key));
  done = google::protobuf::NewCallback<Callback>
         (&cb_obj, &Callback::CallbackFunction);
  vault_service_->GetPacket(&controller, &request, &response, done);
  ASSERT_TRUE(response.IsInitialized());
  ASSERT_EQ(kAck, static_cast<int>(response.result()));
  ASSERT_EQ(static_cast<int>(kNumTestPackets), response.content_size());
  ASSERT_EQ(non_hex_pmid_, response.pmid());
  for (size_t i = 0; i < kNumTestPackets; ++i) {
    ASSERT_EQ(injection_gps.at(i).data(), response.content(i).data());
    ASSERT_EQ(injection_gps.at(i).signature(), response.content(i).signature());
  }
}

struct StorePacketCallback {
  StorePacketCallback() : is_called_back(false) {}
  void Callback() {
    is_called_back = true;
  }
  void Reset() {
    is_called_back = false;
  }
  bool is_called_back;
};

class TestStorePacket : public testing::Test {
 public:
  TestStorePacket() : dir_(""), pmid_public_(""), pmid_private_(""),
    pmid_signed_public_(""), pmid_(""), co_()  {
    co_.set_hash_algorithm(crypto::SHA_512);
  }
 protected:
  virtual void SetUp() {
    dir_ += "ChunkStore";
    dir_ += boost::lexical_cast<std::string>(base::random_32bit_uinteger());
    crypto::RsaKeyPair kp;
    kp.GenerateKeys(4096);
    pmid_public_ = kp.public_key();
    pmid_private_ = kp.private_key();
    pmid_signed_public_ = co_.AsymSign(pmid_public_, "", pmid_private_,
      crypto::STRING_STRING);
    pmid_ = co_.Hash(pmid_public_ + pmid_signed_public_, "",
      crypto::STRING_STRING, false);
  }
  virtual void TearDown() {
    try {
      fs::remove_all(dir_);
    }
    catch(const std::exception &e) {
      printf("%s\n", e.what());
    }
  }
  std::string dir_;
  std::string pmid_public_, pmid_private_, pmid_signed_public_, pmid_;
  crypto::Crypto co_;
};

TEST_F(TestStorePacket, BEH_MAID_StoreSysPacket) {
  VaultChunkStore chunkstore(dir_, 10000, 0);
  ASSERT_TRUE(chunkstore.Init());
  VaultService service(pmid_public_, pmid_private_, pmid_signed_public_,
    &chunkstore, NULL, NULL);
  rpcprotocol::Controller ctrl;
  StorePacketCallback cb;
  maidsafe::StorePacketRequest request;
  maidsafe::StorePacketResponse response;
  google::protobuf::Closure *done = google::protobuf::NewPermanentCallback<
    StorePacketCallback> (&cb, &StorePacketCallback::Callback);
  service.StorePacket(&ctrl, &request, &response, done);
  while (!cb.is_called_back)
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  ASSERT_EQ(kNack, static_cast<int>(response.result()));
  ASSERT_EQ(pmid_, response.pmid());
  response.Clear();
  cb.Reset();

  std::string packetname(co_.Hash("packet1", "", crypto::STRING_STRING, false));
  request.set_packetname(packetname);
  request.set_data_type(maidsafe::SYSTEM_PACKET);
  request.set_append(false);

  service.StorePacket(&ctrl, &request, &response, done);
  while (!cb.is_called_back)
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  ASSERT_EQ(kNack, static_cast<int>(response.result()));
  ASSERT_EQ(pmid_, response.pmid());
  response.Clear();
  cb.Reset();

  // Create the system packet
  std::string private_key, public_key, sig_public_key, packet_id, sig_request;
  CreateRSAKeys(&public_key, &private_key);
  CreateSignedRequest(public_key, private_key, packetname, &packet_id,
    &sig_public_key, &sig_request);

  std::string data("data1");
  maidsafe::GenericPacket *gp = request.add_signed_data();
  gp->set_data(data);
  gp->set_signature(co_.AsymSign(data, "", private_key, crypto::STRING_STRING));

  request.set_key_id(packet_id);
  request.set_public_key(public_key);
  request.set_public_key_signature(sig_public_key);
  request.set_request_signature(sig_request);

  ASSERT_TRUE(request.signed_data(0).IsInitialized());

  service.StorePacket(&ctrl, &request, &response, done);
  while (!cb.is_called_back)
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  ASSERT_EQ(kAck, static_cast<int>(response.result()));
  ASSERT_EQ(pmid_, response.pmid());
  response.Clear();
  cb.Reset();

  delete done;

  std::vector<maidsafe::GenericPacket> result;
  ASSERT_EQ(kSuccess, chunkstore.LoadPacket(packetname, &result));
  ASSERT_EQ(size_t(1), result.size());
  ASSERT_EQ(gp->data(), result[0].data());
  ASSERT_EQ(gp->signature(), result[0].signature());
}

TEST_F(TestStorePacket, BEH_MAID_OverWriteSystemPacket) {
  VaultChunkStore chunkstore(dir_, 10000, 0);
  ASSERT_TRUE(chunkstore.Init());
  VaultService service(pmid_public_, pmid_private_, pmid_signed_public_,
    &chunkstore, NULL, NULL);
  rpcprotocol::Controller ctrl;
  StorePacketCallback cb;
  maidsafe::StorePacketRequest request;
  maidsafe::StorePacketResponse response;
  google::protobuf::Closure *done = google::protobuf::NewPermanentCallback<
    StorePacketCallback> (&cb, &StorePacketCallback::Callback);

  std::string packetname(co_.Hash("packet1", "", crypto::STRING_STRING, false));
  request.set_packetname(packetname);
  request.set_data_type(maidsafe::SYSTEM_PACKET);
  request.set_append(false);

  std::string private_key, public_key, sig_public_key, packet_id, sig_request;
  CreateRSAKeys(&public_key, &private_key);
  CreateSignedRequest(public_key, private_key, packetname, &packet_id,
    &sig_public_key, &sig_request);

  std::string data("data1");
  maidsafe::GenericPacket *gp = request.add_signed_data();
  gp->set_data(data);
  gp->set_signature(co_.AsymSign(data, "", private_key, crypto::STRING_STRING));

  request.set_key_id(packet_id);
  request.set_public_key(public_key);
  request.set_public_key_signature(sig_public_key);
  request.set_request_signature(sig_request);

  service.StorePacket(&ctrl, &request, &response, done);
  while (!cb.is_called_back)
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  ASSERT_EQ(kAck, static_cast<int>(response.result()));
  ASSERT_EQ(pmid_, response.pmid());
  response.Clear();
  cb.Reset();

  std::vector<maidsafe::GenericPacket> result;
  ASSERT_EQ(kSuccess, chunkstore.LoadPacket(packetname, &result));
  ASSERT_EQ(size_t(1), result.size());
  ASSERT_EQ(gp->data(), result[0].data());
  ASSERT_EQ(gp->signature(), result[0].signature());

  // setting false to overwrite
  request.set_append(false);
  request.clear_signed_data();

  std::string new_data("new data");

  maidsafe::GenericPacket *gp1 = request.add_signed_data();
  gp1->set_data(new_data);
  gp1->set_signature(co_.AsymSign(new_data, "", private_key,
    crypto::STRING_STRING));

  service.StorePacket(&ctrl, &request, &response, done);
  while (!cb.is_called_back)
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  ASSERT_EQ(kAck, static_cast<int>(response.result()));
  ASSERT_EQ(pmid_, response.pmid());
  response.Clear();
  cb.Reset();

  result.clear();
  ASSERT_EQ(kSuccess, chunkstore.LoadPacket(packetname, &result));
  ASSERT_EQ(size_t(1), result.size());
  ASSERT_EQ(gp1->data(), result[0].data());
  ASSERT_NE(data, result[0].data());
  ASSERT_EQ(gp1->signature(), result[0].signature());
  delete done;
}

TEST_F(TestStorePacket, BEH_MAID_AppendSystemPacket) {
  VaultChunkStore chunkstore(dir_, 10000, 0);
  ASSERT_TRUE(chunkstore.Init());
  VaultService service(pmid_public_, pmid_private_, pmid_signed_public_,
    &chunkstore, NULL, NULL);
  rpcprotocol::Controller ctrl;
  StorePacketCallback cb;
  maidsafe::StorePacketRequest request;
  maidsafe::StorePacketResponse response;
  google::protobuf::Closure *done = google::protobuf::NewPermanentCallback<
    StorePacketCallback> (&cb, &StorePacketCallback::Callback);

  std::string packetname(co_.Hash("packet1", "", crypto::STRING_STRING, false));
  request.set_packetname(packetname);
  request.set_data_type(maidsafe::SYSTEM_PACKET);
  request.set_append(true);

  std::string private_key, public_key, sig_public_key, packet_id, sig_request;
  CreateRSAKeys(&public_key, &private_key);
  CreateSignedRequest(public_key, private_key, packetname, &packet_id,
    &sig_public_key, &sig_request);

  std::string data("data1");
  maidsafe::GenericPacket *gp = request.add_signed_data();
  gp->set_data(data);
  gp->set_signature(co_.AsymSign(data, "", private_key, crypto::STRING_STRING));

  request.set_key_id(packet_id);
  request.set_public_key(public_key);
  request.set_public_key_signature(sig_public_key);
  request.set_request_signature(sig_request);

  service.StorePacket(&ctrl, &request, &response, done);
  while (!cb.is_called_back)
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  ASSERT_EQ(kAck, static_cast<int>(response.result()));
  ASSERT_EQ(pmid_, response.pmid());
  response.Clear();
  cb.Reset();

  std::vector<maidsafe::GenericPacket> result;
  ASSERT_EQ(kSuccess, chunkstore.LoadPacket(packetname, &result));
  ASSERT_EQ(size_t(1), result.size());
  ASSERT_EQ(gp->data(), result[0].data());
  ASSERT_EQ(gp->signature(), result[0].signature());

  // setting true to append
  request.set_append(true);
  request.clear_signed_data();

  std::string new_data("new data");

  maidsafe::GenericPacket *gp1 = request.add_signed_data();
  gp1->set_data(new_data);
  gp1->set_signature(co_.AsymSign(new_data, "", private_key,
    crypto::STRING_STRING));

  service.StorePacket(&ctrl, &request, &response, done);
  while (!cb.is_called_back)
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  ASSERT_EQ(kAck, static_cast<int>(response.result()));
  ASSERT_EQ(pmid_, response.pmid());
  response.Clear();
  cb.Reset();

  result.clear();
  ASSERT_EQ(kSuccess, chunkstore.LoadPacket(packetname, &result));
  ASSERT_EQ(size_t(2), result.size());

  for (unsigned int i = 0; i < result.size(); ++i) {
    if (result[i].data() != data && result[i].data() != new_data)
      FAIL() << "did not retrieved the correct values";
  }
  delete done;
}

TEST_F(TestStorePacket, BEH_MAID_IncorrectSignatures) {
  VaultChunkStore chunkstore(dir_, 10000, 0);
  ASSERT_TRUE(chunkstore.Init());
  VaultService service(pmid_public_, pmid_private_, pmid_signed_public_,
    &chunkstore, NULL, NULL);
  rpcprotocol::Controller ctrl;
  StorePacketCallback cb;
  maidsafe::StorePacketRequest request;
  maidsafe::StorePacketResponse response;
  google::protobuf::Closure *done = google::protobuf::NewPermanentCallback<
    StorePacketCallback> (&cb, &StorePacketCallback::Callback);

  std::string packetname(co_.Hash("packet1", "", crypto::STRING_STRING, false));
  request.set_packetname(packetname);
  request.set_data_type(maidsafe::SYSTEM_PACKET);
  request.set_append(false);

  std::string private_key, public_key, sig_public_key, packet_id, sig_request;
  CreateRSAKeys(&public_key, &private_key);
  CreateSignedRequest(public_key, private_key, packetname, &packet_id,
    &sig_public_key, &sig_request);

  std::string public_key1, private_key1;
  CreateRSAKeys(&public_key1, &private_key1);

  std::string data("data1");
  maidsafe::GenericPacket *gp = request.add_signed_data();
  gp->set_data(data);
  gp->set_signature(co_.AsymSign(data, "", private_key, crypto::STRING_STRING));

  request.set_key_id(packet_id);
  request.set_public_key(public_key1);
  request.set_public_key_signature(sig_public_key);
  request.set_request_signature(sig_request);

  service.StorePacket(&ctrl, &request, &response, done);
  while (!cb.is_called_back)
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  ASSERT_EQ(kNack, static_cast<int>(response.result()));
  ASSERT_EQ(pmid_, response.pmid());
  response.Clear();
  cb.Reset();

  std::vector<maidsafe::GenericPacket> result;
  ASSERT_EQ(kPacketLoadNotFound, chunkstore.LoadPacket(packetname, &result));
  ASSERT_TRUE(result.empty());

  request.clear_public_key();
  request.set_public_key(public_key);
  request.clear_key_id();
  request.set_key_id("invalid ID");

  service.StorePacket(&ctrl, &request, &response, done);
  while (!cb.is_called_back)
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  ASSERT_EQ(kNack, static_cast<int>(response.result()));
  ASSERT_EQ(pmid_, response.pmid());
  response.Clear();
  cb.Reset();
  ASSERT_EQ(kPacketLoadNotFound, chunkstore.LoadPacket(packetname, &result));
  ASSERT_TRUE(result.empty());

  request.clear_key_id();
  request.set_key_id(packet_id);

  maidsafe::GenericPacket *gp1 = request.add_signed_data();
  gp1->set_data(data + "1");
  gp1->set_signature(co_.AsymSign(data + "1", "", private_key1,
    crypto::STRING_STRING));
  service.StorePacket(&ctrl, &request, &response, done);
  while (!cb.is_called_back)
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  ASSERT_EQ(kNack, static_cast<int>(response.result()));
  ASSERT_EQ(pmid_, response.pmid());
  response.Clear();
  cb.Reset();
  ASSERT_EQ(kPacketLoadNotFound, chunkstore.LoadPacket(packetname, &result));
  ASSERT_TRUE(result.empty());
}

TEST_F(TestStorePacket, BEH_MAID_InvalidOverWrite) {
  VaultChunkStore chunkstore(dir_, 10000, 0);
  ASSERT_TRUE(chunkstore.Init());
  VaultService service(pmid_public_, pmid_private_, pmid_signed_public_,
    &chunkstore, NULL, NULL);
  rpcprotocol::Controller ctrl;
  StorePacketCallback cb;
  maidsafe::StorePacketRequest request;
  maidsafe::StorePacketResponse response;
  google::protobuf::Closure *done = google::protobuf::NewPermanentCallback<
    StorePacketCallback> (&cb, &StorePacketCallback::Callback);

  std::string packetname(co_.Hash("packet1", "", crypto::STRING_STRING, false));
  request.set_packetname(packetname);
  request.set_data_type(maidsafe::SYSTEM_PACKET);
  request.set_append(false);

  std::string private_key, public_key, sig_public_key, packet_id, sig_request;
  CreateRSAKeys(&public_key, &private_key);
  CreateSignedRequest(public_key, private_key, packetname, &packet_id,
    &sig_public_key, &sig_request);

  std::string data("data1");
  maidsafe::GenericPacket *gp = request.add_signed_data();
  gp->set_data(data);
  gp->set_signature(co_.AsymSign(data, "", private_key, crypto::STRING_STRING));

  request.set_key_id(packet_id);
  request.set_public_key(public_key);
  request.set_public_key_signature(sig_public_key);
  request.set_request_signature(sig_request);

  service.StorePacket(&ctrl, &request, &response, done);
  while (!cb.is_called_back)
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  ASSERT_EQ(kAck, static_cast<int>(response.result()));
  ASSERT_EQ(pmid_, response.pmid());
  response.Clear();
  cb.Reset();

  std::vector<maidsafe::GenericPacket> result;
  ASSERT_EQ(kSuccess, chunkstore.LoadPacket(packetname, &result));
  ASSERT_EQ(size_t(1), result.size());
  ASSERT_EQ(gp->data(), result[0].data());
  ASSERT_EQ(gp->signature(), result[0].signature());

  // setting false to overwrite
  request.set_append(false);
  request.clear_signed_data();
  request.clear_public_key();
  request.clear_public_key_signature();
  request.clear_request_signature();
  request.clear_key_id();

  std::string private_key1, public_key1, sig_public_key1, packet_id1,
    sig_request1;
  CreateRSAKeys(&public_key1, &private_key1);
  CreateSignedRequest(public_key1, private_key1, packetname, &packet_id1,
    &sig_public_key1, &sig_request1);

  std::string new_data("new data");

  maidsafe::GenericPacket *gp1 = request.add_signed_data();
  gp1->set_data(new_data);
  gp1->set_signature(co_.AsymSign(new_data, "", private_key1,
    crypto::STRING_STRING));

  request.set_public_key(public_key1);
  request.set_public_key_signature(sig_public_key1);
  request.set_request_signature(sig_request1);
  request.set_key_id(packet_id1);

  service.StorePacket(&ctrl, &request, &response, done);
  while (!cb.is_called_back)
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  ASSERT_EQ(kNack, static_cast<int>(response.result()));
  ASSERT_EQ(pmid_, response.pmid());
  response.Clear();
  cb.Reset();

  result.clear();
  ASSERT_EQ(kSuccess, chunkstore.LoadPacket(packetname, &result));
  ASSERT_EQ(size_t(1), result.size());
  ASSERT_EQ(data, result[0].data());
  delete done;
}

TEST_F(TestStorePacket, BEH_MAID_InvalidAppend) {
  VaultChunkStore chunkstore(dir_, 10000, 0);
  ASSERT_TRUE(chunkstore.Init());
  VaultService service(pmid_public_, pmid_private_, pmid_signed_public_,
    &chunkstore, NULL, NULL);
  rpcprotocol::Controller ctrl;
  StorePacketCallback cb;
  maidsafe::StorePacketRequest request;
  maidsafe::StorePacketResponse response;
  google::protobuf::Closure *done = google::protobuf::NewPermanentCallback<
    StorePacketCallback> (&cb, &StorePacketCallback::Callback);

  std::string packetname(co_.Hash("packet1", "", crypto::STRING_STRING, false));
  request.set_packetname(packetname);
  request.set_data_type(maidsafe::SYSTEM_PACKET);
  request.set_append(true);

  std::string private_key, public_key, sig_public_key, packet_id, sig_request;
  CreateRSAKeys(&public_key, &private_key);
  CreateSignedRequest(public_key, private_key, packetname, &packet_id,
    &sig_public_key, &sig_request);

  std::string data("data1");
  maidsafe::GenericPacket *gp = request.add_signed_data();
  gp->set_data(data);
  gp->set_signature(co_.AsymSign(data, "", private_key, crypto::STRING_STRING));

  request.set_key_id(packet_id);
  request.set_public_key(public_key);
  request.set_public_key_signature(sig_public_key);
  request.set_request_signature(sig_request);

  service.StorePacket(&ctrl, &request, &response, done);
  while (!cb.is_called_back)
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  ASSERT_EQ(kAck, static_cast<int>(response.result()));
  ASSERT_EQ(pmid_, response.pmid());
  response.Clear();
  cb.Reset();

  std::vector<maidsafe::GenericPacket> result;
  ASSERT_EQ(kSuccess, chunkstore.LoadPacket(packetname, &result));
  ASSERT_EQ(size_t(1), result.size());
  ASSERT_EQ(gp->data(), result[0].data());
  ASSERT_EQ(gp->signature(), result[0].signature());

  // setting true to append
  request.set_append(true);
  request.clear_signed_data();

  std::string new_data("new data");

  maidsafe::GenericPacket *gp1 = request.add_signed_data();
  gp1->set_data(new_data);
  gp1->set_signature(co_.AsymSign(new_data, "", private_key,
    crypto::STRING_STRING));
  new_data += "1";
  maidsafe::GenericPacket *gp2 = request.add_signed_data();
  gp2->set_data(new_data);
  gp2->set_signature(co_.AsymSign(new_data, "", private_key,
    crypto::STRING_STRING));

  service.StorePacket(&ctrl, &request, &response, done);
  while (!cb.is_called_back)
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  ASSERT_EQ(kNack, static_cast<int>(response.result()));
  ASSERT_EQ(pmid_, response.pmid());
  response.Clear();
  cb.Reset();

  result.clear();
  ASSERT_EQ(kSuccess, chunkstore.LoadPacket(packetname, &result));
  ASSERT_EQ(size_t(1), result.size());
  ASSERT_EQ(data, result[0].data());

  request.clear_signed_data();
  request.clear_public_key();
  request.clear_public_key_signature();
  request.clear_request_signature();
  request.clear_key_id();

  std::string private_key1, public_key1, sig_public_key1, packet_id1,
    sig_request1;
  CreateRSAKeys(&public_key1, &private_key1);
  CreateSignedRequest(public_key1, private_key1, packetname, &packet_id1,
    &sig_public_key1, &sig_request1);

  maidsafe::GenericPacket *gp3 = request.add_signed_data();
  gp3->set_data(new_data);
  gp3->set_signature(co_.AsymSign(new_data, "", private_key1,
    crypto::STRING_STRING));

  request.set_public_key(public_key1);
  request.set_public_key_signature(sig_public_key1);
  request.set_request_signature(sig_request1);
  request.set_key_id(packet_id1);

  service.StorePacket(&ctrl, &request, &response, done);
  while (!cb.is_called_back)
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  ASSERT_EQ(kNack, static_cast<int>(response.result()));
  ASSERT_EQ(pmid_, response.pmid());
  response.Clear();
  cb.Reset();

  result.clear();
  ASSERT_EQ(kSuccess, chunkstore.LoadPacket(packetname, &result));
  ASSERT_EQ(size_t(1), result.size());
  ASSERT_EQ(data, result[0].data());

  delete done;
}

TEST_F(TestStorePacket, BEH_MAID_StorePDDIR_NOT_SIGNED) {
  VaultChunkStore chunkstore(dir_, 10000, 0);
  ASSERT_TRUE(chunkstore.Init());
  VaultService service(pmid_public_, pmid_private_, pmid_signed_public_,
    &chunkstore, NULL, NULL);
  rpcprotocol::Controller ctrl;
  StorePacketCallback cb;
  maidsafe::StorePacketRequest request;
  maidsafe::StorePacketResponse response;
  google::protobuf::Closure *done = google::protobuf::NewPermanentCallback<
    StorePacketCallback> (&cb, &StorePacketCallback::Callback);

  std::string packetname(co_.Hash("packet1", "", crypto::STRING_STRING, false));
  request.set_packetname(packetname);
  request.set_data_type(maidsafe::PDDIR_NOTSIGNED);
  request.set_append(false);

  std::string data("data1");
  maidsafe::GenericPacket *gp = request.add_signed_data();
  gp->set_data(data);
  gp->set_signature("FFFFFFFFFFFFFFFF");

  service.StorePacket(&ctrl, &request, &response, done);
  while (!cb.is_called_back)
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  ASSERT_EQ(kAck, static_cast<int>(response.result()));
  ASSERT_EQ(pmid_, response.pmid());
  response.Clear();
  cb.Reset();

  std::vector<maidsafe::GenericPacket> result;
  ASSERT_EQ(kSuccess, chunkstore.LoadPacket(packetname, &result));
  ASSERT_EQ(size_t(1), result.size());
  ASSERT_EQ(gp->data(), result[0].data());
  ASSERT_EQ(gp->signature(), result[0].signature());

  request.clear_signed_data();
  data += "1";
  maidsafe::GenericPacket *gp1 = request.add_signed_data();
  gp1->set_data(data);
  gp1->set_signature("FFFFFFFFFFFFFFFF");

  service.StorePacket(&ctrl, &request, &response, done);
  while (!cb.is_called_back)
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  ASSERT_EQ(kNack, static_cast<int>(response.result()));
  ASSERT_EQ(pmid_, response.pmid());

  delete done;
}

TEST_F(TestStorePacket, BEH_MAID_StoreThenLoadSystemPacket) {
  VaultChunkStore chunkstore(dir_, 10000, 0);
  ASSERT_TRUE(chunkstore.Init());
  VaultService service(pmid_public_, pmid_private_, pmid_signed_public_,
    &chunkstore, NULL, NULL);
  rpcprotocol::Controller ctrl;
  StorePacketCallback cb;
  maidsafe::StorePacketRequest request;
  maidsafe::StorePacketResponse response;
  google::protobuf::Closure *done = google::protobuf::NewPermanentCallback<
    StorePacketCallback> (&cb, &StorePacketCallback::Callback);

  std::string packetname(co_.Hash("packet1", "", crypto::STRING_STRING, false));
  request.set_packetname(packetname);
  request.set_data_type(maidsafe::SYSTEM_PACKET);
  request.set_append(false);

  std::string private_key, public_key, sig_public_key, packet_id, sig_request;
  CreateRSAKeys(&public_key, &private_key);
  CreateSignedRequest(public_key, private_key, packetname, &packet_id,
    &sig_public_key, &sig_request);

  std::string data("data1");
  maidsafe::GenericPacket *gp = request.add_signed_data();
  gp->set_data(data);
  gp->set_signature(co_.AsymSign(data, "", private_key, crypto::STRING_STRING));

  request.set_key_id(packet_id);
  request.set_public_key(public_key);
  request.set_public_key_signature(sig_public_key);
  request.set_request_signature(sig_request);

  service.StorePacket(&ctrl, &request, &response, done);
  while (!cb.is_called_back)
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  ASSERT_EQ(kAck, static_cast<int>(response.result()));
  ASSERT_EQ(pmid_, response.pmid());
  response.Clear();
  cb.Reset();

  std::vector<maidsafe::GenericPacket> result;
  ASSERT_EQ(kSuccess, chunkstore.LoadPacket(packetname, &result));
  ASSERT_EQ(size_t(1), result.size());
  ASSERT_EQ(gp->data(), result[0].data());
  ASSERT_EQ(gp->signature(), result[0].signature());

  maidsafe::GetPacketRequest gp_req;
  maidsafe::GetPacketResponse gp_resp;

  gp_req.set_packetname(packetname);
  gp_req.set_key_id(packet_id);
  gp_req.set_public_key(public_key);
  gp_req.set_public_key_signature(sig_public_key);
  gp_req.set_request_signature(sig_request);

  service.GetPacket(&ctrl, &gp_req, &gp_resp, done);
  while (!cb.is_called_back)
    boost::this_thread::sleep(boost::posix_time::milliseconds(10));
  ASSERT_EQ(kAck, static_cast<int>(gp_resp.result()));

  ASSERT_EQ(1, gp_resp.content_size());
  ASSERT_EQ(gp->data(), gp_resp.content(0).data());
  ASSERT_EQ(gp->signature(), gp_resp.content(0).signature());
  ASSERT_EQ(pmid_, gp_resp.pmid());

  delete done;
}

}  // namespace maidsafe_vault
