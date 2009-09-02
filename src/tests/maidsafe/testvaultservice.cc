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
          signed_pmid_public_(),
          pmid_(),
          non_hex_pmid_(),
          channel_manager_(),
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
        signed_pmid_public_ = co.AsymSign(pmid_public_, "", pmid_private_,
                                          crypto::STRING_STRING);
        pmid_ = co.Hash(pmid_public_ + signed_pmid_public_, "",
                        crypto::STRING_STRING, true);
        base::decode_from_hex(pmid_, &non_hex_pmid_);
      }

      try {
        fs::remove_all(chunkstore_dir_);
      }
      catch(const std::exception &e) {
        printf("%s\n", e.what());
      }

      channel_manager_.reset(new rpcprotocol::ChannelManager());
      knode_ = new kad::KNode(channel_manager_, kad::VAULT, pmid_private_,
                              pmid_public_, false, false);
      vault_chunkstore_ = new VaultChunkStore(chunkstore_dir_.string(),
                                              kAvailableSpace, 0);

      vault_service_ = new VaultService(pmid_public_, pmid_private_,
                                        signed_pmid_public_, vault_chunkstore_,
                                        knode_, &poh_);

      svc_channel_ = new rpcprotocol::Channel(channel_manager_.get());
      svc_channel_->SetService(vault_service_);
      channel_manager_->RegisterChannel(vault_service_->GetDescriptor()->name(),
                                        svc_channel_);
    }

    virtual void TearDown() {
      channel_manager_->UnRegisterChannel(
          vault_service_->GetDescriptor()->name());
      channel_manager_->StopTransport();
      channel_manager_->CleanUpTransport();
      delete svc_channel_;
      delete vault_service_;
      delete vault_chunkstore_;
      delete knode_;
      channel_manager_.reset();

      try {
        fs::remove_all(chunkstore_dir_);
      }
      catch(const std::exception &e) {
        printf("%s\n", e.what());
      }
    }

    fs::path chunkstore_dir_;
    std::string pmid_public_, pmid_private_, signed_pmid_public_;
    std::string pmid_, non_hex_pmid_;
    boost::shared_ptr<rpcprotocol::ChannelManager> channel_manager_;
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

  packethandler::GenericPacket gp;
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

TEST_F(VaultServicesTest, BEH_MAID_ServicesRankAuthorityGenerator) {
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);

  std::string rank_authority, test_rank_authority;
  std::string signed_rank_authority, test_signed_rank_authority;
  std::string content("This is a data chunk");
  boost::uint64_t data_size = 20;
  std::string chunkname(co.Hash(content, "", crypto::STRING_STRING, false));
  std::string pmid("abc");

  maidsafe::RankAuthority ra;
  ra.set_chunkname(chunkname);
  ra.set_data_size(data_size);
  ra.set_pmid(pmid);
  rank_authority = ra.SerializeAsString();
  signed_rank_authority = co.AsymSign(rank_authority, "", pmid_private_,
                                      crypto::STRING_STRING);

  vault_service_->RankAuthorityGenerator(chunkname, data_size, pmid,
                                         &test_rank_authority,
                                         &test_signed_rank_authority);
  EXPECT_EQ(rank_authority, test_rank_authority);
  EXPECT_EQ(signed_rank_authority, test_signed_rank_authority);
}

TEST_F(VaultServicesTest, BEH_MAID_ServicesStoreChunkPrep) {
  rpcprotocol::Controller controller;
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
    vault_service_->StoreChunkPrep(&controller, &request, &response, done);
    EXPECT_TRUE(response.IsInitialized());
    EXPECT_NE(kAck, response.result());
    response.Clear();
  }

  request.set_chunkname(chunkname);
  request.set_data_size(kAvailableSpace + 1);
  request.set_pmid(pmid);
  request.set_public_key(pub_key);
  request.set_signed_public_key(sig_pub_key);
  request.set_signed_request(sig_req);

  // too much data
  {
    google::protobuf::Closure *done = google::protobuf::NewCallback<Callback>
        (&cb_obj, &Callback::CallbackFunction);
    vault_service_->StoreChunkPrep(&controller, &request, &response, done);
    EXPECT_TRUE(response.IsInitialized());
    EXPECT_NE(kAck, response.result());
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
    EXPECT_NE(kAck, response.result());
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
    EXPECT_NE(kAck, response.result());
    response.Clear();
  }

  request.set_data_size(content.size());

  // proper request
  {
    google::protobuf::Closure *done = google::protobuf::NewCallback<Callback>
        (&cb_obj, &Callback::CallbackFunction);
    vault_service_->StoreChunkPrep(&controller, &request, &response, done);
    EXPECT_TRUE(response.IsInitialized());
    EXPECT_EQ(kAck, response.result());
    EXPECT_EQ(non_hex_pmid_, response.pmid_id());
  }

  maidsafe::IOUAuthority iou_authority;
  iou_authority.set_data_size(content.size());
  iou_authority.set_pmid(non_hex_pmid_);
  std::string iou_authority_str;
  iou_authority.SerializeToString(&iou_authority_str);
  EXPECT_EQ(iou_authority_str, response.iou_authority());
  std::string signed_iou_authority(co.AsymSign(iou_authority_str, "",
      pmid_private_, crypto::STRING_STRING));
  EXPECT_EQ(signed_iou_authority, response.signed_iou_authority());
}

TEST_F(VaultServicesTest, BEH_MAID_ServicesStoreChunk) {
  rpcprotocol::Controller controller;
  maidsafe::StoreRequest request;
  maidsafe::StoreResponse response;

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

  for (int i = 0; i <= 1; ++i) {
    switch (i) {
      case 0:  // uninitialized request
        break;
      case 1:  // invalid request
        request.set_chunkname(chunkname);
        request.set_data(content);
        request.set_pmid(pmid);
        request.set_public_key("fail");  // !
        request.set_signed_public_key(sig_pub_key);
        request.set_signed_request(sig_req);
        request.set_data_type(maidsafe::DATA);
        // request.set_offset(  );
        // request.set_chunklet_size(  );
        break;
    }

    google::protobuf::Closure *done = google::protobuf::NewCallback<Callback>
        (&cb_obj, &Callback::CallbackFunction);
    vault_service_->StoreChunk(&controller, &request, &response, done);
    EXPECT_TRUE(response.IsInitialized());
    EXPECT_NE(kAck, response.result());
    response.Clear();
  }

  request.set_public_key(pub_key);
  request.set_data("abcdef");

  // TODO(anyone) add more data types
  int data_type[] = { maidsafe::SYSTEM_PACKET, maidsafe::PDDIR_SIGNED,
                      maidsafe::BUFFER_PACKET, maidsafe::DATA };

  // invalid data for all data types
  for (size_t i = 0; i < sizeof(data_type)/sizeof(data_type[0]); ++i) {
    request.set_data_type(data_type[i]);
    google::protobuf::Closure *done = google::protobuf::NewCallback<Callback>
        (&cb_obj, &Callback::CallbackFunction);
    vault_service_->StoreChunk(&controller, &request, &response, done);
    EXPECT_TRUE(response.IsInitialized());
    EXPECT_NE(kAck, response.result());
    response.Clear();
  }

  request.set_data(content);
  request.set_data_type(maidsafe::DATA);

  // #1 make PendingOperationsHandler::FindOperation() fail
  // #2 actually store the chunk
  // #3 try storing again, will make StoreChunkLocal() fail
  for (int i = 0; i < 3; ++i) {
    if (i > 0) {
      EXPECT_EQ(0, poh_.AddPendingOperation(pmid, chunkname, content.size(), "",
                                            "", 0, pub_key, STORE_ACCEPTED));
    }
    google::protobuf::Closure *done = google::protobuf::NewCallback<Callback>
        (&cb_obj, &Callback::CallbackFunction);
    vault_service_->StoreChunk(&controller, &request, &response, done);
    EXPECT_TRUE(response.IsInitialized());
    if (i == 1) {
      EXPECT_EQ(kAck, response.result());
    } else {
      EXPECT_NE(kAck, response.result());
    }
    response.Clear();
  }

  // TODO(Steve) make PendingOperationsHandler::AdvanceStatus() fail (?)

  // check success for all remaining data types
  for (size_t i = 0; i < sizeof(data_type)/sizeof(data_type[0]); ++i) {
    if (data_type[i] == maidsafe::DATA) continue;
    request.set_data_type(data_type[i]);

    switch (data_type[i]) {
      case maidsafe::SYSTEM_PACKET:
      case maidsafe::PDDIR_SIGNED: {
        packethandler::GenericPacket gp;
        gp.set_data("Generic System Packet Data " + base::itos(i));
        gp.set_signature(co.AsymSign(gp.data(), "", priv_key,
                                     crypto::STRING_STRING));
        content = gp.SerializeAsString();
        break;
      }
      case maidsafe::BUFFER_PACKET: {
        packethandler::BufferPacketInfo bpi;
        bpi.set_owner("test bufferpacket " + base::itos(i));
        bpi.set_ownerpublickey(pub_key);
        bpi.add_users("testuser");
        packethandler::BufferPacket bp;
        packethandler::GenericPacket *info = bp.add_owner_info();
        info->set_data(bpi.SerializeAsString());
        info->set_signature(co.AsymSign(info->data(), "", priv_key,
                                        crypto::STRING_STRING));
        content = bp.SerializeAsString();
        break;
      }
    }

    chunkname = co.Hash(content, "", crypto::STRING_STRING, false);
    CreateSignedRequest(pub_key, priv_key, chunkname, &pmid, &sig_pub_key,
                        &sig_req);
    request.set_chunkname(chunkname);
    request.set_data(content);
    request.set_pmid(pmid);
    request.set_signed_public_key(sig_pub_key);
    request.set_signed_request(sig_req);

    EXPECT_EQ(0, poh_.AddPendingOperation(pmid, chunkname, content.size(), "",
                                          "", 0, pub_key, STORE_ACCEPTED));

    google::protobuf::Closure *done = google::protobuf::NewCallback<Callback>
        (&cb_obj, &Callback::CallbackFunction);
    vault_service_->StoreChunk(&controller, &request, &response, done);
    EXPECT_TRUE(response.IsInitialized());
    EXPECT_EQ(kAck, response.result());
    response.Clear();
  }
}

TEST_F(VaultServicesTest, BEH_MAID_ServicesStorePacket) {
  rpcprotocol::Controller controller;
  maidsafe::StoreRequest request;
  maidsafe::StoreResponse response;

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

  for (int i = 0; i <= 2; ++i) {
    switch (i) {
      case 0:  // uninitialized request
        break;
      case 1:  // invalid request
        request.set_chunkname(chunkname);
        request.set_data(content);
        request.set_pmid(pmid);
        request.set_public_key("fail");  // !
        request.set_signed_public_key(sig_pub_key);
        request.set_signed_request(sig_req);
        request.set_data_type(maidsafe::SYSTEM_PACKET);
        // request.set_offset(  );
        // request.set_chunklet_size(  );
        break;
      case 2:  // unsupported data type
        request.set_public_key(pub_key);
        request.set_data_type(maidsafe::DATA);
        break;
    }

    google::protobuf::Closure *done = google::protobuf::NewCallback<Callback>
        (&cb_obj, &Callback::CallbackFunction);
    vault_service_->StorePacket(&controller, &request, &response, done);
    EXPECT_TRUE(response.IsInitialized());
    EXPECT_NE(kAck, response.result());
    response.Clear();
  }

  request.set_data("abcdef");

  // TODO(anyone) add more data types
  int data_type[] = { maidsafe::SYSTEM_PACKET, maidsafe::BUFFER_PACKET };

  // invalid data for all data types
  for (size_t i = 0; i < sizeof(data_type)/sizeof(data_type[0]); ++i) {
    request.set_data_type(data_type[i]);
    google::protobuf::Closure *done = google::protobuf::NewCallback<Callback>
        (&cb_obj, &Callback::CallbackFunction);
    vault_service_->StorePacket(&controller, &request, &response, done);
    EXPECT_TRUE(response.IsInitialized());
    EXPECT_NE(kAck, response.result());
    response.Clear();
  }

  request.set_data(content);

  // check success for all data types; second iteration fails StoreChunkLocal()
  for (int j = 0; j <= 1; ++j) {
    for (size_t i = 0; i < sizeof(data_type)/sizeof(data_type[0]); ++i) {
      request.set_data_type(data_type[i]);
      // printf("*** starting iteration %d.%d ***\n", j, i);

      switch (data_type[i]) {
        case maidsafe::SYSTEM_PACKET: {
          packethandler::GenericPacket gp;
          gp.set_data("Generic System Packet Data " + base::itos(i));
          gp.set_signature(co.AsymSign(gp.data(), "", priv_key,
                                       crypto::STRING_STRING));
          content = gp.SerializeAsString();
          break;
        }
        case maidsafe::BUFFER_PACKET: {
          packethandler::BufferPacketInfo bpi;
          bpi.set_owner("test bufferpacket " + base::itos(i));
          bpi.set_ownerpublickey(pub_key);
          bpi.add_users("testuser");
          packethandler::BufferPacket bp;
          packethandler::GenericPacket *info = bp.add_owner_info();
          info->set_data(bpi.SerializeAsString());
          info->set_signature(co.AsymSign(info->data(), "", priv_key,
                                          crypto::STRING_STRING));
          content = bp.SerializeAsString();
          break;
        }
      }

      chunkname = co.Hash(content, "", crypto::STRING_STRING, false);
      CreateSignedRequest(pub_key, priv_key, chunkname, &pmid, &sig_pub_key,
                          &sig_req);
      request.set_chunkname(chunkname);
      request.set_data(content);
      request.set_pmid(pmid);
      request.set_signed_public_key(sig_pub_key);
      request.set_signed_request(sig_req);

      EXPECT_EQ(0, poh_.AddPendingOperation(pmid, chunkname, content.size(), "",
                                            "", 0, pub_key, STORE_ACCEPTED));

      google::protobuf::Closure *done = google::protobuf::NewCallback<Callback>
          (&cb_obj, &Callback::CallbackFunction);
      vault_service_->StorePacket(&controller, &request, &response, done);
      EXPECT_TRUE(response.IsInitialized());
      if (j == 0) {
        EXPECT_EQ(kAck, response.result());
      } else {
        EXPECT_NE(kAck, response.result());
      }
      response.Clear();
    }
    poh_.ClearPendingOperations();
  }
}

TEST_F(VaultServicesTest, BEH_MAID_ServicesIOUDone) {
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

  for (int i = 0; i <= 2; ++i) {
    switch (i) {
      case 0:  // uninitialized request
        break;
      case 1:  // invalid request
        request.set_chunkname(chunkname);
        // request.set_pmid(pmid);
        request.set_public_key("fail");  // !
        request.set_signed_public_key(sig_pub_key);
        request.set_signed_request(sig_req);
        break;
      case 2:  // make PendingOperationsHandler::AdvanceStatus() fail
        request.set_public_key(pub_key);
        break;
    }

    google::protobuf::Closure *done = google::protobuf::NewCallback<Callback>
        (&cb_obj, &Callback::CallbackFunction);
    vault_service_->IOUDone(&controller, &request, &response, done);
    EXPECT_TRUE(response.IsInitialized());
    EXPECT_NE(kAck, response.result());
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
    EXPECT_EQ(kAck, response.result());
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

  for (int i = 0; i <= 4; ++i) {
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
        request.set_signed_public_key(sig_pub_key);
        request.set_signed_request(sig_req);
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
    EXPECT_NE(kAck, response.result());
    response.Clear();
  }

  poh_.ClearPendingOperations();

  // proper request
  {
    google::protobuf::Closure *done = google::protobuf::NewCallback<Callback>
        (&cb_obj, &Callback::CallbackFunction);
    vault_service_->StoreIOU(&controller, &request, &response, done);
    EXPECT_TRUE(response.IsInitialized());
    EXPECT_EQ(kAck, response.result());
    response.Clear();
  }
}

TEST_F(VaultServicesTest, BEH_MAID_ServicesStoreChunkReference) {
  rpcprotocol::Controller controller;
  maidsafe::StoreReferenceRequest request;
  maidsafe::StoreReferenceResponse response;

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

  for (int i = 0; i <= 2; ++i) {
    switch (i) {
      case 0:  // uninitialized request
        break;
      case 1:  // invalid request
        request.set_chunkname(chunkname);
        request.set_pmid(pmid);
        request.set_signed_pmid("signed pmid");
        request.set_public_key("fail");  // !
        request.set_signed_public_key(sig_pub_key);
        request.set_signed_request(sig_req);
        break;
      case 2:  // make PendingOperationsHandler::GetSizeAndIOU() fail
        request.set_public_key(pub_key);
        break;
      // TODO(Steve) make PendingOperationsHandler::AdvanceStatus() fail (?)
      // TODO(Steve) make KNode::StoreValueLocal() fail (?)
    }

    google::protobuf::Closure *done = google::protobuf::NewCallback<Callback>
        (&cb_obj, &Callback::CallbackFunction);
    vault_service_->StoreChunkReference(&controller, &request, &response, done);
    EXPECT_TRUE(response.IsInitialized());
    EXPECT_NE(kAck, response.result());
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
    EXPECT_EQ(kAck, response.result());
    response.Clear();

    kad::SignedValue signed_value;
    signed_value.set_value(pmid);
    signed_value.set_value_signature(request.signed_pmid());
    std::string ser_signed_value = signed_value.SerializeAsString();

    std::vector<std::string> values;
    ASSERT_TRUE(knode_->FindValueLocal(chunkname, &values));
    ASSERT_EQ(1, values.size());
    ASSERT_EQ(ser_signed_value, values[0]);
  }
}

TEST_F(VaultServicesTest, BEH_MAID_ServicesGetCheck) {
  rpcprotocol::Controller controller;
  maidsafe::GetRequest request;
  maidsafe::GetResponse response;
  maidsafe::CheckChunkRequest check_request;
  maidsafe::CheckChunkResponse check_response;

  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);
  std::string content("This is a data chunk");
  std::string chunkname(co.Hash(content, "", crypto::STRING_STRING, false));

  Callback cb_obj;

  // test Get()'s error handling
  for (int i = 0; i <= 1; ++i) {
    switch (i) {
      case 0:  // uninitialized request
        break;
      case 1:  // make LoadChunkLocal() fail
        request.set_chunkname(chunkname);
        break;
    }

    google::protobuf::Closure *done = google::protobuf::NewCallback<Callback>
        (&cb_obj, &Callback::CallbackFunction);
    vault_service_->Get(&controller, &request, &response, done);
    EXPECT_TRUE(response.IsInitialized());
    EXPECT_NE(kAck, response.result());
    response.Clear();
  }

  // test CheckChunk()'s error handling
  for (int i = 0; i <= 1; ++i) {
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
    EXPECT_NE(kAck, check_response.result());
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
    EXPECT_EQ(kAck, check_response.result());
    response.Clear();

    google::protobuf::Closure *done2 = google::protobuf::NewCallback<Callback>
        (&cb_obj, &Callback::CallbackFunction);
    vault_service_->Get(&controller, &request, &response, done2);
    EXPECT_TRUE(response.IsInitialized());
    EXPECT_EQ(kAck, response.result());
    EXPECT_EQ(content, response.content());
    response.Clear();
  }
}

TEST_F(VaultServicesTest, BEH_MAID_ServicesUpdate) {
  rpcprotocol::Controller controller;
  maidsafe::UpdateRequest request;
  maidsafe::UpdateResponse response;

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

  for (int i = 0; i <= 2; ++i) {
    switch (i) {
      case 0:  // uninitialized request
        break;
      case 1:  // invalid request
        request.set_chunkname(chunkname);
        request.set_data(content);
        request.set_public_key("fail");  // !
        request.set_signed_public_key(sig_pub_key);
        request.set_signed_request(sig_req);
        request.set_data_type(maidsafe::SYSTEM_PACKET);
        break;
      case 2:  // make LoadChunkLocal() fail
        request.set_public_key(pub_key);
        break;
    }

    google::protobuf::Closure *done = google::protobuf::NewCallback<Callback>
        (&cb_obj, &Callback::CallbackFunction);
    vault_service_->Update(&controller, &request, &response, done);
    EXPECT_TRUE(response.IsInitialized());
    EXPECT_NE(kAck, response.result());
    response.Clear();
  }

  ASSERT_TRUE(vault_service_->StoreChunkLocal(chunkname, content));
  request.set_data("abcdef");

  // TODO(anyone) add more data types
  int data_type[] = { maidsafe::SYSTEM_PACKET, maidsafe::BUFFER_PACKET_MESSAGE,
                      maidsafe::PDDIR_SIGNED, maidsafe::BUFFER_PACKET_INFO };

  // invalid data for all data types
  for (size_t i = 0; i < sizeof(data_type)/sizeof(data_type[0]); ++i) {
    request.set_data_type(data_type[i]);
    google::protobuf::Closure *done = google::protobuf::NewCallback<Callback>
        (&cb_obj, &Callback::CallbackFunction);
    vault_service_->Update(&controller, &request, &response, done);
    EXPECT_TRUE(response.IsInitialized());
    EXPECT_NE(kAck, response.result());
    response.Clear();
  }

  // valid data for all data types
  for (size_t i = 0; i < sizeof(data_type)/sizeof(data_type[0]); ++i) {
    request.set_data_type(data_type[i]);
    prev_content = "";
    // printf("** update iteration #%d\n", i);

    switch (data_type[i]) {
      case maidsafe::SYSTEM_PACKET:
      case maidsafe::PDDIR_SIGNED: {
        packethandler::GenericPacket gp;
        gp.set_data("Generic System Packet Data " + base::itos(i));
        gp.set_signature(co.AsymSign(gp.data(), "", priv_key,
                                     crypto::STRING_STRING));
        content = gp.SerializeAsString();
        break;
      }
      case maidsafe::BUFFER_PACKET_MESSAGE: {
        packethandler::GenericPacket gp_msg;
        packethandler::BufferPacketMessage bp_msg;
        bp_msg.set_sender_id("non authuser");
        std::string enc_key = co.AsymEncrypt("key", "", pub_key,
                                             crypto::STRING_STRING);
        bp_msg.set_rsaenc_key(enc_key);
        std::string enc_msg = co.SymmEncrypt("this be a message", "",
                                             crypto::STRING_STRING, "key");
        bp_msg.set_aesenc_message(enc_msg);
        bp_msg.set_type(packethandler::ADD_CONTACT_RQST);

        std::string ser_bp_msg;
        bp_msg.set_sender_public_key(pub_key);
        bp_msg.SerializeToString(&ser_bp_msg);
        gp_msg.set_data(ser_bp_msg);
        gp_msg.set_signature(co.AsymSign(ser_bp_msg, "", priv_key,
                             crypto::STRING_STRING));
        content = gp_msg.SerializeAsString();

        packethandler::BufferPacketInfo bpi;
        bpi.set_owner("test bufferpacket xyz");
        bpi.set_ownerpublickey(pub_key);
        bpi.add_users("testuser");
        packethandler::BufferPacket bp;
        packethandler::GenericPacket *info = bp.add_owner_info();
        std::string ser_bpi;
        bpi.SerializeToString(&ser_bpi);
        info->set_data(ser_bpi);
        info->set_signature(co.AsymSign(ser_bpi, "", priv_key,
                            crypto::STRING_STRING));
        prev_content = bp.SerializeAsString();
        break;
      }
      case maidsafe::BUFFER_PACKET_INFO: {
        packethandler::BufferPacketInfo bpi;
        bpi.set_owner("test bufferpacket");
        bpi.set_ownerpublickey(pub_key);
        bpi.add_users("testuser");
        packethandler::BufferPacket bp;
        packethandler::GenericPacket *info = bp.add_owner_info();
        std::string ser_bpi;
        bpi.SerializeToString(&ser_bpi);
        info->set_data(ser_bpi);
        info->set_signature(co.AsymSign(ser_bpi, "", priv_key,
                            crypto::STRING_STRING));
        prev_content = bp.SerializeAsString();
        content = info->SerializeAsString();
        break;
      }
    }

    if (prev_content.empty())
      prev_content = content;

    chunkname = co.Hash(prev_content, "", crypto::STRING_STRING, false);
    CreateSignedRequest(pub_key, priv_key, chunkname, &pmid, &sig_pub_key,
                        &sig_req);
    request.set_chunkname(chunkname);
    request.set_data(content);
    request.set_signed_public_key(sig_pub_key);
    request.set_signed_request(sig_req);

    ASSERT_TRUE(vault_service_->StoreChunkLocal(chunkname, prev_content));

    google::protobuf::Closure *done = google::protobuf::NewCallback<Callback>
        (&cb_obj, &Callback::CallbackFunction);
    vault_service_->Update(&controller, &request, &response, done);
    EXPECT_TRUE(response.IsInitialized());
    EXPECT_EQ(kAck, response.result());
    response.Clear();
  }
}

TEST_F(VaultServicesTest, BEH_MAID_ServicesGetMessages) {
  rpcprotocol::Controller controller;
  maidsafe::GetMessagesRequest request;
  maidsafe::GetMessagesResponse response;

  std::string pub_key, priv_key, pmid, sig_pub_key, sig_req;
  CreateRSAKeys(&pub_key, &priv_key);
  crypto::Crypto co;
  co.set_symm_algorithm(crypto::AES_256);
  co.set_hash_algorithm(crypto::SHA_512);

  packethandler::BufferPacketInfo bpi;
  bpi.set_owner("test bufferpacket");
  bpi.set_ownerpublickey(pub_key);
  bpi.add_users("testuser");
  packethandler::BufferPacket bp;
  packethandler::GenericPacket *info = bp.add_owner_info();
  std::string ser_bpi;
  bpi.SerializeToString(&ser_bpi);
  info->set_data(ser_bpi);
  info->set_signature(co.AsymSign(ser_bpi, "", priv_key,
                      crypto::STRING_STRING));
  std::string content = bp.SerializeAsString();
  std::string chunkname(co.Hash(content, "", crypto::STRING_STRING, false));
  CreateSignedRequest(pub_key, priv_key, chunkname, &pmid, &sig_pub_key,
                      &sig_req);

  Callback cb_obj;

  for (int i = 0; i <= 3; ++i) {
    switch (i) {
      case 0:  // uninitialized request
        break;
      case 1:  // invalid request
        request.set_buffer_packet_name(chunkname);
        request.set_public_key("fail");  // !
        request.set_signed_public_key(sig_pub_key);
        break;
      case 2:  // make LoadChunkLocal() fail
        request.set_public_key(pub_key);
        break;
      case 3:  // make [vbph]::ValidateOwnerSignature() fail
        ASSERT_TRUE(vault_service_->StoreChunkLocal(chunkname, "fail"));
        break;
      // TODO(Steve) make VaultBufferPacketHandler::GetMessages() fail (?)
    }

    google::protobuf::Closure *done = google::protobuf::NewCallback<Callback>
        (&cb_obj, &Callback::CallbackFunction);
    vault_service_->GetMessages(&controller, &request, &response, done);
    EXPECT_TRUE(response.IsInitialized());
    EXPECT_NE(kAck, response.result());
    response.Clear();
  }

  ASSERT_TRUE(vault_service_->UpdateChunkLocal(chunkname, content));

  // test success
  {
    google::protobuf::Closure *done = google::protobuf::NewCallback<Callback>
        (&cb_obj, &Callback::CallbackFunction);
    vault_service_->GetMessages(&controller, &request, &response, done);
    EXPECT_TRUE(response.IsInitialized());
    EXPECT_EQ(kAck, response.result());
    response.Clear();
  }
}

TEST_F(VaultServicesTest, BEH_MAID_ServicesDelete) {
  rpcprotocol::Controller controller;
  maidsafe::DeleteRequest request;
  maidsafe::DeleteResponse response;

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

  for (int i = 0; i <= 2; ++i) {
    switch (i) {
      case 0:  // uninitialized request
        break;
      case 1:  // invalid request
        request.set_chunkname(chunkname);
        request.set_public_key("fail");  // !
        request.set_signed_public_key(sig_pub_key);
        request.set_signed_request(sig_req);
        request.set_data_type(maidsafe::SYSTEM_PACKET);
        break;
      case 2:  // make LoadChunkLocal() fail
        request.set_public_key(pub_key);
        break;
    }

    google::protobuf::Closure *done = google::protobuf::NewCallback<Callback>
        (&cb_obj, &Callback::CallbackFunction);
    vault_service_->Delete(&controller, &request, &response, done);
    EXPECT_TRUE(response.IsInitialized());
    EXPECT_NE(kAck, response.result());
    response.Clear();
  }

  ASSERT_TRUE(vault_service_->StoreChunkLocal(chunkname, "abcde"));

  // TODO(anyone) add more data types
  int data_type[] = { maidsafe::SYSTEM_PACKET, maidsafe::BUFFER_PACKET,
                      maidsafe::BUFFER_PACKET_MESSAGE, maidsafe::PDDIR_SIGNED };

  // invalid data for all data types
  for (size_t i = 0; i < sizeof(data_type)/sizeof(data_type[0]); ++i) {
    request.set_data_type(data_type[i]);
    google::protobuf::Closure *done = google::protobuf::NewCallback<Callback>
        (&cb_obj, &Callback::CallbackFunction);
    vault_service_->Delete(&controller, &request, &response, done);
    EXPECT_TRUE(response.IsInitialized());
    EXPECT_NE(kAck, response.result());
    response.Clear();
  }

  // test success
  for (size_t i = 0; i < sizeof(data_type)/sizeof(data_type[0]); ++i) {
    request.set_data_type(data_type[i]);

    switch (data_type[i]) {
      case maidsafe::SYSTEM_PACKET:
      case maidsafe::PDDIR_SIGNED: {
        packethandler::GenericPacket gp;
        gp.set_data("Generic System Packet Data " + base::itos(i));
        gp.set_signature(co.AsymSign(gp.data(), "", priv_key,
                                     crypto::STRING_STRING));
        content = gp.SerializeAsString();
        break;
      }
      case maidsafe::BUFFER_PACKET:
      case maidsafe::BUFFER_PACKET_MESSAGE: {
        packethandler::BufferPacketInfo bpi;
        bpi.set_owner("test bufferpacket " + base::itos(i));
        bpi.set_ownerpublickey(pub_key);
        bpi.add_users("testuser");
        packethandler::BufferPacket bp;
        packethandler::GenericPacket *info = bp.add_owner_info();
        info->set_data(bpi.SerializeAsString());
        info->set_signature(co.AsymSign(info->data(), "", priv_key,
                                        crypto::STRING_STRING));
        packethandler::GenericPacket *msg = bp.add_messages();
        msg->set_data("message");
        msg->set_signature(co.AsymSign(msg->data(), "", priv_key,
                                       crypto::STRING_STRING));
        content = bp.SerializeAsString();
        break;
      }
    }

    chunkname = co.Hash(content, "", crypto::STRING_STRING, false);
    CreateSignedRequest(pub_key, priv_key, chunkname, &pmid, &sig_pub_key,
                        &sig_req);
    request.set_chunkname(chunkname);
    request.set_signed_public_key(sig_pub_key);
    request.set_signed_request(sig_req);

    ASSERT_TRUE(vault_service_->StoreChunkLocal(chunkname, content));
    ASSERT_TRUE(vault_service_->HasChunkLocal(chunkname));

    google::protobuf::Closure *done = google::protobuf::NewCallback<Callback>
        (&cb_obj, &Callback::CallbackFunction);
    vault_service_->Delete(&controller, &request, &response, done);
    EXPECT_TRUE(response.IsInitialized());
    EXPECT_EQ(kAck, response.result());
    if (data_type[i] != maidsafe::BUFFER_PACKET_MESSAGE) {
      ASSERT_FALSE(vault_service_->HasChunkLocal(chunkname));
    } else {
      packethandler::BufferPacket bp;
      ASSERT_TRUE(vault_service_->LoadChunkLocal(chunkname, &content));
      ASSERT_TRUE(bp.ParseFromString(content));
      EXPECT_EQ(0, bp.messages_size());
    }
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

  for (int i = 0; i <= 1; ++i) {
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
    EXPECT_NE(kAck, response.result());
    response.Clear();
  }

  ASSERT_TRUE(vault_service_->StoreChunkLocal(chunkname, content));

  // test success
  {
    google::protobuf::Closure *done = google::protobuf::NewCallback<Callback>
        (&cb_obj, &Callback::CallbackFunction);
    vault_service_->ValidityCheck(&controller, &request, &response, done);
    EXPECT_TRUE(response.IsInitialized());
    EXPECT_EQ(kAck, response.result());
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

  for (int i = 0; i <= 2; ++i) {
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
    EXPECT_NE(kAck, response.result());
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

  for (int i = 0; i <= 1; ++i) {
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
    EXPECT_NE(kAck, response.result());
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
    EXPECT_EQ(kAck, response.result());

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

}  // namespace maidsafe_vault
