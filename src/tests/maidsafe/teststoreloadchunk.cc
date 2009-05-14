/*
 * copyright maidsafe.net limited 2008
 * The following source code is property of maidsafe.net limited and
 * is not meant for external use. The use of this code is governed
 * by the license file LICENSE.TXT found in teh root of this directory and also
 * on www.maidsafe.net.
 *
 * You are not free to copy, amend or otherwise use this source code without
 * explicit written permission of the board of directors of maidsafe.net
 *
 *  Created on: Sep 29, 2008
 *      Author: Haiyang, Jose
 */
/*#include "base/utils.h"
#include "maidsafe/client/pdclient.h"
#include "base/crypto.h"
#include "base/rsakeypair.h"
#include "base/calllatertimer.h"
#include <exception>
#include <boost/bind.hpp>
#include <boost/function.hpp>
#include <boost/cstdint.hpp>
#include <boost/asio.hpp>
#include <boost/thread/recursive_mutex.hpp>
#include <vector>
#include "boost/date_time/posix_time/posix_time.hpp"
#include<gtest/gtest.h>
#include "tests/kademlia/fake_callbacks.h"
#include "protobuf/packet.pb.h"

const int kNetworkSize = 10;

class PDClientTest: public testing::Test {
protected:
  PDClientTest() {
    nodes = new kad::KNode *[kNetworkSize];
    io_services = new boost::asio::io_service *[kNetworkSize];
    db = new boost::filesystem::path *[kNetworkSize];
    timers = new base::CallLaterTimer *[kNetworkSize];
    mutex = new boost::recursive_mutex *[kNetworkSize];
    cry_obj.set_symm_algorithm("AES_256");
    cry_obj.set_hash_algorithm("SHA512");
    keys.GenerateKeys(1024);
    sig_pub_key = cry_obj.AsymSign(keys.public_key(), "", keys.private_key(),
      crypto::STRING_STRING);

  }
  virtual ~PDClientTest() {
    delete [] nodes;
    delete [] db;
    delete []timers;
    delete [] mutex;
    delete [] io_services;
    bootstrapping_nodes.clear();
  }
  virtual void SetUp() {
    boost::filesystem::path *curr_dir;
    // start the bootstrapping node
    mutex[0] = new boost::recursive_mutex();
    timers[0] = new base::CallLaterTimer(mutex[0]);
    io_services[0] = new boost::asio::io_service();
    std::string dir = "pdhome"+base::itos(62001);
    curr_dir = new boost::filesystem::path(dir, boost::filesystem::native);
    db[0] = curr_dir;
    nodes[0] = new kad::KNode(io_services[0], *db[0], timers[0], mutex[0],
        kad::VAULT);
    cb.Reset();
    std::vector<kad::Contact> bs_nodes;
    nodes[0]->Join("", 62001, bs_nodes, false, boost::bind(
        &GeneralKadCallback::CallbackFunc, &cb, _1));
    wait_result(&cb, mutex[0]);
    EXPECT_EQ(kad::kRpcResultFailure, cb.result());
    kad::Contact bs_contact(kad::vault_random_id(), nodes[0]->host_ip_,
        nodes[0]->host_port_);
    bootstrapping_nodes.push_back(bs_contact);
    for (int i = 1; i < kNetworkSize; i++) {
      mutex[i] = new boost::recursive_mutex();
      timers[i] = new base::CallLaterTimer(mutex[i]);
      io_services[i] = new boost::asio::io_service();
      dir = "pdhome"+base::itos(62001+i);
      curr_dir = new boost::filesystem::path(dir, boost::filesystem::native);
      db[i] = curr_dir;
      nodes[i] = new kad::KNode(io_services[i], *db[i], timers[i], mutex[i],
          kad::VAULT);
      cb.Reset();
      nodes[i]->Join("", 62001 + i, bootstrapping_nodes, false, boost::bind(
          &GeneralKadCallback::CallbackFunc, &cb, _1));
      wait_result(&cb, mutex[i]);
      EXPECT_EQ(kad::kRpcResultSuccess, cb.result());
    }
    client_mutex = new boost::recursive_mutex();
    client_timer = new base::CallLaterTimer(client_mutex);
    client_io_service = new boost::asio::io_service();
    dir = "pdhome"+base::itos(62001 + kNetworkSize);
    client_db = new boost::filesystem::path(dir, boost::filesystem::native);
    pdclient = new maidsafe::PDClient(client_io_service, *client_db,
      client_timer, client_mutex);
    cb.Reset();
    pdclient->Join("", 62001 + kNetworkSize, bootstrapping_nodes, false, boost::bind(
      &GeneralKadCallback::CallbackFunc, &cb, _1));
    wait_result(&cb, client_mutex);
    ASSERT_EQ(kad::kRpcResultSuccess, cb.result());
  }
  virtual void TearDown(){
    for (int i = 0; i<kNetworkSize; i++) {
      timers[i]->CancelAll();
      cb.Reset();
      nodes[i]->Leave(boost::bind(&GeneralKadCallback::CallbackFunc, &cb, _1));
      wait_result(&cb, mutex[i]);
      std::cout << "node " << i << " left" << std::endl;
      delete nodes[i];
      delete timers[i];
      delete mutex[i];
      delete io_services[i];
      try {
        boost::filesystem::remove_all(*db[i]);
      } catch(std::exception &e) {
        std::cout << "error: " << e.what() << std::endl;
      }
      delete db[i];
    }
    cb.Reset();
    pdclient->Leave(boost::bind(&GeneralKadCallback::CallbackFunc, &cb, _1));
    wait_result(&cb, client_mutex);
    std::cout << "pdclient left" << std::endl;
    delete pdclient;
    delete client_timer;
    delete client_mutex;
    delete client_io_service;
    try {
      boost::filesystem::remove_all(*client_db);
    } catch(std::exception &e) {
      std::cout << "error: " << e.what() << std::endl;
    }
    delete client_db;
  }

  std::vector<kad::Contact> bootstrapping_nodes;
  boost::asio::io_service **io_services;
  kad::KNode **nodes;
  maidsafe::PDClient *pdclient;
  boost::filesystem::path **db;
  base::CallLaterTimer **timers;
  boost::recursive_mutex **mutex;
  boost::recursive_mutex *client_mutex;
  boost::filesystem::path *client_db;
  base::CallLaterTimer *client_timer;
  boost::asio::io_service *client_io_service;
  crypto::Crypto cry_obj;
  GeneralKadCallback cb;
  crypto::RsaKeyPair keys;
  std::string sig_pub_key;
};

TEST_F(PDClientTest, FUNC_KAD_LoadChunk) {
  std::string chunk_content = base::RandomString(250*1024);
  std::string chunk_name = cry_obj.Hash(chunk_content, "",
    crypto::STRING_STRING, false);
  std::string encoded_chunk_name;
  base::encode_to_hex(chunk_name, encoded_chunk_name);
  kad::StoreChunkRequest args;
  StoreResponse result;
  std::string args_str(""), result_str(""), sender_info("");
  args.set_chunkname(chunk_name);
  args.set_content(chunk_content);
  args.set_public_key(keys.public_key());
  args.set_signed_public_key(sig_pub_key);
  std::string sig_req = cry_obj.AsymSign(cry_obj.Hash(keys.public_key() +
    sig_pub_key + encoded_chunk_name, "", crypto::STRING_STRING, true), "",
    keys.private_key(), crypto::STRING_STRING);
  args.set_signed_request(sig_req);
  args.set_data_type(maidsafe::DATA);
  args.SerializeToString(&args_str);
  nodes[2]->RpcStoreChunk(args_str, sender_info, &result_str);
  base::sleep(1);
  ASSERT_TRUE(result.ParseFromString(result_str));
  ASSERT_EQ(kad::kRpcResultSuccess, result.result());
  nodes[5]->RpcStoreChunk(args_str, sender_info, &result_str);
  base::sleep(1);
  nodes[4]->RpcStoreChunk(args_str, sender_info, &result_str);
  base::sleep(1);
  FindCallback cb1;
  pdclient->FindValue(chunk_name,
      boost::bind(&FindCallback::CallbackFunc, &cb1, _1));
  wait_result(&cb1, client_mutex);
  ASSERT_EQ(kad::kRpcResultSuccess, cb1.result());
  ASSERT_EQ(3, cb1.values().size());
  std::string data = cb1.values().front();
  kad::Contact chunkholder;
  ASSERT_TRUE(chunkholder.ParseFromString(data));
  std::cout << "chunkholder: " << chunkholder.ToString() << std::endl;
  LoadChunkCallback cb2;
  cb2.Reset();
  pdclient->LoadChunk(chunk_name,
      boost::bind(&LoadChunkCallback::CallbackFunc, &cb2, _1));
  wait_result(&cb2, client_mutex);
  ASSERT_EQ(kad::kRpcResultSuccess, cb2.result());
  ASSERT_EQ(chunk_content, cb2.content());
}

TEST_F(PDClientTest, FUNC_KAD_LoadChunk_HolderLeaves) {
  std::string chunk_content = base::RandomString(250*1024);
  std::string chunk_name = cry_obj.Hash(chunk_content, "",
    crypto::STRING_STRING, false);
  std::string encoded_chunk_name;
  base::encode_to_hex(chunk_name, encoded_chunk_name);
  kad::StoreChunkRequest args;
  StoreResponse result;
  std::string args_str(""), result_str(""), sender_info("");
  args.set_chunkname(chunk_name);
  args.set_content(chunk_content);
  args.set_public_key(keys.public_key());
  args.set_signed_public_key(sig_pub_key);
  std::string sig_req = cry_obj.AsymSign(cry_obj.Hash(keys.public_key() +
    sig_pub_key + encoded_chunk_name, "", crypto::STRING_STRING, true), "",
    keys.private_key(), crypto::STRING_STRING);
  args.set_signed_request(sig_req);
  args.set_data_type(maidsafe::DATA);
  args.SerializeToString(&args_str);
  nodes[2]->RpcStoreChunk(args_str, sender_info, &result_str);
  base::sleep(3);
  ASSERT_TRUE(result.ParseFromString(result_str));
  ASSERT_EQ(kad::kRpcResultSuccess, result.result());
  nodes[5]->RpcStoreChunk(args_str, sender_info, &result_str);
  base::sleep(3);
  nodes[4]->RpcStoreChunk(args_str, sender_info, &result_str);
  base::sleep(3);
  FindCallback cb1;
  pdclient->FindValue(chunk_name,
      boost::bind(&FindCallback::CallbackFunc, &cb1, _1));
  wait_result(&cb1, client_mutex);
  ASSERT_EQ(kad::kRpcResultSuccess, cb1.result());
  ASSERT_EQ(3, cb1.values().size());
  std::string data = cb1.values().front();
  kad::Contact chunkholder;
  ASSERT_TRUE(chunkholder.ParseFromString(data));
  std::cout << "chunkholder: " << chunkholder.ToString() << std::endl;
  GeneralKadCallback cb2;
  nodes[5]->Leave(boost::bind(&GeneralKadCallback::CallbackFunc, &cb2, _1));
  wait_result(&cb2, mutex[5]);
  cb1.Reset();
  LoadChunkCallback cb3;
  pdclient->LoadChunk(chunk_name,
      boost::bind(&FakeCallback::CallbackFunc, &cb3, _1));
  wait_result(&cb3, client_mutex);
  ASSERT_EQ(kad::kRpcResultSuccess, cb3.result());
  ASSERT_EQ(chunk_content, cb3.content());
}

TEST_F(PDClientTest, FUNC_KAD_LoadChunk_AllChunkHoldersLeave) {
  std::string chunk_content = base::RandomString(250*1024);
  std::string chunk_name = cry_obj.Hash(chunk_content, "",
      crypto::STRING_STRING, false);
  std::string encoded_chunk_name;
  base::encode_to_hex(chunk_name, encoded_chunk_name);
  LoadChunkCallback cb1;
  pdclient->LoadChunk(chunk_name,
      boost::bind(&LoadChunkCallback::CallbackFunc, &cb1, _1));
  wait_result(&cb1, client_mutex);
  ASSERT_EQ(kad::kRpcResultFailure, cb1.result());
  kad::StoreChunkRequest args;
  StoreResponse result;
  std::string args_str(""), result_str(""), sender_info("");
  args.set_chunkname(chunk_name);
  args.set_content(chunk_content);
  args.set_public_key(keys.public_key());
  args.set_signed_public_key(sig_pub_key);
  std::string sig_req = cry_obj.AsymSign(cry_obj.Hash(keys.public_key() +
    sig_pub_key + encoded_chunk_name, "", crypto::STRING_STRING, true), "",
    keys.private_key(), crypto::STRING_STRING);
  args.set_signed_request(sig_req);
  args.set_data_type(maidsafe::DATA);
  args.SerializeToString(&args_str);
  nodes[2]->RpcStoreChunk(args_str, sender_info, &result_str);
  base::sleep(3);
  ASSERT_TRUE(result.ParseFromString(result_str));
  ASSERT_EQ(kad::kRpcResultSuccess, result.result());
  nodes[5]->RpcStoreChunk(args_str, sender_info, &result_str);
  base::sleep(3);
  nodes[4]->RpcStoreChunk(args_str, sender_info, &result_str);
  base::sleep(3);
  cb1.Reset();
  FindCallback cb2;
  pdclient->FindValue(chunk_name,
      boost::bind(&FindCallback::CallbackFunc, &cb2, _1));
  wait_result(&cb2, client_mutex);
  ASSERT_EQ(kad::kRpcResultSuccess, cb2.result());
  ASSERT_EQ(3, cb2.values().size());
  std::string data = cb2.values().front();
  kad::Contact chunkholder;
  ASSERT_TRUE(chunkholder.ParseFromString(data));
  std::cout << "chunkholder: " << chunkholder.ToString() << std::endl;
  GeneralKadCallback cb3;
  nodes[4]->Leave(boost::bind(&FakeCallback::CallbackFunc, &cb3, _1));
  std::cout << "Leaving network" << std::endl;
  base::sleep(1);
  nodes[5]->Leave(boost::bind(&FakeCallback::CallbackFunc, &cb3, _1));
  std::cout << "Leaving network" << std::endl;
  base::sleep(1);
  nodes[2]->Leave(boost::bind(&FakeCallback::CallbackFunc, &cb3, _1));
  std::cout << "Leaving network" << std::endl;
  base::sleep(1);
  cb1.Reset();
  pdclient->LoadChunk(chunk_name,
      boost::bind(&LoadChunkCallback::CallbackFunc, &cb1, _1));
  std::cout << "waiting for load chunk" << std::endl;
  wait_result(&cb1, client_mutex);
  ASSERT_EQ(kad::kRpcResultFailure, cb1.result());
}

TEST_F(PDClientTest, BEH_KAD_Test_StoreChunk) {
  std::string chunk_content = base::RandomString(250*1024);
  std::string chunk_name = cry_obj.Hash(chunk_content, "",
    crypto::STRING_STRING, false);
  std::string encoded_chunk_name;
  base::encode_to_hex(chunk_name, encoded_chunk_name);
  StoreChunkCallback cb1;
  std::string sig_req = cry_obj.AsymSign(cry_obj.Hash(keys.public_key() +
    sig_pub_key + encoded_chunk_name, "", crypto::STRING_STRING, true), "",
    keys.private_key(), crypto::STRING_STRING);
  pdclient->StoreChunk(chunk_name, chunk_content, keys.public_key(),
    sig_pub_key, sig_req, maidsafe::DATA,
    boost::bind(&StoreChunkCallback::CallbackFunc, &cb1, _1));
  wait_result(&cb1, client_mutex);
  ASSERT_EQ(kad::kRpcResultSuccess, cb1.result());
  int copies = 0;
  kad::CheckChunkRequest params;
  kad::CheckChunkResponse result;
  std::string params_str(""), result_str(""), sender_info("");
  params.set_chunkname(chunk_name);
  params.SerializeToString(&params_str);
  for (int i = 0; i < kNetworkSize; i++) {
    nodes[i]->RpcCheckChunk(params_str, sender_info, &result_str);
    if ((result.ParseFromString(result_str)) &&
        (result.result() == kad::kRpcResultSuccess)) {
      copies++;
      kad::LoadChunkRequest args;
      maidsafe::GetResponse load_res;
      std::string ser_args;
      args.set_chunkname(chunk_name);
      args.SerializeToString(&ser_args);
      nodes[i]->RpcLoadChunk(ser_args, sender_info, &result_str);
      ASSERT_TRUE(load_res.ParseFromString(result_str));
      ASSERT_EQ(kad::kRpcResultSuccess, load_res.result());
      ASSERT_EQ(chunk_content, load_res.content());
    }
  }
  std::cout << "number of copies: " << copies << std::endl;
  ASSERT_LE(maidsafe::kMinChunkCopies, copies);
  FindCallback cb2;
  pdclient->FindValue(chunk_name,
    boost::bind(&FindCallback::CallbackFunc, &cb2, _1));
  wait_result(&cb2, client_mutex);
  ASSERT_EQ(kad::kRpcResultSuccess, cb1.result());
}

TEST_F(PDClientTest, BEH_KAD_StoreChunk_InvalidRequest) {
  std::string chunk_content = base::RandomString(250*1024);
  std::string chunk_name = cry_obj.Hash(chunk_content, "",
    crypto::STRING_STRING, false);
  std::string encoded_chunk_name;
  base::encode_to_hex(chunk_name, encoded_chunk_name);
  StoreChunkCallback cb1;
  std::string sig_req = cry_obj.AsymSign(cry_obj.Hash(keys.public_key() +
    sig_pub_key + encoded_chunk_name, "", crypto::STRING_STRING, true), "",
    keys.private_key(), crypto::STRING_STRING);
  crypto::RsaKeyPair otherkeys;
  otherkeys.GenerateKeys(1024);
  ASSERT_NE(keys.public_key(), otherkeys.public_key());
  pdclient->StoreChunk(chunk_name, chunk_content, otherkeys.public_key(),
    sig_pub_key, sig_req, maidsafe::DATA,
    boost::bind(&StoreChunkCallback::CallbackFunc, &cb1, _1));
  wait_result(&cb1, client_mutex);
  ASSERT_EQ(kad::kRpcResultFailure, cb1.result());
  cb1.Reset();
  ASSERT_NE(keys.public_key(), otherkeys.public_key());
  pdclient->StoreChunk(chunk_name, chunk_content, "bad key",
    sig_pub_key, sig_req, maidsafe::DATA,
    boost::bind(&StoreChunkCallback::CallbackFunc, &cb1, _1));
  wait_result(&cb1, client_mutex);
  ASSERT_EQ(kad::kRpcResultFailure, cb1.result());
  cb1.Reset();
  ASSERT_NE(keys.public_key(), otherkeys.public_key());
  pdclient->StoreChunk(chunk_name, chunk_content, keys.public_key(),
    sig_pub_key, "bad_sig_req", maidsafe::DATA,
    boost::bind(&StoreChunkCallback::CallbackFunc, &cb1, _1));
  wait_result(&cb1, client_mutex);
  ASSERT_EQ(kad::kRpcResultFailure, cb1.result());
  cb1.Reset();
  std::string data_incorrect_name = cry_obj.Hash("chunk_content", "",
    crypto::STRING_STRING, false);
  pdclient->StoreChunk(data_incorrect_name, chunk_content, keys.public_key(),
    sig_pub_key, sig_req, maidsafe::DATA,
    boost::bind(&StoreChunkCallback::CallbackFunc, &cb1, _1));
  wait_result(&cb1, client_mutex);
  ASSERT_EQ(kad::kRpcResultFailure, cb1.result());
}

TEST_F(PDClientTest, FUNC_KAD_StoreChunkNoContacts) {
  boost::recursive_mutex *mutex;
  mutex = new boost::recursive_mutex();
  base::CallLaterTimer *timer_;
  timer_ = new base::CallLaterTimer(mutex);
  boost::asio::io_service *io_service_;
  io_service_ = new boost::asio::io_service();
  std::string dir = "pdhome"+base::itos(62001+kNetworkSize+1);
  boost::filesystem::path *curr_dir;
  curr_dir = new boost::filesystem::path(dir, boost::filesystem::native);
  maidsafe::PDClient *pdclient1;
  pdclient1 = new maidsafe::PDClient(io_service_, *curr_dir, timer_, mutex);
  GeneralKadCallback cb1;
  std::vector<kad::Contact> bs;
  pdclient1->Join("", 62001+kNetworkSize+1, bs, false, boost::bind(
      &GeneralKadCallback::CallbackFunc, &cb1, _1));
  wait_result(&cb1, mutex);
  ASSERT_EQ(kad::kRpcResultFailure, cb1.result());
  std::string chunk_content = base::RandomString(250*1024);
  std::string chunk_name = cry_obj.Hash(chunk_content, "",
    crypto::STRING_STRING, false);
  std::string encoded_chunk_name;
  base::encode_to_hex(chunk_name, encoded_chunk_name);
  StoreChunkCallback cb2;
  std::string sig_req = cry_obj.AsymSign(cry_obj.Hash(keys.public_key() +
    sig_pub_key + encoded_chunk_name, "", crypto::STRING_STRING, true), "",
    keys.private_key(), crypto::STRING_STRING);
  pdclient1->StoreChunk(chunk_name, chunk_content, keys.public_key(),
    sig_pub_key, sig_req, maidsafe::DATA,
    boost::bind(&StoreChunkCallback::CallbackFunc, &cb2, _1));
  wait_result(&cb2, client_mutex);
  ASSERT_EQ(kad::kRpcResultFailure, cb2.result());
  pdclient1->Leave(boost::bind(&FakeCallback::CallbackFunc, &cb2, _1));
  base::sleep(1);
  delete pdclient1;
  delete timer_;
  delete mutex;
  delete io_service_;
  try {
    boost::filesystem::remove_all(*curr_dir);
  } catch(std::exception &e) {
    std::cout << "error: " << e.what() << std::endl;
  }
  delete curr_dir;
}

TEST_F(PDClientTest, FUNC_KAD_Store_LoadChunk) {
  std::string chunk_content = base::RandomString(250*1024);
  std::string chunk_name = cry_obj.Hash(chunk_content, "",
      crypto::STRING_STRING, false);
  std::string encoded_chunk_name;
  base::encode_to_hex(chunk_name, encoded_chunk_name);
  StoreChunkCallback cb1;
  std::string sig_req = cry_obj.AsymSign(cry_obj.Hash(keys.public_key() +
    sig_pub_key + encoded_chunk_name, "", crypto::STRING_STRING, true), "",
    keys.private_key(), crypto::STRING_STRING);
  pdclient->StoreChunk(chunk_name, chunk_content,
    keys.public_key(), sig_pub_key, sig_req, maidsafe::DATA,
    boost::bind(&StoreChunkCallback::CallbackFunc, &cb1, _1));
  wait_result(&cb1, client_mutex);
  ASSERT_EQ(kad::kRpcResultSuccess, cb1.result());
  // joining a new client to retrieve the chunk
  boost::recursive_mutex *mutex;
  mutex = new boost::recursive_mutex();
  base::CallLaterTimer *timer_;
  timer_ = new base::CallLaterTimer(mutex);
  boost::asio::io_service *io_service_;
  io_service_ = new boost::asio::io_service();
  std::string dir = "datastore" + base::itos(62001+1+kNetworkSize);
  boost::filesystem::path *curr_dir;
  curr_dir = new boost::filesystem::path(dir, boost::filesystem::native);
  maidsafe::PDClient *pdclient1;
  pdclient1 = new maidsafe::PDClient(io_service_, *curr_dir, timer_, mutex);
  GeneralKadCallback cb2;
  pdclient1->Join("", 62001 + kNetworkSize + 1, bootstrapping_nodes, false,
      boost::bind(&GeneralKadCallback::CallbackFunc, &cb2, _1));
  wait_result(&cb2, mutex);
  ASSERT_EQ(kad::kRpcResultSuccess, cb2.result());
  LoadChunkCallback cb3;
  pdclient1->LoadChunk(chunk_name,
      boost::bind(&LoadChunkCallback::CallbackFunc, &cb3, _1));
  wait_result(&cb3, client_mutex);
  ASSERT_EQ(kad::kRpcResultSuccess, cb3.result());
  ASSERT_EQ(chunk_content, cb3.content());
  pdclient1->Leave(boost::bind(&GeneralKadCallback::CallbackFunc, &cb2, _1));
  base::sleep(1);
  delete pdclient1;
  delete timer_;
  delete mutex;
  delete io_service_;
  try {
    boost::filesystem::remove_all(*curr_dir);
  } catch(std::exception &e) {
    std::cout << "error: " << e.what() << std::endl;
  }
  delete curr_dir;
}

TEST_F(PDClientTest, FUNC_KAD_BasicUpdateChunk) {
  std::string chunk_content = base::RandomString(250*1024);
  std::string chunk_name = cry_obj.Hash(chunk_content, "",
    crypto::STRING_STRING, false);
  std::string encoded_chunk_name;
  base::encode_to_hex(chunk_name, encoded_chunk_name);
  StoreChunkCallback cb1;
  std::string sig_req = cry_obj.AsymSign(cry_obj.Hash(keys.public_key() +
    sig_pub_key + encoded_chunk_name, "", crypto::STRING_STRING, true), "",
    keys.private_key(), crypto::STRING_STRING);
  pdclient->StoreChunk(chunk_name, chunk_content,
    keys.public_key(), sig_pub_key, sig_req, maidsafe::PDDIR_NOTSIGNED,
    boost::bind(&StoreChunkCallback::CallbackFunc, &cb1, _1));
  wait_result(&cb1, client_mutex);
  ASSERT_EQ(kad::kRpcResultSuccess, cb1.result());
  base::sleep(1); // make sure all chunk references are saved!
  std::string new_chunk_content = base::RandomString(250*1024);
  ASSERT_NE(chunk_content, new_chunk_content);
  UpdateChunkCallback cb2;
  pdclient->UpdateChunk(chunk_name, new_chunk_content,
    keys.public_key(), sig_pub_key, sig_req, maidsafe::PDDIR_NOTSIGNED,
    boost::bind(&UpdateChunkCallback::CallbackFunc, &cb2, _1));
  wait_result(&cb2, client_mutex);
  ASSERT_EQ(kad::kRpcResultSuccess, cb2.result())
        << "Failed to update chunk.";
  int copies = 0;
  kad::CheckChunkRequest params;
  std::string params_str(""), result_str("");
  params.set_chunkname(chunk_name);
  params.SerializeToString(&params_str);
  for (int i = 0; i < kNetworkSize; i++) {
    kad::CheckChunkResponse result;
    nodes[i]->RpcCheckChunk(params_str, "", &result_str);
    result.ParseFromString(result_str);
    if (result.result() == kad::kRpcResultSuccess) {
      copies ++;
      kad::LoadChunkRequest loadchunkreq;
      maidsafe::GetResponse loadres;
      loadchunkreq.set_chunkname(chunk_name);
      std::string loadchunkreq_str(""), loadchunkres_str("");
      loadchunkreq.SerializeToString(&loadchunkreq_str);
      nodes[i]->RpcLoadChunk(loadchunkreq_str, "", &loadchunkres_str);
      ASSERT_TRUE(loadres.ParseFromString(loadchunkres_str));
      ASSERT_EQ(kad::kRpcResultSuccess, loadres.result());
      ASSERT_EQ(new_chunk_content, loadres.content());
    }
  }
  ASSERT_LE(maidsafe::kMinChunkCopies, copies) << "Not enough copies updated.";
  FindCallback cb3;
  pdclient->FindValue(chunk_name,
    boost::bind(&FindCallback::CallbackFunc, &cb3, _1));
  wait_result(&cb3, client_mutex);
  ASSERT_EQ(kad::kRpcResultSuccess, cb3.result());
}

TEST_F(PDClientTest, FUNC_KAD_UpdateChunkWithChunkHolderLeave) {
  std::string chunk_content = base::RandomString(250*1024);
  std::string chunk_name = cry_obj.Hash(chunk_content, "",
    crypto::STRING_STRING, false);
  std::string encoded_chunk_name;
  base::encode_to_hex(chunk_name, encoded_chunk_name);
  StoreChunkCallback cb1;
  std::string sig_req = cry_obj.AsymSign(cry_obj.Hash(keys.public_key() +
    sig_pub_key + encoded_chunk_name, "", crypto::STRING_STRING, true), "",
    keys.private_key(), crypto::STRING_STRING);
  pdclient->StoreChunk(chunk_name, chunk_content,
    keys.public_key(), sig_pub_key, sig_req, maidsafe::PDDIR_NOTSIGNED,
    boost::bind(&StoreChunkCallback::CallbackFunc, &cb1, _1));
  wait_result(&cb1, client_mutex);
  ASSERT_EQ(kad::kRpcResultSuccess, cb1.result());
  // kill one node
  int copies = 0;
  int killed_node = 0;
  kad::CheckChunkRequest params;
  std::string params_str(""), result_str("");
  params.set_chunkname(chunk_name);
  params.SerializeToString(&params_str);
  for (int i = 0; i < kNetworkSize; i++) {
    nodes[i]->RpcCheckChunk(params_str, "", &result_str);
    kad::CheckChunkResponse result;
    result.ParseFromString(result_str);
    if (result.result() == kad::kRpcResultSuccess) {
      copies ++;
      kad::LoadChunkRequest loadchunkreq;
      maidsafe::GetResponse loadres;
      loadchunkreq.set_chunkname(chunk_name);
      std::string loadchunkreq_str(""), loadchunkres_str("");
      loadchunkreq.SerializeToString(&loadchunkreq_str);
      nodes[i]->RpcLoadChunk(loadchunkreq_str, "", &loadchunkres_str);
      loadres.ParseFromString(loadchunkres_str);
      ASSERT_EQ(kad::kRpcResultSuccess, loadres.result());
      ASSERT_EQ(chunk_content, loadres.content());
      GeneralKadCallback cbi;
      nodes[i]->Leave(boost::bind(&GeneralKadCallback::CallbackFunc, &cbi, _1));
      wait_result(&cbi, mutex[i]);
      killed_node = i;
      break;
    }
  }
  ASSERT_EQ(1, copies);
  base::sleep(1); // make sure all chunk references are saved!
  std::string new_chunk_content = base::RandomString(250*1024);
  ASSERT_NE(chunk_content, new_chunk_content);
  UpdateChunkCallback cb2;
  pdclient->UpdateChunk(chunk_name, new_chunk_content,
    keys.public_key(), sig_pub_key, sig_req, maidsafe::PDDIR_NOTSIGNED,
    boost::bind(&UpdateChunkCallback::CallbackFunc, &cb2, _1));
  wait_result(&cb2, client_mutex);
  ASSERT_EQ(kad::kRpcResultSuccess, cb2.result())
        << "Failed to update chunk.";
  copies = 0;
  //params, result;
  for (int i = 0; i < kNetworkSize; i++) {
    nodes[i]->RpcCheckChunk(params_str, "", &result_str);
    kad::CheckChunkResponse result;
    result.ParseFromString(result_str);
    if (i != killed_node
        && result.result() == kad::kRpcResultSuccess) {
      copies ++;
      kad::LoadChunkRequest loadchunkreq;
      maidsafe::GetResponse loadres;
      loadchunkreq.set_chunkname(chunk_name);
      std::string loadchunkreq_str(""), loadchunkres_str("");
      loadchunkreq.SerializeToString(&loadchunkreq_str);
      nodes[i]->RpcLoadChunk(loadchunkreq_str, "", &loadchunkres_str);
      loadres.ParseFromString(loadchunkres_str);
      ASSERT_EQ(kad::kRpcResultSuccess, loadres.result());
      ASSERT_EQ(new_chunk_content, loadres.content());
    }
  }
  ASSERT_LE(maidsafe::kMinChunkCopies-1, copies);
  FindCallback cb3;
  pdclient->FindValue(chunk_name,
    boost::bind(&FindCallback::CallbackFunc, &cb3, _1));
  wait_result(&cb3, client_mutex);
  ASSERT_EQ(kad::kRpcResultSuccess, cb3.result());
}

TEST_F(PDClientTest, FUNC_KAD_UpdateMorethanMinCopiesWithHoldersOff) {
  std::string chunk_content = base::RandomString(250*1024);
  std::string chunk_name = cry_obj.Hash(chunk_content, "",
    crypto::STRING_STRING, false);
  std::string encoded_chunk_name;
  base::encode_to_hex(chunk_name, encoded_chunk_name);
  kad::StoreChunkRequest args;
  StoreResponse result;
  std::string args_str(""), result_str("");
  args.set_chunkname(chunk_name);
  args.set_content(chunk_content);
  args.set_public_key(keys.public_key());
  args.set_signed_public_key(sig_pub_key);
  std::string sig_req = cry_obj.AsymSign(cry_obj.Hash(keys.public_key() +
    sig_pub_key + encoded_chunk_name, "", crypto::STRING_STRING, true), "",
    keys.private_key(), crypto::STRING_STRING);
  args.set_signed_request(sig_req);
  args.set_data_type(maidsafe::PDDIR_NOTSIGNED);
  args.SerializeToString(&args_str);
  nodes[1]->RpcStoreChunk(args_str, "", &result_str);
  base::sleep(3);
  ASSERT_TRUE(result.ParseFromString(result_str));
  ASSERT_EQ(kad::kRpcResultSuccess, result.result());
  nodes[2]->RpcStoreChunk(args_str, "", &result_str);
  base::sleep(3);
  ASSERT_TRUE(result.ParseFromString(result_str));
  ASSERT_EQ(kad::kRpcResultSuccess, result.result());
  nodes[4]->RpcStoreChunk(args_str, "", &result_str);
  base::sleep(3);
  ASSERT_TRUE(result.ParseFromString(result_str));
  ASSERT_EQ(kad::kRpcResultSuccess, result.result());
  nodes[6]->RpcStoreChunk(args_str, "", &result_str);
  base::sleep(3);
  ASSERT_TRUE(result.ParseFromString(result_str));
  ASSERT_EQ(kad::kRpcResultSuccess, result.result());
  nodes[7]->RpcStoreChunk(args_str, "", &result_str);
  base::sleep(3);
  ASSERT_TRUE(result.ParseFromString(result_str));
  ASSERT_EQ(kad::kRpcResultSuccess, result.result());
  nodes[8]->RpcStoreChunk(args_str, "", &result_str);
  base::sleep(3);
  ASSERT_TRUE(result.ParseFromString(result_str));
  ASSERT_EQ(kad::kRpcResultSuccess, result.result());
  nodes[9]->RpcStoreChunk(args_str, "", &result_str);
  base::sleep(3);
  ASSERT_TRUE(result.ParseFromString(result_str));
  ASSERT_EQ(kad::kRpcResultSuccess, result.result());
  base::sleep(1);  // make sure all chunk references are saved!
  FindCallback cb1;
  nodes[3]->FindValue(chunk_name,
      boost::bind(&FindCallback::CallbackFunc, &cb1, _1));
  wait_result(&cb1, mutex[3]);
  ASSERT_EQ(kad::kRpcResultSuccess, cb1.result());
  ASSERT_EQ(7, cb1.values().size());
  std::string data = cb1.values().front();
  std::string new_chunk_content = base::RandomString(250*1024);
  ASSERT_NE(chunk_content, new_chunk_content);
  UpdateChunkCallback cb2;
  pdclient->UpdateChunk(chunk_name, new_chunk_content,
    keys.public_key(), sig_pub_key, sig_req, maidsafe::PDDIR_NOTSIGNED,
    boost::bind(&UpdateChunkCallback::CallbackFunc, &cb2, _1));
  wait_result(&cb2, client_mutex);
  ASSERT_EQ(kad::kRpcResultSuccess, cb2.result())
      << "Failed to update chunk.";
  int copies = 0;
  kad::CheckChunkRequest params;
  std::string params_str("");
  params.set_chunkname(chunk_name);
  params.SerializeToString(&params_str);
  for (int i = 0; i < kNetworkSize; i++) {
    kad::CheckChunkResponse result;
    nodes[i]->RpcCheckChunk(params_str, "", &result_str);
    result.ParseFromString(result_str);
    if (result.result() == kad::kRpcResultSuccess) {
      copies++;
      kad::LoadChunkRequest loadchunkreq;
      maidsafe::GetResponse loadres;
      loadchunkreq.set_chunkname(chunk_name);
      std::string loadchunkreq_str(""), loadchunkres_str("");
      loadchunkreq.SerializeToString(&loadchunkreq_str);
      nodes[i]->RpcLoadChunk(loadchunkreq_str, "", &loadchunkres_str);
      loadres.ParseFromString(loadchunkres_str);
      ASSERT_EQ(kad::kRpcResultSuccess, loadres.result());
      ASSERT_EQ(new_chunk_content, loadres.content());
    }
  }
  ASSERT_LE(7, copies);
  FindCallback cb3;
  pdclient->FindValue(chunk_name,
    boost::bind(&FindCallback::CallbackFunc, &cb3, _1));
  wait_result(&cb3, client_mutex);
  ASSERT_EQ(kad::kRpcResultSuccess, cb3.result());
  // kill some nodes
  GeneralKadCallback cb5;
  nodes[1]->Leave(boost::bind(&GeneralKadCallback::CallbackFunc, &cb5, _1));
  wait_result(&cb5, mutex[1]);
  GeneralKadCallback cb6;
  nodes[8]->Leave(boost::bind(&GeneralKadCallback::CallbackFunc, &cb6, _1));
  wait_result(&cb6, mutex[8]);
  // update the chunk again
  base::sleep(1);  // make sure all chunk references are saved!
  std::string new_chunk_content1 = base::RandomString(250*1024);
  ASSERT_NE(new_chunk_content, new_chunk_content1);
  ASSERT_NE(chunk_content, new_chunk_content1);
  UpdateChunkCallback cb7;
  pdclient->UpdateChunk(chunk_name, new_chunk_content1,
    keys.public_key(), sig_pub_key, sig_req, maidsafe::PDDIR_NOTSIGNED,
    boost::bind(&UpdateChunkCallback::CallbackFunc, &cb7, _1));
  wait_result(&cb7, client_mutex);
  ASSERT_EQ(kad::kRpcResultSuccess, cb7.result())
      << "Failed to update chunk.";
  copies = 0;
  for (int i = 0; i < kNetworkSize; i++) {
    kad::CheckChunkResponse result;
    nodes[i]->RpcCheckChunk(params_str, "", &result_str);
    result.ParseFromString(result_str);
    if (i != 1 && i != 8
        && result.result() == kad::kRpcResultSuccess) {
      copies ++;
      kad::LoadChunkRequest loadchunkreq;
      maidsafe::GetResponse loadres;
      loadchunkreq.set_chunkname(chunk_name);
      std::string loadchunkreq_str(""), loadchunkres_str("");
      loadchunkreq.SerializeToString(&loadchunkreq_str);
      nodes[i]->RpcLoadChunk(loadchunkreq_str, "", &loadchunkres_str);
      ASSERT_TRUE(loadres.ParseFromString(loadchunkres_str));
      ASSERT_EQ(kad::kRpcResultSuccess, loadres.result());
      ASSERT_EQ(new_chunk_content1, loadres.content());
    }
  }
  ASSERT_LE(5, copies);
}

TEST_F(PDClientTest, FUNC_KAD_StoreChunkSystemPacket) {
  packethandler::GenericPacket gp;
  gp.set_data(base::RandomString(4096));
  gp.set_signature(cry_obj.AsymSign(gp.data(), "", keys.private_key(),
    crypto::STRING_STRING));
  std::string chunk_content;
  gp.SerializeToString(&chunk_content);;
  std::string chunk_name = cry_obj.Hash(chunk_content, "",
      crypto::STRING_STRING, false);
  std::string encoded_chunk_name;
  base::encode_to_hex(chunk_name, encoded_chunk_name);
  StoreChunkCallback cb1;
  std::string sig_req = cry_obj.AsymSign(cry_obj.Hash(keys.public_key() +
    sig_pub_key + encoded_chunk_name, "", crypto::STRING_STRING, true), "",
    keys.private_key(), crypto::STRING_STRING);
  pdclient->StoreChunk(chunk_name, chunk_content,
    keys.public_key(), sig_pub_key, sig_req, maidsafe::SYSTEM_PACKET,
    boost::bind(&StoreChunkCallback::CallbackFunc, &cb1, _1));
  wait_result(&cb1, client_mutex);
  ASSERT_EQ(kad::kRpcResultSuccess, cb1.result());
  // joining a new client to retrieve the chunk
  boost::recursive_mutex *mutex;
  mutex = new boost::recursive_mutex();
  base::CallLaterTimer *timer_;
  timer_ = new base::CallLaterTimer(mutex);
  boost::asio::io_service *io_service_;
  io_service_ = new boost::asio::io_service();
  std::string dir = "datastore" + base::itos(62001+1+kNetworkSize);
  boost::filesystem::path *curr_dir;
  curr_dir = new boost::filesystem::path(dir, boost::filesystem::native);
  maidsafe::PDClient *pdclient1;
  pdclient1 = new maidsafe::PDClient(io_service_, *curr_dir, timer_, mutex);
  GeneralKadCallback cb2;
  pdclient1->Join("", 62001 + kNetworkSize + 1, bootstrapping_nodes, false,
      boost::bind(&GeneralKadCallback::CallbackFunc, &cb2, _1));
  wait_result(&cb2, mutex);
  ASSERT_EQ(kad::kRpcResultSuccess, cb2.result());
  LoadChunkCallback cb3;
  pdclient1->LoadChunk(chunk_name,
      boost::bind(&LoadChunkCallback::CallbackFunc, &cb3, _1));
  wait_result(&cb3, client_mutex);
  ASSERT_EQ(kad::kRpcResultSuccess, cb3.result());
  ASSERT_EQ(chunk_content, cb3.content());
  packethandler::GenericPacket gp_rec;
  ASSERT_TRUE(gp_rec.ParseFromString(cb3.content()));
  ASSERT_EQ(gp.data(), gp_rec.data());
  ASSERT_EQ(gp.signature(), gp_rec.signature());
  pdclient1->Leave(boost::bind(&GeneralKadCallback::CallbackFunc, &cb2, _1));
  base::sleep(1);
  delete pdclient1;
  delete timer_;
  delete mutex;
  delete io_service_;
  try {
    boost::filesystem::remove_all(*curr_dir);
  } catch(std::exception &e) {
    std::cout << "error: " << e.what() << std::endl;
  }
  delete curr_dir;
}

TEST_F(PDClientTest, FUNC_KAD_StoreChunkSystemPacket_InvalidPacket) {
  packethandler::GenericPacket gp;
  gp.set_data(base::RandomString(4096));
  gp.set_signature(cry_obj.AsymSign(gp.data(), "", keys.private_key(),
    crypto::STRING_STRING));
  std::string chunk_content;
  gp.SerializeToString(&chunk_content);;
  std::string chunk_name = cry_obj.Hash(chunk_content, "",
      crypto::STRING_STRING, false);
  std::string encoded_chunk_name;
  base::encode_to_hex(chunk_name, encoded_chunk_name);
  StoreChunkCallback cb1;
  std::string sig_req = cry_obj.AsymSign(cry_obj.Hash(keys.public_key() +
    sig_pub_key + encoded_chunk_name, "", crypto::STRING_STRING, true), "",
    keys.private_key(), crypto::STRING_STRING);
  pdclient->StoreChunk(chunk_name, base::RandomString(4096),
    keys.public_key(), sig_pub_key, sig_req, maidsafe::SYSTEM_PACKET,
    boost::bind(&StoreChunkCallback::CallbackFunc, &cb1, _1));
  wait_result(&cb1, client_mutex);
  ASSERT_EQ(kad::kRpcResultFailure, cb1.result());
  cb1.Reset();
  FindCallback cb2;
  pdclient->FindValue(chunk_name,
    boost::bind(&FindCallback::CallbackFunc, &cb2, _1));
  wait_result(&cb2, client_mutex);
  ASSERT_EQ(kad::kRpcResultFailure, cb2.result());
  cb2.Reset();
  pdclient->StoreChunk(chunk_name, chunk_content,
    "incorrect pub key", sig_pub_key, sig_req, maidsafe::SYSTEM_PACKET,
    boost::bind(&StoreChunkCallback::CallbackFunc, &cb1, _1));
    wait_result(&cb1, client_mutex);
  ASSERT_EQ(kad::kRpcResultFailure, cb1.result());
  cb1.Reset();
  pdclient->FindValue(chunk_name,
    boost::bind(&FindCallback::CallbackFunc, &cb2, _1));
  wait_result(&cb2, client_mutex);
  ASSERT_EQ(kad::kRpcResultFailure, cb2.result());
  cb1.Reset();
  pdclient->StoreChunk(chunk_name, base::RandomString(4096),
    keys.public_key(), sig_pub_key, sig_req, maidsafe::BUFFER_PACKET,
    boost::bind(&StoreChunkCallback::CallbackFunc, &cb1, _1));
  wait_result(&cb1, client_mutex);
  ASSERT_EQ(kad::kRpcResultFailure, cb1.result());
  cb1.Reset();
  pdclient->StoreChunk(chunk_name, base::RandomString(4096),
    keys.public_key(), sig_pub_key, sig_req, maidsafe::PDDIR_SIGNED,
    boost::bind(&StoreChunkCallback::CallbackFunc, &cb1, _1));
  wait_result(&cb1, client_mutex);
  ASSERT_EQ(kad::kRpcResultFailure, cb1.result());
  cb1.Reset();
  pdclient->StoreChunk(chunk_name, chunk_content,
    keys.public_key(), sig_pub_key, sig_req, maidsafe::BUFFER_PACKET,
    boost::bind(&StoreChunkCallback::CallbackFunc, &cb1, _1));
  wait_result(&cb1, client_mutex);
  ASSERT_EQ(kad::kRpcResultFailure, cb1.result());
}

TEST_F(PDClientTest, FUNC_KAD_StoreSignedPDDir) {
  packethandler::GenericPacket gp;
  gp.set_data(base::RandomString(4096));
  gp.set_signature(cry_obj.AsymSign(gp.data(), "", keys.private_key(),
    crypto::STRING_STRING));
  std::string chunk_content;
  gp.SerializeToString(&chunk_content);;
  std::string chunk_name = cry_obj.Hash("PD_DIR", "",
      crypto::STRING_STRING, false);
  std::string encoded_chunk_name;
  base::encode_to_hex(chunk_name, encoded_chunk_name);
  StoreChunkCallback cb1;
  std::string sig_req = cry_obj.AsymSign(cry_obj.Hash(keys.public_key() +
    sig_pub_key + encoded_chunk_name, "", crypto::STRING_STRING, true), "",
    keys.private_key(), crypto::STRING_STRING);
  pdclient->StoreChunk(chunk_name, chunk_content,
    keys.public_key(), sig_pub_key, sig_req, maidsafe::PDDIR_SIGNED,
    boost::bind(&StoreChunkCallback::CallbackFunc, &cb1, _1));
  wait_result(&cb1, client_mutex);
  ASSERT_EQ(kad::kRpcResultSuccess, cb1.result());
  LoadChunkCallback cb3;
  pdclient->LoadChunk(chunk_name,
      boost::bind(&LoadChunkCallback::CallbackFunc, &cb3, _1));
  wait_result(&cb3, client_mutex);
  ASSERT_EQ(kad::kRpcResultSuccess, cb3.result());
  ASSERT_EQ(chunk_content, cb3.content());
  packethandler::GenericPacket gp_rec;
  ASSERT_TRUE(gp_rec.ParseFromString(cb3.content()));
  ASSERT_EQ(gp.data(), gp_rec.data());
  ASSERT_EQ(gp.signature(), gp_rec.signature());
}

TEST_F(PDClientTest, FUNC_KAD_StoreUnSignedPDDir) {
  std::string chunk_content = base::RandomString(4096);
  std::string chunk_name = cry_obj.Hash("PD_DIR", "",
      crypto::STRING_STRING, false);
  std::string encoded_chunk_name;
  base::encode_to_hex(chunk_name, encoded_chunk_name);
  StoreChunkCallback cb1;
  std::string sig_req = cry_obj.AsymSign(cry_obj.Hash(keys.public_key() +
    sig_pub_key + encoded_chunk_name, "", crypto::STRING_STRING, true), "",
    keys.private_key(), crypto::STRING_STRING);
  pdclient->StoreChunk(chunk_name, chunk_content,
    keys.public_key(), sig_pub_key, sig_req, maidsafe::PDDIR_NOTSIGNED,
    boost::bind(&StoreChunkCallback::CallbackFunc, &cb1, _1));
  wait_result(&cb1, client_mutex);
  ASSERT_EQ(kad::kRpcResultSuccess, cb1.result());
  base::sleep(1);
  LoadChunkCallback cb3;
  pdclient->LoadChunk(chunk_name,
      boost::bind(&LoadChunkCallback::CallbackFunc, &cb3, _1));
  wait_result(&cb3, client_mutex);
  ASSERT_EQ(kad::kRpcResultSuccess, cb3.result());
  ASSERT_EQ(chunk_content, cb3.content());
}

TEST_F(PDClientTest, FUNC_KAD_StoreBUFFER_PACKET) {
  packethandler::BufferPacket bp;
  packethandler::GenericPacket *gp = bp.add_owner_info();
  gp->set_data(base::RandomString(4096));
  gp->set_signature(cry_obj.AsymSign(gp->data(), "", keys.private_key(),
    crypto::STRING_STRING));
  std::string chunk_content;
  bp.SerializeToString(&chunk_content);;
  std::string chunk_name = cry_obj.Hash("BUFERPACKET", "",
      crypto::STRING_STRING, false);
  std::string encoded_chunk_name;
  base::encode_to_hex(chunk_name, encoded_chunk_name);
  StoreChunkCallback cb1;
  std::string sig_req = cry_obj.AsymSign(cry_obj.Hash(keys.public_key() +
    sig_pub_key + encoded_chunk_name, "", crypto::STRING_STRING, true), "",
    keys.private_key(), crypto::STRING_STRING);
  pdclient->StoreChunk(chunk_name, chunk_content,
    keys.public_key(), sig_pub_key, sig_req, maidsafe::BUFFER_PACKET,
    boost::bind(&StoreChunkCallback::CallbackFunc, &cb1, _1));
  wait_result(&cb1, client_mutex);
  ASSERT_EQ(kad::kRpcResultSuccess, cb1.result());
  base::sleep(1);
  LoadChunkCallback cb3;
  pdclient->LoadChunk(chunk_name,
      boost::bind(&LoadChunkCallback::CallbackFunc, &cb3, _1));
  wait_result(&cb3, client_mutex);
  ASSERT_EQ(kad::kRpcResultSuccess, cb3.result());
  ASSERT_EQ(chunk_content, cb3.content());
  packethandler::BufferPacket gp_rec;
  ASSERT_TRUE(gp_rec.ParseFromString(cb3.content()));
}

TEST_F(PDClientTest, FUNC_KAD_UpdateSignedPDDir) {
  packethandler::GenericPacket gp;
  std::string orig_content = base::RandomString(4096);
  gp.set_data(orig_content);
  gp.set_signature(cry_obj.AsymSign(gp.data(), "", keys.private_key(),
    crypto::STRING_STRING));
  std::string chunk_content;
  gp.SerializeToString(&chunk_content);;
  std::string chunk_name = cry_obj.Hash("PD_DIR", "",
      crypto::STRING_STRING, false);
  std::string encoded_chunk_name;
  base::encode_to_hex(chunk_name, encoded_chunk_name);
  StoreChunkCallback cb1;
  std::string sig_req = cry_obj.AsymSign(cry_obj.Hash(keys.public_key() +
    sig_pub_key + encoded_chunk_name, "", crypto::STRING_STRING, true), "",
    keys.private_key(), crypto::STRING_STRING);
  pdclient->StoreChunk(chunk_name, chunk_content,
    keys.public_key(), sig_pub_key, sig_req, maidsafe::PDDIR_SIGNED,
    boost::bind(&StoreChunkCallback::CallbackFunc, &cb1, _1));
  wait_result(&cb1, client_mutex);
  ASSERT_EQ(kad::kRpcResultSuccess, cb1.result());
  base::sleep(1);
  LoadChunkCallback cb3;
  pdclient->LoadChunk(chunk_name,
      boost::bind(&LoadChunkCallback::CallbackFunc, &cb3, _1));
  wait_result(&cb3, client_mutex);
  ASSERT_EQ(kad::kRpcResultSuccess, cb3.result());
  ASSERT_EQ(chunk_content, cb3.content());
  packethandler::GenericPacket gp_rec;
  ASSERT_TRUE(gp_rec.ParseFromString(cb3.content()));
  ASSERT_EQ(gp.data(), gp_rec.data());
  ASSERT_EQ(gp.signature(), gp_rec.signature());

  gp.Clear();
  gp.set_data(base::RandomString(4096));
  gp.set_signature(cry_obj.AsymSign(gp.data(), "", keys.private_key(),
    crypto::STRING_STRING));
  gp.SerializeToString(&chunk_content);
  cb1.Reset();
  pdclient->UpdateChunk(chunk_name, "not a serialised generic packet",
    keys.public_key(), sig_pub_key, sig_req, maidsafe::PDDIR_SIGNED,
    boost::bind(&StoreChunkCallback::CallbackFunc, &cb1, _1));
  wait_result(&cb1, client_mutex);
  ASSERT_EQ(kad::kRpcResultFailure, cb1.result());
  cb1.Reset();
  pdclient->UpdateChunk(chunk_name, chunk_content,
    keys.public_key(), sig_pub_key, sig_req, maidsafe::PDDIR_SIGNED,
    boost::bind(&StoreChunkCallback::CallbackFunc, &cb1, _1));
  wait_result(&cb1, client_mutex);
  ASSERT_EQ(kad::kRpcResultSuccess, cb1.result());
  cb1.Reset();
  cb3.Reset();
  pdclient->LoadChunk(chunk_name,
      boost::bind(&LoadChunkCallback::CallbackFunc, &cb3, _1));
  wait_result(&cb3, client_mutex);
  ASSERT_EQ(kad::kRpcResultSuccess, cb3.result());
  ASSERT_EQ(chunk_content, cb3.content());
  gp_rec.Clear();
  ASSERT_TRUE(gp_rec.ParseFromString(cb3.content()));
  ASSERT_EQ(gp.data(), gp_rec.data());
  ASSERT_EQ(gp.signature(), gp_rec.signature());
  ASSERT_NE(orig_content, gp_rec.data());
}

TEST_F(PDClientTest, FUNC_KAD_UpdateBufferPacket) {
  std::string owner_id("Juan U. Smer");
  std::string bufferpacketname = cry_obj.Hash\
    (owner_id+"BUFFER","", crypto::STRING_STRING, true);
  packethandler::BufferPacket buffer_packet;
  packethandler::GenericPacket *ser_owner_info= buffer_packet.add_owner_info();
  packethandler::BufferPacketInfo buffer_packet_info;
  buffer_packet_info.set_owner(owner_id);
  buffer_packet_info.set_ownerpublickey(keys.public_key());
  buffer_packet_info.set_online(false);
  std::string ser_info;
  buffer_packet_info.SerializeToString(&ser_info);
  ser_owner_info->set_data(ser_info);
  ser_owner_info->set_signature(cry_obj.AsymSign(ser_info,"",keys.private_key(),
    crypto::STRING_STRING));
  std::string chunk_content;
  buffer_packet.SerializeToString(&chunk_content);
  std::string ser_bp = chunk_content;
  std::string sig_req = cry_obj.AsymSign(cry_obj.Hash(keys.public_key()+
    sig_pub_key+bufferpacketname, "", crypto::STRING_STRING, true),"",
    keys.private_key(), crypto::STRING_STRING);
  StoreChunkCallback cb1;
  std::string chunk_name;
  base::decode_from_hex(bufferpacketname, chunk_name);
  pdclient->StoreChunk(chunk_name, chunk_content,
    keys.public_key(), sig_pub_key, sig_req, maidsafe::BUFFER_PACKET,
    boost::bind(&StoreChunkCallback::CallbackFunc, &cb1, _1));
  wait_result(&cb1, client_mutex);
  ASSERT_EQ(kad::kRpcResultSuccess, cb1.result());
  cb1.Reset();
  // sleeping one second to allow chunk references to be stored
  base::sleep(1);
  LoadChunkCallback cb2;
  pdclient->LoadChunk(chunk_name,
    boost::bind(&LoadChunkCallback::CallbackFunc, &cb2, _1));
  wait_result(&cb2, client_mutex);
  ASSERT_EQ(kad::kRpcResultSuccess, cb2.result());
  ASSERT_EQ(chunk_content, cb2.content());
  cb2.Reset();

  std::string key("AESkey");
  packethandler::BufferPacketMessage bpmsg;
  bpmsg.set_sender_id("sender");
  bpmsg.set_rsaenc_key(cry_obj.AsymEncrypt(key, "", keys.public_key(),
    crypto::STRING_STRING));
  cry_obj.set_symm_algorithm("AES_256");
  bpmsg.set_aesenc_message(cry_obj.SymmEncrypt("test msg", "",
    crypto::STRING_STRING, key));
  bpmsg.set_type(packethandler::ADD_CONTACT_RQST);
  bpmsg.set_sender_public_key(keys.public_key());
  std::string ser_bpmsg;
  bpmsg.SerializeToString(&ser_bpmsg);
  packethandler::GenericPacket bpmsg_gp;
  bpmsg_gp.set_data(ser_bpmsg);
  bpmsg_gp.set_signature(cry_obj.AsymSign(ser_bpmsg, "", keys.private_key(),
    crypto::STRING_STRING));
  std::string ser_bpmsg_gp;
  bpmsg_gp.SerializeToString(&ser_bpmsg_gp);
  //Expected result for GetMsgs
  packethandler::ValidatedBufferPacketMessage val_msg;
  val_msg.set_index(bpmsg.rsaenc_key());
  val_msg.set_message(bpmsg.aesenc_message());
  val_msg.set_sender(bpmsg.sender_id());
  val_msg.set_type(bpmsg.type());
  std::string ser_val_msg;
  val_msg.SerializeToString(&ser_val_msg);

  UpdateChunkCallback cb3;
  //Updating bp info not owner and invalid owner info data
  crypto::RsaKeyPair newkeys;
  newkeys.GenerateKeys(1024);
  std::string new_sig_pk = cry_obj.AsymSign(newkeys.public_key(), "",
    newkeys.private_key(), crypto::STRING_STRING);
  std::string new_sig_req = cry_obj.AsymSign(cry_obj.Hash(newkeys.public_key()+
    new_sig_pk+bufferpacketname, "", crypto::STRING_STRING, true),"",
    newkeys.private_key(), crypto::STRING_STRING);
  pdclient->UpdateChunk(chunk_name, ser_bpmsg_gp,
    newkeys.public_key(), new_sig_pk, new_sig_req, maidsafe::BUFFER_PACKET_INFO,
    boost::bind(&UpdateChunkCallback::CallbackFunc, &cb3, _1));
  wait_result(&cb3, client_mutex);
  ASSERT_EQ(kad::kRpcResultFailure, cb3.result());
  cb3.Reset();
  //Adding a message invalid Req
  pdclient->UpdateChunk(chunk_name, ser_bpmsg_gp,
    keys.public_key(), "inv_pub_key", sig_req, maidsafe::BUFFER_PACKET_MESSAGE,
    boost::bind(&UpdateChunkCallback::CallbackFunc, &cb3, _1));
  wait_result(&cb3, client_mutex);
  ASSERT_EQ(kad::kRpcResultFailure, cb3.result());
  cb3.Reset();

  pdclient->UpdateChunk(chunk_name, ser_bpmsg_gp,
    keys.public_key(), sig_pub_key, sig_req, maidsafe::BUFFER_PACKET_MESSAGE,
    boost::bind(&UpdateChunkCallback::CallbackFunc, &cb3, _1));
  wait_result(&cb3, client_mutex);
  ASSERT_EQ(kad::kRpcResultSuccess, cb3.result());
  pdclient->LoadChunk(chunk_name,
    boost::bind(&LoadChunkCallback::CallbackFunc, &cb2, _1));
  wait_result(&cb2, client_mutex);
  ASSERT_EQ(kad::kRpcResultSuccess, cb2.result());
  packethandler::BufferPacket rec_bp;
  ASSERT_TRUE(rec_bp.ParseFromString(cb2.content()));
  ASSERT_EQ(1, rec_bp.messages_size());
  GetMsgsCallback cb4;
  pdclient->GetMessages(chunk_name, keys.public_key(), sig_pub_key,
    boost::bind(&GetMsgsCallback::CallbackFunc, &cb4, _1));
  wait_result(&cb4, client_mutex);
  ASSERT_EQ(kad::kRpcResultSuccess, cb4.result());
  ASSERT_EQ(1, cb4.messages().size());
  ASSERT_EQ(ser_val_msg, cb4.messages().front());
  //Clearing Msgs
  DeleteChunkCallback cb5;
  pdclient->DeleteChunk(chunk_name, keys.public_key(),
    sig_pub_key, sig_req, maidsafe::BUFFER_PACKET_MESSAGE,
    boost::bind(&DeleteChunkCallback::CallbackFunc, &cb5, _1));
  wait_result(&cb5, client_mutex);
  ASSERT_EQ(kad::kRpcResultSuccess, cb5.result());
  cb4.Reset();
  pdclient->GetMessages(chunk_name, keys.public_key(), sig_pub_key,
    boost::bind(&GetMsgsCallback::CallbackFunc, &cb4, _1));
  wait_result(&cb4, client_mutex);
  ASSERT_EQ(kad::kRpcResultSuccess, cb4.result());
  ASSERT_EQ(0, cb4.messages().size());
}*/
