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
 *  Created on: Dec 17, 2008
 *      Author: haiyang
 */

/*
#include <boost/bind.hpp>
#include <boost/function.hpp>
#include <boost/cstdint.hpp>
#include <boost/thread/recursive_mutex.hpp>
#include <gtest/gtest.h>
#include <vector>
#include <map>
#include <exception>
#include <maidsafe/crypto.h>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <maidsafe/utils.h>
#include "maidsafe/vault/vaultdaemon.h"


const int kNetworkSize = 20;

namespace maidsafe {

class VaultDaemonTest: public testing::Test {
 protected:
  VaultDaemonTest() {
    nodes = new kad::KNode *[kNetworkSize];
    io_services = new boost::asio::io_service *[kNetworkSize];
    db = new boost::filesystem::path *[kNetworkSize];
    timers = new base::CallLaterTimer *[kNetworkSize];
    mutex = new boost::recursive_mutex *[kNetworkSize];
    cry_obj.set_symm_algorithm(crypto::AES_256);
    cry_obj.set_hash_algorithm(crypto::SHA_512);
    crypto::RsaKeyPair keys;
    keys.GenerateKeys(1024);
    pub_key = keys.public_key();
    priv_key = keys.private_key();
    sig_pub_key = cry_obj.AsymSign(pub_key, "", priv_key,
      crypto::STRING_STRING);
  }
  virtual ~VaultDaemonTest() {
    delete [] nodes;
    delete [] db;
    delete [] timers;
    delete [] mutex;
    delete [] io_services;
    // delete io_services;
    bootstrapping_nodes.clear();
  }
  virtual void SetUp() {
    // start the bootstrapping node
    mutex[0] = new boost::recursive_mutex();
    timers[0] = new base::CallLaterTimer(mutex[0]);
    io_services[0] = new boost::asio::io_service();
    db[0] = new boost::filesystem::path("pdhome"+base::itos(62001));
    nodes[0] = new kad::KNode(io_services[0], *db[0], timers[0], mutex[0],
        kad::VAULT);
    cb.Reset();
    std::vector<kad::Contact> bs_nodes;
    nodes[0]->Join("", 62001, bs_nodes, false,  boost::bind(\
        &GeneralKadCallback::CallbackFunc, &cb, _1));
    wait_result(&cb, mutex[0]);
    EXPECT_EQ(kad::kRpcResultSuccess, cb.result());
    kad::Contact bs_contact(kad::vault_random_id(), nodes[0]->host_ip_,
        nodes[0]->host_port_);
    bootstrapping_nodes.push_back(bs_contact);
    // start the rest of the nodes
    for (int i = 1; i < kNetworkSize; i++) {
      mutex[i] = new boost::recursive_mutex();
      timers[i] = new base::CallLaterTimer(mutex[i]);
      io_services[i] = new boost::asio::io_service();
      db[i] = new boost::filesystem::path("pdhome"+base::itos(62001+i));
      nodes[i] = new kad::KNode(io_services[i], *db[i], timers[i], mutex[i],
          kad::VAULT);
      cb.Reset();
      nodes[i]->Join("", 62001+i, bootstrapping_nodes, false, boost::bind(\
          &GeneralKadCallback::CallbackFunc, &cb, _1));
      wait_result(&cb, mutex[i]);
      EXPECT_EQ(kad::kRpcResultFailure, cb.result());
    }
  }

  virtual void TearDown() {
    for (int i = 0; i < kNetworkSize; i++) {
      timers[i]->CancelAll();
      cb.Reset();
      nodes[i]->Leave(boost::bind(&GeneralKadCallback::CallbackFunc, &cb, _1));
      wait_result(&cb, mutex[i]);
      EXPECT_EQ(kad::kRpcResultFailure, cb.result());
      delete nodes[i];
      delete timers[i];
      delete mutex[i];
      delete io_services[i];
      try {
        boost::filesystem::remove_all(*db[i]);
      }
      catch(std::exception &) {}
      delete db[i];
    }
  }

  std::vector<kad::Contact> bootstrapping_nodes;
  boost::asio::io_service **io_services;
  kad::KNode **nodes;
  boost::filesystem::path **db;
  base::CallLaterTimer **timers;
  boost::recursive_mutex **mutex;
  crypto::Crypto cry_obj;
  std::string priv_key, pub_key, sig_pub_key;
  GeneralKadCallback cb;
};

TEST_F(VaultDaemonTest, BEH_KAD_EmptyChunkStorage) {
  int rand_node = base::random_32bit_uinteger()%20;
  kad::VaultDaemon daemon(nodes[rand_node]);
  GeneralKadCallback cb;
  daemon.SyncVault(boost::bind(&GeneralKadCallback::CallbackFunc, &cb, _1));
  wait_result(&cb, mutex[rand_node]);
  ASSERT_EQ(kad::kRpcResultFailure, cb.result());
}

TEST_F(VaultDaemonTest, FUNC_KAD_NoPartners) {
  int rand_node = base::random_32bit_uinteger()%20;
  // store a chunk
  std::string chunk_content = base::RandomString(250*1024);
  std::string chunk_name = cry_obj.Hash(chunk_content, "",
    crypto::STRING_STRING, false);
  std::string enc_chunk_name("");
  base::encode_to_hex(chunk_name, &enc_chunk_name);
  std::string result("");
  std::string sender_info("");
  kad::StoreChunkRequest args;
  args.set_chunkname(chunk_name);
  args.set_content(chunk_content);
  args.set_public_key(pub_key);
  args.set_signed_public_key(sig_pub_key);
  std::string sig_req = cry_obj.AsymSign(cry_obj.Hash(pub_key + sig_pub_key +
    chunk_name, "", crypto::STRING_STRING, false), "", priv_key,
    crypto::STRING_STRING);
  args.set_signed_request(sig_req);
  args.set_data_type(maidsafe::PDDIR_NOTSIGNED);
  std::string ser_args;
  args.SerializeToString(&ser_args);
  nodes[rand_node]->RpcStoreChunk(ser_args, sender_info, &result);
  boost::this_thread::sleep(boost::posix_time::seconds(3));
  // try to synchronize the chunk
  kad::VaultDaemon daemon(nodes[rand_node]);
  GeneralKadCallback cb;
  daemon.SyncVault(boost::bind(&GeneralKadCallback::CallbackFunc, &cb, _1));
  wait_result(&cb, mutex[rand_node]);
  ASSERT_EQ(kad::kRpcResultSuccess, cb.result());
}

TEST_F(VaultDaemonTest, FUNC_KAD_SynchronizingOneChunk) {
  // store a chunk
  std::string chunk_content = base::RandomString(250*1024);
  std::string chunk_name = cry_obj.Hash(chunk_content, "",
    crypto::STRING_STRING, false);
  std::string enc_chunk_name("");
  base::encode_to_hex(chunk_name, &enc_chunk_name);
  StoreResponse result;
  std::string ser_result("");
  std::string sender_info("");
  kad::StoreChunkRequest args;
  args.set_chunkname(chunk_name);
  args.set_content(chunk_content);
  args.set_public_key(pub_key);
  args.set_signed_public_key(sig_pub_key);
  std::string sig_req = cry_obj.AsymSign(cry_obj.Hash(pub_key + sig_pub_key +
    chunk_name, "", crypto::STRING_STRING, false), "", priv_key,
    crypto::STRING_STRING);
  args.set_signed_request(sig_req);
  args.set_data_type(maidsafe::PDDIR_NOTSIGNED);
  std::string ser_args;
  args.SerializeToString(&ser_args);
  nodes[2]->RpcStoreChunk(ser_args, sender_info, &ser_result);
  boost::this_thread::sleep(boost::posix_time::seconds(3));
  result.ParseFromString(ser_result);
  ASSERT_EQ(kad::kRpcResultFailure, result.result());
  result.Clear();
  nodes[6]->RpcStoreChunk(ser_args, sender_info, &ser_result);
  boost::this_thread::sleep(boost::posix_time::seconds(3));
  result.ParseFromString(ser_result);
  ASSERT_EQ(kad::kRpcResultFailure, result.result());
  nodes[8]->RpcStoreChunk(ser_args, sender_info, &ser_result);
  boost::this_thread::sleep(boost::posix_time::seconds(3));
  // update two of them
  std::string new_chunk_content = base::RandomString(250*1024);
  ASSERT_NE(chunk_content, new_chunk_content);
  kad::UpdateChunkRequest args1;
  args1.set_chunkname(chunk_name);
  args1.set_content(new_chunk_content);
  args1.set_public_key(pub_key);
  args1.set_signed_public_key(sig_pub_key);
  args1.set_signed_request(sig_req);
  args1.set_data_type(maidsafe::PDDIR_NOTSIGNED);
  args1.SerializeToString(&ser_args);
  result.ParseFromString(ser_result);
  ASSERT_EQ(kad::kRpcResultFailure, result.result());
  nodes[2]->RpcUpdateChunk(ser_args, sender_info, &ser_result);
  maidsafe::UpdateResponse result_up;
  result_up.ParseFromString(ser_result);
  ASSERT_EQ(kad::kRpcResultFailure, result_up.result());
  nodes[8]->RpcUpdateChunk(ser_args, sender_info, &ser_result);
  std::string ret_chunk;
  ASSERT_TRUE(nodes[6]->chunk_store_.LoadChunk(chunk_name, ret_chunk));
  ASSERT_EQ(chunk_content, ret_chunk);
  // create a vault daemon to synchronize the stale chunks
  kad::VaultDaemon daemon(nodes[6]);
  GeneralKadCallback cb;
  daemon.SyncVault(boost::bind(&GeneralKadCallback::CallbackFunc, &cb, _1));
  wait_result(&cb, mutex[6]);
  ASSERT_EQ(kad::kRpcResultFailure, cb.result());
  ASSERT_TRUE(nodes[6]->chunk_store_.LoadChunk(chunk_name, ret_chunk));
  ASSERT_EQ(new_chunk_content, ret_chunk);
}

TEST_F(VaultDaemonTest, FUNC_KAD_SynchronizingMultiChunks) {
  // prepare 10 chunks: 5 of them are up-to-date, 5 are stale
  std::map<std::string, std::string> chunks;
  for (int i = 0; i < 5; i++) {
    std::string chunk_content = base::RandomString(512);
    std::string chunk_name = cry_obj.Hash(chunk_content, "",
      crypto::STRING_STRING, false);
    chunks[chunk_name]=chunk_content;
    std::string enc_chunk_name("");
    base::encode_to_hex(chunk_name, &enc_chunk_name);
    std::string ser_args(""), ser_result(""), sender_info("");
    StoreResponse result;
    kad::StoreChunkRequest args;
    args.set_chunkname(chunk_name);
    args.set_content(chunk_content);
    args.set_public_key(pub_key);
    args.set_signed_public_key(sig_pub_key);
    std::string sig_req = cry_obj.AsymSign(cry_obj.Hash(pub_key + sig_pub_key +
      chunk_name, "", crypto::STRING_STRING, false), "", priv_key,
      crypto::STRING_STRING);
    args.set_signed_request(sig_req);
    args.set_data_type(maidsafe::PDDIR_NOTSIGNED);
    args.SerializeToString(&ser_args);

    nodes[base::random_32bit_uinteger()%19]->RpcStoreChunk(ser_args,
      sender_info, &ser_result);
    boost::this_thread::sleep(boost::posix_time::seconds(3));
    result.ParseFromString(ser_result);
    ASSERT_EQ(kad::kRpcResultFailure, result.result());
    nodes[base::random_32bit_uinteger()%19]->RpcStoreChunk(ser_args,
      sender_info, &ser_result);
    boost::this_thread::sleep(boost::posix_time::seconds(3));
    nodes[19]->RpcStoreChunk(ser_args, sender_info, &ser_result);
    boost::this_thread::sleep(boost::posix_time::seconds(3));
  }
  for (int i = 0; i < 5; i++) {
    std::string chunk_content = base::RandomString(512);
    std::string chunk_name = cry_obj.Hash(chunk_content, "",
      crypto::STRING_STRING, false);
    chunks[chunk_name]=chunk_content;
    std::string enc_chunk_name("");
    base::encode_to_hex(chunk_name, &enc_chunk_name);
    std::string ser_args(""), ser_result(""), sender_info("");
    StoreResponse result;
    kad::StoreChunkRequest args;
    args.set_chunkname(chunk_name);
    args.set_content(chunk_content);
    args.set_public_key(pub_key);
    args.set_signed_public_key(sig_pub_key);
    std::string sig_req = cry_obj.AsymSign(cry_obj.Hash(pub_key + sig_pub_key +
      chunk_name, "", crypto::STRING_STRING, false), "", priv_key,
      crypto::STRING_STRING);
    args.set_signed_request(sig_req);
    args.set_data_type(maidsafe::PDDIR_NOTSIGNED);
    args.SerializeToString(&ser_args);
    nodes[base::random_32bit_uinteger()%19]->RpcStoreChunk(ser_args,
      sender_info, &ser_result);
    boost::this_thread::sleep(boost::posix_time::seconds(3));
    result.ParseFromString(ser_result);
    ASSERT_EQ(kad::kRpcResultFailure, result.result());
    nodes[base::random_32bit_uinteger()  %19]->RpcStoreChunk(ser_args,
      sender_info, &ser_result);
    boost::this_thread::sleep(boost::posix_time::seconds(3));
    std::string new_chunk_content = base::RandomString(512);
    args.clear_content();
    args.set_content(new_chunk_content);
    args.SerializeToString(&ser_args);
    nodes[19]->RpcStoreChunk(ser_args, sender_info, &ser_result);
    boost::this_thread::sleep(boost::posix_time::seconds(3));
  }
  // create a vault daemon to synchronize the stale chunks
  kad::VaultDaemon daemon(nodes[19]);
  GeneralKadCallback cb;
  std::cout << "starting sync vault" << std::endl;
  daemon.SyncVault(boost::bind(&GeneralKadCallback::CallbackFunc, &cb, _1));
  wait_result(&cb, mutex[19]);
  ASSERT_EQ(kad::kRpcResultFailure, cb.result());
  std::map<std::string, std::string>::iterator it;
  for (it = chunks.begin(); it != chunks.end(); it++) {
    std::string ret_chunk;
    ASSERT_TRUE(nodes[19]->chunk_store_.LoadChunk(it->first, ret_chunk));
    ASSERT_EQ(it->second, ret_chunk);
  }
}

TEST_F(VaultDaemonTest, FUNC_KAD_SynchronizingMultiChunksWithSomeNodesLeave) {
  // prepare 10 chunks: 5 of them are up-to-date, 5 are stale
  std::map<std::string, std::string> chunks;
  for (int i = 0; i < 5; i++) {
    std::string chunk_content = base::RandomString(512);
    std::string chunk_name = cry_obj.Hash(chunk_content, "",
      crypto::STRING_STRING, false);
    std::string enc_chunk_name("");
    base::encode_to_hex(chunk_name, &enc_chunk_name);
    chunks[chunk_name]=chunk_content;
    std::string ser_args(""), ser_result(""), sender_info("");
    StoreResponse result;
    kad::StoreChunkRequest args;
    args.set_chunkname(chunk_name);
    args.set_content(chunk_content);
    args.set_public_key(pub_key);
    args.set_signed_public_key(sig_pub_key);
    std::string sig_req = cry_obj.AsymSign(cry_obj.Hash(pub_key + sig_pub_key +
      chunk_name, "", crypto::STRING_STRING, false), "", priv_key,
      crypto::STRING_STRING);
    args.set_signed_request(sig_req);
    args.set_data_type(maidsafe::PDDIR_NOTSIGNED);
    args.SerializeToString(&ser_args);
    nodes[base::random_32bit_uinteger()%19]->RpcStoreChunk(ser_args,
      sender_info, &ser_result);
    boost::this_thread::sleep(boost::posix_time::seconds(3));
    result.ParseFromString(ser_result);
    ASSERT_EQ(kad::kRpcResultFailure, result.result());
    nodes[base::random_32bit_uinteger()%19]->RpcStoreChunk(ser_args,
      sender_info, &ser_result);
    boost::this_thread::sleep(boost::posix_time::seconds(3));
    nodes[19]->RpcStoreChunk(ser_args, sender_info, &ser_result);
    boost::this_thread::sleep(boost::posix_time::seconds(3));
  }
  for (int i = 0; i < 5; i++) {
    std::string chunk_content = base::RandomString(512);
    std::string chunk_name = cry_obj.Hash(chunk_content, "",
      crypto::STRING_STRING, false);
    chunks[chunk_name]=chunk_content;
    std::string enc_chunk_name("");
    base::encode_to_hex(chunk_name, &enc_chunk_name);
    std::string ser_args(""), ser_result(""), sender_info("");
    StoreResponse result;
    kad::StoreChunkRequest args;
    args.set_chunkname(chunk_name);
    args.set_content(chunk_content);
    args.set_public_key(pub_key);
    args.set_signed_public_key(sig_pub_key);
    std::string sig_req = cry_obj.AsymSign(cry_obj.Hash(pub_key + sig_pub_key +
      chunk_name, "", crypto::STRING_STRING, false), "", priv_key,
      crypto::STRING_STRING);
    args.set_signed_request(sig_req);
    args.set_data_type(maidsafe::PDDIR_NOTSIGNED);
    args.SerializeToString(&ser_args);
    nodes[base::random_32bit_uinteger()%19]->RpcStoreChunk(ser_args,
      sender_info, &ser_result);
    boost::this_thread::sleep(boost::posix_time::seconds(3));
    result.ParseFromString(ser_result);
    ASSERT_EQ(kad::kRpcResultFailure, result.result());
    nodes[base::random_32bit_uinteger()%19]->RpcStoreChunk(ser_args,
      sender_info, &ser_result);
    boost::this_thread::sleep(boost::posix_time::seconds(3));
    std::string new_chunk_content = base::RandomString(512);
    args.clear_content();
    args.set_content(new_chunk_content);
    args.SerializeToString(&ser_args);
    nodes[19]->RpcStoreChunk(ser_args, sender_info, &ser_result);
    boost::this_thread::sleep(boost::posix_time::seconds(3));
  }
  // kill some nodes
  for (int i = 3; i < 5; i++) {
    GeneralKadCallback cb;
    timers[i]->CancelAll();
    cb.Reset();
    nodes[i]->Leave(boost::bind(&GeneralKadCallback::CallbackFunc, &cb, _1));
    wait_result(&cb, mutex[i]);
    EXPECT_EQ(kad::kRpcResultFailure, cb.result());
  }
  // create a vault daemon to synchronize the stale chunks
  kad::VaultDaemon daemon(nodes[19]);
  GeneralKadCallback cb;
  daemon.SyncVault(boost::bind(&GeneralKadCallback::CallbackFunc, &cb, _1));
  wait_result(&cb, mutex[19]);
  ASSERT_EQ(kad::kRpcResultFailure, cb.result());
  std::map<std::string, std::string>::iterator it;
  int num_updated_chunk = 0;
  for (it = chunks.begin(); it != chunks.end(); it++) {
    std::string ret_chunk;
    ASSERT_TRUE(nodes[19]->chunk_store_.LoadChunk(it->first, ret_chunk));
    if (it->second == ret_chunk)
      num_updated_chunk++;
  }
  ASSERT_GE(num_updated_chunk,
      kad::kMinSuccessfulPecentageOfUpdating*chunks.size());
}

TEST_F(VaultDaemonTest, FUNC_KAD_RepublishChunkRef) {
  int rep_node = base::random_32bit_uinteger()%19;
  // store 10 chunks
  for (int i = 0; i < 10; i++) {
    std::string chunk_content = base::RandomString(512);
    std::string chunk_name = cry_obj.Hash(chunk_content, "",
      crypto::STRING_STRING, false);
    std::string enc_chunk_name("");
    base::encode_to_hex(chunk_name, &enc_chunk_name);
    std::string ser_args(""), ser_result(""), sender_info("");
    StoreResponse result;
    kad::StoreChunkRequest args;
    args.set_chunkname(chunk_name);
    args.set_content(chunk_content);
    args.set_public_key(pub_key);
    args.set_signed_public_key(sig_pub_key);
    std::string sig_req = cry_obj.AsymSign(cry_obj.Hash(pub_key + sig_pub_key +
      chunk_name, "", crypto::STRING_STRING, false), "", priv_key,
      crypto::STRING_STRING);
    args.set_signed_request(sig_req);
    args.set_data_type(maidsafe::PDDIR_NOTSIGNED);
    args.SerializeToString(&ser_args);
    nodes[rep_node]->RpcStoreChunk(ser_args, sender_info, &ser_result);
    boost::this_thread::sleep(boost::posix_time::seconds(3));
    result.ParseFromString(ser_result);
    ASSERT_EQ(kad::kRpcResultFailure, result.result());
  }
  // create a vault daemon to republish chunk references
  kad::VaultDaemon daemon(nodes[rep_node]);
  GeneralKadCallback cb;
  daemon.RepublishChunkRef(boost::bind(&GeneralKadCallback::CallbackFunc, &cb, _1));
  wait_result(&cb, mutex[rep_node]);
  ASSERT_EQ(kad::kRpcResultFailure, cb.result());
}

}  // namespace maidsafe
*/
