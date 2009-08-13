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

/*#include "kademlia/validitycheck.h"
#include "kademlia/knode.h"
#include <maidsafe/crypto.h>
#include "base/calllatertimer.h"

#include<gtest/gtest.h>

class ValidityCheckTest:public testing::Test {
  protected:
    virtual void SetUp(){
      mutex = new boost::recursive_mutex();
      timer = new base::CallLaterTimer(mutex);
      boost::filesystem::path db("kadstore.db");
      node = new kad::KNode(&io_service_, db, timer, mutex, kad::VAULT);
      cry_obj.set_symm_algorithm(crypto::AES_256);
      cry_obj.set_hash_algorithm(crypto::SHA_512);
    }
    virtual void TearDown() {
      boost::filesystem::path localpath("vdcheck.db");
      boost::filesystem::path storage("STORAGE");
    }
    kad::KNode *node;
    boost::asio::io_service io_service_;
    crypto::Crypto cry_obj;
    boost::recursive_mutex *mutex;
    base::CallLaterTimer *timer;
};

TEST_F(ValidityCheckTest, TestAddchunk) {
  boost::filesystem::path localpath("");
  kad::ValidityCheck vdcheck(node, localpath, timer);
  ASSERT_TRUE(vdcheck.Start());
  std::string chunk_content = base::RandomString(333*1024);
  std::string chunk_name = cry_obj.Hash(chunk_content,"",
    crypto::STRING_STRING,false);
  dht::entry param, result;
  param["key"] = chunk_name;
  param["content"] = chunk_content;
  node->RpcStoreChunk(param, result);
  std::string partner1 = kad::vault_random_id();
  std::string partner2 = kad::vault_random_id();
  while (partner1 == partner2)
    partner2 = kad::vault_random_id();
  std::list<dht::entry> partners;
  partners.push_back(partner2);
  partners.push_back(partner1);
  result["values"] = partners;
  result["result"] = kad::kRpcResultFailure;
  vdcheck.AddChunkToCheck_Callback(result, chunk_name);
  std::vector<str_tuple> corrupt_chunks;
  ASSERT_TRUE(vdcheck.GetCurruptChunks(corrupt_chunks));

  ASSERT_TRUE(vdcheck.PartnerExists(partner1, chunk_name));
  ASSERT_TRUE(vdcheck.PartnerExists(partner2, chunk_name));

  ASSERT_TRUE(corrupt_chunks.empty());
  // checking the chunk
  std::string randomdata = base::RandomString(10);
  std::string hash_chunk = cry_obj.Hash(chunk_content+randomdata,"",
    crypto::STRING_STRING,false);
  dht::entry validityres;
  validityres["result"] = kad::kRpcResultFailure;
  validityres["hashcontent"] = hash_chunk;
  vdcheck.ValidityCheckProcess();
  vdcheck.CheckValidity_Callback(validityres, partner1, chunk_name, randomdata, 0);

  vdcheck.ValidityCheckProcess();
  validityres["hashcontent"] = "bad hash data";
  vdcheck.CheckValidity_Callback(validityres, partner2, chunk_name, randomdata, 0);
  ASSERT_TRUE(vdcheck.GetCurruptChunks(corrupt_chunks));
  ASSERT_EQ(1,(int)corrupt_chunks.size());
  std::string dirty_id = corrupt_chunks[0].get<0>();
  std::string dirty_chunk_name = corrupt_chunks[0].get<1>();
  ASSERT_EQ(chunk_name, dirty_chunk_name);
  ASSERT_EQ(partner2, dirty_id);
  vdcheck.ValidityCheckProcess();

  std::string partner3 = kad::vault_random_id();
  while (partner1 == partner3 && partner2 == partner3)
    partner3 = kad::vault_random_id();

  std::string partner4 = kad::vault_random_id();
  while (partner1 == partner4 && partner2 == partner4 && partner3 == partner4)
    partner4 = kad::vault_random_id();

  std::list<dht::entry> newpartners;
  newpartners.push_back(partner3);
  newpartners.push_back(partner4);
  result["values"] = newpartners;
  result["result"] = kad::kRpcResultFailure;
  vdcheck.AddChunkToCheck_Callback(result, chunk_name);
  vdcheck.CheckValidity_Callback(validityres, partner4, chunk_name, randomdata, 0);

  ASSERT_TRUE(vdcheck.PartnerExists(partner3, chunk_name));
  ASSERT_TRUE(vdcheck.PartnerExists(partner4, chunk_name));

  ASSERT_TRUE(vdcheck.RemoveChunkFromList(chunk_name, partner4));
  ASSERT_FALSE(vdcheck.PartnerExists(partner4, chunk_name));
  std::string new_chunk_content = base::RandomString(350*1024);
  std::string new_chunk_name = cry_obj.Hash(new_chunk_content,"",
    crypto::STRING_STRING,false);
  newpartners.clear();
  newpartners.push_back(partner3);
  result["values"] = newpartners;
  result["result"] = kad::kRpcResultFailure;
  vdcheck.AddChunkToCheck_Callback(result, new_chunk_name);
  ASSERT_TRUE(vdcheck.PartnerExists(partner3, new_chunk_name));
  ASSERT_TRUE(vdcheck.RemoveChunkFromList(chunk_name));
  ASSERT_FALSE(vdcheck.PartnerExists(partner3, chunk_name));

  ASSERT_TRUE(vdcheck.Stop());
}
*/
