#include "maidsafe/utils.h"
#include "maidsafe/client/dataatlashandler.h"
#include "maidsafe/client/keyatlas.h"
#include "maidsafe/client/pddir.h"
#include "maidsafe/client/clientcontroller.h"
#include "protobuf/datamaps.pb.h"
#include "maidsafe/client/selfencryption.h"
#include "maidsafe/client/localstoremanager.h"
#include "maidsafe/client/packetfactory.h"
#include "fs/filesystem.h"
#include <gtest/gtest.h>
#include <iostream>
#include <string>
#include <vector>
#include <stdint.h>
#include "maidsafe/crypto.h"
#include "protobuf/general_messages.pb.h"
#include "protobuf/maidsafe_service_messages.pb.h"

#include <boost/filesystem.hpp>


class FakeCallback{
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

void wait_for_result_seh_(FakeCallback &cb, boost::recursive_mutex *mutex) {
  while (true) {
    {
      base::pd_scoped_lock guard(*mutex);
      if (cb.result != "")
        return;
    }
    boost::this_thread::sleep(boost::posix_time::milliseconds(5));
  }
};


namespace maidsafe{

namespace fs = boost::filesystem;



class DataAtlasHandlerTest : public testing::Test {
public:
DataAtlasHandlerTest() : rec_mutex(), sm(), cb() {}
protected:
  void SetUp() {
    if (fs::exists("KademilaDb.db"))
      fs::remove(fs::path("KademilaDb.db"));
    if (fs::exists("StoreChunks"))
      fs::remove_all("StoreChunks");
    if (fs::exists("KademilaDb.db"))
      printf("Kademila.db still there.\n");
    if (fs::exists("StoreChunks"))
      printf("StoreChunks still there.\n");
    rec_mutex = new boost::recursive_mutex();
    boost::shared_ptr<LocalStoreManager>sm(new LocalStoreManager(rec_mutex));
    // sm = sm_;
    sm->Init(boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
    wait_for_result_seh_(cb, rec_mutex);
    base::GeneralResponse res;
    if ((!res.ParseFromString(cb.result)) ||
        (res.result() == kCallbackFailure)) {
      FAIL();
      return;
    }
    SessionSingleton::getInstance()->SetUsername("user1");
    SessionSingleton::getInstance()->SetPin("1234");
    SessionSingleton::getInstance()->SetPassword("password1");
    SessionSingleton::getInstance()->SetSessionName(false);
    SessionSingleton::getInstance()->SetRootDbKey("whatever");
    crypto::RsaKeyPair rsakp;
    rsakp.GenerateKeys(packethandler::kRsaKeySize);
    SessionSingleton::getInstance()->SetPrivateKey(rsakp.private_key(), MAID_BP);
    SessionSingleton::getInstance()->SetPublicKey(rsakp.public_key(), MAID_BP);
    file_system::FileSystem fsys_;
    fsys_.Mount();
    boost::scoped_ptr<DataAtlasHandler>dah_(new DataAtlasHandler());
    boost::shared_ptr<SEHandler>seh_(new SEHandler(sm.get(), rec_mutex));
    if (dah_->Init(true))
      FAIL();

    //  set up default dirs
    for (int i=0; i<kRootSubdirSize; i++) {
      MetaDataMap mdm_;
      std::string ser_mdm_, key_;
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
      if (kRootSubdir[i][1] == "")
        seh_->GenerateUniqueKey(PRIVATE, "", 0, &key_);
      else
        key_ = kRootSubdir[i][1];
      fs::create_directories(fsys_.MaidsafeHomeDir()+kRootSubdir[i][0]);
      dah_->AddElement(base::TidyPath(kRootSubdir[i][0]), ser_mdm_, "", key_, true);
    }
    cb.Reset();
  }

  void TearDown() {
    // SessionSingleton::getInstance()->ResetSession();
    try {
      boost::this_thread::sleep(boost::posix_time::milliseconds(100));
      file_system::FileSystem fsys_;
      fs::remove_all(fsys_.MaidsafeHomeDir());
      fs::remove_all(fsys_.DbDir());
      fs::remove_all("StoreChunks");
      fs::remove("KademilaDb.db");
    }
    catch(std::exception& e) {
      printf("%s\n", e.what());
    }
  }
  // LocalStoreManager *sm;
  boost::recursive_mutex *rec_mutex;
  boost::shared_ptr<LocalStoreManager> sm;
  FakeCallback cb;
private:
DataAtlasHandlerTest(const maidsafe::DataAtlasHandlerTest&);
DataAtlasHandlerTest &operator=(const maidsafe::DataAtlasHandlerTest&);
};

void PrepareDataMap(const std::string &file_hash, std::string &ser_dm){
  // Creating DataMap
  DataMap dm;
  dm.set_file_hash(file_hash);
  dm.add_chunk_name(base::RandomString(64));
  dm.add_chunk_name(base::RandomString(64));
  dm.add_chunk_name(base::RandomString(64));
  dm.add_encrypted_chunk_name(base::RandomString(64));
  dm.add_encrypted_chunk_name(base::RandomString(64));
  dm.add_encrypted_chunk_name(base::RandomString(64));
  dm.SerializeToString(&ser_dm);
}

void PrepareMetaDataMap(const int32_t id, const std::string &display_name, const itemtype &type,
  const std::string &file_hash, const std::string &stats, const std::string &tag,
  const uint32_t &file_size_high, const uint32_t &file_size_low, const uint32_t &creation_time,
  const uint32_t &last_modified, const uint32_t &last_access, std::string &ser_mdm) {
  MetaDataMap mdm;
  mdm.set_id(id);
  mdm.set_display_name(display_name);
  mdm.set_type(type);
  mdm.add_file_hash(file_hash);
  mdm.set_stats(stats);
  mdm.set_tag(tag);
  mdm.set_file_size_high(file_size_high);
  mdm.set_file_size_low(file_size_low);
  mdm.set_creation_time(creation_time);
  mdm.set_last_modified(last_modified);
  mdm.set_last_access(last_access);
  mdm.SerializeToString(&ser_mdm);
}

void PrepareDataAtlas(PdDir *da, std::vector<std::string> &file_names, std::vector<int32_t> &file_ids,
  std::vector<std::string> &folder_names, std::vector<int32_t> &folder_ids) {
  for (int i = 0; i < 10; i++){
    file_names.push_back(base::RandomString(20));
    file_ids.push_back(base::random_32bit_integer());
  }
  for (int i = 0; i< 3; i++){
    folder_names.push_back(base::RandomString(20));
    folder_ids.push_back(base::random_32bit_integer());
  }
  crypto::Crypto ct;
  ct.set_symm_algorithm("AES_256");
  ct.set_hash_algorithm("SHA512");
  // create 5 files
  for (int i = 0; i < 5; i++){
    std::string file_hash = ct.Hash(base::RandomString(200),"",
        crypto::STRING_STRING, true);
    std::string ser_mdm, ser_dm;
    PrepareMetaDataMap(file_ids[i], file_names[i], REGULAR_FILE,
      file_hash, "Stats", "Tag", 0, 1314, 1111, 2222, 3333, ser_mdm);
    PrepareDataMap(file_hash, ser_dm);
    ASSERT_TRUE(da->AddElement(ser_mdm, ser_dm))\
      <<"DataMap and Metadata of file were not added to DataAtlas";
  }
  // create 2 directories
  // int file_index = 4;
  for (int i = 0; i < 2; i++){
    std::string ser_mdm, ser_dm;
    PrepareMetaDataMap(folder_ids[i], folder_names[i], DIRECTORY,
      "", 0, 0, 0, 0, 4444, 5555, 6666, ser_mdm);
    ASSERT_TRUE(da->AddElement(ser_mdm, ""))\
      <<"Metadata of folder was not added to DataAtlas";
    // // add files to each directory
    // for (int j = 0; j < 2; j++){
    //   file_index += 1;
    //   std::string file_hash = base::RandomString(64);
    //   std::string ser_mdm, ser_dm;
    //   PrepareMetaDataMap(file_hash, file_names[file_index],
    //       file_ids[file_index], folder_ids[i], REGULAR_FILE, ser_mdm);
    //   PrepareDataMap(file_hash, ser_dm);
    //   ASSERT_TRUE(da->AddMSFile(ser_dm, ser_mdm))
    //     <<"DataMap and Metadata of file were not added to DataAtlas";
  }

  // // create 1 directory under the first sub-directory.
  // std::string ser_mdm, ser_dm;
  // PrepareMetaDataMap("", folder_names[2], folder_ids[2], folder_ids[0],
  //     DIRECTORY, ser_mdm);
  // ASSERT_TRUE(da->AddMSFile("", ser_mdm))
  //   <<"DataMap and Metadata of folder were not added to DataAtlas";
  // // create 1 file under the directory above
  // std::string file_hash = base::RandomString(64);
  // PrepareMetaDataMap(file_hash, file_names[9], file_ids[9], folder_ids[2],
  //     REGULAR_FILE, ser_mdm);
  // PrepareDataMap(file_hash, ser_dm);
  // ASSERT_TRUE(da->AddMSFile(ser_dm, ser_mdm))
  //   <<"DataMap and Metadata of file were not added to DataAtlas";
}


TEST_F(DataAtlasHandlerTest, BEH_MAID_AddGetDataMapDA) {
  // Test to insert a DataMap and Retrieve it
  // also checks to retrieve metadata for a filepath
  // checks the testDataMap existance
  boost::scoped_ptr<DataAtlasHandler> dah_(new DataAtlasHandler());
  const char* kDataBaseFile = "kdataatlas.db";
  if (fs::exists(kDataBaseFile))
    fs::remove(kDataBaseFile);
  int result_;
  PdDir data_atlas(kDataBaseFile, CREATE, &result_);

  std::string ser_dm, ser_mdm;
  std::string file_name = "Doc1.doc";
  std::string file_hash = "file hash1";

  // Creating DataMap
  DataMap dm;
  dm.set_file_hash(file_hash);
  dm.add_chunk_name("chunk1");
  dm.add_chunk_name("chunk2");
  dm.add_chunk_name("chunk3");
  dm.add_encrypted_chunk_name("enc_chunk1");
  dm.add_encrypted_chunk_name("enc_chunk2");
  dm.add_encrypted_chunk_name("enc_chunk3");
  dm.SerializeToString(&ser_dm);

  // Creating MetaDataMap
  MetaDataMap mdm;
  mdm.set_id(-2);
  mdm.set_display_name(file_name);
  mdm.set_type(REGULAR_FILE);
  mdm.add_file_hash(file_hash);
  mdm.set_stats("STATS");
  mdm.set_tag("TAG");
  mdm.set_file_size_high(4);
  mdm.set_file_size_low(5);
  mdm.set_creation_time(6);
  mdm.set_last_modified(7);
  mdm.set_last_access(8);
  mdm.SerializeToString(&ser_mdm);

  // Adding it to the DataAtlas
  ASSERT_EQ(0, data_atlas.AddElement(ser_mdm, ser_dm))<<"DataMap and Metadata of file were not added to DataAtlas";

  // Getting the dataMap
  ASSERT_TRUE(data_atlas.DataMapExists(file_hash))<<"DataMap does not exist in DataAtlas";
  std::string data_map, meta_data_map;
  ASSERT_EQ(0, data_atlas.GetDataMapFromHash(file_hash, &data_map))<<"Didn't retrieve DataMap from DataAtlas";
  ASSERT_EQ(0, data_atlas.GetMetaDataMap(file_name, &meta_data_map))<<"Didn't retrieve MetaDataMap from DataAtlas";

  DataMap recovered_dm;
  MetaDataMap recovered_mdm;

  // check serialised DM = original DM (mdm will have changed due to access and modified times being updated)
  ASSERT_EQ(ser_dm, data_map)<<"Retrieved dm is not the same as original dm";
  // ASSERT_EQ(ser_mdm, meta_data_map)<<"Retrieved mdm is not the same as original mdm";

  EXPECT_TRUE(recovered_dm.ParseFromString(data_map));
  EXPECT_TRUE(recovered_mdm.ParseFromString(meta_data_map));

  // check recovered elements = original elements
  EXPECT_EQ(dm.file_hash(), recovered_dm.file_hash())<<"Filehash in datamap recovered is not the same as original datamap";
  EXPECT_NE(mdm.id(), recovered_mdm.id())<<"id in metadatamap recovered is still -2";
  EXPECT_EQ(mdm.display_name(), recovered_mdm.display_name())<<"file name in metadatamap recovered is not the same as original metadatamap";
  EXPECT_EQ(mdm.type(), recovered_mdm.type())<<"type in metadatamap recovered is not the same as original metadatamap";

  EXPECT_EQ(mdm.file_hash(0), recovered_mdm.file_hash(0))<<"file hash in metadatamap recovered is not the same as original metadatamap";
  EXPECT_EQ(mdm.stats(), recovered_mdm.stats())<<"stats in metadatamap recovered is not the same as original metadatamap";
  EXPECT_EQ(mdm.tag(), recovered_mdm.tag())<<"tag in metadatamap recovered is not the same as original metadatamap";
  EXPECT_EQ(mdm.file_size_high(), recovered_mdm.file_size_high())<<"file_size_high in metadatamap recovered is not the same as original metadatamap";
  EXPECT_EQ(mdm.file_size_low(), recovered_mdm.file_size_low())<<"file_size_low in metadatamap recovered is not the same as original metadatamap";
  EXPECT_EQ(mdm.creation_time(), recovered_mdm.creation_time())<<"creation_time in metadatamap recovered is not the same as original metadatamap";
  ASSERT_NE(mdm.last_modified(), recovered_mdm.last_modified())<<"last_modified in metadatamap recovered is the same as original metadatamap";
  ASSERT_NE(mdm.last_access(), recovered_mdm.last_access())<<"last_access in metadatamap recovered is the same as original metadatamap";

  // check recovered DM size = origional DM size
  ASSERT_EQ(dm.chunk_name_size(), recovered_dm.chunk_name_size());

  // check each recovered DM chunk name = each origional DM chunk name
  for (int i = 0; i < dm.chunk_name_size(); i++){
    EXPECT_EQ(dm.chunk_name(i), recovered_dm.chunk_name(i));
  }

  // check recovered encrypted DM size = origional encrypted DM size
  ASSERT_EQ(dm.encrypted_chunk_name_size(), recovered_dm.encrypted_chunk_name_size());

  // check each recovered encrypted DM chunk name = each origional encrypted DM chunk name
  for (int i = 0; i < dm.encrypted_chunk_name_size(); i++){
      EXPECT_EQ(dm.encrypted_chunk_name(i), recovered_dm.encrypted_chunk_name(i));
  }

  ASSERT_EQ(0, data_atlas.Disconnect());

  if (fs::exists(kDataBaseFile))
    fs::remove(kDataBaseFile);
}

TEST_F(DataAtlasHandlerTest, BEH_MAID_AddGetDataMapDAH) {
  boost::scoped_ptr<DataAtlasHandler> dah_(new DataAtlasHandler());
  std::string ser_dm="", ser_mdm="";
  std::string dir_name = base::TidyPath(kRootSubdir[0][0]) + "/";
  std::string file_name = "Doc2.doc";
  std::string element_path = dir_name+file_name;
  std::string file_hash = "file hash1";

  // Creating DataMap
  DataMap dm;
  dm.set_file_hash(file_hash);
  dm.add_chunk_name("chunk1");
  dm.add_chunk_name("chunk2");
  dm.add_chunk_name("chunk3");
  dm.add_encrypted_chunk_name("enc_chunk1");
  dm.add_encrypted_chunk_name("enc_chunk2");
  dm.add_encrypted_chunk_name("enc_chunk3");
  dm.SerializeToString(&ser_dm);

  // Creating MetaDataMap
  MetaDataMap mdm;
  mdm.set_id(-2);
  mdm.set_display_name(file_name);
  mdm.set_type(REGULAR_FILE);
  mdm.add_file_hash(file_hash);
  mdm.set_stats("STATS");
  mdm.set_tag("TAG");
  mdm.set_file_size_high(4);
  mdm.set_file_size_low(5);
  mdm.set_creation_time(6);
  mdm.set_last_modified(7);
  mdm.set_last_access(8);
  mdm.SerializeToString(&ser_mdm);

  // DataAtlasHandler *dah_ = new DataAtlasHandler::getInstance();
  // PdDir *da_newdir_ = dah_->GetPdDir(dir_name.c_str());
  // delete da_newdir_;
  // dah_->DisconnectPdDir(dir_name.c_str());

  // Adding it to the DataAtlas
  ASSERT_EQ(0, dah_->AddElement(element_path, ser_mdm, ser_dm, "", true))<<"DataMap and Metadata of file were not added to DataAtlas";

  // Getting the dataMap
  std::string data_map, meta_data_map;
  ASSERT_EQ(0, dah_->GetDataMap(element_path, &data_map))<<"Didn't retrieve DataMap from DataAtlas";
  ASSERT_EQ(0, dah_->GetMetaDataMap(element_path, &meta_data_map))<<"Didn't retrieve MetaDataMap from DataAtlas";

  DataMap recovered_dm;
  MetaDataMap recovered_mdm;

  // check serialised DM = original DM (mdm will have changed due to access and modified times being updated)
  ASSERT_EQ(ser_dm, data_map)<<"Retrieved dm is not the same as original dm";
  // ASSERT_EQ(ser_mdm, meta_data_map)<<"Retrieved mdm is not the same as original mdm";

  EXPECT_TRUE(recovered_dm.ParseFromString(data_map));
  EXPECT_TRUE(recovered_mdm.ParseFromString(meta_data_map));

  // check recovered elements = original elements
  EXPECT_EQ(dm.file_hash(), recovered_dm.file_hash())<<"Filehash in datamap recovered is not the same as original datamap";
  EXPECT_NE(mdm.id(), recovered_mdm.id())<<"id in metadatamap recovered has not been updated";
  EXPECT_EQ(mdm.display_name(), recovered_mdm.display_name())<<"file name in metadatamap recovered is not the same as original metadatamap";
  EXPECT_EQ(mdm.type(), recovered_mdm.type())<<"type in metadatamap recovered is not the same as original metadatamap";

  EXPECT_EQ(mdm.file_hash(0), recovered_mdm.file_hash(0))<<"file hash in metadatamap recovered is not the same as original metadatamap";
  EXPECT_EQ(mdm.stats(), recovered_mdm.stats())<<"stats in metadatamap recovered is not the same as original metadatamap";
  EXPECT_EQ(mdm.tag(), recovered_mdm.tag())<<"tag in metadatamap recovered is not the same as original metadatamap";
  EXPECT_EQ(mdm.file_size_high(), recovered_mdm.file_size_high())<<"file_size_high in metadatamap recovered is not the same as original metadatamap";
  EXPECT_EQ(mdm.file_size_low(), recovered_mdm.file_size_low())<<"file_size_low in metadatamap recovered is not the same as original metadatamap";
  EXPECT_EQ(mdm.creation_time(), recovered_mdm.creation_time())<<"creation_time in metadatamap recovered is not the same as original metadatamap";
  ASSERT_NE(mdm.last_modified(), recovered_mdm.last_modified())<<"last_modified in metadatamap recovered is the same as original metadatamap";
  ASSERT_NE(mdm.last_access(), recovered_mdm.last_access())<<"last_access in metadatamap recovered is the same as original metadatamap";

  // check recovered DM size = origional DM size
  ASSERT_EQ(dm.chunk_name_size(), recovered_dm.chunk_name_size());

  // check each recovered DM chunk name = each origional DM chunk name
  for (int i = 0; i < dm.chunk_name_size(); i++){
    EXPECT_EQ(dm.chunk_name(i), recovered_dm.chunk_name(i));
  }

  // check recovered encrypted DM size = origional encrypted DM size
  ASSERT_EQ(dm.encrypted_chunk_name_size(), recovered_dm.encrypted_chunk_name_size());

  // check each recovered encrypted DM chunk name = each origional encrypted DM chunk name
  for (int i = 0; i < dm.encrypted_chunk_name_size(); i++){
      EXPECT_EQ(dm.encrypted_chunk_name(i), recovered_dm.encrypted_chunk_name(i));
  }
  // ASSERT_EQ(0, dah_->DisconnectPdDir("My Files/"))<<"Couldn't disconnect from database";
  // ASSERT_TRUE(cc->Logout())<<"Didn't logout properly";
  // delete dah_;
}

TEST_F(DataAtlasHandlerTest, BEH_MAID_ObscureFilename) {
  // Test to insert a DataMap and Retrieve it
  // also checks to retrieve metadata for a filepath
  // checks the testDataMap existance


  // ss = SessionSingleton::getInstance();
  // ASSERT_TRUE(cc->Start(username,pin,password));

  boost::scoped_ptr<DataAtlasHandler> dah_(new DataAtlasHandler());
  std::string ser_dm="", ser_mdm="";
  std::string dir_name = base::TidyPath(kRootSubdir[0][0]) + "/";
  std::string file_name = "Doc¬!£$%^&()-_+={}[];@~#,'''.doc";
  std::string element_path = dir_name+file_name;
  std::string file_hash = "file hash obscure";

  // Creating DataMap
  DataMap dm;
  dm.set_file_hash(file_hash);
  dm.add_chunk_name("chunk1");
  dm.add_chunk_name("chunk2");
  dm.add_chunk_name("chunk3");
  dm.add_encrypted_chunk_name("enc_chunk1");
  dm.add_encrypted_chunk_name("enc_chunk2");
  dm.add_encrypted_chunk_name("enc_chunk3");
  dm.SerializeToString(&ser_dm);

  // Creating MetaDataMap
  MetaDataMap mdm;
  mdm.set_id(-2);
  mdm.set_display_name(file_name);
  mdm.set_type(REGULAR_FILE);
  mdm.add_file_hash(file_hash);
  mdm.set_stats("STATS OBS");
  mdm.set_tag("TAG OBS");
  mdm.set_file_size_high(0);
  mdm.set_file_size_low(20);
  mdm.set_creation_time(10000000);
  mdm.set_last_modified(7);
  mdm.set_last_access(8);
  mdm.SerializeToString(&ser_mdm);

  // Adding it to the DataAtlas
  ASSERT_EQ(0, dah_->AddElement(element_path, ser_mdm, ser_dm, "", true))<<"DataMap and Metadata of file were not added to DataAtlas";

  // Getting the dataMap
  std::string data_map, meta_data_map;
  ASSERT_EQ(0, dah_->GetDataMap(element_path, &data_map))<<"Didn't retrieve DataMap from DataAtlas";
  ASSERT_EQ(0, dah_->GetMetaDataMap(element_path, &meta_data_map))<<"Didn't retrieve MetaDataMap from DataAtlas";

  DataMap recovered_dm;
  MetaDataMap recovered_mdm;

  // check serialised DM = original DM (mdm will have changed due to access and modified times being updated)
  ASSERT_EQ(ser_dm, data_map)<<"Retrieved dm is not the same as original dm";
  // ASSERT_EQ(ser_mdm, meta_data_map)<<"Retrieved mdm is not the same as original mdm";

  EXPECT_TRUE(recovered_dm.ParseFromString(data_map));
  EXPECT_TRUE(recovered_mdm.ParseFromString(meta_data_map));

  // check recovered elements = original elements
  EXPECT_EQ(dm.file_hash(), recovered_dm.file_hash())<<"Filehash in datamap recovered is not the same as original datamap";
  EXPECT_NE(mdm.id(), recovered_mdm.id())<<"id in metadatamap recovered has not been updated";
  EXPECT_EQ(mdm.display_name(), recovered_mdm.display_name())<<"file name in metadatamap recovered is not the same as original metadatamap";
  EXPECT_EQ(mdm.type(), recovered_mdm.type())<<"type in metadatamap recovered is not the same as original metadatamap";

  EXPECT_EQ(mdm.file_hash(0), recovered_mdm.file_hash(0))<<"file hash in metadatamap recovered is not the same as original metadatamap";
  EXPECT_EQ(mdm.stats(), recovered_mdm.stats())<<"stats in metadatamap recovered is not the same as original metadatamap";
  EXPECT_EQ(mdm.tag(), recovered_mdm.tag())<<"tag in metadatamap recovered is not the same as original metadatamap";
  EXPECT_EQ(mdm.file_size_high(), recovered_mdm.file_size_high())<<"file_size_high in metadatamap recovered is not the same as original metadatamap";
  EXPECT_EQ(mdm.file_size_low(), recovered_mdm.file_size_low())<<"file_size_low in metadatamap recovered is not the same as original metadatamap";
  EXPECT_EQ(mdm.creation_time(), recovered_mdm.creation_time())<<"creation_time in metadatamap recovered is not the same as original metadatamap";
  ASSERT_NE(mdm.last_modified(), recovered_mdm.last_modified())<<"last_modified in metadatamap recovered is the same as original metadatamap";
  ASSERT_NE(mdm.last_access(), recovered_mdm.last_access())<<"last_access in metadatamap recovered is the same as original metadatamap";

  // check recovered DM size = origional DM size
  ASSERT_EQ(dm.chunk_name_size(), recovered_dm.chunk_name_size());

  // check each recovered DM chunk name = each origional DM chunk name
  for (int i = 0; i < dm.chunk_name_size(); i++){
    EXPECT_EQ(dm.chunk_name(i), recovered_dm.chunk_name(i));
  }

  // check recovered encrypted DM size = origional encrypted DM size
  ASSERT_EQ(dm.encrypted_chunk_name_size(), recovered_dm.encrypted_chunk_name_size());

  // check each recovered encrypted DM chunk name = each origional encrypted DM chunk name
  for (int i = 0; i < dm.encrypted_chunk_name_size(); i++){
      EXPECT_EQ(dm.encrypted_chunk_name(i), recovered_dm.encrypted_chunk_name(i));
  }
  // ASSERT_EQ(0, dah_->DisconnectPdDir("Test"))<<"Couldn't disconnect from database";
}

TEST_F(DataAtlasHandlerTest, BEH_MAID_RemoveMSFile) {
  // Test to check the removal of a MSFile and the removal of its ms_path

  boost::scoped_ptr<DataAtlasHandler> dah_(new DataAtlasHandler());
  std::string ser_dm="", ser_mdm="", ser_dm_recovered="", ser_mdm_recovered="";
  std::string dir_name = base::TidyPath(kRootSubdir[0][0]) + "/";
  std::string file_name = "Doc3.doc";
  std::string element_path = dir_name+file_name;
  std::string file_hash = "file hash1";

  // Creating DataMap
  DataMap dm;
  dm.set_file_hash(file_hash);
  dm.add_chunk_name("fraser");
  dm.add_chunk_name("douglas");
  dm.add_chunk_name("hutchison");
  dm.add_encrypted_chunk_name("enc_chunk1");
  dm.add_encrypted_chunk_name("enc_chunk2");
  dm.add_encrypted_chunk_name("enc_chunk3");
  dm.SerializeToString(&ser_dm);

  // Creating MetaDataMap
  MetaDataMap mdm;
  mdm.set_id(-2);
  mdm.set_display_name(file_name);
  mdm.set_type(REGULAR_FILE);
  mdm.add_file_hash(file_hash);
  mdm.set_stats("STATS");
  mdm.set_tag("TAG");
  mdm.set_file_size_high(4);
  mdm.set_file_size_low(5);
  mdm.set_creation_time(6);
  mdm.set_last_modified(7);
  mdm.set_last_access(8);
  mdm.SerializeToString(&ser_mdm);

  // Adding it to the DataAtlas
  ASSERT_EQ(0, dah_->AddElement(element_path, ser_mdm, ser_dm, "", true))<<"DataMap and Metadata of file were not added to DataAtlas";

  // Check the added DM exists in the DataAtlas
  ASSERT_EQ(0, dah_->GetDataMap(element_path, &ser_dm_recovered))<<"Didn't retrieve DataMap from DataAtlas";
  ASSERT_EQ(0, dah_->GetMetaDataMap(element_path, &ser_mdm_recovered))<<"Didn't retrieve MetaDataMap from DataAtlas";

  DataMap recovered_dm;
  MetaDataMap recovered_mdm;

  // Check DM is sucessfully removed from the DataAtlas
  ASSERT_EQ(0, dah_->RemoveElement(element_path));

  // Check sucessful deletion of the DM from the DataAtlas
  ASSERT_NE(0, dah_->GetDataMap(element_path, &ser_dm_recovered))<<"DataMap is still in the DataAtlas";
  ASSERT_NE(0, dah_->GetMetaDataMap(element_path, &ser_mdm_recovered))<<"ms_path still in DataAtlas";

  // ASSERT_EQ(0, dah_->DisconnectPdDir("Test"))<<"Couldn't disconnect from database";
}

TEST_F(DataAtlasHandlerTest, BEH_MAID_CopyMSFile) {
  // Test to check copying a MSFile

  boost::scoped_ptr<DataAtlasHandler> dah_(new DataAtlasHandler());
  std::string ser_dm_original="", ser_mdm_original="", ser_dm_recovered_original="", ser_mdm_recovered_original="";
  std::string ser_dm_recovered_copy1="", ser_mdm_recovered_copy1="", ser_dm_recovered_copy2="", ser_mdm_recovered_copy2="";
  std::string ser_dm_exists="", ser_mdm_exists="", ser_dm_recovered_exists="", ser_mdm_recovered_exists="";
  std::string dir_name = base::TidyPath(kRootSubdir[0][0]) + "/";
  std::string file_name_original = "Original.doc";
  std::string file_name_copy = "Copy.doc";
  std::string file_name_exists = "Exists.doc";
  std::string element_path_original = dir_name+file_name_original;
  std::string element_path_copy = dir_name+file_name_copy;
  std::string element_path_exists = dir_name+file_name_exists;
  std::string file_hash_original = "file hash original";
  std::string file_hash_copy = "file hash copy";
  std::string file_hash_exists = "file hash exists";

  // Creating DataMaps
  DataMap dm_original, dm_exists;
  dm_original.set_file_hash(file_hash_original);
  dm_original.add_chunk_name("chunk1_original");
  dm_original.add_chunk_name("chunk2_original");
  dm_original.add_chunk_name("chunk2_original");
  dm_original.add_encrypted_chunk_name("enc_chunk1_original");
  dm_original.add_encrypted_chunk_name("enc_chunk2_original");
  dm_original.add_encrypted_chunk_name("enc_chunk3_original");
  dm_original.SerializeToString(&ser_dm_original);
  dm_exists.set_file_hash(file_hash_exists);
  dm_exists.add_chunk_name("chunk1_exists");
  dm_exists.add_chunk_name("chunk2_exists");
  dm_exists.add_chunk_name("chunk2_exists");
  dm_exists.add_encrypted_chunk_name("enc_chunk1_exists");
  dm_exists.add_encrypted_chunk_name("enc_chunk2_exists");
  dm_exists.add_encrypted_chunk_name("enc_chunk3_exists");
  dm_exists.SerializeToString(&ser_dm_exists);

  // Creating MetaDataMaps
  MetaDataMap mdm_original, mdm_exists;
  mdm_original.set_id(-2);
  mdm_original.set_display_name(file_name_original);
  mdm_original.set_type(REGULAR_FILE);
  mdm_original.add_file_hash(file_hash_original);
  mdm_original.set_stats("STATS_original");
  mdm_original.set_tag("TAG_original");
  mdm_original.set_file_size_high(4);
  mdm_original.set_file_size_low(5);
  mdm_original.set_creation_time(6);
  mdm_original.set_last_modified(7);
  mdm_original.set_last_access(8);
  mdm_original.SerializeToString(&ser_mdm_original);
  mdm_exists.set_id(-2);
  mdm_exists.set_display_name(file_name_exists);
  mdm_exists.set_type(REGULAR_FILE);
  mdm_exists.add_file_hash(file_hash_exists);
  mdm_exists.set_stats("STATS_exists");
  mdm_exists.set_tag("TAG_exists");
  mdm_exists.set_file_size_high(9);
  mdm_exists.set_file_size_low(10);
  mdm_exists.set_creation_time(11);
  mdm_exists.set_last_modified(12);
  mdm_exists.set_last_access(13);
  mdm_exists.SerializeToString(&ser_mdm_exists);

  // Adding them to the DataAtlas
  ASSERT_EQ(0, dah_->AddElement(element_path_original, ser_mdm_original, ser_dm_original, "", true))<<"DataMap and Metadata of file were not added to DataAtlas";
  ASSERT_EQ(0, dah_->AddElement(element_path_exists, ser_mdm_exists, ser_dm_exists, "", true))<<"DataMap and Metadata of file were not added to DataAtlas";

  // Check the added DMs exist in the DataAtlas
  ASSERT_EQ(0, dah_->GetDataMap(element_path_original, &ser_dm_recovered_original))<<"Didn't retrieve DataMap from DataAtlas";
  ASSERT_EQ(0, dah_->GetMetaDataMap(element_path_original, &ser_mdm_recovered_original))<<"Didn't retrieve MetaDataMap from DataAtlas";
  ASSERT_EQ(0, dah_->GetDataMap(element_path_exists, &ser_dm_recovered_exists))<<"Didn't retrieve DataMap from DataAtlas";
  ASSERT_EQ(0, dah_->GetMetaDataMap(element_path_exists, &ser_mdm_recovered_exists))<<"Didn't retrieve MetaDataMap from DataAtlas";

  DataMap recovered_dm_copy1, recovered_dm_exists, recovered_dm_copy2;
  MetaDataMap recovered_mdm_copy1, recovered_mdm_exists, recovered_mdm_copy2;

  // Check file is not copied to non-existant dir
  ASSERT_NE(0, dah_->CopyElement(element_path_original, "non-existant dir/non-existant file", "", false));

  // Check file is not copied to itself
  ASSERT_NE(0, dah_->CopyElement(element_path_original, element_path_original, "", false));

  // Check file is sucessfully copied
  ASSERT_EQ(0, dah_->CopyElement(element_path_original, element_path_copy, "", false));
  ASSERT_EQ(0, dah_->GetDataMap(element_path_copy, &ser_dm_recovered_copy1));
  ASSERT_EQ(0, dah_->GetMetaDataMap(element_path_copy, &ser_mdm_recovered_copy1));
  ASSERT_TRUE(recovered_dm_copy1.ParseFromString(ser_dm_recovered_copy1));
  ASSERT_TRUE(recovered_mdm_copy1.ParseFromString(ser_mdm_recovered_copy1));
  ASSERT_EQ(dm_original.file_hash(), recovered_dm_copy1.file_hash());
  ASSERT_EQ(mdm_original.stats(), recovered_mdm_copy1.stats());
  ASSERT_EQ(0, dah_->GetDataMap(element_path_original, &ser_dm_recovered_original));
  ASSERT_EQ(0, dah_->GetMetaDataMap(element_path_original, &ser_mdm_recovered_original));

  // Check file is not copied over existing file when force bool is set to false
  ASSERT_NE(0, dah_->CopyElement(element_path_original, element_path_exists, "", false));
  ASSERT_EQ(0, dah_->GetDataMap(element_path_exists, &ser_dm_recovered_exists));
  ASSERT_EQ(0, dah_->GetMetaDataMap(element_path_exists, &ser_mdm_recovered_exists));
  ASSERT_TRUE(recovered_dm_exists.ParseFromString(ser_dm_recovered_exists));
  ASSERT_TRUE(recovered_mdm_exists.ParseFromString(ser_mdm_recovered_exists));
  ASSERT_EQ(dm_exists.file_hash(), recovered_dm_exists.file_hash());
  ASSERT_EQ(mdm_exists.stats(), recovered_mdm_exists.stats());

  // Check file is copied over existing file when force bool is set to true
  ASSERT_EQ(0, dah_->CopyElement(element_path_original, element_path_exists, "", true));
  ASSERT_EQ(0, dah_->GetDataMap(element_path_exists, &ser_dm_recovered_copy2));
  ASSERT_EQ(0, dah_->GetMetaDataMap(element_path_exists, &ser_mdm_recovered_copy2));
  ASSERT_TRUE(recovered_dm_copy2.ParseFromString(ser_dm_recovered_copy2));
  ASSERT_TRUE(recovered_mdm_copy2.ParseFromString(ser_mdm_recovered_copy2));
  ASSERT_EQ(dm_original.file_hash(), recovered_dm_copy2.file_hash());
  ASSERT_EQ(mdm_original.stats(), recovered_mdm_copy2.stats());
  ser_dm_recovered_original="";
  ser_mdm_recovered_original="";
  ASSERT_EQ(0, dah_->GetDataMap(element_path_original, &ser_dm_recovered_original));
  ASSERT_EQ(0, dah_->GetMetaDataMap(element_path_original, &ser_mdm_recovered_original));
}

TEST_F(DataAtlasHandlerTest, BEH_MAID_RenameMSFile) {
  // Test to check renaming a MSFile

  boost::scoped_ptr<DataAtlasHandler> dah_(new DataAtlasHandler());
  std::string ser_dm_original="", ser_mdm_original="", ser_dm_recovered_original="", ser_mdm_recovered_original="";
  std::string ser_dm_recovered_copy1="", ser_mdm_recovered_copy1="", ser_dm_recovered_copy2="", ser_mdm_recovered_copy2="";
  std::string ser_dm_exists="", ser_mdm_exists="", ser_dm_recovered_exists="", ser_mdm_recovered_exists="";
  std::string dir_name = base::TidyPath(kRootSubdir[0][0]) + "/";
  std::string file_name_original = "Original.doc";
  std::string file_name_copy = "Original.doc~.copy";
  std::string file_name_exists = "Exists.doc";
  std::string element_path_original = dir_name+file_name_original;
  std::string element_path_copy = dir_name+file_name_copy;
  std::string element_path_exists = dir_name+file_name_exists;
  std::string file_hash_original = "file hash original";
  std::string file_hash_copy = "file hash copy";
  std::string file_hash_exists = "file hash exists";

  // Creating DataMaps
  DataMap dm_original, dm_exists;
  dm_original.set_file_hash(file_hash_original);
  dm_original.add_chunk_name("chunk1_original");
  dm_original.add_chunk_name("chunk2_original");
  dm_original.add_chunk_name("chunk2_original");
  dm_original.add_encrypted_chunk_name("enc_chunk1_original");
  dm_original.add_encrypted_chunk_name("enc_chunk2_original");
  dm_original.add_encrypted_chunk_name("enc_chunk3_original");
  dm_original.SerializeToString(&ser_dm_original);
  dm_exists.set_file_hash(file_hash_exists);
  dm_exists.add_chunk_name("chunk1_exists");
  dm_exists.add_chunk_name("chunk2_exists");
  dm_exists.add_chunk_name("chunk2_exists");
  dm_exists.add_encrypted_chunk_name("enc_chunk1_exists");
  dm_exists.add_encrypted_chunk_name("enc_chunk2_exists");
  dm_exists.add_encrypted_chunk_name("enc_chunk3_exists");
  dm_exists.SerializeToString(&ser_dm_exists);

  // Creating MetaDataMaps
  MetaDataMap mdm_original, mdm_exists;
  mdm_original.set_id(-2);
  mdm_original.set_display_name(file_name_original);
  mdm_original.set_type(REGULAR_FILE);
  mdm_original.add_file_hash(file_hash_original);
  mdm_original.set_stats("STATS_original");
  mdm_original.set_tag("TAG_original");
  mdm_original.set_file_size_high(4);
  mdm_original.set_file_size_low(5);
  mdm_original.set_creation_time(6);
  mdm_original.set_last_modified(7);
  mdm_original.set_last_access(8);
  mdm_original.SerializeToString(&ser_mdm_original);
  mdm_exists.set_id(-2);
  mdm_exists.set_display_name(file_name_exists);
  mdm_exists.set_type(REGULAR_FILE);
  mdm_exists.add_file_hash(file_hash_exists);
  mdm_exists.set_stats("STATS_exists");
  mdm_exists.set_tag("TAG_exists");
  mdm_exists.set_file_size_high(9);
  mdm_exists.set_file_size_low(10);
  mdm_exists.set_creation_time(11);
  mdm_exists.set_last_modified(12);
  mdm_exists.set_last_access(13);
  mdm_exists.SerializeToString(&ser_mdm_exists);

  // Adding them to the DataAtlas
  ASSERT_EQ(0, dah_->AddElement(element_path_original, ser_mdm_original, ser_dm_original, "", true))<<"DataMap and Metadata of file were not added to DataAtlas";
  ASSERT_EQ(0, dah_->AddElement(element_path_exists, ser_mdm_exists, ser_dm_exists, "", true))<<"DataMap and Metadata of file were not added to DataAtlas";

  // Check the added DMs exist in the DataAtlas
  ASSERT_EQ(0, dah_->GetDataMap(element_path_original, &ser_dm_recovered_original))<<"Didn't retrieve DataMap from DataAtlas";
  ASSERT_EQ(0, dah_->GetMetaDataMap(element_path_original, &ser_mdm_recovered_original))<<"Didn't retrieve MetaDataMap from DataAtlas";
  ASSERT_EQ(0, dah_->GetDataMap(element_path_exists, &ser_dm_recovered_exists))<<"Didn't retrieve DataMap from DataAtlas";
  ASSERT_EQ(0, dah_->GetMetaDataMap(element_path_exists, &ser_mdm_recovered_exists))<<"Didn't retrieve MetaDataMap from DataAtlas";

  DataMap recovered_dm_copy1, recovered_dm_exists, recovered_dm_copy2;
  MetaDataMap recovered_mdm_copy1, recovered_mdm_exists, recovered_mdm_copy2;

  // Check file is not renamed to non-existant dir
  ASSERT_NE(0, dah_->RenameElement(element_path_original, "non-existant dir/non-existant file", false));

  // Check file is not renamed to itself
  ASSERT_NE(0, dah_->RenameElement(element_path_original, element_path_original, false));

  // Check file is sucessfully renamed
  ASSERT_EQ(0, dah_->RenameElement(element_path_original, element_path_copy, false));
  ASSERT_EQ(0, dah_->GetDataMap(element_path_copy, &ser_dm_recovered_copy1));
  ASSERT_EQ(0, dah_->GetMetaDataMap(element_path_copy, &ser_mdm_recovered_copy1));
  ASSERT_TRUE(recovered_dm_copy1.ParseFromString(ser_dm_recovered_copy1));
  ASSERT_TRUE(recovered_mdm_copy1.ParseFromString(ser_mdm_recovered_copy1));
  ASSERT_EQ(dm_original.file_hash(), recovered_dm_copy1.file_hash());
  ASSERT_EQ(mdm_original.stats(), recovered_mdm_copy1.stats());
  ASSERT_NE(0, dah_->GetDataMap(element_path_original, &ser_dm_recovered_original));
  ASSERT_NE(0, dah_->GetMetaDataMap(element_path_original, &ser_mdm_recovered_original));

  // Add & check original element again to the DataAtlas
  ASSERT_EQ(0, dah_->AddElement(element_path_original, ser_mdm_original, ser_dm_original, "", true));
  ASSERT_EQ(0, dah_->GetDataMap(element_path_original, &ser_dm_recovered_original));
  ASSERT_EQ(0, dah_->GetMetaDataMap(element_path_original, &ser_mdm_recovered_original));

  // Check file is not renamed over existing file when force bool is set to false
  ASSERT_NE(0, dah_->RenameElement(element_path_original, element_path_exists, false));
  ASSERT_EQ(0, dah_->GetDataMap(element_path_exists, &ser_dm_recovered_exists));
  ASSERT_EQ(0, dah_->GetMetaDataMap(element_path_exists, &ser_mdm_recovered_exists));
  ASSERT_TRUE(recovered_dm_exists.ParseFromString(ser_dm_recovered_exists));
  ASSERT_TRUE(recovered_mdm_exists.ParseFromString(ser_mdm_recovered_exists));
  ASSERT_EQ(dm_exists.file_hash(), recovered_dm_exists.file_hash());
  ASSERT_EQ(mdm_exists.stats(), recovered_mdm_exists.stats());

  // Check file is renamed over existing file when force bool is set to true
  ASSERT_EQ(0, dah_->RenameElement(element_path_original, element_path_exists, true));
  ASSERT_EQ(0, dah_->GetDataMap(element_path_exists, &ser_dm_recovered_copy2));
  ASSERT_EQ(0, dah_->GetMetaDataMap(element_path_exists, &ser_mdm_recovered_copy2));
  ASSERT_TRUE(recovered_dm_copy2.ParseFromString(ser_dm_recovered_copy2));
  ASSERT_TRUE(recovered_mdm_copy2.ParseFromString(ser_mdm_recovered_copy2));
  ASSERT_EQ(dm_original.file_hash(), recovered_dm_copy2.file_hash());
  ASSERT_EQ(mdm_original.stats(), recovered_mdm_copy2.stats());
  ser_dm_recovered_original="";
  ser_mdm_recovered_original="";
  ASSERT_NE(0, dah_->GetDataMap(element_path_original, &ser_dm_recovered_original));
  ASSERT_NE(0, dah_->GetMetaDataMap(element_path_original, &ser_mdm_recovered_original));
}

TEST_F(DataAtlasHandlerTest, BEH_MAID_RemoveMSFileRepeatedDataMap) {
  // Test to check the removal of a MSFile whose DataMap is also in another ms_path
  // so the DataMap must not be removed

  // declare a serialised DataMap and serialised MetaDataMap
  boost::scoped_ptr<DataAtlasHandler> dah_(new DataAtlasHandler());
  std::string ser_dm="", ser_mdm="", ser_mdm2="", ser_dm_recovered="",\
    ser_mdm_recovered="", ser_mdm_recovered2="";
  std::string dir_name = base::TidyPath(kRootSubdir[0][0]) + "/";
  std::string file_name = "Doc4.doc";
  std::string file_name2 = "MyFiLe.doc";
  std::string element_path = dir_name+file_name;
  std::string element_path2 = dir_name+file_name2;
  std::string file_hash = "file hash1";

  // Creating DataMap
  DataMap dm;
  dm.set_file_hash(file_hash);
  dm.add_chunk_name("chunk1");
  dm.add_chunk_name("chunk2");
  dm.add_chunk_name("chunk3");
  dm.add_encrypted_chunk_name("enc_chunk1");
  dm.add_encrypted_chunk_name("enc_chunk2");
  dm.add_encrypted_chunk_name("enc_chunk3");
  dm.SerializeToString(&ser_dm);

  // Creating MetaDataMap
  MetaDataMap mdm;
  mdm.set_id(-2);
  mdm.set_display_name(file_name);
  mdm.set_type(REGULAR_FILE);
  mdm.add_file_hash(file_hash);
  mdm.set_stats("STATS");
  mdm.set_tag("TAG");
  mdm.set_file_size_high(4);
  mdm.set_file_size_low(5);
  mdm.set_creation_time(6);
  mdm.set_last_modified(7);
  mdm.set_last_access(8);
  mdm.SerializeToString(&ser_mdm);

  // Adding it to the DataAtlas
  ASSERT_EQ(0, dah_->AddElement(element_path, ser_mdm, ser_dm, "", true))<<"DataMap and Metadata of file were not added to DataAtlas";

  // Check the added DM exists in the DataAtlas
  ASSERT_EQ(0, dah_->GetDataMap(element_path, &ser_dm_recovered))<<"Didn't retrieve DataMap from DataAtlas";
  ASSERT_EQ(0, dah_->GetMetaDataMap(element_path, &ser_mdm_recovered))<<"Didn't retrieve MetaDataMap from DataAtlas";

  // Creating MetaDataMap
  MetaDataMap mdm2;
  mdm.set_id(-2);
  mdm.set_display_name(file_name2);
  mdm.set_type(SMALL_FILE);
  mdm.add_file_hash(file_hash);
  mdm.set_stats("STATS");
  mdm.set_tag("TAG");
  mdm.set_file_size_high(4);
  mdm.set_file_size_low(5);
  mdm.set_creation_time(6);
  mdm.set_last_modified(7);
  mdm.set_last_access(8);
  mdm.SerializeToString(&ser_mdm2);

  // Adding it to the DataAtlas
  ASSERT_EQ(0, dah_->AddElement(element_path2, ser_mdm2, ser_dm, "", true))<<"DataMap and Metadata of file were not added to DataAtlas";

  // Check the added DM exists in the DataAtlas
  ASSERT_EQ(0, dah_->GetDataMap(element_path2, &ser_dm_recovered))<<"Didn't retrieve DataMap from DataAtlas";
  ASSERT_EQ(0, dah_->GetMetaDataMap(element_path2, &ser_mdm_recovered2))<<"Didn't retrieve MetaDataMap from DataAtlas";

  // Check DM is sucessfully removed from the DataAtlas
  ASSERT_EQ(0, dah_->RemoveElement(element_path));

  // Check sucessful deletion of the ms_path from the DataAtlas and that the DM is still there
  ASSERT_EQ(0, dah_->GetDataMap(element_path2, &ser_dm_recovered))<<"DataMap was removed from the DataAtlas";
  ASSERT_NE(0, dah_->GetMetaDataMap(element_path, &ser_mdm_recovered))<<"ms_path still in DataAtlas";

  // ASSERT_EQ(0, dah_->DisconnectPdDir("Test"))<<"Couldn't disconnect from database";
}

TEST_F(DataAtlasHandlerTest, BEH_MAID_AddRepeatedDataMap) {
  // Test to insert a DataMap and Retrieve it
  // Test to check the removal of a MSFile whose DataMap is also in another ms_path
  // so the DataMap must not be removed

  // declare a serialised DataMap and serialised MetaDataMap
  boost::scoped_ptr<DataAtlasHandler> dah_(new DataAtlasHandler());
  std::string ser_dm="", ser_mdm1="", ser_mdm2="", ser_dm_recovered1="", \
    ser_dm_recovered2="", ser_mdm_recovered1="", ser_mdm_recovered2="";
  std::string dir_name = base::TidyPath(kRootSubdir[0][0]) + "/";
  std::string file_name1 = "Doc5.doc";
  std::string file_name2 = "MyFiLe2.doc";
  std::string element_path1 = dir_name+file_name1;
  std::string element_path2 = dir_name+file_name2;
  std::string file_hash = "file hash1";

  // Creating DataMap
  DataMap dm;
  dm.set_file_hash(file_hash);
  dm.add_chunk_name("chunk1");
  dm.add_chunk_name("chunk2");
  dm.add_chunk_name("chunk3");
  dm.add_encrypted_chunk_name("enc_chunk1");
  dm.add_encrypted_chunk_name("enc_chunk2");
  dm.add_encrypted_chunk_name("enc_chunk3");
  dm.SerializeToString(&ser_dm);

  // Creating MetaDataMap
  MetaDataMap mdm1;
  mdm1.set_id(-2);
  mdm1.set_display_name(file_name1);
  mdm1.set_type(REGULAR_FILE);
  mdm1.add_file_hash(file_hash);
  mdm1.set_stats("STATS1");
  mdm1.set_tag("TAG1");
  mdm1.set_file_size_high(4);
  mdm1.set_file_size_low(5);
  mdm1.set_creation_time(6);
  mdm1.set_last_modified(7);
  mdm1.set_last_access(8);
  mdm1.SerializeToString(&ser_mdm1);

  // Adding it to the DataAtlas
  ASSERT_EQ(0, dah_->AddElement(element_path1, ser_mdm1, ser_dm, "", true))<<"DataMap and Metadata of file were not added to DataAtlas";

  // Creating MetaDataMap
  MetaDataMap mdm2;
  mdm2.set_id(-2);
  mdm2.set_display_name(file_name2);
  mdm2.set_type(SMALL_FILE);
  mdm2.add_file_hash(file_hash);
  mdm2.set_stats("STATS2");
  mdm2.set_tag("TAG2");
  mdm2.set_file_size_high(9);
  mdm2.set_file_size_low(10);
  mdm2.set_creation_time(11);
  mdm2.set_last_modified(12);
  mdm2.set_last_access(13);
  mdm2.SerializeToString(&ser_mdm2);

  // Adding it to the DataAtlas
  ASSERT_EQ(0, dah_->AddElement(element_path2, ser_mdm2, ser_dm, "", true))<<"DataMap and Metadata of file were not added to DataAtlas";

  MetaDataMap recovered_mdm1;
  MetaDataMap recovered_mdm2;

  ASSERT_EQ(0, dah_->GetMetaDataMap(element_path1, &ser_mdm_recovered1))<<"Didn't retrieve MetaDataMap from DataAtlas";
  ASSERT_EQ(0, dah_->GetMetaDataMap(element_path2, &ser_mdm_recovered2))<<"Didn't retrieve MetaDataMap from DataAtlas";
  EXPECT_TRUE(recovered_mdm1.ParseFromString(ser_mdm_recovered1));
  EXPECT_TRUE(recovered_mdm2.ParseFromString(ser_mdm_recovered2));

  ASSERT_EQ(file_name1, recovered_mdm1.display_name());
  ASSERT_EQ(file_name2, recovered_mdm2.display_name());
  ASSERT_EQ(file_hash, recovered_mdm1.file_hash(0));
  ASSERT_EQ(file_hash, recovered_mdm2.file_hash(0));

  DataMap recovered_dm;

  ASSERT_EQ(0, dah_->GetDataMap(element_path1, &ser_dm_recovered1))<<"Didn't retrieve DataMap from DataAtlas";
  EXPECT_TRUE(recovered_dm.ParseFromString(ser_dm_recovered1));
  EXPECT_EQ(dm.file_hash(), recovered_dm.file_hash());
  ASSERT_EQ(dm.chunk_name_size(), recovered_dm.chunk_name_size());
  for (int i = 0; i < dm.chunk_name_size(); i++){
      EXPECT_EQ(dm.chunk_name(i), recovered_dm.chunk_name(i));
  }
  ASSERT_EQ(dm.encrypted_chunk_name_size(), recovered_dm.encrypted_chunk_name_size());
  for (int i = 0; i < dm.encrypted_chunk_name_size(); i++){
      EXPECT_EQ(dm.encrypted_chunk_name(i), recovered_dm.encrypted_chunk_name(i));
  }

  ASSERT_EQ(0, dah_->GetDataMap(element_path2, &ser_dm_recovered2))<<"Didn't retrieve DataMap from DataAtlas";
  EXPECT_EQ(ser_dm_recovered1, ser_dm_recovered2)<<"DataMaps aren't the same";

  // ASSERT_EQ(0, dah_->DisconnectPdDir("Test"))<<"Couldn't disconnect from database";
}

TEST_F(DataAtlasHandlerTest, BEH_MAID_AddEmptyDir){
  // Adds an empty directory to the DataAtlas and then adds a regular file
  // to the directory
  boost::scoped_ptr<DataAtlasHandler> dah_(new DataAtlasHandler());
  std::string ser_dm="", ser_mdm1="", ser_mdm2="", ser_dm_recovered="", \
    ser_mdm_recovered1="", ser_mdm_recovered2="";
  std::string dir_name = base::TidyPath(kRootSubdir[0][0]) + "/";
  std::string file_name1 = "Docs";
  std::string file_name2 = "MyFiLe3.doc";
  std::string element_path1 = dir_name+file_name1;
  std::string element_path2 = element_path1+"/"+file_name2;
  std::string file_hash = "file hash1";

  // Creating DataMap
  DataMap dm;
  dm.set_file_hash(file_hash);
  dm.add_chunk_name("chunk1");
  dm.add_chunk_name("chunk2");
  dm.add_chunk_name("chunk3");
  dm.add_encrypted_chunk_name("enc_chunk1");
  dm.add_encrypted_chunk_name("enc_chunk2");
  dm.add_encrypted_chunk_name("enc_chunk3");
  dm.SerializeToString(&ser_dm);

  // Creating MetaDataMaps
  MetaDataMap mdm1, mdm2;
  mdm1.set_id(-2);
  mdm1.set_display_name(file_name1);
  mdm1.set_type(EMPTY_DIRECTORY);
  mdm1.set_stats("STATS1");
  mdm1.set_tag("TAG1");
  mdm1.set_creation_time(6);
  mdm1.set_last_modified(7);
  mdm1.set_last_access(8);
  mdm1.SerializeToString(&ser_mdm1);
  mdm2.set_id(-2);
  mdm2.set_display_name(file_name2);
  mdm2.set_type(REGULAR_FILE);
  mdm2.add_file_hash(file_hash);
  mdm2.set_stats("STATS2");
  mdm2.set_tag("TAG2");
  mdm2.set_file_size_high(9);
  mdm2.set_file_size_low(10);
  mdm2.set_creation_time(11);
  mdm2.set_last_modified(12);
  mdm2.set_last_access(13);
  mdm2.SerializeToString(&ser_mdm2);

  MetaDataMap recovered_mdm1, recovered_mdm2;
  DataMap recovered_dm;

  //  Add and retrieve data for folder
  ASSERT_EQ(0, dah_->AddElement(element_path1, ser_mdm1, "", "Dir Key", true))<<"Metadata of directory was not added to DataAtlas";
  ASSERT_EQ(0, dah_->GetMetaDataMap(element_path1, &ser_mdm_recovered1))<<"Didn't retrieve MetaDataMap from DataAtlas";
  EXPECT_TRUE(recovered_mdm1.ParseFromString(ser_mdm_recovered1))<<"Metadata corrupted (cannot be parsed)";
  ASSERT_EQ(mdm1.display_name(), recovered_mdm1.display_name())<<"Display name has changed in MetaDataMap";
  ASSERT_EQ(mdm1.type(), recovered_mdm1.type())<<"Directory type has changed in MetaDataMap";
  ASSERT_EQ(mdm1.stats(), recovered_mdm1.stats())<<"Stats have changed in MetaDataMap";
  ASSERT_EQ(mdm1.tag(), recovered_mdm1.tag())<<"Tag has changed in MetaDataMap";
  ASSERT_EQ(mdm1.file_size_high(), recovered_mdm1.file_size_high())<<"file_size_high has changed in MetaDataMap";
  ASSERT_EQ(mdm1.file_size_low(), recovered_mdm1.file_size_low())<<"file_size_low has changed in MetaDataMap";
  ASSERT_EQ(mdm1.creation_time(), recovered_mdm1.creation_time())<<"Creation time has changed in MetaDataMap";
  ASSERT_NE(mdm1.last_modified(), recovered_mdm1.last_modified())<<"Last modified time has not changed in MetaDataMap";
  ASSERT_NE(mdm1.last_access(), recovered_mdm1.last_access())<<"Last access time has not changed in MetaDataMap";

  //  Add and retrieve data for file
  ASSERT_EQ(0, dah_->AddElement(element_path2, ser_mdm2, ser_dm, "", true))<<"Metadata and DataMap of file was not added to DataAtlas";
  ASSERT_EQ(0, dah_->GetMetaDataMap(element_path2, &ser_mdm_recovered2))<<"Didn't retrieve MetaDataMap from DataAtlas";
  ASSERT_EQ(0, dah_->GetDataMap(element_path2, &ser_dm_recovered))<<"Didn't retrieve DataMap from DataAtlas";
  EXPECT_TRUE(recovered_mdm2.ParseFromString(ser_mdm_recovered2))<<"MetaDataMap corrupted (cannot be parsed)";
  ASSERT_EQ(mdm2.display_name(), recovered_mdm2.display_name())<<"Display name has changed in MetaDataMap";
  ASSERT_EQ(mdm2.type(), recovered_mdm2.type())<<"File type has changed in MetaDataMap";
  ASSERT_EQ(mdm2.file_hash(0), recovered_mdm2.file_hash(0))<<"File hash has changed in MetaDataMap";
  ASSERT_EQ(mdm2.stats(), recovered_mdm2.stats())<<"Stats have changed in MetaDataMap";
  ASSERT_EQ(mdm2.tag(), recovered_mdm2.tag())<<"Tag has changed in MetaDataMap";
  ASSERT_EQ(mdm2.file_size_high(), recovered_mdm2.file_size_high())<<"file_size_high has changed in MetaDataMap";
  ASSERT_EQ(mdm2.file_size_low(), recovered_mdm2.file_size_low())<<"file_size_low has changed in MetaDataMap";
  ASSERT_EQ(mdm2.creation_time(), recovered_mdm2.creation_time())<<"Creation time has changed in MetaDataMap";
  ASSERT_NE(mdm2.last_modified(), recovered_mdm2.last_modified())<<"Last modified time has not changed in MetaDataMap";
  ASSERT_NE(mdm2.last_access(), recovered_mdm2.last_access())<<"Last access time has not changed in MetaDataMap";
  ASSERT_EQ(ser_dm, ser_dm_recovered)<<"DataMap different from original";
  EXPECT_TRUE(recovered_dm.ParseFromString(ser_dm_recovered))<<"DataMap corrupted (cannot be parsed)";

  // TODO:-
  // ASSERT_EQ(DIRECTORY, recovered_mdm1.type())<<"Directory MetaDataMap not updated from 'EMPTY_DIRECTORY'";
}

TEST_F(DataAtlasHandlerTest, BEH_MAID_EmptyFileHandling){
  // Adds an empty file to the directory, then changes the file to non-empty
  boost::scoped_ptr<DataAtlasHandler> dah_(new DataAtlasHandler());
  std::string ser_dm1="", ser_mdm1="", ser_dm_recovered1="", ser_mdm_recovered1="";
  std::string ser_dm2="", ser_mdm2="", ser_dm_recovered2="", ser_mdm_recovered2="";
  std::string dir_name = base::TidyPath(kRootSubdir[0][0]) + "/";
  std::string file_name = "MyFiLe4.doc";
  std::string element_path = dir_name+file_name;
  std::string file_hash_empty = "empty file hash";
  std::string file_hash_regular = "regular file hash";

  // Creating DataMap
  DataMap dm1;
  dm1.set_file_hash(file_hash_empty);
  dm1.SerializeToString(&ser_dm1);

  // Creating MetaDataMap
  MetaDataMap mdm1;
  mdm1.set_id(-2);
  mdm1.set_display_name(file_name);
  mdm1.set_type(EMPTY_FILE);
  mdm1.add_file_hash(file_hash_empty);
  mdm1.set_stats("EMPTY STATS3");
  mdm1.set_tag("EMPTY TAG3");
  mdm1.set_file_size_high(0);
  mdm1.set_file_size_low(0);
  mdm1.set_creation_time(14);
  mdm1.set_last_modified(15);
  mdm1.set_last_access(16);
  mdm1.SerializeToString(&ser_mdm1);

  MetaDataMap recovered_mdm1;
  DataMap recovered_dm1;

  //  Add and retrieve data for file
  ASSERT_EQ(0, dah_->AddElement(element_path, ser_mdm1, ser_dm1, "", true))<<"Metadata and DataMap of file was not added to DataAtlas";
  ASSERT_EQ(0, dah_->GetMetaDataMap(element_path, &ser_mdm_recovered1))<<"Didn't retrieve MetaDataMap from DataAtlas";
  ASSERT_EQ(0, dah_->GetDataMap(element_path, &ser_dm_recovered1))<<"Didn't retrieve DataMap from DataAtlas";
  EXPECT_TRUE(recovered_mdm1.ParseFromString(ser_mdm_recovered1))<<"MetaDataMap corrupted (cannot be parsed)";
  EXPECT_TRUE(recovered_dm1.ParseFromString(ser_dm_recovered1))<<"DataMap corrupted (cannot be parsed)";
  ASSERT_EQ(mdm1.display_name(), recovered_mdm1.display_name())<<"Metadata different from original";
  ASSERT_EQ(ser_dm1, ser_dm_recovered1)<<"DataMap different from original";

  //  Update DataMap
  DataMap dm2;
  dm2.set_file_hash(file_hash_regular);
  dm2.add_chunk_name("chunka");
  dm2.add_chunk_name("chunkb");
  dm2.add_chunk_name("chunkc");
  dm2.add_encrypted_chunk_name("enc_chunkd");
  dm2.add_encrypted_chunk_name("enc_chunke");
  dm2.add_encrypted_chunk_name("enc_chunkf");
  dm2.SerializeToString(&ser_dm2);

  //  Update MetaDataMap
  MetaDataMap mdm2;
  mdm2.set_id(-2);
  mdm2.set_display_name(file_name);
  mdm2.set_type(REGULAR_FILE);
  mdm2.add_file_hash(file_hash_regular);
  mdm2.set_stats("REGULAR STATS3");
  mdm2.set_tag("REGULAR TAG3");
  mdm2.set_file_size_high(1);
  mdm2.set_file_size_low(999);
  mdm2.set_creation_time(999);
  mdm2.set_last_modified(15);
  mdm2.set_last_access(16);
  EXPECT_TRUE(mdm2.SerializeToString(&ser_mdm2))<<"Didn't serialise the MetaDataMap";

  MetaDataMap recovered_mdm2;
  DataMap recovered_dm2;

  ASSERT_EQ(0, dah_->ModifyMetaDataMap(element_path, ser_mdm2, ser_dm2))<<"Didn't modify DataAtlas";
  ASSERT_EQ(0, dah_->GetMetaDataMap(element_path, &ser_mdm_recovered2))<<"Didn't retrieve MetaDataMap from DataAtlas";
  ASSERT_EQ(0, dah_->GetDataMap(element_path, &ser_dm_recovered2))<<"Didn't retrieve DataMap from DataAtlas";
  EXPECT_TRUE(recovered_mdm2.ParseFromString(ser_mdm_recovered2))<<"MetaDataMap corrupted (cannot be parsed)";
  EXPECT_TRUE(recovered_dm2.ParseFromString(ser_dm_recovered2))<<"DataMap corrupted (cannot be parsed)";
  ASSERT_EQ(recovered_mdm1.id(), recovered_mdm2.id())<<"ID has changed in MetaDataMap";
  ASSERT_EQ(mdm1.display_name(), recovered_mdm2.display_name())<<"Display name has changed in MetaDataMap";
  ASSERT_NE(mdm1.type(), recovered_mdm2.type())<<"File type has not changed in MetaDataMap";
  ASSERT_NE(mdm1.file_hash(0), recovered_mdm2.file_hash(0))<<"Hash has not changed in MetaDataMap";
  ASSERT_NE(mdm1.stats(), recovered_mdm2.stats())<<"Stats have not changed in MetaDataMap";
  ASSERT_NE(mdm1.tag(), recovered_mdm2.tag())<<"Tag has not changed in MetaDataMap";
  ASSERT_NE(mdm1.file_size_high(), recovered_mdm2.file_size_high())<<"file_size_high has not changed in MetaDataMap";
  ASSERT_NE(mdm1.file_size_low(), recovered_mdm2.file_size_low())<<"file_size_low has not changed in MetaDataMap";
  ASSERT_EQ(mdm1.creation_time(), recovered_mdm2.creation_time())<<"Creation time has changed in MetaDataMap";
  ASSERT_NE(dm1.file_hash(), recovered_dm2.file_hash())<<"Hash has not changed in DataMap";
  ASSERT_NE("", recovered_dm2.chunk_name(0))<<"Chunk 1 has not changed in DataMap";
  ASSERT_NE("", recovered_dm2.chunk_name(1))<<"Chunk 2 has not changed in DataMap";
  ASSERT_NE("", recovered_dm2.chunk_name(2))<<"Chunk 3 has not changed in DataMap";
  ASSERT_NE("", recovered_dm2.encrypted_chunk_name(0))<<"Enc Chunk 1 has not changed in DataMap";
  ASSERT_NE("", recovered_dm2.encrypted_chunk_name(1))<<"Enc Chunk 2 has not changed in DataMap";
  ASSERT_NE("", recovered_dm2.encrypted_chunk_name(2))<<"Enc Chunk 3 has not changed in DataMap";
}

TEST_F(DataAtlasHandlerTest, BEH_MAID_AddKeys) {
  // Test to add a public/private key pairs to the Keyring
  // std::string kKeyRingFile = fsys_.MaidsafeDir()+"/keyring1.db";
  // if (fs::exists(kKeyRingFile))
  //   fs::remove(kKeyRingFile);
  // dah_->CreateKeysDb(kKeyRingFile);


  boost::scoped_ptr<DataAtlasHandler> dah_(new DataAtlasHandler());
  std::string public_key = "public key maid"; // once the crypto component is ready this can change to actual RSA keys
  std::string private_key = "private key maid";
  std::string id = "maidID"; // name of the packet that stores the key in the dht
  std::stringstream out;
  out << MAID;
  // PacketType package_type = MAID;
  std::string package_type = out.str();

  ASSERT_EQ(0, dah_->AddKeys(package_type, id, private_key, public_key))<<"Fail to add to key ring";

  ASSERT_EQ(id, dah_->GetPackageID(package_type))<<"could not retrieve ID for packet type stored";
  ASSERT_EQ(private_key, dah_->GetPrivateKey(package_type))<<"could not retrieve private key for packet type stored";
  ASSERT_EQ(public_key, dah_->GetPublicKey(package_type))<<"could not retrieve public key for packet type stored";

  // Add a second key
  public_key = "public key pmid"; // once the crypto component is ready this can change to actual RSA keys
  private_key = "private key pmid";
  id = "pmidID"; // name of the packet that stores the key in the dht
  // package_type = PMID;
  out.str("");
  out << PMID;
  package_type = out.str();

  ASSERT_EQ(0, dah_->AddKeys(package_type, id, private_key, public_key))<<"Fail to add to key ring";

  ASSERT_EQ(id, dah_->GetPackageID(package_type))<<"could not retrieve ID for packet type stored";
  ASSERT_EQ(private_key, dah_->GetPrivateKey(package_type))<<"could not retrieve private key for packet type stored";
  ASSERT_EQ(public_key, dah_->GetPublicKey(package_type))<<"could not retrieve public key for packet type stored";

  // Replace the first key
  public_key = "public key maid two"; // once the crypto component is ready this can change to actual RSA keys
  private_key = "private key maid two";
  id = "maidID2"; // name of the packet that stores the key in the dht
  // package_type = MAID;
  out.str("");
  out << MAID;
  package_type = out.str();

  ASSERT_EQ(0, dah_->AddKeys(package_type, id, private_key, public_key))<<"Fail to add to key ring";

  ASSERT_EQ(id, dah_->GetPackageID(package_type))<<"could not retrieve ID for packet type stored";
  ASSERT_EQ(private_key, dah_->GetPrivateKey(package_type))<<"could not retrieve private key for packet type stored";
  ASSERT_EQ(public_key, dah_->GetPublicKey(package_type))<<"could not retrieve public key for packet type stored";

  // dah_->DisconnectKeysDb();
  // ASSERT_EQ(0, dah_->DisconnectKeysDb())<<"Did not disconnect correctly.";
  // fs::remove(fsys_.MaidsafeDir()+"/84e3eb1c67711668b6424fe0c38bf2212757697e");
}

TEST_F(DataAtlasHandlerTest, BEH_MAID_RemoveKeys) {
  // Test to check the removal of a public/private key pair and ID from the DataAtlas
  // std::string kKeyRingFile = fsys_.MaidsafeDir()+"/keyring2.db";
  // if (fs::exists(kKeyRingFile))
  //   fs::remove(kKeyRingFile);
  // dah_->CreateKeysDb(kKeyRingFile);


  boost::scoped_ptr<DataAtlasHandler> dah_(new DataAtlasHandler());
  std::string public_key = "public key"; // once the crypto component is ready this can change to actual RSA keys
  std::string private_key = "private key";
  std::string id = "maidID"; // name of the packet that stores the key in the dht
  // PacketType package_type = MAID;
  std::stringstream out;
  out << MAID;
  std::string package_type = out.str();

  ASSERT_EQ(0, dah_->AddKeys(package_type, id, private_key, public_key));
  // getting id, private_key, and public_key

  // Add a second key
  public_key = "public key pmid"; // once the crypto component is ready this can change to actual RSA keys
  private_key = "private key pmid";
  id = "pmidID"; // name of the packet that stores the key in the dht
  // package_type = PMID;
  out.str("");
  out << PMID;
  package_type = out.str();

  ASSERT_EQ(0, dah_->AddKeys(package_type, id, private_key, public_key))<<"Fail to add to key ring";

  // package_type = MAID;
  out.str("");
  out << MAID;
  package_type = out.str();

  ASSERT_EQ(0, dah_->RemoveKeys(package_type));
  ASSERT_EQ("", dah_->GetPackageID(package_type))<<"id for packet type is still in key ring";
  ASSERT_EQ("", dah_->GetPrivateKey(package_type))<<"private key for packet type is still in key ring";
  ASSERT_EQ("", dah_->GetPublicKey(package_type))<<"public key for packet type is still in key ring";
}











/*
TEST_F(DataAtlasHandlerTest, Serialise) {
  // Test to serialise the DataAtlas

  string ser_da;
  DataAtlasHandler data_atlas_handler2;
  const char* kDataBaseFile2 = "dataatlas2.db";
  data_atlas_handler2.Init(kDataBaseFile2);

  // DataAtlasHandler data_atlas_handler2;
  //   empty DataAtlas must return empty vector of msfiles
  vector<int32_t> filepaths;
  data_atlas_handler.ListFolder(0, filepaths);
  EXPECT_TRUE(filepaths.empty());
  ser_da = data_atlas_handler.SerialiseDataAtlas();
  ASSERT_TRUE(data_atlas_handler2.ParseFromStringDataAtlas(ser_da));
  data_atlas_handler2.ListFolder(0, filepaths);
  ASSERT_TRUE(filepaths.empty());

  // delete &data_atlas_handler2;
  // Adding DataMaps to the DataAtlas
  string ser_dm, ser_mdm;

  unsigned int i;
  bool result;
  DataMap dm;
  MetaDataMap mdm;
  string name[5];
  string filehashes[5] = {"fh1","fh2","fh3","fh4","fh5"};
  name[0] = "doc1.doc";
  name[1] = "doc2.doc";
  name[2] = "doc3.doc";
  name[3] = "doc4.doc";
  name[4] = "song1.mp3";


  for (i=0; i < 5; i++){
  // Creating DataMap
    dm.set_file_hash(filehashes[i]);
    dm.add_chunk_name("chunk1");
    dm.add_chunk_name("chunk2");
    dm.add_chunk_name("chunk3");
    dm.add_encrypted_chunk_name("enc_chunk1");
    dm.add_encrypted_chunk_name("enc_chunk2");
    dm.add_encrypted_chunk_name("enc_chunk3");
    dm.SerializeToString(&ser_dm);
    dm.clear_file_hash();
    dm.clear_chunk_name();
    dm.clear_encrypted_chunk_name();
    // Creating MetaDataMap
    mdm.set_id(i+1);
    mdm.set_parent_id(0);
    mdm.set_name(name[i]);
    mdm.add_file_hash(filehashes[i]);
    mdm.set_type(REGULAR_FILE);
    mdm.SerializeToString(&ser_mdm);
    mdm.clear_id();
    mdm.clear_name();
    mdm.clear_type();
    mdm.clear_file_hash();
    result = data_atlas_handler.AddMSFile(ser_dm, ser_mdm);
  }

  //  5 data maps have now been added to the DataAtlas

  // Add two key pairs to the DataAtlas


  ASSERT_TRUE(data_atlas_handler.AddKeys(MAID, "maidID", "private_key1", "public_key1"));
  ASSERT_TRUE(data_atlas_handler.AddKeys(ANMID, "ANMID", "private_key2", "public_key2"));

  data_atlas_handler.ListFolder(0, filepaths);
  ASSERT_TRUE(filepaths.size() == 5);

  string maidID = data_atlas_handler.GetPackageID(MAID);
  string anmidID = data_atlas_handler.GetPackageID(ANMID);

  string maid_privkey = data_atlas_handler.GetPrivateKey(MAID);
  string anmid_privkey = data_atlas_handler.GetPrivateKey(ANMID);

  string maid_pubkey = data_atlas_handler.GetPublicKey(MAID);
  string anmid_pubkey = data_atlas_handler.GetPublicKey(ANMID);



  DataAtlasHandler data_atlas_handler3;
  const char* kDataBaseFile3 = "dataatlas3.db";
  data_atlas_handler3.Init(kDataBaseFile3);


  //  Now serialise the DataAtlas

  ser_da = data_atlas_handler.SerialiseDataAtlas();
  ASSERT_TRUE(data_atlas_handler3.ParseFromStringDataAtlas(ser_da));

  // check that the serialised DataAtlas returns the values we originally wrote to it
  vector<int32_t> filepaths2;
  data_atlas_handler3.ListFolder(0, filepaths2);
  ASSERT_EQ(filepaths.size(), filepaths2.size());

  for (i=0; i < filepaths.size(); i++)
      EXPECT_TRUE(filepaths[i] == filepaths2[i]);

  ASSERT_EQ(maidID,data_atlas_handler3.GetPackageID(MAID));
  ASSERT_EQ(anmidID,data_atlas_handler3.GetPackageID(ANMID));
  ASSERT_EQ(maid_privkey,data_atlas_handler3.GetPrivateKey(MAID));
  ASSERT_EQ(anmid_privkey,data_atlas_handler3.GetPrivateKey(ANMID));
  ASSERT_EQ(maid_pubkey,data_atlas_handler3.GetPublicKey(MAID));
  ASSERT_EQ(anmid_pubkey,data_atlas_handler3.GetPublicKey(ANMID));

  data_atlas_handler2.Close();
  data_atlas_handler3.Close();

}
*/








TEST_F(DataAtlasHandlerTest, ReturnKeyRingList) {
  // std::string kKeyRingFile = fsys_.MaidsafeDir()+"/keyring3.db";
  // if (fs::exists(kKeyRingFile))
  //   fs::remove(kKeyRingFile);
  // dah_->CreateKeysDb(kKeyRingFile);

  // declare an empty local list of Key_Type
  boost::scoped_ptr<DataAtlasHandler> dah_(new DataAtlasHandler());
  std::list<Key_Type> local_empty_key_ring_list;
  for (int i=0; i<7; i++) {
    // dah_->RemoveKeys((PacketType)i);
    dah_->RemoveKeys(base::itos(i));
  }

  // write an empty KeyRing from the DB to the local variable
  dah_->GetKeyRing(&local_empty_key_ring_list);

  // check local list is empty
  ASSERT_TRUE(local_empty_key_ring_list.empty());

  // create some IDs
  const int no_of_ids = 6;

  std::stringstream out;

  Key_Type test_data[no_of_ids];

  test_data[0].package_type = PMID;
  test_data[0].id = "PMID";
  test_data[0].private_key = "private key pmid";
  test_data[0].public_key = "public key pmid";

  test_data[4].package_type = MAID;
  test_data[4].id = "MAID";
  test_data[4].private_key = "private key maid";
  test_data[4].public_key = "public key maid";

  test_data[1].package_type = ANMID;
  test_data[1].id = "ANMID";
  test_data[1].private_key = "private key anmid";
  test_data[1].public_key = "public key anmid";

  test_data[2].package_type = ANTMID;
  test_data[2].id = "ANTMID";
  test_data[2].private_key = "private key antmid";
  test_data[2].public_key = "public key antmid";

  test_data[3].package_type = ANSMID;
  test_data[3].id = "ANSMID";
  test_data[3].private_key = "private key ansmid";
  test_data[3].public_key = "public key ansmid";

  test_data[5].package_type = ANMPID;
  test_data[5].id = "ANMPID";
  test_data[5].private_key = "private key anmpid";
  test_data[5].public_key = "public key anmpid";

  int i;

  // Add IDs to the Database
  for (i=0; i<no_of_ids; i++) {
      out << test_data[i].package_type;
      std::string package_type = out.str();
      /*ASSERT_EQ(0, dah_->AddKeys(test_data[i].package_type, test_data[i].id, test_data[i].private_key, test_data[i].public_key))\*/
      ASSERT_EQ(0, dah_->AddKeys(package_type, test_data[i].id, test_data[i].private_key, test_data[i].public_key))\
        <<"Failed to add an ID to key ring";
      out.str("");
  }

  // declare a local list of Key_Type
  std::list<Key_Type> local_key_ring_list;

  // write the KeyRing in the DB to the local_key_ring_list variable
  dah_->GetKeyRing(&local_key_ring_list);

  // check local_key_ring is not empty
  ASSERT_FALSE(local_key_ring_list.empty()) << "Key Ring Database has no entries";

  ASSERT_EQ((unsigned)no_of_ids, local_key_ring_list.size()) << "Key Ring Database length is not equal to the number of IDs";


  int j;
  for (j=0; j < no_of_ids; j++) {

    Key_Type templine=local_key_ring_list.front();
    local_key_ring_list.pop_front();

    ASSERT_EQ(test_data[j].package_type, templine.package_type) << "package_type retrieved from DB is corrupted";
    ASSERT_EQ(test_data[j].id, templine.id) << "id retrieved from DB is corrupted";
    ASSERT_EQ(test_data[j].private_key, templine.private_key) << "private_key retrieved from DB is corrupted";
    ASSERT_EQ(test_data[j].public_key, templine.public_key) << "public_key retrieved from DB is corrupted";
  }
}





/*
TEST_F(DataAtlasHandlerTest, AddGetShare) {
  std::vector<std::string> file_names;
  std::vector<int32_t> file_ids;
  std::vector<std::string> folder_names;
  std::vector<int32_t> folder_ids;
  PrepareDataAtlas(&data_atlas_handler, file_names, file_ids, folder_names,
    folder_ids);
  // prepare the share
  int32_t share_id = rand();
  std::string share_name = base::RandomString(256);
  std::string owner = "Haiyang.Ma";
  std::vector<int32_t> share_items;
  share_items.push_back(file_ids[0]);
  share_items.push_back(file_ids[1]);
  share_items.push_back(folder_ids[0]);
  share_items.push_back(folder_ids[1]);
  std::vector<std::string> users;
  users.push_back("Richard.Johnstone");
  users.push_back("Jose.Crineros");
  users.push_back("David.Irvine");
  std::map<std::string, std::string> buffer_messages;
  std::vector<std::string> share_items1;
  share_items1.push_back("/nonexistingMSPath/file.doc");
  ASSERT_FALSE(data_atlas_handler.AddShare(share_id, share_name, owner,
    share_items1, users, buffer_messages))<<"Should fail to create a share \
      because the items donot exist in the current dataatlas.";
  buffer_messages.clear();

  std::vector<std::string> share_items_paths;

  for (int i=0;i<(int)share_items.size();i++){
    std::string path;
    ASSERT_TRUE(data_atlas_handler.GetMaidsafePath(share_items[i], path));
    share_items_paths.push_back(path);
  }

  ASSERT_TRUE(data_atlas_handler.AddShare(share_id, share_name, owner,
    share_items_paths, users, buffer_messages))<<"Failed to create a share";
  ASSERT_EQ((unsigned)3, buffer_messages.size())<<"Should generate 3 buffer messages";
  ASSERT_EQ(share_name, data_atlas_handler.GetShareName(share_id));
  std::vector<int32_t> get_share_items;
  data_atlas_handler.GetShareFromMeItems(share_id, get_share_items);
  ASSERT_EQ((unsigned)4, get_share_items.size());
  // try to parse the buffer messages
  DataAtlasHandler another_dah;
  const char* kDataBaseFile2 = "dataatlas2.db";
  std::map<std::string, std::string>::iterator it;
  for (it = buffer_messages.begin(); it != buffer_messages.end(); it++){
    // make sure it receives what was shared.
    bool is_found = false;
    for (int i = 0; i< (int)users.size(); i++){
      if (users[i] == (*it).first){
        is_found = true;
        break;
      }
    }
    ASSERT_TRUE(is_found);
    another_dah.Init(kDataBaseFile2);
    ASSERT_TRUE(another_dah.HandleShareBufferMessage((*it).second));
    std::vector<int32_t> ids;
    another_dah.ListSharesToMe(ids);
    ASSERT_EQ((unsigned)1, ids.size());
    ASSERT_EQ(share_id, ids[0]);
    ASSERT_EQ(share_name, another_dah.GetShareToMeName(share_id));
    ASSERT_EQ(owner, another_dah.GetShareToMeOwner(share_id));
    std::vector<int32_t> share_items;
    another_dah.ListShareToMeItems(share_id, 0, share_items);
    ASSERT_EQ((unsigned)4, share_items.size());
    MetaDataMap mdm_tmp;
    DataMap dm_tmp;
    int file_count = 0;
    int folder_count = 0;
    std::string ser_mdm, ser_mdm1, ser_dm, ser_dm1;
    // there should be 4 items under root
    for (int i = 0; i< 4; i++){
      ASSERT_TRUE(another_dah.GetShareToMeMetaDataMap(share_id,
          share_items[i], mdm_tmp));
      ASSERT_EQ(mdm_tmp.id(), share_items[i]);
      ASSERT_EQ(0, mdm_tmp.parent_id());
      for (int j = 0; j < 10; j++){
        if (mdm_tmp.id() == file_ids[j]){
          ASSERT_EQ( REGULAR_FILE, mdm_tmp.type());
          ASSERT_EQ(file_names[j], mdm_tmp.name());
          ASSERT_EQ(1, mdm_tmp.file_hash_size());
          ASSERT_TRUE(another_dah.GetShareToMeDataMap(share_id,
              mdm_tmp.file_hash(0), dm_tmp));
          dm_tmp.SerializeToString(&ser_dm);
          ser_dm1 = data_atlas_handler.GetDataMap(mdm_tmp.file_hash(0));
          ASSERT_EQ(ser_dm, ser_dm1);
          file_count++;
          break;
        }
      }
      for (int j = 0; j < 3; j++){
        if (mdm_tmp.id() == folder_ids[j]){
          ASSERT_EQ(mdm_tmp.type(), DIRECTORY);
          ASSERT_EQ(mdm_tmp.name(), folder_names[j]);
          ASSERT_EQ(0, mdm_tmp.file_hash_size());
          folder_count++;
          std::vector<int32_t> share_items1;
          another_dah.ListShareToMeItems(share_id, mdm_tmp.id(), share_items1);
          if (j == 0){
            ASSERT_EQ((unsigned)3, share_items1.size());
            folder_count ++;
            file_count += 3;
          }
          else{
            ASSERT_EQ((unsigned)2, share_items1.size());
            file_count += 2;
          }
          break;
        }
      }
    }
    ASSERT_EQ(7, file_count);
    ASSERT_EQ(3, folder_count);
    another_dah.Close();
  }
  ASSERT_FALSE(data_atlas_handler.AddShare(share_id, share_name, owner,
      share_items_paths, users, buffer_messages))<<"Should not allow adding a\
        duplicate share";
}

TEST_F(DataAtlasHandlerTest, RemoveShare) {
  std::vector<std::string> file_names;
  std::vector<int32_t> file_ids;
  std::vector<std::string> folder_names;
  std::vector<int32_t> folder_ids;
  PrepareDataAtlas(&data_atlas_handler, file_names, file_ids, folder_names,
    folder_ids);
  // prepare the share
  int32_t share_id = rand();
  std::string share_name = base::RandomString(256);
  std::string owner = "Haiyang.Ma";
  std::vector<int32_t> share_items;
  share_items.push_back(file_ids[rand()%10]);
  std::vector<std::string> users;
  users.push_back("Richard.Johnstone");
  std::map<std::string, std::string> buffer_messages;
  // add a share
  std::vector<std::string> share_items_paths;

  for (int i=0;i<(int)share_items.size();i++){
    std::string path;
    ASSERT_TRUE(data_atlas_handler.GetMaidsafePath(share_items[i], path));
    share_items_paths.push_back(path);
  }
  ASSERT_TRUE(data_atlas_handler.AddShare(share_id, share_name, owner,
    share_items_paths, users, buffer_messages))<<"Failed to create a share";
  std::vector<int32_t> share_ids;
  data_atlas_handler.ListSharesFromMe(share_ids);
  ASSERT_EQ((unsigned)1, share_ids.size());
  // send the buffer message to a remote peer
  ASSERT_EQ((unsigned)1, buffer_messages.size());
  DataAtlasHandler another_dah;
  const char* kDataBaseFile2 = "dataatlas2.db";
  another_dah.Init(kDataBaseFile2);
  ASSERT_TRUE(another_dah.HandleShareBufferMessage(\
    (*buffer_messages.begin()).second));
  std::vector<int32_t> shares_to_me;
  another_dah.ListSharesToMe(shares_to_me);
  ASSERT_EQ((unsigned)1, shares_to_me.size());
  buffer_messages.clear();
  // remove the share
  ASSERT_TRUE(data_atlas_handler.RemoveShare(share_id, buffer_messages));
  // now it should be gone
  share_ids.clear();
  data_atlas_handler.ListSharesFromMe(share_ids);
  ASSERT_EQ((unsigned)0, share_ids.size());
  // notify the remote peer to remove the share
  shares_to_me.clear();
  ASSERT_EQ((unsigned)1, buffer_messages.size());
  ASSERT_TRUE(another_dah.HandleShareBufferMessage(\
    (*buffer_messages.begin()).second));
  another_dah.ListSharesToMe(shares_to_me);
  ASSERT_EQ((unsigned)0, shares_to_me.size());
  // couldn't remove a non-existing share
  buffer_messages.clear();
  ASSERT_FALSE(data_atlas_handler.RemoveShare(share_id, buffer_messages));
  another_dah.Close();
}

TEST_F(DataAtlasHandlerTest, ListShares) {
  std::vector<std::string> file_names;
  std::vector<int32_t> file_ids;
  std::vector<std::string> folder_names;
  std::vector<int32_t> folder_ids;
  PrepareDataAtlas(&data_atlas_handler, file_names, file_ids, folder_names,
    folder_ids);
  // prepare the share
  int32_t share_id = rand();
  std::string share_name = base::RandomString(256);
  std::string owner = "Haiyang.Ma";
  std::vector<int32_t> share_items;
  share_items.push_back(file_ids[rand()%10]);
  std::vector<std::string> users;
  users.push_back("Richard.Johnstone");
  std::map<std::string, std::string> buffer_messages;
  // add a share
  std::vector<std::string> share_items_paths;

  for (int i=0;i<(int)share_items.size();i++){
    std::string path;
    ASSERT_TRUE(data_atlas_handler.GetMaidsafePath(share_items[i], path));
    share_items_paths.push_back(path);
  }
  ASSERT_TRUE(data_atlas_handler.AddShare(share_id, share_name, owner,
    share_items_paths, users, buffer_messages))<<"Failed to create a share";
  std::vector<int32_t> share_ids;
  data_atlas_handler.ListSharesFromMe(share_ids);
  ASSERT_EQ((unsigned)1, share_ids.size());
  ASSERT_EQ(share_id, share_ids[0]);
  std::vector<int32_t> share_items2;
  data_atlas_handler.GetShareFromMeItems(share_id, share_items2);
  ASSERT_EQ(share_items[0], share_items2[0]);
  ASSERT_EQ(share_name, data_atlas_handler.GetShareName(share_id));
  std::vector<std::string> users1;
  data_atlas_handler.GetShareUsers(share_id, users1);
  ASSERT_EQ(users.size(), users1.size());
  ASSERT_EQ(users[0], users1[0]);
  // parse the buffer message
  ASSERT_EQ((unsigned)1, buffer_messages.size());
  DataAtlasHandler another_dah;
  const char* kDataBaseFile2 = "dataatlas2.db";
  another_dah.Init(kDataBaseFile2);
  ASSERT_TRUE(another_dah.HandleShareBufferMessage( (*buffer_messages.begin()).second));
  std::vector<int32_t> shares_to_me;
  another_dah.ListSharesToMe(shares_to_me);
  ASSERT_EQ((unsigned)1, shares_to_me.size());
  ASSERT_EQ(share_id, shares_to_me[0]);
  ASSERT_EQ(share_name, another_dah.GetShareToMeName(share_id));
  ASSERT_EQ(owner, another_dah.GetShareToMeOwner(share_id));
  another_dah.Close();
}

TEST_F(DataAtlasHandlerTest, AddItemsToShare) {
  std::vector<std::string> file_names;
  std::vector<int32_t> file_ids;
  std::vector<std::string> folder_names;
  std::vector<int32_t> folder_ids;
  PrepareDataAtlas(&data_atlas_handler, file_names, file_ids, folder_names,
    folder_ids);
  // prepare the share
  int32_t share_id = rand();
  std::string share_name = base::RandomString(256);
  std::string owner = "Haiyang.Ma";
  std::vector<int32_t> share_items;
  share_items.push_back(file_ids[0]);
  share_items.push_back(folder_ids[0]);
  std::vector<std::string> users;
  users.push_back("Richard.Johnstone");
  std::map<std::string, std::string> buffer_messages;
  // add a share
  std::vector<std::string> share_items_paths;

  for (int i=0;i<(int)share_items.size();i++){
    std::string path;
    ASSERT_TRUE(data_atlas_handler.GetMaidsafePath(share_items[i], path));
    share_items_paths.push_back(path);
  }
  ASSERT_TRUE(data_atlas_handler.AddShare(share_id, share_name, owner,
    share_items_paths, users, buffer_messages))<<"Failed to create a share";
  std::vector<int32_t> share_ids;
  data_atlas_handler.ListSharesFromMe(share_ids);
  ASSERT_EQ((unsigned)1, share_ids.size());
  share_items.clear();
  data_atlas_handler.GetShareFromMeItems(share_id, share_items);
  ASSERT_EQ((unsigned)2, share_items.size());
  bool isFound = false;
  for (unsigned int i = 0; i < share_items.size(); i++){
    if (share_items[i] == file_ids[0])
      isFound = true;
  }
  ASSERT_TRUE(isFound);
  isFound = false;
  for (unsigned int i = 0; i < share_items.size(); i++){
    if (share_items[i] == folder_ids[0])
      isFound = true;
  }
  ASSERT_TRUE(isFound);
  // send the buffer message to a remote peer
  ASSERT_EQ((unsigned)1, buffer_messages.size());
  DataAtlasHandler another_dah;
  const char* kDataBaseFile2 = "dataatlas2.db";
  another_dah.Init(kDataBaseFile2);
  ASSERT_TRUE(another_dah.HandleShareBufferMessage(\
    (*buffer_messages.begin()).second));
  std::vector<int32_t> shares_to_me;
  another_dah.ListSharesToMe(shares_to_me);
  ASSERT_EQ((unsigned)1, shares_to_me.size());
  ASSERT_EQ(share_id, shares_to_me[0]);
  share_items.clear();
  another_dah.ListShareToMeItems(shares_to_me[0], 0, share_items);
  ASSERT_EQ((unsigned)2, share_items.size());
  isFound = false;
  for (unsigned int i = 0; i < share_items.size(); i++){
    if (share_items[i] == file_ids[0])
      isFound = true;
  }
  ASSERT_TRUE(isFound);
  isFound = false;
  for (unsigned int i = 0; i < share_items.size(); i++){
    if (share_items[i] == folder_ids[0])
      isFound = true;
  }
  ASSERT_TRUE(isFound);
  buffer_messages.clear();
  // add items to share
  share_items.clear();
  share_items.push_back(file_ids[1]);
  share_items.push_back(folder_ids[1]);

  std::vector<std::string> share_items_paths1;

  for (int i=0;i<(int)share_items.size();i++){
    std::string path;
    ASSERT_TRUE(data_atlas_handler.GetMaidsafePath(share_items[i], path));
    share_items_paths1.push_back(path);
  }

  ASSERT_TRUE(data_atlas_handler.AddShareItems(share_id,
      share_items_paths1, buffer_messages))<<"Failed to add items to a share";
  share_ids.clear();
  data_atlas_handler.ListSharesFromMe(share_ids);
  ASSERT_EQ((unsigned)1, share_ids.size());
  share_items.clear();
  data_atlas_handler.GetShareFromMeItems(share_id, share_items);
  ASSERT_EQ((unsigned)4, share_items.size());
  isFound = false;
  for (unsigned int i = 0; i < share_items.size(); i++){
    if (share_items[i] == file_ids[0])
      isFound = true;
  }
  ASSERT_TRUE(isFound);
  isFound = false;
  for (unsigned int i = 0; i < share_items.size(); i++){
    if (share_items[i] == folder_ids[0])
      isFound = true;
  }
  ASSERT_TRUE(isFound);
  isFound = false;
  for (unsigned int i = 0; i < share_items.size(); i++){
    if (share_items[i] == file_ids[1])
      isFound = true;
  }
  ASSERT_TRUE(isFound);
  isFound = false;
  for (unsigned int i = 0; i < share_items.size(); i++){
    if (share_items[i] == folder_ids[1])
      isFound = true;
  }
  ASSERT_TRUE(isFound);
  // send the buffer message to a remote peer
  ASSERT_EQ((unsigned)1, buffer_messages.size());
  ASSERT_TRUE(another_dah.HandleShareBufferMessage(\
    (*buffer_messages.begin()).second));
  shares_to_me.clear();
  another_dah.ListSharesToMe(shares_to_me);
  ASSERT_EQ((unsigned)1, shares_to_me.size());
  ASSERT_EQ(share_id, shares_to_me[0]);
  share_items.clear();
  another_dah.ListShareToMeItems(shares_to_me[0], 0, share_items);
  ASSERT_EQ((unsigned)4, share_items.size());
  isFound = false;
  for (unsigned int i = 0; i < share_items.size(); i++){
    if (share_items[i] == file_ids[0])
      isFound = true;
  }
  ASSERT_TRUE(isFound);
  isFound = false;
  for (unsigned int i = 0; i < share_items.size(); i++){
    if (share_items[i] == folder_ids[0])
      isFound = true;
  }
  ASSERT_TRUE(isFound);
  isFound = false;
  for (unsigned int i = 0; i < share_items.size(); i++){
    if (share_items[i] == file_ids[1])
      isFound = true;
  }
  ASSERT_TRUE(isFound);
  isFound = false;
  for (unsigned int i = 0; i < share_items.size(); i++){
    if (share_items[i] == folder_ids[1])
      isFound = true;
  }
  ASSERT_TRUE(isFound);
  another_dah.Close();
}

TEST_F(DataAtlasHandlerTest, RemoveItemsFromShare) {
  std::vector<std::string> file_names;
  std::vector<int32_t> file_ids;
  std::vector<std::string> folder_names;
  std::vector<int32_t> folder_ids;
  PrepareDataAtlas(&data_atlas_handler, file_names, file_ids, folder_names,
    folder_ids);
  // prepare the share
  int32_t share_id = rand();
  std::string share_name = base::RandomString(256);
  std::string owner = "Haiyang.Ma";
  std::vector<int32_t> share_items;
  share_items.push_back(file_ids[0]);
  share_items.push_back(file_ids[1]);
  share_items.push_back(folder_ids[0]);
  share_items.push_back(folder_ids[1]);
  std::vector<std::string> users;
  users.push_back("Richard.Johnstone");
  std::map<std::string, std::string> buffer_messages;
  // add a share
  std::vector<std::string> share_items_paths;

  for (int i=0;i<(int)share_items.size();i++){
    std::string path;
    ASSERT_TRUE(data_atlas_handler.GetMaidsafePath(share_items[i], path));
    share_items_paths.push_back(path);
  }
  ASSERT_TRUE(data_atlas_handler.AddShare(share_id, share_name, owner,
    share_items_paths, users, buffer_messages))<<"Failed to create a share";
  std::vector<int32_t> share_ids;
  data_atlas_handler.ListSharesFromMe(share_ids);
  ASSERT_EQ((unsigned)1, share_ids.size());
  share_items.clear();
  data_atlas_handler.GetShareFromMeItems(share_id, share_items);
  ASSERT_EQ((unsigned)4, share_items.size());
  bool isFound = false;
  for (unsigned int i = 0; i < share_items.size(); i++){
    if (share_items[i] == file_ids[0])
      isFound = true;
  }
  ASSERT_TRUE(isFound);
  isFound = false;
  for (unsigned int i = 0; i < share_items.size(); i++){
    if (share_items[i] == folder_ids[0])
      isFound = true;
  }
  ASSERT_TRUE(isFound);
  isFound = false;
  for (unsigned int i = 0; i < share_items.size(); i++){
    if (share_items[i] == file_ids[1])
      isFound = true;
  }
  ASSERT_TRUE(isFound);
  isFound = false;
  for (unsigned int i = 0; i < share_items.size(); i++){
    if (share_items[i] == folder_ids[1])
      isFound = true;
  }
  ASSERT_TRUE(isFound);
  // send the buffer message to a remote peer
  ASSERT_EQ((unsigned)1, buffer_messages.size());
  DataAtlasHandler another_dah;
  const char* kDataBaseFile2 = "dataatlas2.db";
  another_dah.Init(kDataBaseFile2);
  ASSERT_TRUE(another_dah.HandleShareBufferMessage(\
    (*buffer_messages.begin()).second));
  std::vector<int32_t> shares_to_me;
  another_dah.ListSharesToMe(shares_to_me);
  ASSERT_EQ((unsigned)1, shares_to_me.size());
  ASSERT_EQ(share_id, shares_to_me[0]);
  share_items.clear();
  another_dah.ListShareToMeItems(shares_to_me[0], 0, share_items);
  ASSERT_EQ((unsigned)4, share_items.size());
  isFound =false;
  for (unsigned int i = 0; i < share_items.size(); i++){
    if (share_items[i] == file_ids[0])
      isFound = true;
  }
  ASSERT_TRUE(isFound);
  isFound = false;
  for (unsigned int i = 0; i < share_items.size(); i++){
    if (share_items[i] == folder_ids[0])
      isFound = true;
  }
  ASSERT_TRUE(isFound);
  isFound = false;
  for (unsigned int i = 0; i < share_items.size(); i++){
    if (share_items[i] == file_ids[1])
      isFound = true;
  }
  ASSERT_TRUE(isFound);
  isFound = false;
  for (unsigned int i = 0; i < share_items.size(); i++){
    if (share_items[i] == folder_ids[1])
      isFound = true;
  }
  ASSERT_TRUE(isFound);
  buffer_messages.clear();
  // remove items from the share
  share_items.clear();
  share_items.push_back(file_ids[0]);
  share_items.push_back(folder_ids[0]);
  ASSERT_TRUE(data_atlas_handler.DelItemsFromShare(share_id, share_items,
      buffer_messages));
  share_ids.clear();
  data_atlas_handler.ListSharesFromMe(share_ids);
  ASSERT_EQ((unsigned)1, share_ids.size());
  share_items.clear();
  data_atlas_handler.GetShareFromMeItems(share_id, share_items);
  ASSERT_EQ((unsigned)2, share_items.size());
  isFound = false;
  for (unsigned int i = 0; i < share_items.size(); i++){
    if (share_items[i] == file_ids[1])
      isFound = true;
  }
  ASSERT_TRUE(isFound);
  isFound = false;
  for (unsigned int i = 0; i < share_items.size(); i++){
    if (share_items[i] == folder_ids[1])
      isFound = true;
  }
  ASSERT_TRUE(isFound);
  // sent buffer message to the remote peer
  ASSERT_EQ((unsigned)1,buffer_messages.size());
  ASSERT_TRUE(another_dah.HandleShareBufferMessage(\
    (*buffer_messages.begin()).second));
  another_dah.ListSharesToMe(shares_to_me);
  ASSERT_EQ((unsigned)1, shares_to_me.size());
  ASSERT_EQ(share_id, shares_to_me[0]);
  share_items.clear();
  another_dah.ListShareToMeItems(shares_to_me[0], 0, share_items);
  ASSERT_EQ((unsigned)2, share_items.size());
  isFound = false;
  for (unsigned int i = 0; i < share_items.size(); i++){
    if (share_items[i] == file_ids[1])
      isFound = true;
  }
  ASSERT_TRUE(isFound);
  isFound = false;
  for (unsigned int i = 0; i < share_items.size(); i++){
    if (share_items[i] == folder_ids[1])
      isFound = true;
  }
  ASSERT_TRUE(isFound);
  another_dah.Close();
}

TEST_F(DataAtlasHandlerTest, AddUsersToShare) {
  std::vector<std::string> file_names;
  std::vector<int32_t> file_ids;
  std::vector<std::string> folder_names;
  std::vector<int32_t> folder_ids;
  PrepareDataAtlas(&data_atlas_handler, file_names, file_ids, folder_names,
    folder_ids);
  // prepare the share
  int32_t share_id = rand();
  std::string share_name = base::RandomString(256);
  std::string owner = "Haiyang.Ma";
  std::vector<int32_t> share_items;
  share_items.push_back(file_ids[rand()%10]);
  std::vector<std::string> users;
  users.push_back("Richard.Johnstone");
  std::map<std::string, std::string> buffer_messages;
  // add a share
  std::vector<std::string> share_items_paths;

  for (int i=0;i<(int)share_items.size();i++){
    std::string path;
    ASSERT_TRUE(data_atlas_handler.GetMaidsafePath(share_items[i], path));
    share_items_paths.push_back(path);
  }
  ASSERT_TRUE(data_atlas_handler.AddShare(share_id, share_name, owner,
    share_items_paths, users, buffer_messages))<<"Failed to create a share";
  std::vector<int32_t> share_ids;
  data_atlas_handler.ListSharesFromMe(share_ids);
  ASSERT_EQ((unsigned)1, share_ids.size());
  ASSERT_EQ((unsigned)1, buffer_messages.size());
  std::string buffer_message1 = (*buffer_messages.begin()).second;
  buffer_messages.clear();
  // add a new user to the current share
  users.clear();
  users.push_back("David.Irvine");
  ASSERT_TRUE(data_atlas_handler.AddShareUsers(share_id, users, buffer_messages));
  ASSERT_EQ((unsigned)1, buffer_messages.size());
  std::string buffer_message2 = (*buffer_messages.begin()).second;
  // it should generate the same buffer message as the previous one
  ASSERT_EQ(buffer_message1, buffer_message2);
  ASSERT_EQ("David.Irvine",(*buffer_messages.begin()).first);

}

TEST_F(DataAtlasHandlerTest, RemoveUsersFromShare) {
  std::vector<std::string> file_names;
  std::vector<int32_t> file_ids;
  std::vector<std::string> folder_names;
  std::vector<int32_t> folder_ids;
  PrepareDataAtlas(&data_atlas_handler, file_names, file_ids, folder_names,
    folder_ids);
  // prepare the share
  int32_t share_id = rand();
  std::string share_name = base::RandomString(256);
  std::string owner = "Haiyang.Ma";
  std::vector<int32_t> share_items;
  share_items.push_back(file_ids[rand()%10]);
  std::vector<std::string> users;
  users.push_back("Richard.Johnstone");
  users.push_back("David.Irvine");
  std::map<std::string, std::string> buffer_messages;
  // add a share
  std::vector<std::string> share_items_paths;

  for (int i=0;i<(int)share_items.size();i++){
    std::string path;
    ASSERT_TRUE(data_atlas_handler.GetMaidsafePath(share_items[i], path));
    share_items_paths.push_back(path);
  }
  ASSERT_TRUE(data_atlas_handler.AddShare(share_id, share_name, owner,
    share_items_paths, users, buffer_messages))<<"Failed to create a share";
  std::vector<int32_t> share_ids;
  data_atlas_handler.ListSharesFromMe(share_ids);
  ASSERT_EQ((unsigned)1, share_ids.size());
  users.clear();
  data_atlas_handler.GetShareUsers(share_id, users);
  ASSERT_EQ((unsigned)2, users.size());
  // send the buffer message to a remote peer
  ASSERT_EQ((unsigned)2, buffer_messages.size());
  DataAtlasHandler another_dah;
  const char* kDataBaseFile2 = "dataatlas2.db";
  another_dah.Init(kDataBaseFile2);
  ASSERT_TRUE(another_dah.HandleShareBufferMessage(\
      (*buffer_messages.begin()).second));
  std::vector<int32_t> ids;
  another_dah.ListSharesToMe(ids);
  ASSERT_EQ((unsigned)1, ids.size());
  ASSERT_EQ(share_id, ids[0]);
  // remove the user from the share
  users.clear();
  users.push_back("Richard.Johnstone");
  ASSERT_TRUE(data_atlas_handler.DelShareUsers(share_id, users,
      buffer_messages));
  // share is still there and "Richard" should be removed from the user list
  share_ids.clear();
  data_atlas_handler.ListSharesFromMe(share_ids);
  ASSERT_EQ((unsigned)1, share_ids.size());
  users.clear();
  data_atlas_handler.GetShareUsers(share_id, users);
  ASSERT_EQ((unsigned)1, users.size());
  ASSERT_EQ("David.Irvine", users[0]);
  // send the buffer message to a remote peer
  ASSERT_EQ((unsigned)1, buffer_messages.size());
  ASSERT_TRUE(another_dah.HandleShareBufferMessage(\
        (*buffer_messages.begin()).second));
  ids.clear();
  // share should be remove from this user
  another_dah.ListSharesToMe(ids);
  ASSERT_EQ((unsigned)0, ids.size());
}

TEST_F(DataAtlasHandlerTest, ShareInDataAtlas) {
  std::vector<std::string> file_names;
  std::vector<int32_t> file_ids;
  std::vector<std::string> folder_names;
  std::vector<int32_t> folder_ids;
  PrepareDataAtlas(&data_atlas_handler, file_names, file_ids, folder_names,
    folder_ids);
  // prepare the share
  int32_t share_id = rand();
  std::string share_name = base::RandomString(256);
  std::string owner = "Haiyang.Ma";
  std::vector<int32_t> share_items;
  share_items.push_back(file_ids[0]);
  share_items.push_back(file_ids[1]);
  share_items.push_back(folder_ids[0]);
  share_items.push_back(folder_ids[1]);
  std::vector<std::string> users;
  users.push_back("Richard.Johnstone");
  std::map<std::string, std::string> buffer_messages;
  std::vector<std::string> share_items_paths;

  for (int i=0;i<(int)share_items.size();i++){
    std::string path;
    ASSERT_TRUE(data_atlas_handler.GetMaidsafePath(share_items[i], path));
    share_items_paths.push_back(path);
  }
  ASSERT_TRUE(data_atlas_handler.AddShare(share_id, share_name, owner,
    share_items_paths, users, buffer_messages))<<"Failed to create a share";
  // serialize the dataatlas
  std::string ser_data_atlas = data_atlas_handler.SerialiseDataAtlas();
  DataAtlasHandler dah3;
  const char* kDataBaseFile3 = "dataatlas3.db";
  dah3.Init(kDataBaseFile3);
  ASSERT_TRUE(dah3.ParseFromStringDataAtlas(ser_data_atlas));
  // make sure the share is still there unchanged
  ASSERT_EQ(share_name, dah3.GetShareName(share_id));
  std::vector<int32_t> get_share_items;
  dah3.GetShareFromMeItems(share_id, get_share_items);
  ASSERT_EQ((unsigned)4, get_share_items.size());
  dah3.Close();
  // try to parse the buffer messages
  crypto::Crypto ct;
  ct.set_symm_algorithm("AES_256");
  ct.set_hash_algorithm("SHA512");
  DataAtlasHandler another_dah;
  const char* kDataBaseFile2 = "dataatlas2.db";
  std::map<std::string, std::string>::iterator it;
  it = buffer_messages.begin();
  another_dah.Init(kDataBaseFile2);
  ASSERT_TRUE(another_dah.HandleShareBufferMessage((*it).second));

  // serialize the dataatlas
  std::string ser_data_atlas2 = another_dah.SerialiseDataAtlas();
  another_dah.Close();
  DataAtlasHandler dah4;
  const char* kDataBaseFile4 = "dataatlas4.db";
  dah4.Init(kDataBaseFile4);
  ASSERT_TRUE(dah4.ParseFromStringDataAtlas(ser_data_atlas2));
  // make sure the share is still there unchanged
  std::vector<int32_t> ids;
  dah4.ListSharesToMe(ids);
  ASSERT_EQ((unsigned)1, ids.size());
  ASSERT_EQ(share_id, ids[0]);
  ASSERT_EQ(share_name, dah4.GetShareToMeName(share_id));
  ASSERT_EQ(owner, dah4.GetShareToMeOwner(share_id));
  // std::vector<int32_t> share_items;
  dah4.ListShareToMeItems(share_id, 0, share_items);
  ASSERT_EQ((unsigned)4, share_items.size());
  MetaDataMap mdm_tmp;
  DataMap dm_tmp;
  int file_count = 0;
  int folder_count = 0;
  std::string ser_mdm, ser_mdm1, ser_dm, ser_dm1;
  // there should be 4 items under root
  for (int i = 0; i< 4; i++){
    ASSERT_TRUE(dah4.GetShareToMeMetaDataMap(share_id,
        share_items[i], mdm_tmp));
    ASSERT_EQ(mdm_tmp.id(), share_items[i]);
    ASSERT_EQ(0, mdm_tmp.parent_id());
    for (int j = 0; j < 10; j++){
      if (mdm_tmp.id() == file_ids[j]){
        ASSERT_EQ( REGULAR_FILE, mdm_tmp.type());
        ASSERT_EQ(file_names[j], mdm_tmp.name());
        ASSERT_EQ(1, mdm_tmp.file_hash_size());
        ASSERT_TRUE(dah4.GetShareToMeDataMap(share_id,
            mdm_tmp.file_hash(0), dm_tmp));
        dm_tmp.SerializeToString(&ser_dm);
        ser_dm1 = data_atlas_handler.GetDataMap(mdm_tmp.file_hash(0));
        ASSERT_EQ(ser_dm, ser_dm1);
        file_count++;
        break;
      }
    }
    for (int j = 0; j < 3; j++){
      if (mdm_tmp.id() == folder_ids[j]){
        ASSERT_EQ(mdm_tmp.type(), DIRECTORY);
        ASSERT_EQ(mdm_tmp.name(), folder_names[j]);
        ASSERT_EQ(0, mdm_tmp.file_hash_size());
        folder_count++;
        std::vector<int32_t> share_items1;
        dah4.ListShareToMeItems(share_id, mdm_tmp.id(), share_items1);
        if (j == 0){
          ASSERT_EQ((unsigned)3, share_items1.size());
          folder_count ++;
          file_count += 3;
        }
        else{
          ASSERT_EQ((unsigned)2, share_items1.size());
          file_count += 2;
        }
        break;
      }
    }
  }
  ASSERT_EQ(7, file_count);
  ASSERT_EQ(3, folder_count);
  dah4.Close();
}

TEST_F(DataAtlasHandlerTest, GetMaidsafeFullPath) {
  std::vector<std::string> file_names;
  std::vector<int32_t> file_ids;
  std::vector<std::string> folder_names;
  std::vector<int32_t> folder_ids;
  PrepareDataAtlas(&data_atlas_handler, file_names, file_ids, folder_names,
    folder_ids);
  std::string expected_path;
  expected_path = "/";
  expected_path += file_names[0];
  std::string maidsafe_path;
  ASSERT_TRUE(data_atlas_handler.GetMaidsafePath(file_ids[0], maidsafe_path));
  ASSERT_EQ(expected_path, maidsafe_path);
  expected_path = "/";
  expected_path += folder_names[0];
  expected_path += "/";
  expected_path += folder_names[2];
  expected_path += "/";
  expected_path += file_names[9];
  maidsafe_path = "";
  ASSERT_TRUE(data_atlas_handler.GetMaidsafePath(file_ids[9], maidsafe_path));
  ASSERT_EQ(expected_path, maidsafe_path);
}

TEST_F(DataAtlasHandlerTest, GetDataMapFromPath) {
  std::vector<std::string> file_names;
  std::vector<int32_t> file_ids;
  std::vector<std::string> folder_names;
  std::vector<int32_t> folder_ids;
  PrepareDataAtlas(&data_atlas_handler, file_names, file_ids, folder_names,
    folder_ids);
  std::string maidsafe_path;
  maidsafe_path = "/";
  maidsafe_path += file_names[0];
  std::string ser_dm;
  ASSERT_TRUE(data_atlas_handler.GetDataMapFromPath(maidsafe_path, ser_dm));
  DataMap dm;
  dm.ParseFromString(ser_dm);
  ASSERT_EQ(dm.chunk_name_size(), 3);
  maidsafe_path = "/";
  maidsafe_path += folder_names[0];
  maidsafe_path += "/";
  maidsafe_path += folder_names[2];
  maidsafe_path += "/";
  maidsafe_path += file_names[9];
  ASSERT_TRUE(data_atlas_handler.GetDataMapFromPath(maidsafe_path, ser_dm));
  dm.Clear();
  dm.ParseFromString(ser_dm);
  ASSERT_EQ(dm.chunk_name_size(), 3);
}
*/

} // namespace maidsafe
