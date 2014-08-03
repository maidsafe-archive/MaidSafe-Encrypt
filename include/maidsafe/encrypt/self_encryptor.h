/*  Copyright 2011 MaidSafe.net limited

    This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
    version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
    licence you accepted on initial access to the Software (the "Licences").

    By contributing code to the MaidSafe Software, or to this project generally, you agree to be
    bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
    directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
    available at: http://www.maidsafe.net/licenses

    Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
    under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
    OF ANY KIND, either express or implied.

    See the Licences for the specific language governing permissions and limitations relating to
    use of the MaidSafe Software.                                                                 */

#ifndef MAIDSAFE_ENCRYPT_SELF_ENCRYPTOR_H_
#define MAIDSAFE_ENCRYPT_SELF_ENCRYPTOR_H_

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <array>
#include <vector>
#include <map>
#include "boost/numeric/ublas/vector_sparse.hpp"
#include "boost/numeric/ublas/io.hpp"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/types.h"
#include "maidsafe/common/data_buffer.h"

#include "maidsafe/encrypt/data_map.h"
// #include "maidsafe/encrypt/config.h"

namespace maidsafe {

namespace encrypt {
class Cache;
namespace test {
class PrivateSelfEncryptorTest;
}

class SelfEncryptor {

 public:
  SelfEncryptor(DataMap& data_map, DataBuffer<std::string>& buffer,
                std::function<NonEmptyString(const std::string&)> get_from_store);
  ~SelfEncryptor();
  SelfEncryptor(const SelfEncryptor&) = delete;
  SelfEncryptor(SelfEncryptor&&) = delete;
  SelfEncryptor& operator=(SelfEncryptor) = delete;

  bool Write(const char* data, uint32_t length, uint64_t position);
  bool Read(char* data, uint32_t length, uint64_t position);
  // Can truncate up or down
  bool Truncate(uint64_t position);
  // Forces all buffered data to be encrypted.  Missing portions of the file are filled with '\0's
  void Close();
  bool Flush();
  uint64_t size() const { return file_size_; }
  const DataMap& data_map() const { return data_map_; }
  const DataMap& original_data_map() const { return kOriginalDataMap_; }

  friend class test::PrivateSelfEncryptorTest;

 private:
  // read in all data and up to next 2 chunks
  void PrepareWindow(uint32_t length, uint64_t position, bool write);
  // Retrieves the encrypted chunk from chunk_store_ and decrypts it to "data".
  ByteVector DecryptChunk(uint32_t chunk_num);
  // Retrieves appropriate pre-hashes from data_map_ and constructs key, IV and
  // encryption pad.
  void GetPadIvKey(uint32_t this_chunk_num, ByteVector& key, ByteVector& iv, ByteVector& pad);
  // Encrypts the chunk and stores in chunk_store_
  void EncryptChunk(uint32_t chunk_num, ByteVector data, uint32_t length);
  void DeleteChunk(uint32_t chunk_num);
  void CleanUpAfterException() { } //std::swap(data_map_, kOriginalDataMap_); }
  // ###############################################################################
  // these are some handy helper methods to translate position and lengths into chunk
  // numbers etc.
  uint32_t GetChunkSize(uint32_t chunk_num);
  uint32_t GetNumChunks();
  std::pair<uint64_t, uint64_t> GetStartEndPositions(uint32_t chunk_number);
  uint32_t GetNextChunkNumber(uint32_t chunk_number);      // not ++chunk_number
  uint32_t GetPreviousChunkNumber(uint32_t chunk_number);  // not --chunk_number
  uint32_t GetChunkNumber(uint64_t position);
  //########end of helpers#########################################################

  enum class ChunkStatus {
    to_be_hashed,
    to_be_encrypted,
    stored,  // therefor only being used as read cache`
    remote
  };

  DataMap& data_map_, kOriginalDataMap_;
  boost::numeric::ublas::compressed_vector<byte> sequencer_;
  std::map<uint32_t, ChunkStatus> chunks_;
  std::unique_ptr<Cache> read_cache_;
  DataBuffer<std::string>& buffer_;
  std::function<NonEmptyString(const std::string&)> get_from_store_;
  uint64_t file_size_;
  bool closed_;
  mutable std::mutex data_mutex_;
};

}  // namespace encrypt

}  // namespace maidsafe

#endif  // MAIDSAFE_ENCRYPT_SELF_ENCRYPTOR_H_
