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

#include "maidsafe/encrypt/data_map_encryptor.h"

#include <cstdint>
#include <algorithm>
#include <limits>
#include <set>
#include <tuple>
#include <utility>
#include <memory>

#ifdef __MSVC__
#pragma warning(push, 1)
#endif
#include "cryptopp/aes.h"
#include "cryptopp/gzip.h"
#include "cryptopp/modes.h"
#include "cryptopp/mqueue.h"
#include "cryptopp/sha.h"
#ifdef __MSVC__
#pragma warning(pop)
#endif

#include "boost/exception/all.hpp"
#include "maidsafe/common/config.h"
#include "maidsafe/common/error.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/on_scope_exit.h"
#include "maidsafe/common/profiler.h"
#include "maidsafe/common/types.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/common/serialisation/serialisation.h"

#include "maidsafe/encrypt/config.h"
#include "maidsafe/encrypt/xor.h"
#include "maidsafe/encrypt/data_map.h"

namespace maidsafe {

namespace encrypt {

const EncryptionAlgorithm kSelfEncryptionVersion = EncryptionAlgorithm::kSelfEncryptionVersion0;
const EncryptionAlgorithm kDataMapEncryptionVersion =
    EncryptionAlgorithm::kDataMapEncryptionVersion0;

namespace {

// SHA512 of 'parent_id' concatenated with 'this_id'
ByteVector GetEncryptionHash(const Identity& parent_id, const Identity& this_id) {
  ByteVector encryption_input(parent_id.string());
  encryption_input.reserve(identity_size * 2);
  const ByteVector& this_id_str(this_id.string());
  encryption_input.insert(encryption_input.end(), this_id_str.begin(), this_id_str.end());
  ByteVector encryption_hash(crypto::SHA512::DIGESTSIZE);
  CryptoPP::SHA512().CalculateDigest(&encryption_hash.data()[0], encryption_input.data(),
                                     encryption_input.size());
  return encryption_hash;
}

// SHA512 of 'this_id' concatenated with 'parent_id'
ByteVector GetXorHash(const Identity& parent_id, const Identity& this_id) {
  ByteVector xor_input(this_id.string());
  xor_input.reserve(identity_size * 2);
  const ByteVector& parent_id_str(parent_id.string());
  xor_input.insert(xor_input.end(), parent_id_str.begin(), parent_id_str.end());
  ByteVector xor_hash(crypto::SHA512::DIGESTSIZE);
  CryptoPP::SHA512().CalculateDigest(&xor_hash.data()[0], xor_input.data(), xor_input.size());
  return xor_hash;
}

DataMap DecryptUsingVersion0(const Identity& parent_id, const Identity& this_id,
                             const SerialisedData& encrypted_data_map) {
  EncryptionAlgorithm data_map_encryption_version;
  std::string encrypted_data_map_str;
  Parse(encrypted_data_map, data_map_encryption_version, encrypted_data_map_str);

  if (data_map_encryption_version != EncryptionAlgorithm::kDataMapEncryptionVersion0)
    BOOST_THROW_EXCEPTION(MakeError(EncryptErrors::invalid_encryption_version));

  ByteVector encryption_hash(GetEncryptionHash(parent_id, this_id));
  ByteVector xor_hash(GetXorHash(parent_id, this_id));
  CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption decryptor(
      &encryption_hash.data()[0], crypto::AES256_KeySize,
      &encryption_hash.data()[crypto::AES256_KeySize]);

  std::string serialised_data_map;
  CryptoPP::StringSource filter(
      encrypted_data_map_str, true,
      new XORFilter(new CryptoPP::StreamTransformationFilter(
                        decryptor, new CryptoPP::StringSink(serialised_data_map)),
                    &xor_hash.data()[0], crypto::SHA512::DIGESTSIZE));

  return ConvertFromString<DataMap>(serialised_data_map);
}

}  // unnamed namespace

SerialisedData EncryptDataMap(const Identity& parent_id, const Identity& this_id,
                              const DataMap& data_map) {
  assert(parent_id.string().size() == static_cast<size_t>(crypto::SHA512::DIGESTSIZE));
  assert(this_id.string().size() == static_cast<size_t>(crypto::SHA512::DIGESTSIZE));

  SerialisedData serialised_data_map(Serialise(data_map));
  ByteVector encryption_hash(GetEncryptionHash(parent_id, this_id));
  ByteVector xor_hash(GetXorHash(parent_id, this_id));
  CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption encryptor(
      &encryption_hash.data()[0], crypto::AES256_KeySize,
      &encryption_hash.data()[crypto::AES256_KeySize]);

  std::string encrypted_data_map;
  CryptoPP::StreamTransformationFilter aes_filter(
      encryptor, new XORFilter(new CryptoPP::StringSink(encrypted_data_map), &xor_hash.data()[0],
                               crypto::SHA512::DIGESTSIZE));
  aes_filter.Put2(&serialised_data_map.data()[0], serialised_data_map.size(), -1, true);

  assert(!encrypted_data_map.empty());

  return Serialise(kDataMapEncryptionVersion, encrypted_data_map);
}

DataMap DecryptDataMap(const Identity& parent_id, const Identity& this_id,
                       const SerialisedData& encrypted_data_map) {
  assert(parent_id.string().size() == static_cast<size_t>(crypto::SHA512::DIGESTSIZE));
  assert(this_id.string().size() == static_cast<size_t>(crypto::SHA512::DIGESTSIZE));
  assert(!encrypted_data_map.empty());

  // Don't switch here - just assume most current encryption version is being used and try
  // progressively older versions until one works
  // try {
  //   return DecryptUsingVersion1(parent_id, this_id, encrypted_data_map);
  // }
  // catch (const encrypt_error& error) {
  //   if (error.code() != MakeError(EncryptErrors::invalid_encryption_version).code())
  //     throw;
  // }

  return DecryptUsingVersion0(parent_id, this_id, encrypted_data_map);
}

}  // namespace encrypt

}  // namespace maidsafe
