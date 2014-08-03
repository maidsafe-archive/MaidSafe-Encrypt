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

#include "maidsafe/encrypt/config.h"
#include "maidsafe/encrypt/xor.h"
#include "maidsafe/encrypt/cache.h"
#include "maidsafe/encrypt/data_map.h"
#include "maidsafe/encrypt/data_map.pb.h"

namespace maidsafe {

namespace encrypt {

const EncryptionAlgorithm kSelfEncryptionVersion = EncryptionAlgorithm::kSelfEncryptionVersion0;
const EncryptionAlgorithm kDataMapEncryptionVersion =
    EncryptionAlgorithm::kDataMapEncryptionVersion0;

namespace {

DataMap DecryptUsingVersion0(const Identity& parent_id, const Identity& this_id,
                             const protobuf::EncryptedDataMap& protobuf_encrypted_data_map) {
  if (protobuf_encrypted_data_map.data_map_encryption_version() !=
      static_cast<uint32_t>(EncryptionAlgorithm::kDataMapEncryptionVersion0)) {
    BOOST_THROW_EXCEPTION(MakeError(EncryptErrors::invalid_encryption_version));
  }

  size_t inputs_size(parent_id.string().size() + this_id.string().size());
  byte* enc_hash = new byte[crypto::SHA512::DIGESTSIZE];
  byte* xor_hash = new byte[crypto::SHA512::DIGESTSIZE];
  on_scope_exit([=] {
    delete enc_hash;
    delete xor_hash;
  });
  CryptoPP::SHA512().CalculateDigest(
      enc_hash, reinterpret_cast<const byte*>((parent_id.string() + this_id.string()).data()),
      inputs_size);
  CryptoPP::SHA512().CalculateDigest(
      xor_hash, reinterpret_cast<const byte*>((this_id.string() + parent_id.string()).data()),
      inputs_size);

  CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption decryptor(enc_hash, crypto::AES256_KeySize,
                                                          enc_hash + crypto::AES256_KeySize);

  std::string serialised_data_map;
  CryptoPP::StringSource filter(
      protobuf_encrypted_data_map.contents(), true,
      new XORFilter(
          new CryptoPP::StreamTransformationFilter(
              decryptor, new CryptoPP::Gunzip(new CryptoPP::StringSink(serialised_data_map))),
          xor_hash, crypto::SHA512::DIGESTSIZE));

  DataMap data_map;
  ParseDataMap(serialised_data_map, data_map);
  return data_map;
}

}  // unnamed namespace

crypto::CipherText EncryptDataMap(const Identity& parent_id, const Identity& this_id,
                                  const DataMap& data_map) {
  assert(parent_id.string().size() == static_cast<size_t>(crypto::SHA512::DIGESTSIZE));
  assert(this_id.string().size() == static_cast<size_t>(crypto::SHA512::DIGESTSIZE));

  std::string serialised_data_map;
  SerialiseDataMap(data_map, serialised_data_map);

  ByteVector array_data_map(serialised_data_map.data(),
                            serialised_data_map.data() + serialised_data_map.size());

  size_t inputs_size(parent_id.string().size() + this_id.string().size());
  byte* enc_hash = new byte[crypto::SHA512::DIGESTSIZE];
  byte* xor_hash = new byte[crypto::SHA512::DIGESTSIZE];
  on_scope_exit([=] {
    delete[] enc_hash;
    delete[] xor_hash;
  });

  CryptoPP::SHA512().CalculateDigest(
      enc_hash, reinterpret_cast<const byte*>((parent_id.string() + this_id.string()).data()),
      inputs_size);
  CryptoPP::SHA512().CalculateDigest(
      xor_hash, reinterpret_cast<const byte*>((this_id.string() + parent_id.string()).data()),
      inputs_size);

  CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption encryptor(enc_hash, crypto::AES256_KeySize,
                                                          enc_hash + crypto::AES256_KeySize);

  protobuf::EncryptedDataMap protobuf_encrypted_data_map;
  protobuf_encrypted_data_map.set_data_map_encryption_version(
      static_cast<uint32_t>(kDataMapEncryptionVersion));
  CryptoPP::Gzip aes_filter(
      new CryptoPP::StreamTransformationFilter(
          encryptor,
          new XORFilter(new CryptoPP::StringSink(*protobuf_encrypted_data_map.mutable_contents()),
                        xor_hash, crypto::SHA512::DIGESTSIZE)),
      1);
  aes_filter.Put2(&array_data_map[0], array_data_map.size(), -1, true);

  assert(!protobuf_encrypted_data_map.contents().empty());

  return crypto::CipherText(NonEmptyString(protobuf_encrypted_data_map.SerializeAsString()));
}

DataMap DecryptDataMap(const Identity& parent_id, const Identity& this_id,
                       const std::string& encrypted_data_map) {
  assert(parent_id.string().size() == static_cast<size_t>(crypto::SHA512::DIGESTSIZE));
  assert(this_id.string().size() == static_cast<size_t>(crypto::SHA512::DIGESTSIZE));
  assert(!encrypted_data_map.empty());

  protobuf::EncryptedDataMap protobuf_encrypted_data_map;
  if (!protobuf_encrypted_data_map.ParseFromString(encrypted_data_map))
    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::parsing_error));

  // Don't switch here - just assume most current encryption version is being used and try
  // progressively older versions until one works
  // try {
  //   return DecryptUsingVersion1(parent_id, this_id, protobuf_encrypted_data_map);
  // }
  // catch (const encrypt_error& error) {
  //   if (error.code() != MakeError(EncryptErrors::invalid_encryption_version).code())
  //     throw;
  // }

  return DecryptUsingVersion0(parent_id, this_id, protobuf_encrypted_data_map);
}

}  // namespace encrypt

}  // namespace maidsafe
