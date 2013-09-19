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

#include "maidsafe/encrypt/self_encryptor.h"

namespace maidsafe {
namespace encrypt {

namespace {

/*
void DebugPrint(bool encrypting,
                uint32_t chunk_num,
                ByteArray pad,
                ByteArray key,
                ByteArray iv,
                const byte* plain_data,
                uint32_t plain_data_length,
                const std::string &encrypted_data) {
  std::string pad_str(Base32Substr(std::string(
      reinterpret_cast<char*>(pad.get()), detail::kPadSize)));
  std::string key_str(Base32Substr(std::string(
      reinterpret_cast<char*>(key.get()), crypto::AES256_KeySize)));
  std::string iv_str(Base32Substr(std::string(
      reinterpret_cast<char*>(iv.get()), crypto::AES256_IVSize)));
  std::string plain(Base32Substr(crypto::Hash<crypto::SHA512>(std::string(
      reinterpret_cast<const char*>(plain_data), plain_data_length))));
  std::string encrypted(Base32Substr(crypto::Hash<crypto::SHA512>(
      encrypted_data)));
  LOG(kInfo) << (encrypting ? "\nEncrypt chunk " : "\nDecrypt chunk ")
             << chunk_num << "\nPad: " << pad_str << "   Key: " << key_str
             << "   IV: " << iv_str << "   Plain: " << plain << "   Encrypted: "
             << encrypted;
}
*/

}  // unnamed namespace

crypto::CipherText EncryptDataMap(const Identity& parent_id,
                                  const Identity& this_id,
                                  DataMapPtr data_map) {
  assert(parent_id.string().size() == static_cast<size_t>(crypto::SHA512::DIGESTSIZE));
  assert(this_id.string().size() == static_cast<size_t>(crypto::SHA512::DIGESTSIZE));
  assert(data_map);

  std::string serialised_data_map, encrypted_data_map;
  SerialiseDataMap(*data_map, serialised_data_map);

  ByteArray array_data_map(GetNewByteArray(static_cast<uint32_t>(serialised_data_map.size())));
  uint32_t copied(MemCopy(array_data_map, 0, serialised_data_map.c_str(), Size(array_data_map)));
  assert(Size(array_data_map) == copied);

  size_t inputs_size(parent_id.string().size() + this_id.string().size());
  ByteArray enc_hash(GetNewByteArray(crypto::SHA512::DIGESTSIZE)),
            xor_hash(GetNewByteArray(crypto::SHA512::DIGESTSIZE));
  CryptoPP::SHA512().CalculateDigest(enc_hash.get(),
                                     reinterpret_cast<const byte*>((parent_id.string() +
                                                                    this_id.string()).data()),
                                     inputs_size);
  CryptoPP::SHA512().CalculateDigest(xor_hash.get(),
                                     reinterpret_cast<const byte*>((this_id.string() +
                                                                    parent_id.string()).data()),
                                     inputs_size);

  CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption encryptor(
      enc_hash.get(),
      crypto::AES256_KeySize,
      enc_hash.get() + crypto::AES256_KeySize);

  encrypted_data_map.reserve(copied);
  CryptoPP::Gzip aes_filter(
      new CryptoPP::StreamTransformationFilter(encryptor,
          new detail::XORFilter(
              new CryptoPP::StringSink(encrypted_data_map),
              xor_hash.get(),
              crypto::SHA512::DIGESTSIZE)),
      6);
  aes_filter.Put2(array_data_map.get(), copied, -1, true);

  assert(!encrypted_data_map.empty());

  return crypto::CipherText(encrypted_data_map);
}

void DecryptDataMap(const Identity& parent_id,
                    const Identity& this_id,
                    const std::string &encrypted_data_map,
                    DataMapPtr data_map) {
  assert(parent_id.string().size() == static_cast<size_t>(crypto::SHA512::DIGESTSIZE));
  assert(this_id.string().size() == static_cast<size_t>(crypto::SHA512::DIGESTSIZE));
  assert(!encrypted_data_map.empty());
  assert(data_map);

  std::string serialised_data_map;
  size_t inputs_size(parent_id.string().size() + this_id.string().size());
  ByteArray enc_hash(GetNewByteArray(crypto::SHA512::DIGESTSIZE)),
            xor_hash(GetNewByteArray(crypto::SHA512::DIGESTSIZE));
  CryptoPP::SHA512().CalculateDigest(enc_hash.get(),
                                      reinterpret_cast<const byte*>((parent_id.string() +
                                                                    this_id.string()).data()),
                                      inputs_size);
  CryptoPP::SHA512().CalculateDigest(xor_hash.get(),
                                      reinterpret_cast<const byte*>((this_id.string() +
                                                                    parent_id.string()).data()),
                                      inputs_size);

  CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption decryptor(
      enc_hash.get(),
      crypto::AES256_KeySize,
      enc_hash.get() + crypto::AES256_KeySize);

  CryptoPP::StringSource filter(encrypted_data_map, true,
      new detail::XORFilter(
          new CryptoPP::StreamTransformationFilter(
              decryptor,
              new CryptoPP::Gunzip(new CryptoPP::StringSink(serialised_data_map))),
          xor_hash.get(),
          crypto::SHA512::DIGESTSIZE));

  ParseDataMap(serialised_data_map, *data_map);
}

}  // namespace encrypt
}  // namespace maidsafe
