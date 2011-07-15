/*******************************************************************************
 *  Copyright 2008-2011 maidsafe.net limited                                   *
 *                                                                             *
 *  The following source code is property of maidsafe.net limited and is not   *
 *  meant for external use.  The use of this code is governed by the license   *
 *  file LICENSE.TXT found in the root of this directory and also on           *
 *  www.maidsafe.net.                                                          *
 *                                                                             *
 *  You are not free to copy, amend or otherwise use this source code without  *
 *  the explicit written permission of the board of directors of maidsafe.net. *
 ***************************************************************************//**
 * @file  utils.cc
 * @brief Helper functions for self-encryption engine.
 * @date  2008-09-09
 */

#include "maidsafe/encrypt/utils.h"

#include <algorithm>
#include <set>
#ifdef __MSVC__
#  pragma warning(push, 1)
#  pragma warning(disable: 4702)
#endif

#include "cryptopp/gzip.h"
#include "cryptopp/hex.h"
#include "cryptopp/aes.h"
#include "cryptopp/modes.h"
#include "cryptopp/rsa.h"
#include "cryptopp/osrng.h"
#include "cryptopp/integer.h"
#include "cryptopp/pwdbased.h"
#include "cryptopp/cryptlib.h"
#include "cryptopp/filters.h"

#ifdef __MSVC__
#  pragma warning(pop)
#endif
#include "boost/filesystem/fstream.hpp"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/encrypt/config.h"
#include "maidsafe/encrypt/data_map.h"
#include "maidsafe/encrypt/log.h"

namespace fs = boost::filesystem;

namespace maidsafe {

namespace encrypt {

namespace utils {

/**
 * Implementation of XOR transformation filter to allow pipe-lining
 *
 */
size_t XORFilter::Put2(const byte* inString,
                      size_t length,
                      int messageEnd,
                      bool blocking) {
  // Anything to process for us? If not, we will pass it on
  // to the lower filter just in case... from example
  if((length == 0))
        return AttachedTransformation()->Put2(inString,
                                          length,
                                          messageEnd,
                                          blocking);
  if((pad_.size() == 0))
    throw CryptoPP::Exception(CryptoPP::Exception::INVALID_DATA_FORMAT,
                              "XORFilter zero length PAD passed");

  size_t pad_limit(pad_.size()); 
  size_t buffer_size(length);
  // Do XOR

  byte *pad = new byte[pad_limit];
  memcpy(pad, pad_.c_str(), pad_limit);
  
  byte *buffer = new byte[length];

  for (size_t i = 0; i <= length; ++i) {
     buffer[i] = inString[i] ^ pad[i%pad_limit]; // don't overrun the pad
   }

  return AttachedTransformation()->Put2(buffer,
                                        length,
                                        messageEnd,
                                        blocking );
}  

/**
 * Implementation of an AES transformation filter to allow pipe-lining
 * This can be done with cfb - do not change cypher without reading a lot !
 */
size_t AESFilter::Put2(const byte* inString,
                      size_t length,
                      int messageEnd,
                      bool blocking) {
  // Anything to process for us? If not, we will pass it on
  // to the lower filter just in case... from example
  if((length == 0))
        return AttachedTransformation()->Put2(inString,
                                          length,
                                          messageEnd,
                                          blocking);
        
  byte byte_key[crypto::AES256_KeySize], byte_iv[crypto::AES256_IVSize];
  // Encryption key - seems efficient enough for now
  CryptoPP::StringSource(enc_hash_.substr(0, crypto::AES256_KeySize),
                        true,
                        new CryptoPP::ArraySink(byte_key,
                                                sizeof(byte_key)));
  // IV
  CryptoPP::StringSource(enc_hash_.substr(crypto::AES256_KeySize,
                                        crypto::AES256_IVSize),
                                        true,
                                    new CryptoPP::ArraySink(byte_iv,
                                                            sizeof(byte_iv)));
    byte *out_string = new byte[length];
  if (encrypt_) {
  // Encryptor object
  CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption encryptor(byte_key,
    sizeof(byte_key), byte_iv);
    encryptor.ProcessData((byte*)out_string, (byte*)inString, length);
  } else {
  //decryptor object
    CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption decryptor(byte_key,
    sizeof(byte_key), byte_iv);
     decryptor.ProcessData((byte*)out_string, (byte*)inString, length);
  }
  return AttachedTransformation()->Put2(out_string,
                                         length,
                                         messageEnd,
                                         blocking);
};

bool IsCompressedFile(const fs::path &file_path) {
  size_t ext_count = sizeof(kNoCompressType) / sizeof(kNoCompressType[0]);
  std::set<std::string> exts(kNoCompressType, kNoCompressType + ext_count);
  return (exts.find(boost::to_lower_copy(file_path.extension().string())) !=
          exts.end());
}

/**
 * Tries to compress the given sample using the specified compression type.
 * If that yields savings of at least 10%, we assume this can be extrapolated to
 * all the data.
 *
 * @param sample A data sample.
 * @param self_encryption_type Compression type.
 * @return True if input data is likely compressible.
 */
bool CheckCompressibility(const std::string &sample,
                          const uint32_t &self_encryption_type) {
  if (sample.empty())
    return false;

  std::string compressed_sample(Compress(sample, self_encryption_type));
  double ratio = static_cast<double>(compressed_sample.size()) / sample.size();
  return !compressed_sample.empty() && ratio <= 0.9;
}

/**
 * @param self_encryption_params Parameters for the self-encryption algorithm.
 * @return True if parameters sane.
 */
bool CheckParams(const SelfEncryptionParams &self_encryption_params) {
  if (self_encryption_params.max_chunk_size == 0) {
    DLOG(ERROR) << "CheckParams: Chunk size can't be zero." << std::endl;
    return false;
  }

  if (self_encryption_params.max_includable_data_size < kMinChunks - 1) {
    DLOG(ERROR) << "CheckParams: Max includable data size must be at least "
                << kMinChunks - 1 << "." << std::endl;
    return false;
  }

  if (kMinChunks * self_encryption_params.max_includable_chunk_size >=
      self_encryption_params.max_includable_data_size) {
    DLOG(ERROR) << "CheckParams: Max includable data size must be bigger than "
                   "all includable chunks." << std::endl;
    return false;
  }

  if (kMinChunks * self_encryption_params.max_chunk_size <
      self_encryption_params.max_includable_data_size) {
    DLOG(ERROR) << "CheckParams: Max includable data size can't be bigger than "
                << kMinChunks << " chunks." << std::endl;
    return false;
  }

  return true;
}

std::string Compress(const std::string &input,
                     const uint32_t &self_encryption_type) {
  switch (self_encryption_type & kCompressionMask) {
    case kCompressionNone:
      return input;
    case kCompressionGzip:
      return crypto::Compress(input, kCompressionRatio);
    default:
      DLOG(ERROR) << "Compress: Invalid compression type passed." << std::endl;
  }
  return "";
}

std::string Uncompress(const std::string &input,
                       const uint32_t &self_encryption_type) {
  switch (self_encryption_type & kCompressionMask) {
    case kCompressionNone:
      return input;
    case kCompressionGzip:
      return crypto::Uncompress(input);
    default:
      DLOG(ERROR) << "Uncompress: Invalid compression type passed."
                  << std::endl;
  }
  return "";
}

std::string Hash(const std::string &input,
                 const uint32_t &self_encryption_type) {
  switch (self_encryption_type & kHashingMask) {
    case kHashingSha1:
      return crypto::Hash<crypto::SHA1>(input);
    case kHashingSha512:
      return crypto::Hash<crypto::SHA512>(input);
    case kHashingTiger:
      return crypto::Hash<crypto::Tiger>(input);
    default:
      DLOG(ERROR) << "Hash: Invalid hashing type passed." << std::endl;
  }
  return "";
}

/**
 * We expand the input string by simply repeating it until we reach the required
 * output size. Instead of just repeating it, we could as well repeatedly hash
 * it and append the resulting hashes. But this is thought to not be any more
 * secure than simple repetition when used together with encryption, just a lot
 * slower, so we avoid it until disproven.
 */
bool ResizeObfuscationHash(const std::string &input,
                           const size_t &required_size,
                           std::string *resized_data) {
  if (input.empty() || !resized_data)
    return false;

  resized_data->resize(required_size);
  if (required_size == 0)
    return true;
  size_t input_size(std::min(input.size(), required_size)), copied(input_size);
  memcpy(&((*resized_data)[0]), input.data(), input_size);
  while (copied < required_size) {
    // input_size = std::min(input.size(), required_size - copied);  // slow
    input_size = std::min(copied, required_size - copied);  // fast
    memcpy(&((*resized_data)[copied]), resized_data->data(), input_size);
    copied += input_size;
  }
  return true;
}


std::string XOR(const std::string data, const std::string pad){
std::string result;
        CryptoPP::StringSource (data,true,
                               new XORFilter(
                               new CryptoPP::StringSink(result),
                               pad
                              ));
        return result;
}
  

bool SelfEncryptChunk(std::shared_ptr<std::string> content,
                             const std::string &encryption_hash,
                             const std::string &obfuscation_hash,
                             const uint32_t &self_encryption_type) {
  if (content->empty() || encryption_hash.empty() || obfuscation_hash.empty()) {
    DLOG(ERROR) << "SelfEncryptChunk: Invalid arguments passed." << std::endl;
    return false;
  }
  if (((self_encryption_type & kCompressionMask) == kCompressionNone) &&
      ((self_encryption_type & kObfuscationMask) == kObfuscationNone) &&
      ((self_encryption_type & kCryptoMask) == kCryptoNone))
    return false; // nothing to do !!
  std::string processed_content;
  
// Attach and detach operations to anchor
  Anchor anchor;

 // compression
  switch (self_encryption_type & kCompressionMask) {
    case kCompressionNone:
      break;
    case kCompressionGzip:
      anchor.Attach(new CryptoPP::Gzip(
         new CryptoPP::StringSink(processed_content), kCompressionRatio));
      break;
    default:
      DLOG(ERROR) << "Compress: Invalid compression type passed." << std::endl;
  }

  // obfuscation
  switch (self_encryption_type & kObfuscationMask) {
    case kObfuscationNone:
      break;
    case kObfuscationRepeated:
      {
        std::string prefix;
        if (encryption_hash.size() > crypto::AES256_KeySize) {
          // add the remainder of the encryption hash to the obfuscation hash
          prefix = encryption_hash.substr(crypto::AES256_KeySize);
        }
        std::string obfuscation_pad = prefix + obfuscation_hash;

        anchor.Attach(new XORFilter(
                      new CryptoPP::StringSink(processed_content),
                      obfuscation_pad
                      ));
      }
      break;
    default:
      DLOG(ERROR) << "SelfEncryptChunk: Invalid obfuscation type passed."
                  << std::endl;
      return false;
  }

  // encryption
  // Get the hash out
  // add redirector to AESFilter instead of stringsink
      std::string hash;
      CryptoPP::SHA512 SHA512;
      CryptoPP::HashFilter get_hash(SHA512,
          new CryptoPP::StringSink(processed_content));
  switch (self_encryption_type & kCryptoMask) {
    case kCryptoNone:
      break;
    case kCryptoAes256:
      {
        std::string enc_hash;
        if (!ResizeObfuscationHash(encryption_hash,
                                   crypto::AES256_KeySize +
                                       crypto::AES256_IVSize,
                                   &enc_hash)) {
          DLOG(ERROR) << "SelfEncryptChunk: Could not expand encryption hash."
                      << std::endl;
          return false;
        }

      CryptoPP::SHA512  hash; 
      anchor.Attach(new AESFilter(
                      new CryptoPP::StringSink(processed_content), 
                    enc_hash,
                    true));
     // std::cout << processed_content << std::endl;
      }
      break;
    default:
      DLOG(ERROR) << "SelfEncryptChunk: Invalid encryption type passed."
                  << std::endl;
      return false;
  }

  anchor.Put(reinterpret_cast<const byte*>(content->c_str()), content->size());
  anchor.MessageEnd();
  std::swap(*content,processed_content);
  std::string this_hash;
  //std::cout << " My HASH is " << get_hash. << std::endl;
  return true;
}

bool SelfDecryptChunk(std::shared_ptr<std::string> content,
                             const std::string &encryption_hash,
                             const std::string &obfuscation_hash,
                             const uint32_t &self_encryption_type) {
  if (content->empty() || encryption_hash.empty() || obfuscation_hash.empty()) {
    DLOG(ERROR) << "SelfDecryptChunk: Invalid arguments passed." << std::endl;
    return false;
  }
  if (((self_encryption_type & kCompressionMask) == kCompressionNone) &&
      ((self_encryption_type & kObfuscationMask) == kObfuscationNone) &&
      ((self_encryption_type & kCryptoMask) == kCryptoNone))
    return false; // nothing to do !!
  std::string processed_content;
  processed_content.reserve(content->size());

// Attach and detach operations to anchor
  Anchor anchor;
  // decryption
  switch (self_encryption_type & kCryptoMask) {
    case kCryptoNone:
      break;
    case kCryptoAes256:
      {
        std::string enc_hash;
        if (!ResizeObfuscationHash(encryption_hash,
                                   crypto::AES256_KeySize +
                                       crypto::AES256_IVSize,
                                   &enc_hash)) {
          DLOG(ERROR) << "SelfDecryptChunk: Could not expand encryption hash."
                      << std::endl;
          return false;
        }
      anchor.Attach(new AESFilter(
                    new CryptoPP::StringSink(processed_content),
                    enc_hash,
                    false));
      }
      break;
    default:
      DLOG(ERROR) << "SelfDecryptChunk: Invalid encryption type passed."
                  << std::endl;
      return false;
  }

  // de-obfuscation
  switch (self_encryption_type & kObfuscationMask) {
    case kObfuscationNone:
      break;
    case kObfuscationRepeated:
      {
        std::string prefix;
        if (encryption_hash.size() > crypto::AES256_KeySize) {
          // add the remainder of the encryption hash to the obfuscation hash
          prefix = encryption_hash.substr(crypto::AES256_KeySize);
        }
        std::string obfuscation_pad = prefix + obfuscation_hash;
        anchor.Attach(new XORFilter(
                      new CryptoPP::StringSink(processed_content),
                      obfuscation_pad
                      ));
      }
      break;
    default:
      DLOG(ERROR) << "SelfDecryptChunk: Invalid obfuscation type passed."
                  << std::endl;
      return false;
  }

  // decompression
  switch (self_encryption_type & kCompressionMask) {
    case kCompressionNone:
      break;
    case kCompressionGzip:
      anchor.Attach(new CryptoPP::Gunzip(
        new CryptoPP::StringSink(processed_content)));
      break;
    default:
      DLOG(ERROR) << "Compress: Invalid compression type passed." << std::endl;
  }
  anchor.Put(reinterpret_cast<const byte*>(content->c_str()), content->size());
  anchor.MessageEnd();
  std::swap(*content, processed_content);
  return true;
}

}  // namespace utils

}  // namespace encrypt

}  // namespace maidsafe
