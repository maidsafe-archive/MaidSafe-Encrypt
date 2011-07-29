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
#include "cryptopp/channels.h"
#include "cryptopp/mqueue.h"

#ifdef __MSVC__
#  pragma warning(pop)
#endif
#include "boost/filesystem/fstream.hpp"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/common/chunk_store.h"
#include "maidsafe/encrypt/config.h"
#include "maidsafe/encrypt/data_map.h"
#include "maidsafe/encrypt/log.h"
#include "maidsafe/encrypt/utils.h"

namespace fs = boost::filesystem;

namespace maidsafe {

namespace encrypt {
/**
 * Implementation of XOR transformation filter to allow pipe-lining
 *
 */
size_t XORFilter::Put2(const byte* inString,
                      size_t length,
                      int messageEnd,
                      bool blocking) {
  // Anything to process for us? If not, we will pass it on
  // to the lower filter just in case
  if((length == 0))
        return AttachedTransformation()->Put2(inString,
                                          length,
                                          messageEnd,
                                          blocking);
  if((pad_length_ == 0))
    throw CryptoPP::Exception(CryptoPP::Exception::INVALID_DATA_FORMAT,
                              "XORFilter zero length PAD passed");

  size_t buffer_size(length);
  // Do XOR

  byte *buffer = new byte[length];

  for (size_t i = 0; i <= length; ++i) {
     buffer[i] = inString[i] ^ pad_[i%pad_length_]; // don't overrun the pad
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
  if((length == 0))
        return AttachedTransformation()->Put2(inString,
                                          length,
                                          messageEnd,
                                          blocking);

    byte *out_string = new byte[length];
  if (encrypt_) {
  // Encryptor object
  CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption encryptor(key_,
    32, iv_);
    encryptor.ProcessData((byte*)out_string, (byte*)inString, length);
  } else {
  //decryptor object
    CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption decryptor(this->key_,
    32, this->iv_);
     decryptor.ProcessData((byte*)out_string, (byte*)inString, length);
  }
  return AttachedTransformation()->Put2(out_string,
                                         length,
                                         messageEnd,
                                         blocking);
};


bool SE::Write (const char* data, size_t length, bool complete) {
  main_encrypt_queue_.Put(const_cast<byte*>(reinterpret_cast<const byte*>(data)), length);
  length_ += length; // keep size so far

  size_t qlength = main_encrypt_queue_.MaxRetrievable();

  if (length_ < chunk_size_ * 3)
    if (!complete)
      return true; // not finished getting data
    else
      chunk_size_ = (length_ - 1) / 3;

// small files direct to data map
  if ((chunk_size_ *3 < 1025) && complete) {
    byte *i;
    main_encrypt_queue_.Get(i, qlength);
    data_map_.content = i;
    chunk_size_ = 1024*256;
    main_encrypt_queue_.SkipAll();
    main_encrypt_queue_.Initialize();
    return true;
  }

// START

  if (data_map_.chunks.size() < 2) { // need first 2 hashes
    main_encrypt_queue_.TransferTo(chunk1_hash_filter, chunk_size_);
    chunk1_hash_filter.MessageEnd();
    main_encrypt_queue_.TransferTo(chunk2_hash_filter, chunk_size_);
    chunk2_hash_filter.MessageEnd();
    ChunkDetails2 chunk1_data, chunk2_data;
    chunk1_data.pre_hash = const_cast<byte*>(reinterpret_cast<const byte *>(chunk1_and_hash_.substr(0, 64).c_str()));
    chunk1_data.pre_size = chunk_size_;
    data_map_.chunks.push_back(chunk1_data);
    chunk2_data.pre_hash = const_cast<byte*>(reinterpret_cast<const byte *>(chunk2_and_hash_.substr(0, 64).c_str()));
    chunk2_data.pre_size = chunk_size_;
    data_map_.chunks.push_back(chunk2_data);
  }
  
  while (main_encrypt_queue_.MaxRetrievable() > chunk_size_) {
    EncryptChunkFromQueue(99);
  }

  if (complete) {
    size_t complete_q_length = main_encrypt_queue_.MaxRetrievable();
    if (complete_q_length < 1025)
      main_encrypt_queue_.Get(data_map_.content, complete_q_length);
    else {
      chunk_size_ = (complete_q_length / 3) - 1; 
        if ((chunk_size_ *3 < 1025) && complete) {
          main_encrypt_queue_.Get(data_map_.content , qlength);
          chunk_size_ = 1024*256;
        }
      EncryptChunkFromQueue(99);
      chunk_size_ = (1024 * 256);
    }
    EncryptChunkFromQueue(0);
    EncryptChunkFromQueue(1);
    chunk_size_ = 1024*256;
  }
// If we are not finished main_queue_ still has data in it !!
  return true;
}

bool SE::EncryptChunkFromQueue(size_t chunk) {
    std::string chunk_content;
    byte *pre_hash;
    byte *pre_enc_hashn, *test, *processign_content;
    if ((chunk != 0) && (chunk != 1)) {
     main_encrypt_queue_.TransferTo(current_chunk_hash_filter_, chunk_size_);
     current_chunk_hash_filter_.MessageEnd();
    }
    
    size_t last_chunk_number = (data_map_.chunks.size() -1);
    byte *key;
    byte *iv;
    std::copy(data_map_.chunks[last_chunk_number].pre_hash,
              data_map_.chunks[last_chunk_number].pre_hash + 32,
              key);
    std::copy(data_map_.chunks[last_chunk_number].pre_hash + 32,
              data_map_.chunks[last_chunk_number].pre_hash + 48,
              iv);

    byte *obfuscation_pad;
    memcpy(obfuscation_pad, data_map_.chunks[last_chunk_number].pre_hash, 64);
    memcpy(obfuscation_pad,
           data_map_.chunks[last_chunk_number - 1].pre_hash,
           64);

    XORFilter aes_filter(
//                    new AESFilter(
                     new XORFilter(
                        new CryptoPP::HashFilter(hash_,
                          new CryptoPP::StringSink(chunk_content)
                        , true)
                     , obfuscation_pad, 128)
                   /*, key , iv, true)*/);

    if (chunk == 0) {
      size_t size = chunk1_and_hash_.size() + 1;
      byte *putdata;
      std::copy(chunk1_and_hash_.begin(), chunk1_and_hash_.end(), putdata);
      aes_filter.Put(putdata, size);
      aes_filter.MessageEnd();
      std::string post_hash = chunk_content.substr(0,64);
      //std::copy (chunk_content, chunk_content + 64, post_hash);
      std::string post_data = chunk_content.substr(64);
      size_t post_size = chunk_size_;
      data_map_.chunks[0].size = post_size;
      data_map_.chunks[0].hash = const_cast<byte*>(reinterpret_cast<const byte *>(post_hash.c_str()));
      chunk_store_->Store(post_hash, post_data);
    } else if (chunk == 1) {
      size_t size = chunk2_and_hash_.size() + 1;
      byte *putdata;
      std::copy(chunk2_and_hash_.begin(), chunk2_and_hash_.end(), putdata);
      aes_filter.Put(putdata, size);
      aes_filter.MessageEnd();
      std::string post_hash = chunk_content.substr(0,64);
      std::string post_data = chunk_content.substr(64);
      size_t post_size = chunk_size_;
      data_map_.chunks[1].size = post_size;
      data_map_.chunks[1].hash = const_cast<byte*>(reinterpret_cast<const byte *>(post_hash.c_str()));
      chunk_store_->Store(post_hash, post_data);
    } else {
      size_t size = 200; //current_chunk_and_hash_.size() + 1;
      byte *putdata;
      std::copy(current_chunk_and_hash_.begin(), current_chunk_and_hash_.end(), putdata);
      //putdata[size] = '\0';
      aes_filter.Put(putdata, size);
      aes_filter.MessageEnd();
      std::string post_hash = chunk_content.substr(0,64);
      //std::copy (chunk_content, chunk_content + 64, post_hash);
      std::string post_data = chunk_content.substr(64);
      size_t post_size = chunk_size_;
      ChunkDetails2 chunk_details;
      chunk_details.pre_hash = const_cast<byte*>(reinterpret_cast<const byte *>(current_chunk_and_hash_.substr(0, 64).c_str()));
      chunk_details.pre_size = chunk_size_;
      chunk_details.size = post_size;
      chunk_details.hash = const_cast<byte*>(reinterpret_cast<const byte *>(post_hash.c_str()));
      data_map_.chunks.push_back(chunk_details);
      chunk_store_->Store(post_hash, post_data);
     }


    return true;
}

bool SE::Read(char* data, std::shared_ptr<DataMap2> data_map)
{
  if (!data_map)
    data_map.reset(new DataMap2(data_map_));
  auto itr = data_map->chunks.end();
  --itr;
  byte *N_1_pre_hash = (*itr).pre_hash;
  --itr;
  byte *N_2_pre_hash = (*itr).pre_hash;

  Anchor anchor;

  for(auto it = data_map->chunks.begin(); it != data_map->chunks.end(); ++it) {
    byte *pre_hash = (*it).pre_hash;
    byte obfuscation_pad[128];
    memcpy(obfuscation_pad, N_1_pre_hash, 64);
    memcpy(obfuscation_pad, N_2_pre_hash, 64);

    byte key[32];
    byte iv[16];
    std::copy(N_1_pre_hash, N_1_pre_hash + 32, key);
    std::copy(N_1_pre_hash + 32, N_1_pre_hash + 48, iv);

    XORFilter xor_filter(new XORFilter(
            new AESFilter(
                new CryptoPP::ArraySink(reinterpret_cast< byte* >(data),
                                        data_map->size),
                key, iv, false),
            obfuscation_pad));

    std::string hash(reinterpret_cast< char const* >((*it).hash),
                     sizeof((*it).hash));
    std::string content(chunk_store_->Get(hash));
    byte content_bytes[content.size()];
    std::copy(content.begin(), content.end(), content_bytes);
    xor_filter.Put(content_bytes, content.size());

    N_2_pre_hash = N_1_pre_hash;
    N_1_pre_hash = pre_hash;
  }
}

bool SE::PartialRead(char * data, size_t position, size_t length,
                     std::shared_ptr<DataMap2> data_map) {
  if (!data_map)
    data_map.reset(new DataMap2(data_map_));
  size_t itr_position(0);
  size_t bytes_read(0);
  size_t chunk_size(256 * 1024);

  auto itr = data_map->chunks.end();
  --itr;
  byte *N_1_pre_hash = (*itr).pre_hash;
  --itr;
  byte *N_2_pre_hash = (*itr).pre_hash;

  Anchor anchor;
  bool start_read(false);
  bool read_finished(false);

  auto it = data_map->chunks.begin();
  auto it_end = data_map->chunks.end();

  while ((it != it_end) && (!read_finished)) {
    byte *pre_hash = (*it).pre_hash;

    if (!start_read) {
      if ((itr_position + chunk_size) >= position) {
        start_read = true;
      }
    } else {
      if (itr_position >= (position + length)) {
        read_finished = true;
      } else {
        byte obfuscation_pad[128];
        memcpy(obfuscation_pad, N_1_pre_hash, 64);
        memcpy(obfuscation_pad, N_2_pre_hash, 64);

        byte key[32];
        byte iv[16];
        std::copy(N_1_pre_hash, N_1_pre_hash + 32, key);
        std::copy(N_1_pre_hash + 32, N_1_pre_hash + 48, iv);

        anchor.Attach(new XORFilter(
                new AESFilter(
                    new CryptoPP::ArraySink(reinterpret_cast< byte* >(data),
                                            length),
                    key, iv, false),
                obfuscation_pad));

        std::string hash(reinterpret_cast< char const* >((*it).hash),
                        sizeof((*it).hash));
        std::string content(chunk_store_->Get(hash));
        byte content_bytes[content.size()];
        std::copy(content.begin(), content.end(), content_bytes);

        size_t start = itr_position >= position ? 0 : itr_position - position;
        start = start % chunk_size;
        size_t end = (itr_position + (*it).pre_size) < (position + length) ?
                        (*it).size : (position + length) - itr_position;
        end = end % chunk_size;
        size_t size = end - start + 1;
        byte sub_content_bytes[size];
        std::copy(content_bytes + start, content_bytes + end,
                  sub_content_bytes);

        anchor.Put(sub_content_bytes, size);

        anchor.Detach();
      }
    }

    N_2_pre_hash = N_1_pre_hash;
    N_1_pre_hash = pre_hash;
    itr_position += (*it).pre_size;
    ++it;
  }
}



}  // namespace encrypt

}  // namespace maidsafe
