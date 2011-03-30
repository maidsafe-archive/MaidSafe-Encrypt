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
 * @file  self_encryption.cc
 * @brief Provides self-encryption/self-decryption functionality.
 * @date  2008-09-09
 */

#include "maidsafe-encrypt/self_encryption.h"

#include <array>
#include <map>
#include <memory>
#include <set>
#include <sstream>
#include <vector>

#include "maidsafe/common/chunk_store.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"
#include "maidsafe-encrypt/config.h"
#include "maidsafe-encrypt/data_map.h"
#include "maidsafe-encrypt/self_encryption_stream.h"
#include "maidsafe-encrypt/utils.h"
#include "boost/filesystem/fstream.hpp"

namespace fs = boost::filesystem;

namespace maidsafe {

namespace encrypt {

/**
 * Splits data from input stream into chunks, compresses them if possible,
 * obfuscates and then encrypts them. Chunk metadata is stored in the DataMap.
 *
 * @param input_stream The stream providing data to self-encrypt.
 * @param try_compression Whether to attempt compression of the data.
 * @param self_encryption_params Parameters for the self-encryption algorithm.
 * @param data_map DataMap to be populated with chunk metadata.
 * @param chunk_store ChunkStore for resulting chunks.
 * @return Result of the operation.
 */
int SelfEncrypt(std::shared_ptr<std::istream> input_stream,
                bool try_compression,
                const SelfEncryptionParams &self_encryption_params,
                std::shared_ptr<DataMap> data_map,
                std::shared_ptr<ChunkStore> chunk_store) {
  if (!input_stream || !data_map || !chunk_store) {
    DLOG(ERROR) << "SelfEncrypt: One of the pointers is null." << std::endl;
    return kNullPointer;
  }

  if (!utils::CheckParams(self_encryption_params)) {
    DLOG(ERROR) << "SelfEncrypt: Invalid parameters passed." << std::endl;
    return kInvalidInput;
  }

  // TODO(Steve) pass size in for proper streaming, avoid seeking
  input_stream->seekg(0, std::ios::end);
  std::streampos pos = input_stream->tellg();

  if (!input_stream->good() || pos < 1) {
    DLOG(ERROR) << "SelfEncrypt: Input stream is invalid." << std::endl;
    return kInvalidInput;
  }
  std::uint64_t data_size(static_cast<std::uint64_t>(pos));

  bool compress(false);
  if (try_compression) {
    if (data_size < 2 * kCompressionSampleSize)
      input_stream->seekg(0);
    else
      input_stream->seekg((data_size - kCompressionSampleSize) / 2);
    std::string test_data(kCompressionSampleSize, 0);
    input_stream->read(&(test_data[0]), kCompressionSampleSize);
    test_data.resize(input_stream->gcount());
    compress = utils::CheckCompressibility(test_data, kCompressionGzip);
  }

  data_map->self_encryption_type =
      kHashingSha512 | kObfuscationRepeated | kCryptoAes256;
  if (compress)
    data_map->self_encryption_type |= kCompressionGzip;
  else
    data_map->self_encryption_type |= kCompressionNone;

  data_map->size = data_size;

  input_stream->clear();
  input_stream->seekg(0);

  if (data_size <= self_encryption_params.max_includable_data_size) {
    // No chunking, include data in DataMap
    data_map->chunks.clear();
    data_map->content.resize(data_size);
    input_stream->read(&(data_map->content[0]), data_size);
    if (input_stream->bad() || input_stream->gcount() != data_size) {
      DLOG(ERROR) << "SelfEncrypt: Failed to read content." << std::endl;
      return kIoError;
    }
    return kSuccess;
  }

  std::vector<std::uint32_t> chunk_sizes;
  if (!utils::CalculateChunkSizes(data_size, self_encryption_params,
                                  &chunk_sizes) ||
      chunk_sizes.size() < 3) {
    DLOG(ERROR) << "SelfEncrypt: CalculateChunkSizes failed." << std::endl;
    return kChunkSizeError;
  }

  std::uint32_t tail(0);
  if (chunk_sizes.back() <= self_encryption_params.max_includable_chunk_size) {
    tail = chunk_sizes.back();
    chunk_sizes.pop_back();
  }

  size_t chunk_count(chunk_sizes.size());
  std::map<std::string, size_t> processed_chunks;
  std::array<std::string, 3> chunk_content, chunk_hash;  // sliding window = 3

  // read the first 2 chunks and calculate their hashes
  chunk_content[0].resize(chunk_sizes[0]);
  input_stream->read(&(chunk_content[0][0]), chunk_sizes[0]);
  chunk_content[1].resize(chunk_sizes[1]);
  input_stream->read(&(chunk_content[1][0]), chunk_sizes[1]);
  if (input_stream->bad()) {
    DLOG(ERROR) << "SelfEncrypt: Failed to read content." << std::endl;
    return kIoError;
  }
  chunk_hash[0] = utils::Hash(chunk_content[0], data_map->self_encryption_type);
  chunk_hash[1] = utils::Hash(chunk_content[1], data_map->self_encryption_type);

  for (size_t i = 0; i < chunk_count; ++i) {
    // read the second next chunk and calculate its hash
    std::uint32_t idx = (i + 2) % 3;
    if (i + 2 < chunk_count) {
      chunk_content[idx].resize(chunk_sizes[i + 2]);
      input_stream->read(&(chunk_content[idx][0]), chunk_sizes[i + 2]);
      if (input_stream->bad() || input_stream->gcount() != chunk_sizes[i + 2]) {
        DLOG(ERROR) << "SelfEncrypt: Failed to read content." << std::endl;
        return kIoError;
      }
      chunk_hash[idx] = utils::Hash(chunk_content[idx],
                                    data_map->self_encryption_type);
    } else {
      chunk_hash[idx] = data_map->chunks[(i + 2) % chunk_count].pre_hash;
    }

    ChunkDetails chunk;
    chunk.pre_hash = chunk_hash[i % 3];
    chunk.pre_size = chunk_sizes[i];

    bool chunk_match(false);
    {
      auto prev_chunk_it = processed_chunks.find(chunk.pre_hash);
      if (prev_chunk_it != processed_chunks.end()) {
        std::string next_hash, next_next_hash;
        size_t diff = i - prev_chunk_it->second;
        if (diff > 2) {
          next_hash = data_map->chunks[(prev_chunk_it->second + 1) %
                                       chunk_count].pre_hash;
          next_next_hash = data_map->chunks[(prev_chunk_it->second + 2) %
                                            chunk_count].pre_hash;
        } else if (diff == 2) {
          next_hash = data_map->chunks[(prev_chunk_it->second + 1) %
                                       chunk_count].pre_hash;
          next_next_hash = chunk.pre_hash;
        } else {  // diff == 1
          next_hash = chunk.pre_hash;
          next_next_hash = chunk_hash[(i + 1) % 3];
        }

        if (next_hash == chunk_hash[(i + 1) % 3] &&
            next_next_hash == chunk_hash[(i + 2) % 3])
          chunk_match = true;
      }
      // further optimisation: store/check triple of hashes in processed_chunks
    }

    if (chunk_match) {
      // we already processed an identical chunk (with same 2 successors) before
      ChunkDetails &prev_chunk =
          data_map->chunks[processed_chunks[chunk.pre_hash]];
      // chunk.content = prev_chunk.content;
      chunk.hash = prev_chunk.hash;
      chunk.size = prev_chunk.size;
      // DLOG(INFO) << "SelfEncrypt: chunk cache hit" << std::endl;
      data_map->chunks.push_back(chunk);
    } else {
      chunk_content[i % 3] = utils::SelfEncryptChunk(
          chunk_content[i % 3], chunk_hash[(i + 1) % 3],
          chunk_hash[(i + 2) % 3], data_map->self_encryption_type);

      chunk.hash = utils::Hash(chunk_content[i % 3],
                               data_map->self_encryption_type);
      chunk.size = chunk_content[i % 3].size();
      // sic: chunk.content left empty

      if (!chunk_store->Store(chunk.hash, chunk_content[i % 3])) {
        DLOG(ERROR) << "SelfEncrypt: Could not store chunk." << std::endl;
        return kEncryptError;
      }

      processed_chunks[chunk.pre_hash] = data_map->chunks.size();
      data_map->chunks.push_back(chunk);
    }
  }

  if (tail > 0) {
    data_map->content.resize(tail);
    input_stream->read(&(data_map->content[0]), tail);
  }

  return kSuccess;
}

/**
 * Splits data from input string into chunks, compresses them if possible,
 * obfuscates and then encrypts them. Chunk metadata is stored in the DataMap.
 *
 * @param input_string The string providing data to self-encrypt.
 * @param try_compression Whether to attempt compression of the data.
 * @param self_encryption_params Parameters for the self-encryption algorithm.
 * @param data_map DataMap to be populated with chunk metadata.
 * @param chunk_store ChunkStore for resulting chunks.
 * @return Result of the operation.
 */
int SelfEncrypt(const std::string &input_string,
                bool try_compression,
                const SelfEncryptionParams &self_encryption_params,
                std::shared_ptr<DataMap> data_map,
                std::shared_ptr<ChunkStore> chunk_store) {
  std::shared_ptr<std::istringstream> input_stream(new std::istringstream(
      input_string));
  return SelfEncrypt(input_stream, try_compression, self_encryption_params,
                     data_map, chunk_store);
}

/**
 * Splits data from input file into chunks, compresses them if possible,
 * obfuscates and then encrypts them. Chunk metadata is stored in the DataMap.
 *
 * Based on the file extension, a decision is made whether an attempt to
 * compress the data should be undertaken. Use SelfEncrypt for streams if you
 * want to override this behaviour.
 *
 * @param input_file The file providing data to self-encrypt.
 * @param self_encryption_params Parameters for the self-encryption algorithm.
 * @param data_map DataMap to be populated with chunk metadata.
 * @param chunk_store ChunkStore for resulting chunks.
 * @return Result of the operation.
 */
int SelfEncrypt(const fs::path &input_file,
                const SelfEncryptionParams &self_encryption_params,
                std::shared_ptr<DataMap> data_map,
                std::shared_ptr<ChunkStore> chunk_store) {
  std::shared_ptr<fs::ifstream> input_stream(new fs::ifstream(
      input_file, std::ios::in | std::ios::binary));
  int result(SelfEncrypt(input_stream, !utils::IsCompressedFile(input_file),
                         self_encryption_params, data_map, chunk_store));
  input_stream->close();
  return result;
}

/**
 * All required chunks should be available in the given ChunkStore.
 *
 * @param data_map DataMap with chunk information.
 * @param chunk_store ChunkStore providing required chunks.
 * @param output_stream Stream receiving resulting data.
 * @return Result of the operation.
 */
int SelfDecrypt(std::shared_ptr<DataMap> data_map,
                std::shared_ptr<ChunkStore> chunk_store,
                std::shared_ptr<std::ostream> output_stream) {
  if (!data_map || !chunk_store || !output_stream)
    return kNullPointer;

  if (!output_stream->good()) {
    DLOG(ERROR) << "SelfDecrypt: Output stream is invalid."
                << std::endl;
    return kIoError;
  }

  SelfEncryptionStream input_stream(data_map, chunk_store);

  // input_stream >> output_stream->rdbuf();
  std::streamsize buffer_size(io::optimal_buffer_size(input_stream));
  char *buffer = new char[buffer_size];
  while (input_stream.good()) {
    input_stream.read(buffer, buffer_size);
    output_stream->write(buffer, input_stream.gcount());
  }
  delete buffer;

  std::streamsize copied_size(output_stream->tellp());

  if (copied_size != data_map->size) {
    DLOG(ERROR) << "SelfDecrypt: Amount of data read (" << copied_size
                << ") does not match total data size (" << data_map->size
                << ")." << std::endl;
    return kDecryptError;
  }

  if (!input_stream.eof() || !output_stream->good()) {
    DLOG(ERROR) << "SelfDecrypt: Stream read operation failed." << std::endl;
    return kDecryptError;
  }

  return kSuccess;
}

/**
 * All required chunks should be available in the given ChunkStore.
 *
 * @param data_map DataMap with chunk information.
 * @param chunk_store ChunkStore providing required chunks.
 * @param output_string String receiving resulting data.
 * @return Result of the operation.
 */
int SelfDecrypt(std::shared_ptr<DataMap> data_map,
                std::shared_ptr<ChunkStore> chunk_store,
                std::string *output_string) {
  if (!output_string)
    return kNullPointer;
  std::shared_ptr<std::ostringstream> output_stream(new std::ostringstream);
  int result(SelfDecrypt(data_map, chunk_store, output_stream));
  *output_string = output_stream->str();
  return result;
}

/**
 * All required chunks should be available in the given ChunkStore.
 *
 * @param data_map DataMap with chunk information.
 * @param chunk_store ChunkStore providing required chunks.
 * @param overwrite Whether to overwrite an already existing output file.
 * @param output_file Path to file receiving resulting data.
 * @return Result of the operation.
 */
int SelfDecrypt(std::shared_ptr<DataMap> data_map,
                std::shared_ptr<ChunkStore> chunk_store,
                bool overwrite,
                const fs::path &output_file) {
  try {
    if (fs::exists(output_file)) {
      if (overwrite)
        fs::remove(output_file);
      else
        return kFileAlreadyExists;
    }
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("SelfDecryptToFile: %s\n", e.what());
#endif
    return kIoError;
  }
  std::shared_ptr<fs::ofstream> output_stream(new fs::ofstream(
      output_file, std::ios::out | std::ios::trunc | std::ios::binary));
  int result(SelfDecrypt(data_map, chunk_store, output_stream));
  output_stream->close();
  return result;
}

/**
 * Looks through the DataMap and checks if it exists in the given ChunkStore.
 *
 * @param data_map DataMap with chunk information.
 * @param chunk_store ChunkStore providing required chunks.
 * @param missing_chunks Pointer to vector to receive list of unavailable
 *                       chunks' names, or NULL if not needed.
 * @return True if all chunks exist, otherwise false.
 */
bool ChunksExist(std::shared_ptr<DataMap> data_map,
                 std::shared_ptr<ChunkStore> chunk_store,
                 std::vector<std::string> *missing_chunks) {
  if (!data_map || !chunk_store)
    return false;
  bool result(true);
  if (missing_chunks)
    missing_chunks->clear();
  for (auto it = data_map->chunks.begin(); it != data_map->chunks.end(); ++it) {
    if (!chunk_store->Has(it->hash)) {
      if (missing_chunks)
        missing_chunks->push_back(it->hash);
      result = false;
    }
  }
  return result;
}

}  // namespace encrypt

}  // namespace maidsafe
