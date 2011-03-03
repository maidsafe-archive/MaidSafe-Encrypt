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

#include <map>
#include <set>
#include <sstream>
#include <vector>

#include "maidsafe-dht/common/crypto.h"
#include "maidsafe-dht/common/log.h"
#include "maidsafe-dht/common/utils.h"
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
 * Derived chunks will be created in output_dir.
 *
 * @param input_stream The stream providing data to self-encrypt.
 * @param output_dir Directory to store derived chunks in.
 * @param try_compression Whether to attempt compression of the data.
 * @param self_encryption_params Parameters for the self-encryption algorithm.
 * @param data_map DataMap to be populated with chunk metadata.
 * @return Result of the operation.
 */
int SelfEncrypt(std::istream *input_stream,
                const fs::path &output_dir,
                bool try_compression,
                const SelfEncryptionParams &self_encryption_params,
                DataMap *data_map) {
  if (!data_map || !input_stream) {
    DLOG(ERROR) << "EncryptContent: One of the pointers is null." << std::endl;
    return kNullPointer;
  }

  // TODO pass size in for proper streaming, avoid seeking
  input_stream->seekg(0, std::ios::end);
  std::streampos pos = input_stream->tellg();

  if (!input_stream->good() || pos < 1) {
    DLOG(ERROR) << "EncryptContent: Input stream is invalid." << std::endl;
    return kInvalidInput;
  }
  std::uint64_t data_size(static_cast<std::uint64_t>(pos));

  bool compress(false);
  if (try_compression) {
    if (2 * data_size > kCompressionSampleSize)
      input_stream->seekg(0);
    else
      input_stream->seekg((data_size - kCompressionSampleSize) / 2);
    compress = utils::CheckCompressibility(input_stream);
    if (compress)
      data_map->compression_type = kGzipCompression;
  }

  data_map->self_encryption_type = kObfuscate3AES256;
  data_map->size = data_size;

  input_stream->seekg(0);

  if (data_size <= self_encryption_params.max_includable_data_size) {
    // No chunking, include data in DataMap
    data_map->chunks.clear();
    data_map->content.resize(data_size);
    input_stream->read(&(data_map->content[0]), data_size);
    if (input_stream->bad() || input_stream->gcount() != data_size) {
      DLOG(ERROR) << "EncryptContent: Failed to read content." << std::endl;
      return kIoError;
    }
    if (compress) {
      data_map->content = crypto::Compress(data_map->content,
                                           kCompressionLevel);
      if (data_map->content.empty()) {
        DLOG(ERROR) << "EncryptContent: Failed to compress content."
                    << std::endl;
        return kCompressionError;
      }
    }
    return kSuccess;
  }

  // FIXME find method to guarantee constant chunk size with compression
  compress = false;
  data_map->compression_type = kNoCompression;

  std::vector<std::uint32_t> chunk_sizes;
  if (!utils::CalculateChunkSizes(data_size, self_encryption_params,
                                  &chunk_sizes) ||
      chunk_sizes.size() < 3) {
    DLOG(ERROR) << "EncryptContent: CalculateChunkSizes failed." << std::endl;
    return kChunkSizeError;
  }

  size_t chunk_count(chunk_sizes.size());
  std::map<std::string, size_t> processed_chunks;
  std::string chunk_content[3], chunk_hash[3];  // sliding window of size 3

  // read the first 2 chunks and calculate their hashes
  chunk_content[0].resize(chunk_sizes[0]);
  input_stream->read(&(chunk_content[0][0]), chunk_sizes[0]);
  chunk_content[1].resize(chunk_sizes[1]);
  input_stream->read(&(chunk_content[1][0]), chunk_sizes[1]);
  if (input_stream->bad()) {
    DLOG(ERROR) << "EncryptContent: Failed to read content." << std::endl;
    return kIoError;
  }
  chunk_hash[0] = crypto::Hash<crypto::SHA512>(chunk_content[0]);
  chunk_hash[1] = crypto::Hash<crypto::SHA512>(chunk_content[1]);

  for (size_t i = 0; i < chunk_count; ++i) {
    // read the second next chunk and calculate its hash
    std::uint32_t idx = (i + 2) % 3;
    if (i + 2 < chunk_count) {
      chunk_content[idx].resize(chunk_sizes[i + 2]);
      input_stream->read(&(chunk_content[idx][0]), chunk_sizes[i + 2]);
      if (input_stream->bad() || input_stream->gcount() != chunk_sizes[i + 2]) {
        DLOG(ERROR) << "EncryptContent: Failed to read content." << std::endl;
        return kIoError;
      }
      chunk_hash[idx] = crypto::Hash<crypto::SHA512>(chunk_content[idx]);
    } else {
      chunk_hash[idx] = data_map->chunks[(i + 2) % chunk_count].pre_hash;
    }

    ChunkDetails chunk;
    chunk.pre_hash = chunk_hash[i % 3];
    chunk.pre_size = chunk_sizes[i];

    if (processed_chunks.count(chunk.pre_hash) > 0) {
      // we already processed an identical chunk before
      ChunkDetails &prev_chunk =
          data_map->chunks[processed_chunks[chunk.pre_hash]];
      chunk.content = prev_chunk.content;
      chunk.hash = prev_chunk.hash;
      chunk.size = prev_chunk.size;
      // DLOG(INFO) << "SelfEncrypt: chunk cache hit" << std::endl;
    } else {
      if (compress) {
        chunk_content[i % 3] = crypto::Compress(chunk_content[i % 3],
                                                kCompressionLevel);
        if (chunk_content[i % 3].empty()) {
          DLOG(ERROR) << "EncryptContent: Failed to compress chunk content."
                      << std::endl;
          return kCompressionError;
        }
      }

      if (chunk_sizes[i] <= self_encryption_params.max_includable_chunk_size) {
        chunk.content = chunk_content[i % 3];
        chunk.size = chunk_content[i % 3].size();
        // sic: chunk.hash left empty
      } else {
        chunk_content[i % 3] = utils::SelfEncryptChunk(chunk_content[i % 3],
                                                      chunk_hash[(i + 1) % 3],
                                                      chunk_hash[(i + 2) % 3]);

        chunk.hash = crypto::Hash<crypto::SHA512>(chunk_content[i % 3]);
        chunk.size = chunk_content[i % 3].size();  // encrypt. might add padding
        // sic: chunk.content left empty

        // write chunk file
        fs::path chunk_path = output_dir / EncodeToHex(chunk.hash);
        if (!fs::exists(chunk_path)) {
          // only try writing chunk if it hasn't been created before
          if (!utils::WriteFile(chunk_path, chunk_content[i % 3])) {
            DLOG(ERROR) << "EncryptContent: Can't write chunk data to "
                        << chunk_path.c_str() << std::endl;
            return kIoError;
          }
        }
      }

      processed_chunks[chunk.pre_hash] = data_map->chunks.size();
    }

    data_map->chunks.push_back(chunk);
  }
  return kSuccess;
}

/**
 * Splits data from input string into chunks, compresses them if possible,
 * obfuscates and then encrypts them. Chunk metadata is stored in the DataMap.
 *
 * Derived chunks will be created in output_dir.
 *
 * @param input_string The string providing data to self-encrypt.
 * @param output_dir Directory to store derived chunks in.
 * @param try_compression Whether to attempt compression of the data.
 * @param self_encryption_params Parameters for the self-encryption algorithm.
 * @param data_map DataMap to be populated with chunk metadata.
 * @return Result of the operation.
 */
int SelfEncrypt(const std::string &input_string,
                const fs::path &output_dir,
                bool try_compression,
                const SelfEncryptionParams &self_encryption_params,
                DataMap *data_map) {
  std::istringstream input_stream(input_string);
  return SelfEncrypt(&input_stream, output_dir, try_compression,
                     self_encryption_params, data_map);
}

/**
 * Splits data from input file into chunks, compresses them if possible,
 * obfuscates and then encrypts them. Chunk metadata is stored in the DataMap.
 *
 * Based on the file extension, a decision is made whether an attempt to
 * compress the data should be undertaken. Use SelfEncrypt for streams if you
 * want to override this behaviour.
 *
 * Derived chunks will be created in output_dir.
 *
 * @param input_file The file providing data to self-encrypt.
 * @param output_dir Directory to store derived chunks in.
 * @param self_encryption_params Parameters for the self-encryption algorithm.
 * @param data_map DataMap to be populated with chunk metadata.
 * @return Result of the operation.
 */
int SelfEncrypt(const fs::path &input_file,
                const fs::path &output_dir,
                const SelfEncryptionParams &self_encryption_params,
                DataMap *data_map) {
  fs::ifstream input_stream(input_file, std::ios::in | std::ios::binary);
  int result(SelfEncrypt(&input_stream, output_dir,
                         utils::IsCompressedFile(input_file),
                         self_encryption_params, data_map));
  input_stream.close();
  return result;
}

/**
 * All neccessary chunks should be available in the given directory and named as
 * hex-encoded hashes of their contents.
 *
 * @param data_map DataMap with chunk information.
 * @param input_dir Location of the chunk files.
 * @param output_stream Pointer to stream receiving resulting data.
 * @return Result of the operation.
 */
int SelfDecrypt(const DataMap &data_map,
                const fs::path &input_dir,
                std::ostream *output_stream) {
  if (!output_stream)
    return kNullPointer;

  if (!output_stream->good()) {
    DLOG(ERROR) << "SelfDecrypt: Output stream is invalid."
                << std::endl;
    return kIoError;
  }

  SelfEncryptionStream input_stream(data_map, input_dir);

  // input_stream >> output_stream->rdbuf();
  std::streamsize buffer_size(io::optimal_buffer_size(input_stream));
  char *buffer = new char[buffer_size];
  while (input_stream.good()) {
    input_stream.read(buffer, buffer_size);
    output_stream->write(buffer, input_stream.gcount());
  }
  delete buffer;

  std::streamsize copied_size(output_stream->tellp());

  if (copied_size != data_map.size) {
    DLOG(ERROR) << "SelfDecrypt: Amount of data read (" << copied_size
                << ") does not match total data size (" << data_map.size << ")."
                << std::endl;
    return kDecryptError;
  }

  if (!input_stream.eof() || !output_stream->good()) {
    DLOG(ERROR) << "SelfDecrypt: Stream read operation failed." << std::endl;
    return kDecryptError;
  }

  return kSuccess;
}

/**
 * All neccessary chunks should be available in the given directory and named as
 * hex-encoded hashes of their contents.
 *
 * @param data_map DataMap with chunk information.
 * @param input_dir Location of the chunk files.
 * @param output_string Pointer to string receiving resulting data.
 * @return Result of the operation.
 */
int SelfDecrypt(const DataMap &data_map,
                const fs::path &input_dir,
                std::string *output_string) {
  if (!output_string)
    return kNullPointer;
  std::ostringstream output_stream;
  int result(SelfDecrypt(data_map, input_dir, &output_stream));
  *output_string = output_stream.str();
  return result;
}

/**
 * All neccessary chunks should be available in the given directory and named as
 * hex-encoded hashes of their contents.
 *
 * @param data_map DataMap with chunk information.
 * @param input_dir Location of the chunk files.
 * @param overwrite Whether to overwrite an already existing output file.
 * @param output_file Path to file receiving resulting data.
 * @return Result of the operation.
 */
int SelfDecrypt(const DataMap &data_map,
                const fs::path &input_dir,
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
  fs::ofstream output_stream(output_file, std::ios::out | std::ios::trunc |
                                          std::ios::binary);
  int result(SelfDecrypt(data_map, input_dir, &output_stream));
  output_stream.close();
  return result;
}

/**
 * Looks through the DataMap and, unless a chunk's content is included, checks
 * if a file with the hex-encoded pre-encryption hash exists in the given
 * directory.
 *
 * @param data_map DataMap with chunk information.
 * @param input_dir Location of the chunk files.
 * @param missing_chunks Pointer to vector to receive list of unavailable
 *                       chunks' names, or NULL if not needed.
 * @return True if all chunk files exist, otherwise false;
 */
bool ChunksExist(const DataMap &data_map,
                 const fs::path &input_dir,
                 std::vector<std::string> *missing_chunks) {
  bool result(true);
  if (missing_chunks)
    missing_chunks->clear();
  for (auto it = data_map.chunks.begin(); it != data_map.chunks.end(); ++it) {
    if (it->content.empty() && !fs::exists(input_dir / EncodeToHex(it->hash))) {
      if (missing_chunks)
        missing_chunks->push_back(it->hash);
      result = false;
    }
  }
  return result;
}

}  // namespace encrypt

}  // namespace maidsafe
