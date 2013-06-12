
/*******************************************************************************
*  Copyright 2011 MaidSafe.net limited                                         *
*                                                                              *
*  The following source code is property of MaidSafe.net limited and is not    *
*  meant for external use.  The use of this code is governed by the license    *
*  file LICENSE.TXT found in the root of this directory and also on            *
*  www.MaidSafe.net.                                                           *
*                                                                              *
*  You are not free to copy, amend or otherwise use this source code without   *
*  the explicit written permission of the board of directors of MaidSafe.net.  *
*******************************************************************************/

// #include <array>
// #include <cstdio>
// #include <functional>
// #include <set>
// #include <string>
//
// #include "boost/algorithm/string.hpp"
// #ifdef WIN32
// #  pragma warning(push)
// #  pragma warning(disable: 4308)
// #endif
// #include "boost/archive/text_oarchive.hpp"
// #ifdef WIN32
// #  pragma warning(pop)
// #endif
// #include "boost/archive/text_iarchive.hpp"
// #include "boost/filesystem.hpp"
// #include "boost/format.hpp"
// #include "boost/lexical_cast.hpp"
// #include "boost/serialization/map.hpp"
// #include "maidsafe/common/crypto.h"
// #include "maidsafe/common/file_chunk_store.h"
// #include "maidsafe/common/log.h"
// #include "maidsafe/common/utils.h"
// #include "maidsafe/encrypt/data_map.h"
// #include "maidsafe/encrypt/self_encryption.h"
// #include "maidsafe/encrypt/utils.h"
//
// namespace fs = boost::filesystem;
// namespace mse = maidsafe::encrypt;
//
// namespace maidsafe {
// namespace encrypt {
// namespace demo {
//
// enum ReturnCodes {
//   kSuccess = 0,
//   kNoArgumentsError,
//   kCommandError,
//   kInvalidArgumentsError,
//   kGenerateError,
//   kEncryptError,
//   kDecryptError
// };
//
// /// Formats and scales a byte value with IEC units
// std::string FormatByteValue(const uint64_t &value) {
//   const std::array<std::string, 7> kUnits = { {
//       "Bytes", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"
//   } };
//   double val(value);
//   size_t mag(0);
//   while (mag < kUnits.size() && val >= 1000.0) {
//     ++mag;
//     val /= 1024.0;
//   }
//   return (boost::format("%.3g %s") % val % kUnits[mag]).str();
// }
//
// // from http://stackoverflow.com/questions/1746136/
// //      how-do-i-normalize-a-pathname-using-boostfilesystem
// fs::path Normalise(const fs::path &directory_path) {
//   fs::path result;
//   for (fs::path::iterator it = directory_path.begin();
//        it != directory_path.end(); ++it) {
//     if (*it == "..") {
//       // /a/b/.. is not necessarily /a if b is a symbolic link
//       if (fs::is_symlink(result))
//         result /= *it;
//       // /a/b/../.. is not /a/b/.. under most circumstances
//       // We can end up with ..s in our result because of symbolic links
//       else if (result.filename() == "..")
//         result /= *it;
//       // Otherwise it should be safe to resolve the parent
//       else
//         result = result.parent_path();
//     } else if (*it == ".") {
//       // Ignore
//     } else {
//       // Just cat other path entries
//       result /= *it;
//     }
//   }
//   return result;
// }
//
// int Generate(const int &chunk_size,
//              const std::string &pattern,
//              const fs::path &file_name) {
//   if (chunk_size < 1) {
//     printf("Error: Chunk size must be bigger than zero.\n");
//     return kGenerateError;
//   }
//
//   std::string content;
//   for (size_t i = 0; i < pattern.size(); ++i)
//     if (pattern[i] == '#')
//       content.append(RandomString(chunk_size));
//     else
//       content.append(chunk_size, pattern[i]);
//
//   if (!WriteFile(file_name, content)) {
//     printf("Error: Could not write contents to file '%s'.\n",
//            file_name.c_str());
//     return kGenerateError;
//   }
//
//   return kSuccess;
// }
//
// int Encrypt(const fs::path &input_path,
//             const fs::path &chunk_path,
//             const fs::path &meta_path,
//             const SelfEncryptionParams &self_encryption_params) {
//   if (!fs::exists(input_path)) {
//     printf("Error: Encryption input path not found.\n");
//     return kEncryptError;
//   }
//
//   bool error(false);
//   uint64_t total_size(0), failed_size(0), chunks_size(0),
//                 uncompressed_chunks_size(0),  meta_size(0);
//   boost::posix_time::time_duration total_duration;
//   std::set<std::string> chunks;
//   std::vector<fs::path> files;
//   std::map<std::string, DataMap> data_maps;
//
//   fs::path full_path;
//   try {
//     if (input_path.is_absolute())
//       full_path = Normalise(input_path);
//     else
//       full_path = Normalise(fs::current_path() / input_path);
//     if (fs::is_directory(full_path)) {
//       printf("Discovering directory contents ...\n");
//       fs::recursive_directory_iterator directory_it(full_path);
//       while (directory_it != fs::recursive_directory_iterator()) {
//         if (fs::is_regular_file(*directory_it))
//           files.push_back(std::string(directory_it->path().string()).erase(
//               0, full_path.string().size() + 1));
//         ++directory_it;
//       }
//       printf("Found %u files in %s\n", files.size(), full_path.c_str());
//     } else {
//       files.push_back(full_path.filename());
//       full_path.remove_filename();
//     }
//   }
//   catch(...) {
//     printf("Error: Self-encryption failed while discovering files in %s\n",
//            full_path.c_str());
//     error = true;
//   }
//
//   std::shared_ptr<FileChunkStore> chunk_store(new FileChunkStore(true,
//       std::bind(&crypto::HashFile<crypto::SHA512>, std::placeholders::_1)));
//   chunk_store->Init(chunk_path);
//
//   for (auto file = files.begin(); file != files.end(); ++file) {
//     boost::system::error_code ec;
//     uint64_t file_size(fs::file_size(full_path / (*file), ec));
//     if (ec)
//       file_size = 0;
//     printf("Processing %s (%s) ...\n", file->c_str(),
//            FormatByteValue(file_size).c_str());
//     if (file_size == 0)
//       continue;
//
//     total_size += file_size;
//
//     DataMapPtr data_map(new DataMap);
//     boost::posix_time::ptime start_time(
//         boost::posix_time::microsec_clock::universal_time());
//     if (SelfEncrypt(full_path / (*file), self_encryption_params, data_map,
//                     chunk_store) ==  kSuccess) {
//       total_duration += boost::posix_time::microsec_clock::universal_time() -
//                         start_time;
//       data_maps[file->string()] = *data_map;
// //       meta_size += sizeof(DataMap) + data_map->content.size();
//       for (auto it = data_map->chunks.begin(); it != data_map->chunks.end();
//            ++it) {
// //         meta_size += sizeof(ChunkDetails) + it->hash.size() +
// //                     it->pre_hash.size();
//         if (!it->hash.empty() && chunks.count(it->hash) == 0) {
//           chunks.insert(it->hash);
//           chunks_size += it->size;
//           uncompressed_chunks_size += it->pre_size;
//         }
//       }
//     } else {
//       failed_size += file_size;
//       error = true;
//       printf("Error: Self-encryption failed for %s\n", file->c_str());
//     }
//   }
//
//   std::string ser_data_maps;
//   {
//     std::ostringstream ser_data_maps_stream;
//     boost::archive::text_oarchive oa(ser_data_maps_stream);
//     oa << data_maps;
//     ser_data_maps = crypto::Compress(ser_data_maps_stream.str(), 9);
//   }
//   meta_size = ser_data_maps.size();
//   if (!WriteFile(meta_path, ser_data_maps))
//     printf("Error: Self-encryption could not store meta data.\n");
//
//   double chunk_ratio(0), meta_ratio(0), failed_ratio(0);
//   if (total_size > 0) {
//     chunk_ratio = 100.0 * chunks_size / total_size;
//     meta_ratio = 100.0 * meta_size / total_size;
//     failed_ratio = 100.0 * failed_size / total_size;
//   }
//
//   printf("\nResults:\n"
//          "  Max chunk size: %s\n"
//          "  Data processed: %s in %u files (%s/s)\n"
//          "  Size of chunks: %s (uncompressed %s) in %u files (%.3g%%)\n"
//          "+ Meta data size: %s (%.3g%%)\n"
//          "+ Failed entries: %s (%.3g%%)\n"
//          "= Space required: %s (%.3g%%)\n",
//          FormatByteValue(self_encryption_params.max_chunk_size).c_str(),
//          FormatByteValue(total_size).c_str(), files.size(),
//          FormatByteValue(1000 * total_size /
//                          total_duration.total_milliseconds()).c_str(),
//          FormatByteValue(chunks_size).c_str(),
//          FormatByteValue(uncompressed_chunks_size).c_str(),
//          chunks.size(), chunk_ratio,
//          FormatByteValue(meta_size).c_str(), meta_ratio,
//          FormatByteValue(failed_size).c_str(), failed_ratio,
//          FormatByteValue(chunks_size + meta_size + failed_size).c_str(),
//          chunk_ratio + meta_ratio + failed_ratio);
//
//   return error ? kEncryptError : kSuccess;
// }
//
// int Decrypt(const fs::path &chunk_path,
//             const fs::path &meta_path,
//             const fs::path &output_path) {
//   bool error(false);
//   uint64_t total_size(0);
//   boost::posix_time::time_duration total_duration;
//   std::map<std::string, DataMap> data_maps;
//
//   std::string ser_data_maps;
//   if (ReadFile(meta_path, &ser_data_maps)) {
//   std::istringstream ser_data_maps_stream(crypto::Uncompress(ser_data_maps));
//     boost::archive::text_iarchive ia(ser_data_maps_stream);
//     ia >> data_maps;
//   } else {
//     printf("Error: Self-decryption could not load meta data.\n");
//   }
//
//   printf("Decrypting %u files to %s ...\n",
//          data_maps.size(), output_path.c_str());
//
//   boost::system::error_code ec;
//   std::shared_ptr<FileChunkStore> chunk_store(new FileChunkStore(true,
//       std::bind(&crypto::HashFile<crypto::SHA512>, std::placeholders::_1)));
//   chunk_store->Init(chunk_path);
//
//   for (auto dm = data_maps.begin(); dm != data_maps.end(); ++dm) {
//     printf("Restoring %s (%s) ...\n", dm->first.c_str(),
//            FormatByteValue(dm->second.size).c_str());
//     if (dm->second.size == 0)
//       continue;
//
//     total_size += dm->second.size;
//
//     DataMapPtr data_map(new DataMap);
//     *data_map = dm->second;
//     fs::path file_path(output_path / dm->first);
//     fs::create_directories(file_path, ec);
//     boost::posix_time::ptime start_time(
//         boost::posix_time::microsec_clock::universal_time());
//     if (SelfDecrypt(data_map, chunk_store, true, file_path) == kSuccess) {
//       total_duration += boost::posix_time::microsec_clock::universal_time() -
//                         start_time;
//     } else {
//       error = true;
//       printf("Error: Self-decryption failed for %s\n", dm->first.c_str());
//     }
//   }
//
//   printf("\nRestored %s to %u files (%s/s)\n",
//          FormatByteValue(total_size).c_str(), data_maps.size(),
//          FormatByteValue(1000 * total_size /
//                          total_duration.total_milliseconds()).c_str());
//
//   return error ? kDecryptError : kSuccess;
// }
//
// }  // namespace demo
// }  // namespace encrypt
// }  // namespace maidsafe
//
// int main(int argc, char* argv[]) {
//   maidsafe::InitLogging(argv[0]);
//   // setting output to be stderr
//   FLAGS_logtostderr = true;
//   FLAGS_minloglevel = google::ERROR;
//
//   FLAGS_ms_logging_common = false;
//
//   if (argc < 2) {
//     printf("Demo application for MaidSafe-Encrypt\n\n"
//            "Usage: %s <command> [<argument>...]\n\n"
//            "The following commands are available:\n"
//            "  generate <chunk-size> <pattern> <file-name>\n"
//         "    Generates a file by writing chunks of the given size according "
//                 "to a\n    pattern, in which each character represents the "
//               "chunk contents. The given\n    character gets repeated, with "
//               "the exception of '#', which results in a\n    random chunk.\n"
//                 "    Example: \"gen 128 aabaa#aab file.dat\"\n\n"
//            "  encrypt <input-file> <chunk-dir> <meta-file>\n"
//            "          [<chunk-sz> <inc-chunk-sz> <inc-data-sz>]\n"
//          "    Applies self-encryption to the given file, storing chunks and "
//                 "meta data at\n    the given paths. Optional parameters, in "
//               "order, are:\n    - maximum chunk size (bytes)\n    - maximum "
//               "includable chunk size (bytes)\n    - maximum includable data "
//                 "size (bytes)\n    Example: \"encrypt file.dat chunks/ "
//                 "meta.dat 262144 256 1024\"\n\n"
//            "  encrypt <input-dir> <chunk-dir> <meta-file>\n"
//            "          [<chunk-sz> <inc-chunk-sz> <inc-data-sz>]\n"
//            "    Like above, but for each file in the given input directory "
//                 "(recursive).\n\n"
//            "  decrypt <chunk-dir> <meta-file> <output-dir>\n"
//            "    Decrypts chunks to files specified by the meta data file.\n"
//                 "    Example: decrypt chunks/ meta.dat output/\n\n",
//            argv[0]);
//     return mse::demo::kNoArgumentsError;
//   }
//
//   std::string command(boost::to_lower_copy(std::string(argv[1])));
//   if (command == "generate") {
//     if (argc == 5) {
//       int chunk_size(0);
//       try {
//         chunk_size = boost::lexical_cast<int>(std::string(argv[2]));
//       }
//       catch(...) {}
//       return mse::demo::Generate(chunk_size, argv[3], argv[4]);
//     }
//   } else if (command == "encrypt") {
//     if (argc == 5) {
//       mse::SelfEncryptionParams sep;
//       return mse::demo::Encrypt(argv[2], argv[3], argv[4], sep);
//     } else if (argc == 8) {
//       try {
//         mse::SelfEncryptionParams sep(
//             boost::lexical_cast<uint32_t>(std::string(argv[5])),
//             boost::lexical_cast<uint32_t>(std::string(argv[6])),
//             boost::lexical_cast<uint32_t>(std::string(argv[7])));
//         if (mse::utils::CheckParams(sep))
//           return mse::demo::Encrypt(argv[2], argv[3], argv[4], sep);
//       }
//       catch(...) {}
//       printf("Error: Invalid size arguments passed.\n");
//       return mse::demo::kInvalidArgumentsError;
//     }
//   } else if (command == "decrypt") {
//     if (argc == 5)
//       return mse::demo::Decrypt(argv[2], argv[3], argv[4]);
//   } else {
//     printf("Error: Unrecognised command '%s'.\n", command.c_str());
//     return mse::demo::kCommandError;
//   }
//
//   printf("Error: Wrong number of arguments supplied to command '%s' (%d).\n",
//          command.c_str(), argc - 2);
//   return mse::demo::kInvalidArgumentsError;
// }
