/*******************************************************************************
 *  Copyright 2009 maidsafe.net limited                                        *
 *                                                                             *
 *  The following source code is property of maidsafe.net limited and is not   *
 *  meant for external use.  The use of this code is governed by the license   *
 *  file LICENSE.TXT found in the root of this directory and also on           *
 *  www.maidsafe.net.                                                          *
 *                                                                             *
 *  You are not free to copy, amend or otherwise use this source code without  *
 *  the explicit written permission of the board of directors of maidsafe.net. *
 ***************************************************************************//**
 * @file  config.h
 * @brief Definition of error codes, typedef, forward declarations, etc.
 * @date  2009-10-12
 */

#ifndef MAIDSAFE_ENCRYPT_CONFIG_H_
#define MAIDSAFE_ENCRYPT_CONFIG_H_

#include <cstdint>
#include <string>

namespace maidsafe {

namespace encrypt {

enum ReturnCode {
  kSuccess = 0,
  kEncryptError = -200001,
  kDecryptError = -200002,
  kInputTooSmall = -200003,
  kChunkSizeError = -200004,
  kPreEncryptionHashError = -200005,
  kIoError = -200006,
  kCompressionError = -200007,
  kFilesystemError = -200008,
  kNoFileHash = -200009,
  kChunkPathNotFound = -200010,
  kFileAlreadyExists = -200011,
  kWrongVersion = -200012,
  kBadChunk = -200013,
  kBadDataMap = -200014,
  kNullPointer = -200015
};

const std::string kVersion("Mk II");
const std::uint16_t kMinChunks(3);
const std::uint16_t kMaxChunks(40);
const std::uint64_t kDefaultChunkSize(262144);
// static_cast<boost::uint16_t>(kDefaultChunkletSize) MUST be a multiple of
// 2*IV for AES encryption, i.e. multiple of 32.
const std::uint16_t kDefaultChunkletSize(16384);
const std::uint16_t kMinChunkletSize(32);
const std::string kNoCompressType[] = {".jpg", ".jpeg", ".jpe", ".jfif",
  ".gif", ".png", ".mp3", ".mp4", ".0", ".000", ".7z", ".ace", ".ain", ".alz",
  ".apz", ".ar", ".arc", ".ari", ".arj", ".axx", ".ba", ".bh", ".bhx", ".boo",
  ".bz", ".bz2", ".bzip2", ".c00", ".c01", ".c02", ".car", ".cbr", ".cbz",
  ".cp9", ".cpgz", ".cpt", ".dar", ".dd", ".deb", ".dgc", ".dist", ".ecs",
  ".efw", ".fdp", ".gca", ".gz", ".gzi", ".gzip", ".ha", ".hbc", ".hbc2",
  ".hbe", ".hki", ".hki1", ".hki2", ".hki3", ".hpk", ".hyp", ".ice", ".ipg",
  ".ipk", ".ish", ".j", ".jgz", ".jic", ".kgb", ".lbr", ".lha", ".lnx", ".lqr",
  ".lzh", ".lzm", ".lzma", ".lzo", ".lzx", ".md", ".mint", ".mpkg", ".mzp",
  ".p7m", ".package", ".pae", ".pak", ".paq6", ".paq7", ".paq8", ".par",
  ".par2", ".pbi", ".pcv", ".pea", ".pf", ".pim", ".pit", ".piz", ".pkg",
  ".pup", ".puz", ".pwa", ".qda", ".r00", ".r01", ".r02", ".r03", ".rar",
  ".rev", ".rk", ".rnc", ".rpm", ".rte", ".rz", ".rzs", ".s00", ".s01", ".s02",
  ".s7z", ".sar", ".sdn", ".sea", ".sen", ".sfs", ".sfx", ".sh", ".shar",
  ".shk", ".shr", ".sit", ".sitx", ".spt", ".sqx", ".sqz", ".tar", ".tbz2",
  ".tgz", ".tlz", ".uc2", ".uha", ".vsi", ".wad", ".war", ".wot", ".xef",
  ".xez", ".xpi", ".xx", ".y", ".yz", ".z", ".zap", ".zfsendtotarget", ".zip",
  ".zix", ".zoo", ".zz"};

}  // namespace encrypt

}  // namespace maidsafe

#endif  // MAIDSAFE_ENCRYPT_CONFIG_H_
