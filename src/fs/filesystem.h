/* copyright maidsafe.net limited 2008
 * ==========================================================================
 *
 *       Filename:  filesystem.h
 *
 *    Description:
 *
 *        Version:  1.0
 *        Created:  09/11/2008 02:14:28 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  David Irvine (di), david.irvine@maidsafe.net
 *        Company:  maidsafe.net limited
 *
 *
 * The following source code is property of maidsafe.net limited and
 * is not meant for external use. The use of this code is governed
 * by the license file LICENSE.TXT found in the root of this directory and also
 * on www.maidsafe.net.
 *
 * You are not free to copy, amend or otherwise use this source code without
 * explicit written permission of the board of directors of maidsafe.net
 *
 *
 * ==========================================================================
 */

#ifndef FS_FILESYSTEM_H_
#define FS_FILESYSTEM_H_

#include <boost/filesystem.hpp>
#include <string>

namespace fs = boost::filesystem;

namespace maidsafe {
enum DefConLevels {kDefCon1 = 1, kDefCon2, kDefCon3};
}  // namespace maidsafe

namespace file_system {

const boost::uint8_t kMaxRemoveDirAttempts(5);

fs::path HomeDir();
fs::path ApplicationDataDir();
fs::path TempDir();
fs::path LocalStoreManagerDir();
fs::path MaidsafeDir(const std::string &session_name);
fs::path MaidsafeHomeDir(const std::string &session_name);
fs::path MaidsafeFuseDir(const std::string &session_name);
fs::path DbDir(const std::string &session_name);
fs::path MakeRelativeMSPath(const std::string &entry,
                            const std::string &session_name);
fs::path FullMSPathFromRelPath(const std::string &entry,
                               const std::string &session_name);
int Mount(const std::string &session_name,
          const maidsafe::DefConLevels &defcon);
int UnMount(const std::string &session_name,
            const maidsafe::DefConLevels &defcon);
int FuseMountPoint(const std::string &session_name);
bool RemoveDir(const fs::path &dir, const boost::uint8_t &max_attempts);

}  // namespace file_system

class FSMS;

class FSOSX;

#endif  // FS_FILESYSTEM_H_
