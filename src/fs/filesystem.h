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
#include <vector>
#include "maidsafe/client/sessionsingleton.h"

namespace fs = boost::filesystem;
namespace file_system {

class FileSystem {
  private:
    // We should mount the maidsafe dirs by
    // 1: unencrypting existing one if it exists (we need to identify this)
    // this can be done with a session name perhaps  (safety)
    // 2: if not exist create an encrypted mount point and put stuff there
    // so if machine crashes and we cannot clear up then
    // we just leave an encrypted file (with AES256 encryption)
    // still does not mean we can have sensitive data there though !!!

    maidsafe::DefConLevels defcon_;  // this is set in the sesion singleton
    bool CreateDirs();
    bool DeleteDirs();

  public:
    bool FuseMountPoint();
    bool Mount();
    bool UnMount();  // unmount and rewrite space with 0's TODO
    // bool WritePath(fs::path path, bool is_dir_, PathStatus state=DONE);
    bool OpenPath(std::string path);
    std::string MakeMSPath(std::string entry);
    std::string MakeRelativeMSPath(std::string entry);
    std::string FullMSPathFromRelPath(const std::string &path_);
    std::string FullMSPathFromRelPath(const char *path_);
    std::string HomeDir();
    std::string ApplicationDataDir();
    static std::string TempDir();
    static std::string LocalStoreManagerDir();
    std::string MaidsafeDir();
    std::string MaidsafeHomeDir();
    std::string MaidsafeFuseDir();
    std::string ProcessDir();  // temp dir
    std::string DbDir();  // dir to store dbs
};

}  // namespace file_system

class FSMS;

class FSOSX;

#endif  // FS_FILESYSTEM_H_
