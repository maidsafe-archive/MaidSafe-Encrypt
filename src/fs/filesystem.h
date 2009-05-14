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
#include <string>
#include <vector>
#include "boost/filesystem.hpp"
#include "base/config.h"
#include "maidsafe/client/sessionsingleton.h"
// if (BOOST_PLATFORM == "linux")
//   #include "fs/l_fuse/fusecpp.h"

// #define DEBUG_

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
    bool DeleteDirs();

  // protected:
  // to allow reuse if extended
  public:
    FileSystem();
    ~FileSystem();
    // enum PathStatus {PROCESSING, ENCRYPTED, DONE};
    bool CreateDirs();  // create directories of required needs to be private
    bool FuseMountPoint();
    bool Mount();  //  Eventually actually mount a FUSE drive
    bool UnMount();  // unmount and rewrite space with 0's TODO
    // bool WritePath(fs::path path, bool is_dir_, PathStatus state=DONE);
    // write to fs
    bool OpenPath(std::string path);  // read from fs
    std::string MakeMSPath(std::string entry);
    std::string MakeRelativeMSPath(std::string entry);
    std::string FullMSPathFromRelPath(const std::string &path_);
    std::string FullMSPathFromRelPath(const char *path_);
    std::string HomeDir();  // when using fuse this will be altered
    std::string ApplicationDataDir();
    std::string MaidsafeDir();
    std::string MaidsafeHomeDir();  // save read ms files here
    std::string MaidsafeFuseDir();
    std::vector<fs::path> CacheDirs(std::vector<fs::path> cachedir_);
    // store chunks here (defcon 2 leave them)
    std::string ProcessDir();  // temp dir
    // std::string NetDir(); // temp dir to emulate network
    std::string DbDir();  // dir to store dbs
    std::string SessionName();  // name of current session TODO move to session!
    bool SetSessionName();  // name of current session  TODO move to session !
};

}  // namespace file_system

class FSMS;

class FSOSX;




/*
inline std::string HomeDir()
{
file_system::FileSystem *fsys;
fsys = file_system::FileSystem::getInstance();
return fsys->HomeDir();
}

inline long long int FreeHomeSpace() {
  std::string  dir = HomeDir();
  if (dir != "")
  {
    fs::path entry(dir);
    fs::space_info spi( fs::space( entry ) );
  return  spi.free;
  }
  else
  {
  return -1;
  }
}


inline long long int TotalHomeSpace() {
  std::string  dir = HomeDir();
  if (dir != "")
  {
    fs::path entry(dir);
    fs::space_info spi( fs::space( entry ) );
  return  spi.capacity;
  }
  else
  {
  return -1;
  }
}

inline long long int AvailableHomeSpace() {
  std::string dir  = HomeDir();
  if (dir != "")
  {
    fs::path entry(dir);
    fs::space_info spi( fs::space( entry ) );
  return  spi.available;
  }
  else
  {
  return -1;
  }
}
*/


#endif  // FS_FILESYSTEM_H_
