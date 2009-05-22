/* copyright maidsafe.net limited 2008
 * ==========================================================================
 *
 *       Filename:  filesystem.cc
 *
 *    Description:  filesystem mount / unmount commands.
 *    Also includes on-access scanner.
 *
 *        Version:  1.0
 *        Created:  09/11/2008 11:51:39 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  David Irvine (di), david.irvine@maidsafe.net
 *        Company:  maidsafe.net limited
 *
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

#include "fs/filesystem.h"

#include <boost/filesystem.hpp>
#include <boost/filesystem/convenience.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/scoped_ptr.hpp>
#ifdef MAIDSAFE_WIN32
#include <shlwapi.h>
#endif
#include <algorithm>
#include <string>
#include <vector>

#include "maidsafe/maidsafe-dht.h"
#include "maidsafe/client/sessionsingleton.h"
#include "maidsafe/maidsafe.h"

namespace fs = boost::filesystem;

namespace file_system {

FileSystem::FileSystem() : defcon_(maidsafe::DEFCON2) {}

FileSystem::~FileSystem() {}


bool FileSystem::Mount() {
  // is session valid ?
  if (maidsafe::SessionSingleton::getInstance()->Username() == "")
    return false;
  if (FileSystem::CreateDirs())
    return true;
  else
    return false;
}

bool FileSystem::UnMount() {
  if (maidsafe::SessionSingleton::getInstance()->Username() == "") {
    printf("fs.cc blank username (returned false): %s\n",
           maidsafe::SessionSingleton::getInstance()->Username().c_str());
    return false;
  }

  if (FileSystem::DeleteDirs()) {
#ifdef DEBUG
    printf("fs.cc delete dirs was sucessful\n");
#endif
    return true;
  } else {
#ifdef DEBUG
     printf("fs.cc delete dirs returned false\n");
#endif
    return false;
  }
}

std::string FileSystem::HomeDir() {
  std::string dirname;
  if (std::getenv("USERPROFILE"))
    dirname = std::getenv("USERPROFILE");
  else if (std::getenv("userprofile"))
    dirname = std::getenv("userprofile");
  else if (std::getenv("HOME"))
    dirname = std::getenv("HOME");
  else
    dirname ="";
  return dirname;
}

std::string FileSystem::ApplicationDataDir() {
  fs::path app_path("");
#if defined(MAIDSAFE_POSIX)
  app_path = fs::path("/var/cache/maidsafe/", fs::native);
#elif defined(MAIDSAFE_WIN32)
  TCHAR szpth[MAX_PATH];
  if (SUCCEEDED(SHGetFolderPath(NULL, CSIDL_COMMON_APPDATA, NULL, 0, szpth))) {
    std::ostringstream stm;
    const std::ctype<char> &ctfacet =
        std::use_facet< std::ctype<char> >(stm.getloc());
    for (size_t i = 0; i < wcslen(szpth); ++i)
      stm << ctfacet.narrow(szpth[i], 0);
    app_path = fs::path(stm.str(), fs::native);
    app_path /= "maidsafe";
  }
#elif defined(MAIDSAFE_APPLE)
  app_path = fs::path("/Library/maidsafe/", fs::native);
#endif
  return app_path.string();
}

std::string FileSystem::MaidsafeDir() {
  fs::path maidsafe_dir(HomeDir(), fs::native);
  std::string tmp_dir = ".maidsafe" + SessionName();
  maidsafe_dir = maidsafe_dir / tmp_dir;
  return maidsafe_dir.string();
}

std::vector<fs::path> FileSystem::CacheDirs(std::vector<fs::path> cachedir_) {
  int no_of_dirs_ = cachedir_.size();
  for (int dir_no_ = 0; dir_no_ != no_of_dirs_; dir_no_++) {
    for (int i = 0; i != 16; i++) {
      std::ostringstream hexadec_;
      hexadec_ << std::hex << i;
      fs::path newpath_ = cachedir_[dir_no_] / hexadec_.str();
      cachedir_.push_back(newpath_);
    }
  }
  cachedir_.erase(cachedir_.begin(), cachedir_.begin()+no_of_dirs_);
  return cachedir_;
}

std::string FileSystem::MaidsafeHomeDir() {
  fs::path ms_dir(FileSystem::MaidsafeDir(), fs::native);
  fs::path home_dir = ms_dir / "msroot";
  return home_dir.string();
}

std::string FileSystem::MaidsafeFuseDir() {
  fs::path ms_dir(FileSystem::MaidsafeDir(), fs::native);
  std::string mount_dir("maidsafe-");
  mount_dir +=
    maidsafe::SessionSingleton::getInstance()->SessionName().substr(0, 8);
  fs::path fuse_dir = ms_dir / mount_dir;
  return fuse_dir.string();
}

std::string FileSystem::ProcessDir() {
  fs::path ms_dir(FileSystem::MaidsafeDir(), fs::native);
  fs::path process_dir = ms_dir / "process";
  return process_dir.string();
}

std::string FileSystem::DbDir() {
  fs::path ms_dir(FileSystem::MaidsafeDir(), fs::native);
  fs::path db_dir = ms_dir / "dir";
  return db_dir.string();
}

std::string FileSystem::SessionName() {
  return maidsafe::SessionSingleton::getInstance()->SessionName();
}

std::string FileSystem::MakeMSPath(std::string entry) {
  //  Get full path
  fs::path path_(fs::initial_path<fs::path>() );
  path_ = fs::system_complete(fs::path(entry, fs::native));

  std::string result(path_.string());
  fs::path ms_path_(MaidsafeHomeDir(), fs::native);
  fs::path home_path(HomeDir(), fs::native);

  if (path_.string().substr(0, ms_path_.string().size())
      == ms_path_.string()) {
    return result;
  } else if (path_.string().substr(0, home_path.string().size())
    == home_path.string()) {
    result.erase(0, home_path.string().size());
    result.insert(0, ms_path_.string());
  } else {
    std::string root_path = home_path.root_path().string();
    result.erase(0, root_path.size());
    result.insert(0, ms_path_.string());
  }
  return result;
}

std::string FileSystem::MakeRelativeMSPath(std::string entry) {
  fs::path path_(entry, fs::native);
  std::string result(path_.string());
  fs::path ms_path_(MaidsafeHomeDir(), fs::native);
  fs::path home_path(HomeDir(), fs::native);
  fs::path ms_home_path(MaidsafeFuseDir(), fs::native);
  if (path_.string().substr(0, ms_path_.string().size())
      == ms_path_.string()) {
    result.erase(0, ms_path_.string().size());
    return result;
  } else if (path_.string().substr(0, ms_home_path.string().size())
      == ms_home_path.string()) {
    result.erase(0, ms_home_path.string().size());
    return result;
  } else if (path_.string().substr(0, home_path.string().size())
      == home_path.string()) {
    result.erase(0, home_path.string().size());
    return result;
  } else {
    return entry;
  }
}


std::string FileSystem::FullMSPathFromRelPath(const std::string &path_) {
  fs::path full_path_(MaidsafeHomeDir(), fs::native);
  full_path_ /= path_;
  return full_path_.string();
}

std::string FileSystem::FullMSPathFromRelPath(const char *path_) {
  std::string str_path_(path_);
  return FullMSPathFromRelPath(str_path_);
}


bool FileSystem::CreateDirs() {
  fs::path ms_home_path_(MaidsafeHomeDir(), fs::native);
  // if this is created OK, so is MaidsafeDir
  // TODO(username): If exists but is a read only dir or a file,throw exception
#ifdef DEBUG_
  if (fs::exists(ms_home_path_))
    printf("fs.cc Already Exists: %s\n", ms_home_path_.string().c_str());
#endif
  if (!fs::exists(ms_home_path_)) {
#ifdef DEBUG_
    printf("fs.cc Creating %s\n", ms_home_path_.string().c_str());
#endif
  fs::create_directories(ms_home_path_);
  }
  //  create cache dirs, and process dir
  fs::path ms_path_(MaidsafeDir(), fs::native);
  std::vector<fs::path> dir_;
  dir_.push_back(ms_path_);
  // dir_ = CacheDirs(CacheDirs(CacheDirs(dir_)));
  // dir_.push_back(fs::path(NetDir(), fs::native));
  dir_.push_back(fs::path(ProcessDir(), fs::native));
  dir_.push_back(fs::path(DbDir(), fs::native));
//  dir_.push_back(fs::path(MaidsafeFuseDir(), fs::native));
  for (unsigned int i = 0; i != dir_.size() ;i++) {
  // TODO(user): If exists but is a read only dir or a file, throw exception
    if (fs::exists(dir_[i])) {
#ifdef DEBUG_
      printf("fs.cc Already Exists: %s\n", dir_[i].string().c_str());
#endif
    }
    if (!fs::exists(dir_[i])) {
#ifdef DEBUG_
      printf("fs.cc Creating %s\n", dir_[i].string().c_str());
#endif
      fs::create_directories(dir_[i]);
    }
  }
  return true;
}

bool FileSystem::FuseMountPoint() {
  if (!fs::exists(fs::path(MaidsafeFuseDir(), fs::native))) {
  #ifdef DEBUG
    std::cout <<  "fs.cc Creating " << MaidsafeFuseDir() <<std::endl;
  #endif
    fs::create_directories(fs::path(MaidsafeFuseDir(), fs::native));
  }
  return true;
}

bool FileSystem::DeleteDirs() {
  bool result = false;
  defcon_ = maidsafe::SessionSingleton::getInstance()->DefConLevel();
  switch (defcon_) {
    case 1: {
      boost::scoped_ptr<fs::path> process_dir(new fs::path(
        FileSystem::ProcessDir()));
      boost::scoped_ptr<fs::path> db_dir(new fs::path(FileSystem::DbDir()));
      result = ((fs::remove_all(*process_dir)) && (fs::remove_all(*db_dir)));
#ifdef DEBUG
      printf("fs.cc tidying db and process dirs only, as in DefCon 1 mode.\n");
#endif
      break;}

    case 2: {
      boost::scoped_ptr<fs::path> home_dir(new fs::path(
        FileSystem::MaidsafeHomeDir()));
      // boost::scoped_ptr<fs::path> net_dir(new fs::path(FileSystem::NetDir();
      boost::scoped_ptr<fs::path> process_dir(new fs::path(
        FileSystem::ProcessDir()));
      boost::scoped_ptr<fs::path> db_dir(new fs::path(FileSystem::DbDir()));

      // delete home, process and db dir, leave cache dir only
      result = ((fs::remove_all(*home_dir)) && (fs::remove_all(*process_dir))
        && (fs::remove_all(*db_dir)));
#ifdef DEBUG
      printf("fs.cc deleting all dirs apart from maidsafe/cache dir, ");
      printf("as in DefCon 2 mode.\n");
#endif
      break;}

    case 3: {
      boost::scoped_ptr<fs::path> maidsafe_dir(new fs::path(
        FileSystem::MaidsafeDir()));
#ifdef DEBUG
      printf("fs.cc deleting all dirs since in DefCon 3 mode.\n");
#endif

      // delete maidsafe root dir
      result = fs::remove_all(*maidsafe_dir);
      break;}
    default: result = false;
  }
  return result;
}

}  // namespace file_system
