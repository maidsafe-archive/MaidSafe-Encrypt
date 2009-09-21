/* copyright maidsafe.net limited 2008
 * ==========================================================================
 *
 *       Filename:  fslinux.cc
 *
 *    Description:
 *
 *        Version:  1.0
 *        Created:  09/19/2008 05:13:25 PM
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
#include "fs/l_fuse/fslinux.h"

#include <boost/filesystem/convenience.hpp>
#include <boost/bind.hpp>
#include <boost/filesystem/path.hpp>

#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/time.h>
#include <ulockmgr.h>
#include <sys/stat.h>
#include <fuse/fuse.h>
#include <pwd.h>
#include <string>
#include <cstdlib>

#include "maidsafe/client/clientcontroller.h"
#include "protobuf/datamaps.pb.h"



namespace fs = boost::filesystem;

namespace fs_l_fuse {

// run the fuse loop in a thread.fuse loop session captures system events.
void fuse_loop_session(struct fuse *fuse, int multithreaded) {
  int res;
  if (multithreaded)
    res = fuse_loop_mt(fuse);
  else
    res = fuse_loop(fuse);
  if (res == -1)
    maidsafe::SessionSingleton::getInstance()->SetMounted(-1);
}



FSLinux::FSLinux()
:fuse_dispatcher_(NULL), fuse_(NULL), mountpoint_('\0'), res(0) {
//   fuse_dispatcher_->set_init(&FSLinux::ms_init);
//   fuse_dispatcher_->set_destroy(&FSLinux::ms_destroy);

  fuse_dispatcher_ = new fuse_cpp::FuseDispatcher();

  fuse_dispatcher_->set_link(&FSLinux::ms_link);
  fuse_dispatcher_->set_access(&FSLinux::ms_access);
  fuse_dispatcher_->set_chmod(&FSLinux::ms_chmod);
  fuse_dispatcher_->set_chown(&FSLinux::ms_chown);
  fuse_dispatcher_->set_create(&FSLinux::ms_create);
  fuse_dispatcher_->set_fgetattr(&FSLinux::ms_fgetattr);
  fuse_dispatcher_->set_flush(&FSLinux::ms_flush);
  fuse_dispatcher_->set_fsync(&FSLinux::ms_fsync);
  fuse_dispatcher_->set_fsyncdir(&FSLinux::ms_fsyncdir);
  fuse_dispatcher_->set_ftruncate(&FSLinux::ms_ftruncate);
  fuse_dispatcher_->set_getattr(&FSLinux::ms_getattr);
  fuse_dispatcher_->set_readdir(&FSLinux::ms_readdir);
  // fuse_dispatcher_->set_getxattr(&FSLinux::ms_getxattr);
  fuse_dispatcher_->set_mkdir(&FSLinux::ms_mkdir);
  fuse_dispatcher_->set_mknod(&FSLinux::ms_mknod);
  fuse_dispatcher_->set_open(&FSLinux::ms_open);
  fuse_dispatcher_->set_opendir(&FSLinux::ms_opendir);
  fuse_dispatcher_->set_read(&FSLinux::ms_read);
  fuse_dispatcher_->set_readdir(&FSLinux::ms_readdir);
  fuse_dispatcher_->set_readlink(&FSLinux::ms_readlink);
  fuse_dispatcher_->set_release(&FSLinux::ms_release);
  fuse_dispatcher_->set_releasedir(&FSLinux::ms_releasedir);
  fuse_dispatcher_->set_rename(&FSLinux::ms_rename);
  fuse_dispatcher_->set_rmdir(&FSLinux::ms_rmdir);
  fuse_dispatcher_->set_statfs(&FSLinux::ms_statfs);
  fuse_dispatcher_->set_unlink(&FSLinux::ms_unlink);
  fuse_dispatcher_->set_utime(&FSLinux::ms_utime);
  fuse_dispatcher_->set_write(&FSLinux::ms_write);
}

FSLinux::~FSLinux() {
}

bool FSLinux::Mount(const std::string &path, const std::string &debug_mode) {
  std::string drive_name("maidsafe");
  // drive_name += maidsafe::SessionSingleton::getInstance()->SessionName();
  umask(0);
  char **opts;
  opts = new char*[6];
  opts[0] = const_cast<char*>(drive_name.c_str());
  opts[1] = const_cast<char*>(path.c_str());
  opts[2] = const_cast<char*>(debug_mode.c_str());
  opts[3] = const_cast<char*>("-s");
  std::string fground = "-f";
  opts[4] = const_cast<char*>(fground.c_str());
  // std::string nonempty_ = "-o nonempty";
  // opts[5] = (char*)nonempty_.c_str();
  printf("opts[1] en el Mount: %s", opts[1]);
  int multithreaded;
  fuse_operations *op = fuse_dispatcher_->get_fuseOps();
  // fuse_setup operation will be deprecated from API 3.0
  // fuse_ = fuse_setup(5, opts, op, sizeof(*(op)), &mountpoint_,
  //     &multithreaded, NULL);
  struct fuse_args args = FUSE_ARGS_INIT(5, opts);
  struct fuse_chan *ch;
  int foreground;
  int res = fuse_parse_cmdline(&args, &mountpoint_, &multithreaded,
    &foreground);
  if (res == -1)
    return false;
  ch = fuse_mount(mountpoint_, &args);
  if (!ch) {
    fuse_opt_free_args(&args);
    free(mountpoint_);
    return false;
  }
  fuse_ = fuse_new(ch, &args, op, sizeof(*(op)), NULL);
  fuse_opt_free_args(&args);
  if ((fuse_ == NULL) || (fuse_daemonize(foreground) == -1) ||
      (fuse_set_signal_handlers(fuse_get_session(fuse_)) == -1)) {
    fuse_unmount(mountpoint_, ch);
    if (fuse_)
      fuse_destroy(fuse_);
    return false;
  }
  boost::thread thrd_(boost::bind(fuse_loop_session, fuse_,
    multithreaded));
  return true;
}

void FSLinux::UnMount() {
  if (fuse_) {
    fuse_exit(fuse_);
    struct fuse_session *se = fuse_get_session(fuse_);
    struct fuse_chan *ch = fuse_session_next_chan(se, NULL);
    fuse_remove_signal_handlers(se);
    fuse_unmount(mountpoint_, ch);
    fuse_destroy(fuse_);
    free(mountpoint_);
    fuse_ = NULL;
  }
}

int FSLinux::ms_readlink(const char *path, char *, size_t) {
  printf("ms_readlink %s\n", path);
  return 0;
}
int FSLinux::ms_chmod(const char *path, mode_t) {
  printf("ms_chmod %s\n", path);
  return 0;
}
int FSLinux::ms_chown(const char *path, uid_t, gid_t) {
  printf("ms_chown %s\n", path);
  return 0;
}
int FSLinux::ms_truncate(const char *path, off_t) {
  printf("ms_truncate %s\n", path);
  return 0;
}
int FSLinux::ms_utime(const char *path, struct utimbuf *) {
  printf("ms_utime %s\n", path);
  return 0;
}
int FSLinux::ms_flush(const char *path, struct fuse_file_info *) {
  printf("ms_flush %s\n", path);
  return 0;
}
int FSLinux::ms_fsync(const char *path, int, struct fuse_file_info *) {
  printf("ms_fsync %s\n", path);
  return 0;
}
int FSLinux::ms_setxattr(const char *path, const char *, const char *,
                         size_t, int) {
  printf("ms_setxattr %s\n", path);
  return 0;
}
int FSLinux::ms_getxattr(const char *path, const char *, char *, size_t) {
  printf("ms_getxattr %s\n", path);
  return 0;
}
int FSLinux::ms_listxattr(const char *path, char *, size_t) {
  printf("ms_listxattr %s\n", path);
  return 0;
}
int FSLinux::ms_removexattr(const char *path, const char *) {
  printf("ms_removexattr %s\n", path);
  return 0;
}
int FSLinux::ms_fsyncdir(const char *path, int, struct fuse_file_info *) {
  printf("ms_fsyncdir %s\n", path);
  return 0;
}
int FSLinux::ms_ftruncate(const char *path, off_t, struct fuse_file_info *) {
  printf("ms_ftruncate %s\n", path);
  return 0;
}
int FSLinux::ms_releasedir(const char *path, struct fuse_file_info *) {
  printf("ms_releasedir: %s\n", path);
  return 0;
}
int FSLinux::ms_opendir(const char *path, struct fuse_file_info *) {
  printf("ms_opendir: %s\n", path);
  return 0;
}

int FSLinux::ms_access(const char *path, int mask) {
  std::string path_(path);
  printf("ms_access path: %s\n", path);
  printf("ms_access mask: %d\n", mask);
  return 0;
}

int FSLinux::ms_link(const char *o_path, const char *n_path) {
  std::string o_path_, n_path_;
  o_path_ = std::string(o_path);
  n_path_ = std::string(n_path);
  printf("ms_link PATHS: %s\t\t%s", o_path, n_path);
  // if path is not in an authorised dirs, return error "Permission denied"
  // TODO(Fraser): set bool gui_private_share_ to true if gui has
  //               requested a private share be set up.
  bool gui_private_share_(false);
  if (maidsafe::ClientController::getInstance()->ReadOnly(
      base::TidyPath(n_path_), gui_private_share_))
    return -13;

  if (maidsafe::ClientController::getInstance()->link(base::TidyPath(o_path_),
      base::TidyPath(n_path_)) != 0)
    return -errno;
  o_path_ = "";
  n_path_ = "";
  return 0;
}

int FSLinux::ms_open(const char *path, struct fuse_file_info *fi) {
  std::string path_(path);
#ifdef DEBUG
  printf("ms_open path(%s): %i.\n", path, fi->flags);
#endif
  std::string rel_path_(path);
  file_system::FileSystem fsys_;
  path_ = fsys_.MaidsafeHomeDir() + path_;

  fs::path some_path(path_);
  if (!fs::exists(some_path.parent_path()))
    fs::create_directories(some_path.parent_path());
  if (!fs::exists(path_))
    maidsafe::ClientController::getInstance()->read(base::TidyPath(rel_path_));

  int fd;

  fd = open(path_.c_str(), fi->flags);
  if (fd == -1)
    return -errno;

  fi->fh = fd;
  printf("\t file handle: %llu\n", fi->fh);
  return 0;
}

int FSLinux::ms_read(const char *path, char *data, size_t size, off_t offset, \
  struct fuse_file_info *fi) {
  std::string path_(path);
  printf("ms_read: %s\tfile handle: %llu", path, fi->fh);
  file_system::FileSystem fsys_;
  path_ = fsys_.MaidsafeHomeDir() + path_;

  int res;

  (void) path;
  res = pread(fi->fh, data, size, offset);
  if (res == -1)
    res = -errno;

  return res;
}

int FSLinux::ms_release(const char *path, struct fuse_file_info *fi) {
  printf("ms_release: %s -- %d -- ", path, fi->flags);
  printf("file handle %llu\n", fi->fh);
  std::string path_(path);
  file_system::FileSystem fsys_;
  path_ = fsys_.MaidsafeHomeDir() + path_;
  std::string original_path_(path);
  close(fi->fh);

  switch (fi->flags) {
    case 0:
//     case 2:
      return 0;
    case 32768:
      if (!maidsafe::ClientController::getInstance()->atime(base::TidyPath(
           original_path_)))
        return -errno;
      break;
    default:
      if (maidsafe::ClientController::getInstance()->write(base::TidyPath(
          original_path_)) != 0)
        return -errno;
      break;
  }
  return 0;
}

int FSLinux::ms_write(const char *path, const char *data, size_t size,
                      off_t offset, struct fuse_file_info *fi) {
  std::string path_(path);
  file_system::FileSystem fsys_;
  path_ = fsys_.MaidsafeHomeDir() + path_;
  printf("-------------------------------------\n");
  printf("-------------------------------------\n");
  printf("-------------------------------------\n");
  printf("ms_write PATH: %s\n", path);
  printf("\t file handle: %llu", fi->fh);

  fs::path full_path_(path_);
  fs::path branch_path_ = full_path_.parent_path();
  if (!fs::exists(branch_path_))
    fs::create_directories(branch_path_);

  int res;

  (void) path;
  res = pwrite(fi->fh, data, size, offset);
  if (res == -1)
    res = -errno;

  return res;
}

int FSLinux::ms_getattr(const char *path, struct stat *stbuf) {
  std::string path_;
  path_ = std::string(path);
  printf("ms_getattr: %s\n", path);

//  // if path is not in an authorised dirs, return error "Permission denied"
//  // TODO(Fraser): set bool gui_private_share_ to true if gui has
//  //               requested a private share be set up.
//  bool gui_private_share_(false);
//  if (maidsafe::ClientController::getInstance()->ReadOnly(
//      base::TidyPath(path_), gui_private_share_))
//    return -13;

  if (path_ == "/") {
    stbuf->st_mode = S_IFDIR | 0444;
    stbuf->st_nlink = 2;
    stbuf->st_size = 4*1024;
    stbuf->st_uid = fuse_get_context()->uid;
    stbuf->st_gid = fuse_get_context()->gid;
    stbuf->st_mtime = base::get_epoch_milliseconds();
    stbuf->st_atime = base::get_epoch_milliseconds();
    return 0;
  }

  std::string ser_mdm;
  if (maidsafe::ClientController::getInstance()->getattr(
      base::TidyPath(path_), ser_mdm) != 0) {
#ifdef DEBUG
    printf("CC getattr came back as failed.\n");
#endif
    return -errno;
  }
  maidsafe::MetaDataMap mdm;
  if (ser_mdm != "" && !mdm.ParseFromString(ser_mdm))
    return -ENOENT;
  //   printf("ms_getattr: died: " << lala << std::endl;

//  bool ro = maidsafe::ClientController::getInstance()->ReadOnly(
//    base::TidyPath(path_), false);

  int res = 0;
  memset(stbuf, 0, sizeof(struct stat));
  if (ser_mdm != "") {
    if (mdm.type() == maidsafe::EMPTY_FILE || mdm.type()
       == maidsafe::REGULAR_FILE || mdm.type() == maidsafe::SMALL_FILE) {
//      if (ro)
//        stbuf->st_mode = S_IFREG | 0444;
//      else
        stbuf->st_mode = S_IFREG | 0644;
      stbuf->st_nlink = 1;
      stbuf->st_size = mdm.file_size_low();
      stbuf->st_uid = fuse_get_context()->uid;
      stbuf->st_gid = fuse_get_context()->gid;
      stbuf->st_mtime = mdm.last_modified();
      stbuf->st_atime = mdm.last_access();
    } else if (mdm.type() == maidsafe::EMPTY_DIRECTORY || mdm.type()
        == maidsafe::DIRECTORY) {
        stbuf->st_mode = S_IFDIR | 0755;
        stbuf->st_nlink = 2;
        stbuf->st_size = 4*1024;
        stbuf->st_uid = fuse_get_context()->uid;
        stbuf->st_gid = fuse_get_context()->gid;
        stbuf->st_mtime = mdm.last_modified();
        stbuf->st_atime = mdm.last_access();
    }
  } else {
     //   printf("ms_getattr: died again --" << ser_mdm <<"--"<<std::endl;
     res = -errno;
  }
  path_ = "";
  return res;
}

int FSLinux::ms_fgetattr(const char *path, struct stat *stbuf,
                         struct fuse_file_info *fi) {
  std::string path_;
  path_ = std::string(path);
  printf("ms_fgetattr PATH: %s -- %d\n", path, fi->flags);

  std::string ser_mdm;
  int n = maidsafe::ClientController::getInstance()->getattr(base::TidyPath(
    path_), ser_mdm);
  maidsafe::MetaDataMap mdm;
  mdm.ParseFromString(ser_mdm);

  bool ro = maidsafe::ClientController::getInstance()->ReadOnly(
    base::TidyPath(path_), false);

  if (ro)
    stbuf->st_mode = S_IFREG | 0444;
  else
    stbuf->st_mode = S_IFREG | 0644;
  stbuf->st_nlink = 1;
  stbuf->st_size = mdm.file_size_low();  // TODO(user): this is wrong !!!!! DI.
  stbuf->st_uid = fuse_get_context()->uid;
  stbuf->st_gid = fuse_get_context()->gid;
  stbuf->st_mtime = mdm.last_modified();
  stbuf->st_atime = mdm.last_modified();
  path_ = "";
  return n;
}

int FSLinux::ms_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
  off_t offset, struct fuse_file_info *fi) {
  std::string path_;
  path_ = std::string(path);
    printf("ms_readdir PATH:  %s\n", path);

  std::map<std::string, maidsafe::itemtype> children;
  if (maidsafe::ClientController::getInstance()->readdir(base::TidyPath(
    path_), children) != 0)
    return -errno;

  (void) offset;
  (void) fi;
  filler(buf, ".", NULL, 0);
  filler(buf, "..", NULL, 0);
  while (!children.empty()) {
    std::string s = children.begin()->first;
    filler(buf, s.c_str(), NULL, 0);
    children.erase(children.begin());
  }
  path_ = "";

  file_system::FileSystem fsys_;
  if (fs::exists(fsys_.HomeDir()+"/.thumbnails/fail/"))
    fs::remove_all(fsys_.HomeDir()+"/.thumbnails/fail/");

  return 0;
}

int FSLinux::ms_mkdir(const char *path, mode_t mode) {
  std::string path_(path);
  std::string path1_(path);
  // if path is not in an authorised dirs, return error "Permission denied"
  // TODO(Fraser): set bool gui_private_share_ to true if gui has
  //               requested a private share be set up.
  bool gui_private_share_(false);
  if (maidsafe::ClientController::getInstance()->ReadOnly(
      base::TidyPath(path1_), gui_private_share_))
    return -13;

  file_system::FileSystem fsys_;
  path_ = fsys_.MaidsafeHomeDir() + path_;
  fs::path full_path_(path_);
  if (!fs::exists(full_path_))
    fs::create_directories(full_path_);
  printf("ms_mkdir PATH: %s -- %d\n", path1_.c_str(), mode);
  if (maidsafe::ClientController::getInstance()->mkdir(base::TidyPath(
      path1_)) != 0)
    return -errno;
  path_ = "";
  return 0;
}

int FSLinux::ms_rename(const char *o_path, const char *n_path) {
  std::string o_path_, n_path_;
  o_path_ = std::string(o_path);
  n_path_ = std::string(n_path);
  // if path is not in an authorised dirs, return error "Permission denied"
  // TODO(Fraser): set bool gui_private_share_ to true if gui has
  //               requested a private share be set up.
  bool gui_private_share_(false);
  if (maidsafe::ClientController::getInstance()->ReadOnly(
      base::TidyPath(o_path_), gui_private_share_))
    return -13;

  if (maidsafe::ClientController::getInstance()->ReadOnly(
      base::TidyPath(n_path_), gui_private_share_))
    return -13;

  printf("ms_rename PATHS: %s -- %s\n", o_path, n_path);
  if (maidsafe::ClientController::getInstance()->rename(base::TidyPath(
    o_path_), base::TidyPath(n_path_)) != 0)
    return -errno;
  file_system::FileSystem fsys_;
  if (fs::exists(fsys_.MaidsafeHomeDir()+n_path_))
    fs::remove(fsys_.MaidsafeHomeDir()+n_path_);
  if (fs::exists(fsys_.MaidsafeHomeDir()+o_path_)) {
    fs::rename((fsys_.MaidsafeHomeDir()+o_path_),
      (fsys_.MaidsafeHomeDir()+n_path_));
  }
  o_path_ = "";
  n_path_ = "";
  return 0;
}

int FSLinux::ms_statfs(const char *path, struct statvfs *stbuf) {
    printf("++++++++++++++++++++++++++++++++++++\n");
    printf("++++++++++++++++++++++++++++++++++++\n");
    printf("+++++++++++ ms_statfs PATH:  %s\n", path);
    printf("++++++++++++++++++++++++++++++++++++\n");
    printf("++++++++++++++++++++++++++++++++++++\n");

  stbuf->f_bsize = 99999999;
  stbuf->f_bavail = 99999999;
  stbuf->f_favail = 1000000000;
  stbuf->f_bfree = 99999999;
  stbuf->f_files = 9999999;
  stbuf->f_ffree = 9999999;
  stbuf->f_flag = 9999999;

  return 0;
}

int FSLinux::ms_mknod(const char *path, mode_t mode, dev_t) {
  std::string path_(path);
  // if path is not in an authorised dirs, return error "Permission denied"
  // TODO(Fraser): set bool gui_private_share_ to true if gui has
  //               requested a private share be set up.
  bool gui_private_share_(false);
  if (maidsafe::ClientController::getInstance()->ReadOnly(
      base::TidyPath(path_), gui_private_share_))
    return -13;

  int res = open(path, O_CREAT | O_EXCL | O_WRONLY, mode);
  printf("ms_mknod PATH: %s -- %d\n\n", path, res);
  if (res >= 0)
    res = close(res);
  if (maidsafe::ClientController::getInstance()->mknod(base::TidyPath(
      path_)) != 0)
    return -errno;
  return 0;
}

int FSLinux::ms_create(const char *path,
                       mode_t mode,
                       struct fuse_file_info *fi) {
  std::string path_(path);
  std::string path1_(path);

  // if path is not in an authorised dirs, return error "Permission denied"
  // TODO(Fraser): set bool gui_private_share_ to true if gui has
  //               requested a private share be set up.
  bool gui_private_share_(false);
  if (maidsafe::ClientController::getInstance()->ReadOnly(
      base::TidyPath(path1_), gui_private_share_))
    return -13;

  file_system::FileSystem fsys_;
  path_ = fsys_.MaidsafeHomeDir() + path_;
  fs::path full_path_(path_);
  fs::path branch_path_ = full_path_.parent_path();
  if (!fs::exists(branch_path_))
    fs::create_directories(branch_path_);
//     printf("ms_create abs PATH:  %s\n", path);
//   int res = open(path_.c_str(), O_CREAT | O_EXCL | O_WRONLY, mode);
//   if (res >= 0)
//     res = close(res);

  int fd;

  fd = open(path_.c_str(), fi->flags, mode);
  if (fd == -1)
    return -errno;

  fi->fh = fd;

  printf("ms_create rel PATH: %s -- %d\n", path1_.c_str(), fd);
  if (maidsafe::ClientController::getInstance()->mknod(base::TidyPath(
      path1_)) != 0)
    return -errno;
  path_ = "";
  return 0;
}

int FSLinux::ms_rmdir(const char *path) {
  std::string path_;
  path_ = std::string(path);
  printf("ms_rmdir PATH:  %s\n", path);
  // if path is not in an authorised dirs, return error "Permission denied"
  // TODO(Fraser): set bool gui_private_share_ to true if gui has
  //               requested a private share be set up.
  bool gui_private_share_(false);
  if (maidsafe::ClientController::getInstance()->ReadOnly(
      base::TidyPath(path_), gui_private_share_))
    return -13;

  std::map<std::string, maidsafe::itemtype> children;
  maidsafe::ClientController::getInstance()->readdir(base::TidyPath(
    path_), children);
  if (!children.empty())
    return -ENOTEMPTY;

  if (maidsafe::ClientController::getInstance()->rmdir(base::TidyPath(
      path_)) != 0)
    return -errno;
  path_ = "";

  return 0;
}

int FSLinux::ms_unlink(const char *path) {
  std::string path_;
  path_ = std::string(path);
  printf("ms_unlink PATH:  %s\n", path);
  // if path is not in an authorised dirs, return error "Permission denied"
  // TODO(Fraser): set bool gui_private_share_ to true if gui has
  //               requested a private share be set up.
  bool gui_private_share_(false);
  if (maidsafe::ClientController::getInstance()->ReadOnly(
      base::TidyPath(path_), gui_private_share_))
    return -13;

  if (maidsafe::ClientController::getInstance()->unlink(base::TidyPath(
      path_)) != 0)
    return -errno;
  file_system::FileSystem fsys_;
  path_ = fsys_.MaidsafeHomeDir() + path_;
  if (fs::exists(path_))
    fs::remove(path_);
  path_ = "";
  return 0;
}

}  // namespace
