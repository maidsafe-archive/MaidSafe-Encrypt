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
#include <map>

#include "fs/filesystem.h"
#include "maidsafe/utils.h"
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

FSLinux::FSLinux() : fuse_dispatcher_(NULL), fuse_(NULL), mountpoint_('\0'),
                     res(0) {
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
  umask(0);
  char **opts;
  opts = new char*[6];
  opts[0] = const_cast<char*>(drive_name.c_str());
  opts[1] = const_cast<char*>(path.c_str());
  opts[2] = const_cast<char*>(debug_mode.c_str());
  opts[3] = const_cast<char*>("-s");
  std::string fground = "-f";
  opts[4] = const_cast<char*>(fground.c_str());

#ifdef DEBUG
  printf("opts[1] en el Mount: %s\n", opts[1]);
#endif

  int multithreaded;
  fuse_operations *op = fuse_dispatcher_->get_fuseOps();
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
  if (fuse_ == NULL || fuse_daemonize(foreground) == -1 ||
      fuse_set_signal_handlers(fuse_get_session(fuse_)) == -1) {
    fuse_unmount(mountpoint_, ch);
    if (fuse_)
      fuse_destroy(fuse_);
    return false;
  }
  boost::thread thrd_(boost::bind(fuse_loop_session, fuse_, multithreaded));
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

#ifdef DEBUG
int FSLinux::ms_readlink(const char *path, char*, size_t) {
  printf("ms_readlink %s\n", path);
#else
int FSLinux::ms_readlink(const char *, char*, size_t) {
#endif
  return 0;
}

#ifdef DEBUG
int FSLinux::ms_chmod(const char *path, mode_t) {
  printf("ms_chmod %s\n", path);
#else
int FSLinux::ms_chmod(const char *, mode_t) {
#endif
  return 0;
}

#ifdef DEBUG
int FSLinux::ms_chown(const char *path, uid_t, gid_t) {
  printf("ms_chown %s\n", path);
#else
int FSLinux::ms_chown(const char *, uid_t, gid_t) {
#endif
  return 0;
}

#ifdef DEBUG
int FSLinux::ms_truncate(const char *path, off_t) {
  printf("ms_truncate %s\n", path);
#else
  int FSLinux::ms_truncate(const char *, off_t) {
#endif
  return 0;
}

#ifdef DEBUG
int FSLinux::ms_utime(const char *path, struct utimbuf*) {
  printf("ms_utime %s\n", path);
#else
int FSLinux::ms_utime(const char *, struct utimbuf*) {
#endif
  return 0;
}

#ifdef DEBUG
int FSLinux::ms_flush(const char *path, struct fuse_file_info*) {
  printf("ms_flush %s\n", path);
#else
int FSLinux::ms_flush(const char *, struct fuse_file_info*) {
#endif
  return 0;
}

#ifdef DEBUG
int FSLinux::ms_fsync(const char *path, int, struct fuse_file_info*) {
  printf("ms_fsync %s\n", path);
#else
int FSLinux::ms_fsync(const char *, int, struct fuse_file_info*) {
#endif
  return 0;
}
#ifdef DEBUG
int FSLinux::ms_setxattr(const char *path, const char*, const char*, size_t,
                         int) {
	printf("ms_setxattr %s\n", path);
#else
int FSLinux::ms_setxattr(const char *, const char*, const char*, size_t,
                         int) {
#endif
  return 0;
}

#ifdef DEBUG
int FSLinux::ms_getxattr(const char *path, const char*, char*, size_t) {
  printf("ms_getxattr %s\n", path);
#else
int FSLinux::ms_getxattr(const char *, const char*, char*, size_t) {
#endif
  return 0;
}

#ifdef DEBUG
int FSLinux::ms_listxattr(const char *path, char*, size_t) {
  printf("ms_listxattr %s\n", path);
#else
int FSLinux::ms_listxattr(const char *, char*, size_t) {
#endif
  return 0;
}

#ifdef DEBUG
int FSLinux::ms_removexattr(const char *path, const char*) {
  printf("ms_removexattr %s\n", path);
#else
int FSLinux::ms_removexattr(const char *, const char*) {
#endif
  return 0;
}

#ifdef DEBUG
int FSLinux::ms_fsyncdir(const char *path, int, struct fuse_file_info*) {
  printf("ms_fsyncdir %s\n", path);
#else
int FSLinux::ms_fsyncdir(const char *, int, struct fuse_file_info*) {
#endif
  return 0;
}

#ifdef DEBUG
int FSLinux::ms_ftruncate(const char *path, off_t, struct fuse_file_info*) {
  printf("ms_ftruncate %s\n", path);
#else
int FSLinux::ms_ftruncate(const char *, off_t, struct fuse_file_info*) {
#endif
  return 0;
}

#ifdef DEBUG
int FSLinux::ms_releasedir(const char *path, struct fuse_file_info*) {
  printf("ms_releasedir: %s\n", path);
#else
int FSLinux::ms_releasedir(const char *, struct fuse_file_info*) {
#endif
  return 0;
}

#ifdef DEBUG
int FSLinux::ms_opendir(const char *path, struct fuse_file_info*) {
  printf("ms_opendir: %s\n", path);
#else
int FSLinux::ms_opendir(const char *, struct fuse_file_info*) {
#endif
  return 0;
}

#ifdef DEBUG
int FSLinux::ms_access(const char *path, int mask) {
  printf("ms_access path: %s\n", path);
  printf("ms_access mask: %d\n", mask);
#else
int FSLinux::ms_access(const char *, int mask) {
#endif
  return 0;
}

int FSLinux::ms_link(const char *o_path, const char *n_path) {
  std::string lo_path, ln_path;
  lo_path = std::string(o_path);
  ln_path = std::string(n_path);
#ifdef DEBUG
  printf("ms_link PATHS: %s\t\t%s", o_path, n_path);
#endif
  // if path is not in an authorised dirs, return error "Permission denied"
  // TODO(Fraser): set bool gui_private_share to true if gui has
  //               requested a private share be set up.
  bool gui_private_share(false);
  if (maidsafe::ClientController::getInstance()->ReadOnly(
      maidsafe::TidyPath(ln_path), gui_private_share))
    return -13;

  if (maidsafe::ClientController::getInstance()->link(
      maidsafe::TidyPath(lo_path), maidsafe::TidyPath(ln_path)) != 0)
    return -errno;
  return 0;
}

int FSLinux::ms_open(const char *path, struct fuse_file_info *fi) {
  std::string lpath(path);
#ifdef DEBUG
  printf("ms_open path(%s): %i.\n", path, fi->flags);
#endif
  std::string rel_path(path);
  lpath = (file_system::MaidsafeHomeDir(
          maidsafe::SessionSingleton::getInstance()->SessionName()) / lpath)
              .string();

  fs::path some_path(lpath);
  try {
    if (!fs::exists(some_path.parent_path()))
      fs::create_directories(some_path.parent_path());
    if (!fs::exists(lpath))
      maidsafe::ClientController::getInstance()->read(
          maidsafe::TidyPath(rel_path));
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("ms_open path(%s): filesystem error.\n", path);
#endif
    return -errno;
  }

  int fd;

  fd = open(lpath.c_str(), fi->flags);
  if (fd == -1)
    return -errno;

  fi->fh = fd;
#ifdef DEBUG
  printf("\t file handle: %llu\n", fi->fh);
#endif
  return 0;
}

int FSLinux::ms_read(const char *path, char *data, size_t size, off_t offset,
                     struct fuse_file_info *fi) {
  std::string lpath(path);
#ifdef DEBUG
  printf("ms_read: %s\tfile handle: %llu", path, fi->fh);
#endif
  lpath = (file_system::MaidsafeHomeDir(
          maidsafe::SessionSingleton::getInstance()->SessionName()) / lpath)
              .string();

  int res;

  (void) path;
  res = pread(fi->fh, data, size, offset);
  if (res == -1)
    res = -errno;

  return res;
}

int FSLinux::ms_release(const char *path, struct fuse_file_info *fi) {
#ifdef DEBUG
  printf("ms_release: %s -- %d -- ", path, fi->flags);
  printf("file handle %llu\n", fi->fh);
#endif
  std::string lpath(path);
  lpath = (file_system::MaidsafeHomeDir(
          maidsafe::SessionSingleton::getInstance()->SessionName()) / lpath)
              .string();
  std::string original_path(path);
  close(fi->fh);

  switch (fi->flags) {
    case 0:
//     case 2:
      return 0;
    case 32768:
      if (!maidsafe::ClientController::getInstance()->atime(maidsafe::TidyPath(
           original_path)))
        return -errno;
      break;
    default:
      if (maidsafe::ClientController::getInstance()->write(maidsafe::TidyPath(
          original_path)) != 0)
        return -errno;
      break;
  }
  return 0;
}

int FSLinux::ms_write(const char *path, const char *data, size_t size,
                      off_t offset, struct fuse_file_info *fi) {
  std::string lpath(path);
  lpath = (file_system::MaidsafeHomeDir(
          maidsafe::SessionSingleton::getInstance()->SessionName()) / lpath)
              .string();
#ifdef DEBUG
  printf("ms_write PATH: %s\n", path);
  printf("\t file handle: %llu", fi->fh);
#endif

  fs::path full_path(lpath);
  fs::path branch_path = full_path.parent_path();
  try {
    if (!fs::exists(branch_path))
      fs::create_directories(branch_path);
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("FSLinux::ms_write - failed to create directory %s\n", path);
#endif
  }

  int res;

  (void) path;
  res = pwrite(fi->fh, data, size, offset);
  if (res == -1)
    res = -errno;

  return res;
}

int FSLinux::ms_getattr(const char *path, struct stat *stbuf) {
  std::string lpath;
  lpath = std::string(path);
#ifdef DEBUG
  printf("ms_getattr: %s\n", path);
#endif

  if (lpath == "/") {
    stbuf->st_mode = S_IFDIR | 0444;
    stbuf->st_nlink = 2;
    stbuf->st_size = 4*1024;
    stbuf->st_uid = fuse_get_context()->uid;
    stbuf->st_gid = fuse_get_context()->gid;
    stbuf->st_mtime = base::GetEpochMilliseconds();
    stbuf->st_atime = base::GetEpochMilliseconds();
    return 0;
  }

  std::string ser_mdm;
  if (maidsafe::ClientController::getInstance()->getattr(
      maidsafe::TidyPath(lpath), &ser_mdm) != 0) {
#ifdef DEBUG
    printf("CC getattr came back as failed.\n");
#endif
    return -errno;
  }
  maidsafe::MetaDataMap mdm;
  if (ser_mdm != "" && !mdm.ParseFromString(ser_mdm))
    return -ENOENT;

  int res = 0;
  memset(stbuf, 0, sizeof(struct stat));
  if (ser_mdm != "") {
    if (mdm.type() == maidsafe::EMPTY_FILE ||
        mdm.type() == maidsafe::REGULAR_FILE ||
        mdm.type() == maidsafe::SMALL_FILE) {
      stbuf->st_mode = S_IFREG | 0644;
      stbuf->st_nlink = 1;
      stbuf->st_size = mdm.file_size_low();
      stbuf->st_uid = fuse_get_context()->uid;
      stbuf->st_gid = fuse_get_context()->gid;
      stbuf->st_mtime = mdm.last_modified();
      stbuf->st_atime = mdm.last_access();
    } else if (mdm.type() == maidsafe::EMPTY_DIRECTORY ||
               mdm.type() == maidsafe::DIRECTORY) {
      stbuf->st_mode = S_IFDIR | 0755;
      stbuf->st_nlink = 2;
      stbuf->st_size = 4*1024;
      stbuf->st_uid = fuse_get_context()->uid;
      stbuf->st_gid = fuse_get_context()->gid;
      stbuf->st_mtime = mdm.last_modified();
      stbuf->st_atime = mdm.last_access();
    }
  } else {
     res = -errno;
  }
  return res;
}

int FSLinux::ms_fgetattr(const char *path, struct stat *stbuf,
                         struct fuse_file_info *fi) {
  std::string lpath(path);
#ifdef DEBUG
  printf("ms_fgetattr PATH: %s -- %d\n", path, fi->flags);
#endif

  std::string ser_mdm;
  int n = maidsafe::ClientController::getInstance()->getattr(
          maidsafe::TidyPath(lpath), &ser_mdm);
  maidsafe::MetaDataMap mdm;
  mdm.ParseFromString(ser_mdm);

  bool ro = maidsafe::ClientController::getInstance()->ReadOnly(
            maidsafe::TidyPath(lpath), false);

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
  return n;
}

int FSLinux::ms_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                        off_t offset, struct fuse_file_info *fi) {
  std::string lpath(path);
#ifdef DEBUG
  printf("ms_readdir PATH:  %s\n", path);
#endif

  std::map<std::string, maidsafe::ItemType> children;
  if (maidsafe::ClientController::getInstance()->readdir(
      maidsafe::TidyPath(lpath), &children) != 0)
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

  try {
    if (fs::exists(file_system::HomeDir() / ".thumbnails/fail/"))
      fs::remove_all(file_system::HomeDir() / ".thumbnails/fail/");
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("FSLinux::ms_readdir - Failed to delete thumbs.\n");
#endif
  }

  return 0;
}

int FSLinux::ms_mkdir(const char *path, mode_t mode) {
  std::string lpath(path);
  std::string lpath1(path);
  // if path is not in an authorised dirs, return error "Permission denied"
  // TODO(Fraser): set bool gui_private_share to true if gui has
  //               requested a private share be set up.
  bool gui_private_share(false);
  if (maidsafe::ClientController::getInstance()->ReadOnly(
      maidsafe::TidyPath(lpath1), gui_private_share))
    return -13;

  lpath = (file_system::MaidsafeHomeDir(
          maidsafe::SessionSingleton::getInstance()->SessionName()) / lpath)
              .string();
  fs::path full_path(lpath);
  try {
    if (!fs::exists(full_path))
      fs::create_directories(full_path);
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("FSLinux::ms_mkdir - Failed to create directory %s\n", path);
#endif
  }
#ifdef DEBUG
  printf("ms_mkdir PATH: %s -- %d\n", lpath1.c_str(), mode);
#endif
  if (maidsafe::ClientController::getInstance()->mkdir(
      maidsafe::TidyPath(lpath1)) != 0)
    return -errno;

  return 0;
}

int FSLinux::ms_rename(const char *o_path, const char *n_path) {
  std::string lo_path(o_path), ln_path(n_path);
  // if path is not in an authorised dirs, return error "Permission denied"
  // TODO(Fraser): set bool gui_private_share to true if gui has
  //               requested a private share be set up.
  bool gui_private_share(false);
  if (maidsafe::ClientController::getInstance()->ReadOnly(
      maidsafe::TidyPath(lo_path), gui_private_share))
    return -13;

  if (maidsafe::ClientController::getInstance()->ReadOnly(
      maidsafe::TidyPath(ln_path), gui_private_share))
    return -13;

#ifdef DEBUG
  printf("ms_rename PATHS: %s -- %s\n", o_path, n_path);
#endif
  if (maidsafe::ClientController::getInstance()->rename(
      maidsafe::TidyPath(lo_path), maidsafe::TidyPath(ln_path)) != 0)
    return -errno;
  std::string s_name = maidsafe::SessionSingleton::getInstance()->SessionName();

  try {
    if (fs::exists(file_system::MaidsafeHomeDir(s_name) / ln_path))
      fs::remove(file_system::MaidsafeHomeDir(s_name) / ln_path);
    if (fs::exists(file_system::MaidsafeHomeDir(s_name) / lo_path))
      fs::rename((file_system::MaidsafeHomeDir(s_name) / lo_path),
                 (file_system::MaidsafeHomeDir(s_name) / ln_path));
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("FSLinux::ms_rename - Failed to remove and rename.\n");
#endif
  }
  return 0;
}

int FSLinux::ms_statfs(const char *path, struct statvfs *stbuf) {
#ifdef DEBUG
  printf("ms_statfs PATH:  %s\n", path);
#endif

  // TODO(Team): Populate this struct with live info from the account.
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
  std::string lpath(path);
  // if path is not in an authorised dirs, return error "Permission denied"
  // TODO(Fraser): set bool gui_private_share to true if gui has
  //               requested a private share be set up.
  bool gui_private_share(false);
  if (maidsafe::ClientController::getInstance()->ReadOnly(
      maidsafe::TidyPath(lpath), gui_private_share))
    return -13;

  int res = open(path, O_CREAT | O_EXCL | O_WRONLY, mode);
#ifdef DEBUG
  printf("ms_mknod PATH: %s -- %d\n\n", path, res);
#endif

  if (res >= 0)
    res = close(res);
  if (maidsafe::ClientController::getInstance()->mknod(
      maidsafe::TidyPath(lpath)) != 0)
    return -errno;
  return 0;
}

int FSLinux::ms_create(const char *path,
                       mode_t mode,
                       struct fuse_file_info *fi) {
  std::string lpath(path);
  std::string lpath1(path);

  // if path is not in an authorised dirs, return error "Permission denied"
  // TODO(Fraser): set bool gui_private_share to true if gui has
  //               requested a private share be set up.
  bool gui_private_share(false);
  if (maidsafe::ClientController::getInstance()->ReadOnly(
      maidsafe::TidyPath(lpath1), gui_private_share))
    return -13;

  lpath = (file_system::MaidsafeHomeDir(
          maidsafe::SessionSingleton::getInstance()->SessionName()) / lpath)
              .string();
  fs::path full_path(lpath);
  fs::path branch_path = full_path.parent_path();
  try {
    if (!fs::exists(branch_path))
      fs::create_directories(branch_path);
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("FSLinux::ms_create - Failed to create directory %s\n", path);
#endif
  }

  int fd;
  fd = open(lpath.c_str(), fi->flags, mode);
  if (fd == -1)
    return -errno;

  fi->fh = fd;

#ifdef DEBUG
  printf("ms_create rel PATH: %s -- %d\n", lpath1.c_str(), fd);
#endif
  if (maidsafe::ClientController::getInstance()->mknod(
      maidsafe::TidyPath(lpath1)) != 0)
    return -errno;

  return 0;
}

int FSLinux::ms_rmdir(const char *path) {
  std::string lpath(path);
#ifdef DEBUG
  printf("ms_rmdir PATH: %s\n", path);
#endif
  // if path is not in an authorised dirs, return error "Permission denied"
  // TODO(Fraser): set bool gui_private_share to true if gui has
  //               requested a private share be set up.
  bool gui_private_share(false);
  if (maidsafe::ClientController::getInstance()->ReadOnly(
      maidsafe::TidyPath(lpath), gui_private_share))
    return -13;

  std::map<std::string, maidsafe::ItemType> children;
  maidsafe::ClientController::getInstance()->readdir(
      maidsafe::TidyPath(lpath), &children);
  if (!children.empty())
    return -ENOTEMPTY;

  if (maidsafe::ClientController::getInstance()->rmdir(maidsafe::TidyPath(
      lpath)) != 0)
    return -errno;

  return 0;
}

int FSLinux::ms_unlink(const char *path) {
  std::string lpath(path);
#ifdef DEBUG
  printf("ms_unlink PATH:  %s\n", path);
#endif
  // if path is not in an authorised dirs, return error "Permission denied"
  // TODO(Fraser): set bool gui_private_share to true if gui has
  //               requested a private share be set up.
  bool gui_private_share(false);
  if (maidsafe::ClientController::getInstance()->ReadOnly(
      maidsafe::TidyPath(lpath), gui_private_share))
    return -13;

  if (maidsafe::ClientController::getInstance()->unlink(
      maidsafe::TidyPath(lpath)) != 0)
    return -errno;
  lpath = (file_system::MaidsafeHomeDir(
          maidsafe::SessionSingleton::getInstance()->SessionName()) / lpath)
              .string();
  try {
    if (fs::exists(lpath))
      fs::remove(lpath);
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("FSLinux::ms_unlink - Remove path failed\n");
#endif
  }

  return 0;
}

}  // namespace fs_l_fuse
