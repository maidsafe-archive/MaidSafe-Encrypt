/* copyright maidsafe.net limited 2008
 * ==========================================================================
 *
 *       Filename:  fslinux.h
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

#ifndef MAIDSAFE_FUSE_LINUX_FSLINUX_H_
#define MAIDSAFE_FUSE_LINUX_FSLINUX_H_

#include <string>

#include "maidsafe/client/clientcontroller.h"
#include "maidsafe/fuse/linux/fusecpp.h"

namespace fs_l_fuse {

class FSLinux {
 private:
  FSLinux &operator=(const FSLinux&);
  FSLinux(const FSLinux&);
  fuse_cpp::FuseDispatcher *fuse_dispatcher_;
  struct fuse *fuse_;
  char *mountpoint_;
  int res;

 public:
  FSLinux();
  ~FSLinux();
  bool Mount(const std::string &path, const std::string &debug_mode);
  void UnMount();
  static int ms_readlink(const char *path, char *, size_t);
  static int ms_getattr(const char *path, struct stat *stbuf);
  static int ms_mknod(const char *path, mode_t mode, dev_t rdev);
  static int ms_mkdir(const char *path, mode_t mode);
  static int ms_unlink(const char *path);
  static int ms_rmdir(const char *path);
  static int ms_rename(const char *o_path, const char *n_path);
  static int ms_link(const char *o_path, const char *n_path);
  static int ms_chmod(const char *path, mode_t);
  static int ms_chown(const char *path, uid_t, gid_t);
  static int ms_truncate(const char *path, off_t);
  static int ms_utime(const char *path, struct utimbuf *);
  static int ms_open(const char *path, struct fuse_file_info *);
  static int ms_read(const char *path, char *, size_t, off_t,
      struct fuse_file_info *);
  static int ms_write(const char *path, const char *data, size_t, off_t,
      struct fuse_file_info *);
  static int ms_statfs(const char *path, struct statvfs *stbuf);
  static int ms_flush(const char *path, struct fuse_file_info *);
  static int ms_release(const char *path, struct fuse_file_info *);
  static int ms_fsync(const char *path, int, struct fuse_file_info *);
  static int ms_setxattr(const char *path, const char *, const char *, size_t,
      int);
  static int ms_getxattr(const char *path, const char *, char *, size_t);
  static int ms_listxattr(const char *path, char *, size_t);
  static int ms_removexattr(const char *path, const char *);
  static int ms_opendir(const char *path, struct fuse_file_info *);
  static int ms_readdir(const char *path, void *buf,
      fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi);
  static int ms_releasedir(const char *path, struct fuse_file_info *);
  static int ms_fsyncdir(const char *path, int, struct fuse_file_info *);
  static int ms_access(const char *path, int mask);
  static int ms_create(const char *path, mode_t, struct fuse_file_info *);
  static int ms_ftruncate(const char *path, off_t, struct fuse_file_info *);
  static int ms_fgetattr(const char *path, struct stat *, struct
      fuse_file_info *);
};
}  // namespace fs_l_fuse
#endif  // MAIDSAFE_FUSE_LINUX_FSLINUX_H_
