/*
 * copyright maidsafe.net limited 2008
 * The following source code is property of maidsafe.net limited and
 * is not meant for external use. The use of this code is governed
 * by the license file LICENSE.TXT found in the root of this directory and also
 * on www.maidsafe.net.
 *
 * You are not free to copy, amend or otherwise use this source code without
 * explicit written permission of the board of directors of maidsafe.net
 *
 *  Created on: Nov 13, 2008
 *      Author: Team
 */

#ifndef MAIDSAFE_FUSE_LINUX_FUSECPP_H_
#define MAIDSAFE_FUSE_LINUX_FUSECPP_H_
#define FUSE_USE_VERSION 26
#include <string.h>
#include <fuse/fuse.h>
#include <fuse/fuse_lowlevel.h>

namespace fuse_cpp {

  typedef int(*readlink) (const char *, char *, size_t);  // NOLINT
  typedef int(*getattr) (const char *, struct stat *);  // NOLINT
  typedef int(*setattr) (const char *, struct stat *);  // NOLINT
  typedef int(*getdir) (const char *, fuse_dirh_t, fuse_dirfil_t);  // NOLINT
  typedef int(*mknod) (const char *, mode_t, dev_t);  // NOLINT
  typedef int(*mkdir) (const char *, mode_t);  // NOLINT
  typedef int(*unlink) (const char *);  // NOLINT
  typedef int(*rmdir) (const char *);  // NOLINT
  typedef int(*symlink) (const char *, const char *);  // NOLINT
  typedef int(*rename) (const char *, const char *);  // NOLINT
  typedef int(*link) (const char *, const char *);  // NOLINT
  typedef int(*chmod) (const char *, mode_t);  // NOLINT
  typedef int(*chown) (const char *, uid_t, gid_t);  // NOLINT
  typedef int(*truncate) (const char *, off_t);  // NOLINT
  typedef int(*utime) (const char *, struct utimbuf *);  // NOLINT
  typedef int(*open) (const char *, struct fuse_file_info *);  // NOLINT
  typedef int(*read) (const char *, char *, size_t, off_t,  // NOLINT
    struct fuse_file_info *);  // NOLINT
  typedef int(*write) (const char *, const char *, size_t, off_t,  // NOLINT
    struct fuse_file_info *);  // NOLINT
  typedef int(*statfs) (const char *, struct statvfs *);  // NOLINT
  typedef int(*flush) (const char *, struct fuse_file_info *);  // NOLINT
  typedef int(*release) (const char *, struct fuse_file_info *);  // NOLINT
  typedef int(*fsync) (const char *, int, struct fuse_file_info *);  // NOLINT
  typedef int(*setxattr) (const char *, const char *,  // NOLINT
    const char *, size_t, int);  // NOLINT
  typedef int(*getxattr) (const char *, const char *, char *, size_t);  // NOLINT
  typedef int(*listxattr) (const char *, char *, size_t);  // NOLINT
  typedef int(*removexattr) (const char *, const char *);  // NOLINT
  typedef int(*opendir) (const char *, struct fuse_file_info *);  // NOLINT
  typedef int(*readdir) (const char *, void *, fuse_fill_dir_t,  // NOLINT
                        off_t offset , struct fuse_file_info *);  // NOLINT
  typedef int(*releasedir) (const char *, struct fuse_file_info *);  // NOLINT
  typedef int(*fsyncdir) (const char *, int, struct fuse_file_info *);  // NOLINT
  typedef void *(*init) (struct fuse_conn_info *conn);  // NOLINT
  typedef void (*destroy) (void *a);  // NOLINT
  typedef int(*access) (const char *, int);  // NOLINT
  typedef int(*create) (const char *, mode_t, struct fuse_file_info *);  // NOLINT
  typedef int(*ftruncate) (const char *, off_t, struct fuse_file_info *);  // NOLINT
  typedef int(*fgetattr) (const char *, struct stat *,  // NOLINT
    struct fuse_file_info *);  // NOLINT

  // FuseDispatcher: this is a C++ binding for the fuse system
  //
  // to use: declare the appropriate routine in a class as static to
  // the above typedefs then before calling fuse_main, instantiate
  // the dispatcher and call the routines that you wish to field.
  // Those not called will be handeled by the fuse defaults.

class FuseDispatcher {
 private:
  struct fuse_operations theOps;

 public:
  FuseDispatcher() : theOps() {
    memset(&theOps, 0, sizeof(struct fuse_operations) );
  }
  FuseDispatcher &operator=(const FuseDispatcher & rhs);

  struct fuse_operations *get_fuseOps() { return &theOps; }

  void set_getattr(getattr ptr) { theOps.getattr = ptr; }
  // void set_setattr  (setattr ptr) { theOps.setattr = ptr; }
  void set_readlink(readlink ptr) { theOps.readlink = ptr; }
  void set_getdir(getdir ptr) { theOps.getdir = ptr; }
  void set_mknod(mknod ptr) { theOps.mknod = ptr; }
  void set_mkdir(mkdir ptr) { theOps.mkdir = ptr; }
  void set_unlink(unlink ptr) { theOps.unlink = ptr; }
  void set_rmdir(rmdir ptr) { theOps.rmdir = ptr; }
  void set_symlink(symlink ptr) { theOps.symlink = ptr; }
  void set_rename(rename ptr) { theOps.rename = ptr; }
  void set_link(link  ptr) { theOps.link = ptr; }
  void set_chmod(chmod ptr) { theOps.chmod = ptr; }
  void set_chown(chown ptr) { theOps.chown = ptr; }
  void set_truncate(truncate ptr) { theOps.truncate = ptr; }
  void set_utime(utime ptr) { theOps.utime = ptr; }
  void set_open(open ptr) { theOps.open = ptr;}
  void set_read(read ptr) { theOps.read = ptr; }
  void set_write(write ptr) { theOps.write = ptr; }
  void set_statfs(statfs ptr) { theOps.statfs = ptr; }
  void set_flush(flush ptr) { theOps.flush = ptr; }
  void set_release(release ptr) { theOps.release = ptr; }
  void set_fsync(fsync ptr) { theOps.fsync = ptr; }
  // void set_setxattr (setxattr    ptr) { theOps.setxattr = ptr; }
  // void set_getxattr (getxattr    ptr) { theOps.getxattr = ptr; }
  // void set_listxattr  (listxattr   ptr) { theOps.listxattr = ptr; }
  // void set_removexattr  (removexattr ptr) { theOps.removexattr = ptr; }
  void set_opendir(opendir ptr) { theOps.opendir = ptr; }
  void set_readdir(readdir ptr) { theOps.readdir = ptr; }
  void set_releasedir(releasedir ptr) { theOps.releasedir = ptr; }
  void set_fsyncdir(fsyncdir ptr) { theOps.fsyncdir = ptr; }
  void set_init(init ptr) { theOps.init = ptr; }
  void set_destroy(destroy ptr) { theOps.destroy = ptr; }
  void set_access(access ptr) { theOps.access = ptr; }
  void set_create(create ptr) { theOps.create = ptr; }
  void set_ftruncate(ftruncate ptr) { theOps.ftruncate = ptr; }
  void set_fgetattr(fgetattr ptr) { theOps.fgetattr = ptr; }
};
}

#endif  // MAIDSAFE_FUSE_LINUX_FUSECPP_H_


