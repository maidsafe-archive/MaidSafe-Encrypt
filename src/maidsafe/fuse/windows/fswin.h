/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Description:
* Version:      1.0
* Created:      2010-03-17-20.31.17
* Revision:     none
* Compiler:     gcc
* Author:       Fraser Hutchison (fh), fraser.hutchison@maidsafe.net
* Company:      maidsafe.net limited
*
* The following source code is property of maidsafe.net limited and is not
* meant for external use.  The use of this code is governed by the license
* file LICENSE.TXT found in the root of this directory and also on
* www.maidsafe.net.
*
* You are not free to copy, amend or otherwise use this source code without
* the explicit written permission of the board of directors of maidsafe.net.
*
* ============================================================================
*/

#ifndef MAIDSAFE_FUSE_WINDOWS_FSWIN_H_
#define MAIDSAFE_FUSE_WINDOWS_FSWIN_H_

#include <windows.h>
#include <dokan.h>

#include <string>

namespace fs_w_fuse {

void Mount(char drive);

bool UnMount(char drive);

}  // namespace fs_w_fuse

#endif  // MAIDSAFE_FUSE_WINDOWS_FSWIN_H_
