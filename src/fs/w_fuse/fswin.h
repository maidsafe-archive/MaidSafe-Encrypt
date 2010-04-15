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

#ifndef FS_W_FUSE_FSWIN_H_
#define FS_W_FUSE_FSWIN_H_

#include <windows.h>
#include <dokan.h>

#include <string>

namespace fs_w_fuse {

#define WinCheckFlag(val, flag) if (val&flag) { DbgPrint(L"\t\t" L#flag L"\n"); }  // NOLINT

static WCHAR RootDirectory[MAX_PATH];

static void DbgPrint(LPCWSTR format, ...);

static void DbgPrint(LPCSTR format, ...);

static void GetFilePath(PWCHAR filePath, LPCWSTR FileName);

static std::string WstrToStr(LPCWSTR in_wstr);

static void GetMountPoint(char drive, LPWSTR mount_point);

static FILETIME GetFileTime(ULONGLONG linuxtime);

static int __stdcall WinCreateFile(LPCWSTR FileName,
                                   DWORD AccessMode,
                                   DWORD ShareMode,
                                   DWORD CreationDisposition,
                                   DWORD FlagsAndAttributes,
                                   PDOKAN_FILE_INFO DokanFileInfo);

static int __stdcall WinCreateDirectory(LPCWSTR FileName,
                                        PDOKAN_FILE_INFO);

static int __stdcall WinOpenDirectory(LPCWSTR FileName,
                                      PDOKAN_FILE_INFO DokanFileInfo);

static int __stdcall WinCloseFile(LPCWSTR FileName,
                                  PDOKAN_FILE_INFO DokanFileInfo);

static int __stdcall WinCleanup(LPCWSTR FileName,
                                PDOKAN_FILE_INFO DokanFileInfo);

static int __stdcall WinReadFile(LPCWSTR FileName,
                                 LPVOID Buffer,
                                 DWORD BufferLength,
                                 LPDWORD ReadLength,
                                 LONGLONG Offset,
                                 PDOKAN_FILE_INFO DokanFileInfo);

static int __stdcall WinWriteFile(LPCWSTR FileName,
                                  LPCVOID Buffer,
                                  DWORD NumberOfBytesToWrite,
                                  LPDWORD NumberOfBytesWritten,
                                  LONGLONG Offset,
                                  PDOKAN_FILE_INFO DokanFileInfo);

static int __stdcall WinFlushFileBuffers(LPCWSTR FileName,
                                         PDOKAN_FILE_INFO DokanFileInfo);

static int __stdcall WinGetFileInformation(
    LPCWSTR FileName,
    LPBY_HANDLE_FILE_INFORMATION HandleFileInformation,
    PDOKAN_FILE_INFO DokanFileInfo);

static int __stdcall WinFindFiles(LPCWSTR FileName,
                                  PFillFindData FillFindData,
                                  PDOKAN_FILE_INFO DokanFileInfo);

static int __stdcall WinDeleteFile(LPCWSTR FileName, PDOKAN_FILE_INFO);

static int __stdcall WinDeleteDirectory(LPCWSTR FileName, PDOKAN_FILE_INFO);

static int __stdcall WinMoveFile(LPCWSTR FileName,
                                 LPCWSTR NewFileName,
                                 BOOL ReplaceIfExisting,
                                 PDOKAN_FILE_INFO DokanFileInfo);

static int __stdcall WinLockFile(LPCWSTR FileName,
                                 LONGLONG ByteOffset,
                                 LONGLONG Length,
                                 PDOKAN_FILE_INFO DokanFileInfo);

static int __stdcall WinSetEndOfFile(LPCWSTR FileName,
                                     LONGLONG ByteOffset,
                                     PDOKAN_FILE_INFO DokanFileInfo);

static int __stdcall WinSetAllocationSize(LPCWSTR FileName,
                                          LONGLONG AllocSize,
                                          PDOKAN_FILE_INFO DokanFileInfo);

static int __stdcall WinSetFileAttributes(LPCWSTR FileName,
                                          DWORD FileAttributes,
                                          PDOKAN_FILE_INFO);

static int __stdcall WinSetFileTime(LPCWSTR FileName,
                                    CONST FILETIME *CreationTime,
                                    CONST FILETIME *LastAccessTime,
                                    CONST FILETIME *LastWriteTime,
                                    PDOKAN_FILE_INFO DokanFileInfo);

static int __stdcall WinUnlockFile(LPCWSTR FileName,
                                   LONGLONG ByteOffset,
                                   LONGLONG Length,
                                   PDOKAN_FILE_INFO DokanFileInfo);

static int __stdcall WinGetFileSecurity(
    LPCWSTR FileName,
    PSECURITY_INFORMATION SecurityInformation,
    PSECURITY_DESCRIPTOR SecurityDescriptor,
    ULONG BufferLength,
    PULONG LengthNeeded,
    PDOKAN_FILE_INFO DokanFileInfo);

static int __stdcall WinSetFileSecurity(
    LPCWSTR FileName,
    PSECURITY_INFORMATION SecurityInformation,
    PSECURITY_DESCRIPTOR SecurityDescriptor,
    ULONG SecurityDescriptorLength,
    PDOKAN_FILE_INFO DokanFileInfo);

static int __stdcall WinGetVolumeInformation(LPWSTR VolumeNameBuffer,
                                             DWORD VolumeNameSize,
                                             LPDWORD VolumeSerialNumber,
                                             LPDWORD MaximumComponentLength,
                                             LPDWORD FileSystemFlags,
                                             LPWSTR FileSystemNameBuffer,
                                             DWORD FileSystemNameSize,
                                             PDOKAN_FILE_INFO DokanFileInfo);

static int __stdcall WinUnmount(PDOKAN_FILE_INFO);

static void CallMount(char drive);

void Mount(char drive);

bool UnMount(char drive);

}  // namespace fs_w_fuse

#endif  // FS_W_FUSE_FSWIN_H_
