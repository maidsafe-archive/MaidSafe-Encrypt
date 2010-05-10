/*

Copyright (c) 2007, 2008 Hiroki Asakawa info@dokan-dev.net


Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#include "fs/w_fuse/fswin.h"

#include <winbase.h>
#include <boost/lexical_cast.hpp>

#include <list>
#include <map>
#include <vector>

#include "maidsafe/client/clientcontroller.h"
#include "maidsafe/utils.h"

namespace fs = boost::filesystem;

namespace fs_w_fuse {

#ifdef __MSVC__
#define WinCheckFlag(val, flag) if (val&flag) { DbgPrint(L"\t\t" L#flag L"\n"); }  // NOLINT
#else
#define WinCheckFlag(val, flag) if (val&flag) { DbgPrint(L"\t\t" #flag L"\n"); }  // NOLINT
#endif

std::list<ULONG64> to_encrypt_;
std::list<std::string> to_delete_;

static WCHAR RootDirectory[MAX_PATH];

static void DbgPrint(const WCHAR *format, ...) {
#ifdef DEBUG
  WCHAR buffer[512];
  va_list argp;
  va_start(argp, format);
  vswprintf(buffer, format, argp);
  va_end(argp);
  OutputDebugStringW(buffer);
#endif
}

static void DbgPrint(const CHAR *format, ...) {
#ifdef DEBUG
  CHAR buffer[512];
  va_list argp;
  va_start(argp, format);
  vsprintf(buffer, format, argp);
  va_end(argp);
  OutputDebugStringA(buffer);
#endif
}

static void GetFilePath(PWCHAR filePath, const WCHAR *FileName) {
  RtlZeroMemory(filePath, MAX_PATH);
  wcsncpy(filePath, RootDirectory, wcslen(RootDirectory));
  wcsncat(filePath, FileName, wcslen(FileName));
}

static std::string WstrToStr(const WCHAR *in_wstr) {
  std::ostringstream stm;
  const std::ctype<char> &ctfacet =
      std::use_facet< std::ctype<char> >(stm.getloc());
  for (size_t i = 0; i < wcslen(in_wstr); ++i)
    stm << ctfacet.narrow(in_wstr[i], 0);
  return maidsafe::TidyPath(stm.str());
}

//  void GetFilePath(std::string *filePathStr, const WCHAR *FileName) {
//    std::ostringstream stm;
//    const std::ctype<char> &ctfacet =
//        std::use_facet< std::ctype<char> >(stm.getloc());
//    for (size_t i = 0; i < wcslen(FileName); ++i)
//      stm << ctfacet.narrow(FileName[i], 0);
//    fs::path path_(stm.str());
//    *filePathStr = maidsafe::TidyPath(path_.string());
//  }

static void GetMountPoint(char drive, LPWSTR mount_point) {
  std::locale loc;
  mount_point[0] = std::use_facet< std::ctype<wchar_t> >(loc).widen(drive);
  mount_point[1] = L':';
  mount_point[2] = L'\0';
}

static void PrintUserName(PDOKAN_FILE_INFO DokanFileInfo) {
  HANDLE handle;
  UCHAR buffer[1024];
  DWORD returnLength;
  WCHAR accountName[256];
  WCHAR domainName[256];
  DWORD accountLength = sizeof(accountName) / sizeof(WCHAR);
  DWORD domainLength = sizeof(domainName) / sizeof(WCHAR);
  PTOKEN_USER tokenUser;
  SID_NAME_USE snu;

  handle = DokanOpenRequestorToken(DokanFileInfo);
  if (handle == INVALID_HANDLE_VALUE) {
    DbgPrint(L"  DokanOpenRequestorToken failed\n");
    return;
  }

  if (!GetTokenInformation(handle, TokenUser, buffer, sizeof(buffer),
      &returnLength)) {
    DbgPrint(L"  GetTokenInformation failed: %d\n", GetLastError());
    CloseHandle(handle);
    return;
  }

  CloseHandle(handle);

  tokenUser = (PTOKEN_USER)buffer;
  if (!LookupAccountSid(NULL, tokenUser->User.Sid, accountName, &accountLength,
      domainName, &domainLength, &snu)) {
    DbgPrint(L"  LookupAccountSid failed: %d\n", GetLastError());
    return;
  }

  DbgPrint(L"  AccountName: %s, DomainName: %s\n", accountName, domainName);
}

static FILETIME GetFileTime(ULONGLONG linuxtime) {
  FILETIME filetime, ft;
  SYSTEMTIME systime;
  systime.wYear = 1970;
  systime.wMonth = systime.wDay = 1;
  systime.wHour = systime.wMinute = systime.wSecond = systime.wMilliseconds = 0;
  SystemTimeToFileTime(&systime, &ft);

  ULARGE_INTEGER g;
  g.HighPart = ft.dwHighDateTime;
  g.LowPart = ft.dwLowDateTime;

  g.QuadPart += linuxtime*10000000;

  filetime.dwHighDateTime = g.HighPart;
  filetime.dwLowDateTime = g.LowPart;

  return filetime;
}

static int __stdcall WinCreateFile(const WCHAR *FileName,
                                   DWORD AccessMode,
                                   DWORD ShareMode,
                                   DWORD CreationDisposition,
                                   DWORD FlagsAndAttributes,
                                   PDOKAN_FILE_INFO DokanFileInfo) {
  WCHAR filePath[MAX_PATH];
  HANDLE handle;
//  DWORD fileAttr;
  DbgPrint(L"WinCreateFile\nFileName: %s\n", FileName);
  PrintUserName(DokanFileInfo);
  GetFilePath(filePath, FileName);

  std::string relPathStr(WstrToStr(FileName));
  std::string rootStr(WstrToStr(RootDirectory));
  // WCHAR DokanPath[MAX_PATH];
  // GetDokanFilePath(DokanPath, FileName);
  // build the required maidsafe branch dirs
  // (if we have the file already in the DA)
  bool created_cache_dir_ = false;
  fs::path rel_path_(relPathStr);
  fs::path branch_path_ = rel_path_.branch_path();

  //  std::cout << "relPathStr = " << relPathStr;
  //  std::cout << " and branch_path_ = " << branch_path_ << std::endl;

  // if path is not in an authorised dirs, return error "Permission denied"
  // TODO(Fraser#5#): set bool gui_private_share_ to true if gui has
  //                  requested a private share be set up.

  // CAN'T HAVE THIS CHECK HERE, BECAUSE THAT RENDERS ALL FILES INVISIBLE
//  bool gui_private_share_(false);
//  if (maidsafe::ClientController::getInstance()->ReadOnly(relPathStr,
//                                                          gui_private_share_))
//    return -5;

//  // if we're in root and not in one of the pre-loaded dirs, deny access
//  if (branch_path_.string()=="" && !(relPathStr=="\\" || relPathStr=="/" )) {
//    bool ok_=false;
//    for (int i=0; i<kRootSubdirSize; i++) {
//      if (relPathStr==maidsafe::TidyPath(kRootSubdir[i][0])) {
//        ok_=true;
//        break;
//      }
//    }
//    if (!ok_){
//      std::cout << "aaaaaaaaaaaaaaaaaaaaaa" << std::endl;
//      return -5; //  ERROR_ACCESS_DENIED
//    }
//  }
  fs::path full_branch_path_(rootStr);
  full_branch_path_ /= branch_path_;
  std::string ser_mdm = "";  // , ser_mdm_branch;
  maidsafe::MetaDataMap mdm;
  if (!maidsafe::ClientController::getInstance()->getattr(relPathStr,
                                                          ser_mdm)) {
    if (!fs::exists(full_branch_path_)) {
      try {
        fs::create_directories(full_branch_path_);
      }
      catch(const std::exception &e) {
        DbgPrint("In WinCreateFile: %s\n", e.what());
        DWORD error = GetLastError();
        return error * -1;
      }
      created_cache_dir_ = true;
    }
  }
  //  if it's a file, decrypt it to the maidsafe dir or else create dir
  if (!fs::exists(filePath) && ser_mdm != "") {
    mdm.ParseFromString(ser_mdm);
    if (mdm.type() < 3) {  // i.e. if this is a file
      int res = maidsafe::ClientController::getInstance()->read(relPathStr);
      DbgPrint("In WinCreateFile: Decryption of %s: %i\n", relPathStr.c_str(),
               res);
    } else if (mdm.type() == 4 || mdm.type() == 5) {  //  i.e. if this is a dir
      DbgPrint(L"In WinCreateFile: Making dir %s\n", filePath);
      fs::create_directory(filePath);
    } else {
      DbgPrint("In WinCreateFile: don't recognise mdm type.\n");
      return -99999;
    }
  }
  WinCheckFlag(ShareMode, FILE_SHARE_READ);  // 0x00000001
  WinCheckFlag(ShareMode, FILE_SHARE_WRITE);  // 0x00000002
  WinCheckFlag(ShareMode, FILE_SHARE_DELETE);  // 0x00000004
  WinCheckFlag(AccessMode, GENERIC_READ);  // 0x80000000L
  WinCheckFlag(AccessMode, GENERIC_WRITE);  // 0x40000000L
  WinCheckFlag(AccessMode, GENERIC_EXECUTE);  // 0x20000000L
  WinCheckFlag(AccessMode, DELETE);  // 0x00010000L
  WinCheckFlag(AccessMode, FILE_READ_DATA);  // 0x0001 - file & pipe
  WinCheckFlag(AccessMode, FILE_READ_ATTRIBUTES);  // 0x0080 - all
  WinCheckFlag(AccessMode, FILE_READ_EA);  // 0x0008 - file & directory
  WinCheckFlag(AccessMode, READ_CONTROL);  // 0x00020000L
  WinCheckFlag(AccessMode, FILE_WRITE_DATA);  // 0x0002 - file & pipe
  WinCheckFlag(AccessMode, FILE_WRITE_ATTRIBUTES);  // 0x0100 - all
  WinCheckFlag(AccessMode, FILE_WRITE_EA);  // 0x0010 - file & directory
  WinCheckFlag(AccessMode, FILE_APPEND_DATA);  // 0x0004 - file
  WinCheckFlag(AccessMode, WRITE_DAC);  // 0x00040000L
  WinCheckFlag(AccessMode, WRITE_OWNER);  // 0x00080000L
  WinCheckFlag(AccessMode, SYNCHRONIZE);  // 0x00100000L
  WinCheckFlag(AccessMode, FILE_EXECUTE);  // 0x0020 - file
  WinCheckFlag(AccessMode, STANDARD_RIGHTS_READ);  // 0x00020000L
  WinCheckFlag(AccessMode, STANDARD_RIGHTS_WRITE);  // 0x00020000L
  WinCheckFlag(AccessMode, STANDARD_RIGHTS_EXECUTE);  // 0x00020000L


//  // When filePath is a directory, needs to change the flag so that the file
//  // can be opened.
//  fileAttr = GetFileAttributes(filePath);
//  if (fileAttr && fileAttr & FILE_ATTRIBUTE_DIRECTORY) {

  if (fs::is_directory(filePath)) {
    DokanFileInfo->IsDirectory = TRUE;
    // get db for *this* dir (we've already got db for parent)
    std::string relPathStrElement(relPathStr), ser_mdm_dir("");
    relPathStrElement += "/a";
    if (maidsafe::ClientController::getInstance()->getattr(relPathStrElement,
                                                           ser_mdm_dir)) {
//      printf("yyyyyyyyyyyyyyyyyyyyyyyyyyyyyy\n");
    }
//    handle = CreateFile(
//      filePath,
//      0,
//      FILE_SHARE_READ|FILE_SHARE_WRITE,
//      NULL,
//      OPEN_EXISTING,
//      FILE_FLAG_BACKUP_SEMANTICS,
//      NULL);
//    if (handle == INVALID_HANDLE_VALUE) {
//      DWORD error = GetLastError();
//      DbgPrint(L"\t\terror code = %ld\n\n", error);
//      std::cout << "fdsfdsafdsfdsf" << std::endl;
//      return error * -1;
//    }
//    DokanFileInfo->Context = (ULONG64)handle;
    return 0;
//  } else if (rel_path_.leaf() == "Thumbs.db" ||
//             rel_path_.leaf() == "desktop.ini") {
//    // TODO(Haiyang): treat thumbs.db in a proper way, this is temp solution!
//    std::cout << "Creating Thumbs.db, desktop.ini requested. No way!";
//    std::cout << std::endl;
//    return -5;
  }
  handle = CreateFile(
    filePath,
    AccessMode,  // GENERIC_READ|GENERIC_WRITE|GENERIC_EXECUTE,
    ShareMode,
    NULL,  // security attribute
    CreationDisposition,
    FlagsAndAttributes,  // |FILE_FLAG_NO_BUFFERING,
    NULL);  // template file handle

  if (handle == INVALID_HANDLE_VALUE) {
    DWORD error = GetLastError();
    if (created_cache_dir_ && fs::exists(full_branch_path_)) {
      fs::remove(full_branch_path_);
    }
    DbgPrint("In WinCreateFile: handle == INVALID_HANDLE_VALUE\t error = %lu\n",
           error);
#ifdef DEBUG
    if (CreationDisposition == OPEN_EXISTING)
      DbgPrint("OPEN_EXISTING\n");
    if (CreationDisposition == CREATE_NEW)
      DbgPrint("CREATE_NEW\n");
#endif
    return error * -1;  // error codes are negated val of Win Sys Error codes
  }
  DokanFileInfo->Context = (ULONG64)handle;
  to_delete_.push_back(relPathStr);
//  std::list<std::string>::iterator dit;
//  std::cout << "FileNames for deletion: ";
//  for (dit = to_delete_.begin(); dit != to_delete_.end(); ++dit) {
//   std::cout << *dit << "\t";
//  }
//  std::cout << std::endl << std::endl;

  if (CreationDisposition != CREATE_NEW)
    return 0;
  DbgPrint("In WinCreateFile: Encyption decider.\n");
  std::list<ULONG64>::iterator it;
  for (it = to_encrypt_.begin(); it != to_encrypt_.end(); ++it) {
    if (*it == DokanFileInfo->Context)
      return 0;
  }
  DbgPrint("In WinCreateFile: Adding to encryption list\n");
  to_encrypt_.push_back(DokanFileInfo->Context);
  return 0;
}

static int __stdcall WinCreateDirectory(const WCHAR *FileName,
                                        PDOKAN_FILE_INFO) {
  DbgPrint(L"WinCreateDirectory\nFileName: %s\n", FileName);
  WCHAR filePath[MAX_PATH];
  GetFilePath(filePath, FileName);
  if (wcslen(FileName) == 1)
    return 0;
  std::string dir_path_str(WstrToStr(filePath));
  fs::path dir_path(dir_path_str);
  DbgPrint("In WinCreateDirectory, dir_path_str: %s\n",
         dir_path.string().c_str());

//  if (!fs::exists(dir_path)) {

  // must use CreateDirectory rather than boost::filesystem::create_directories
  // to avoid removing existing files from directory
  if (!CreateDirectory(filePath, NULL)) {
    DWORD error = GetLastError();
    DbgPrint("In WinCreateDirectory, error: %lu\n", error);
    return error * -1;  // error code is negated val of Win Sys Error code
  }
//  }
  std::string relPathStr(WstrToStr(FileName));
  DbgPrint("In WinCreateDirectory, ms_mkdir PATH: %s\n", relPathStr.c_str());
  bool gui_private_share_(false);
  if (maidsafe::ClientController::getInstance()->ReadOnly(relPathStr,
      gui_private_share_))
    return -5;

  int n = maidsafe::ClientController::getInstance()->mkdir(relPathStr);
  if (n != 0)
    return n;
  return 0;
}

static int __stdcall WinOpenDirectory(const WCHAR *FileName,
                                      PDOKAN_FILE_INFO DokanFileInfo) {
  DbgPrint(L"WinOpenDirectory\nFileName: %s\n", FileName);
  WCHAR filePath[MAX_PATH];
  HANDLE handle;
  DWORD attr;
  GetFilePath(filePath, FileName);
  attr = GetFileAttributes(filePath);
  if (attr == INVALID_FILE_ATTRIBUTES) {
    DWORD error = GetLastError();
    DbgPrint("In WinOpenDirectory, error = %lu\n\n", error);
    return error * -1;
  }
  if (!(attr & FILE_ATTRIBUTE_DIRECTORY)) {
    return -1;
  }

  // WCHAR DokanPath[MAX_PATH];
  // GetDokanFilePath(DokanPath, FileName);
  handle = CreateFile(filePath,
                      0,
                      FILE_SHARE_READ|FILE_SHARE_WRITE,
                      NULL,
                      OPEN_EXISTING,
                      FILE_FLAG_BACKUP_SEMANTICS,
                      NULL);
  if (handle == INVALID_HANDLE_VALUE) {
    DbgPrint("In WinOpenDirectory, handle == INVALID_HANDLE_VALUE\n");
    DWORD error = GetLastError();
    DbgPrint(L"In WinOpenDirectory, error = %lu\n\n", error);
    return error * -1;
  }
  DokanFileInfo->Context = (ULONG64)handle;
  return 0;
}

static int __stdcall WinCloseFile(const WCHAR *FileName,
                                  PDOKAN_FILE_INFO DokanFileInfo) {
  DbgPrint(L"WinCloseFile\nFileName: %s\n", FileName);
  WCHAR filePath[MAX_PATH];
  GetFilePath(filePath, FileName);
  if (DokanFileInfo->Context) {
    CloseHandle((HANDLE)DokanFileInfo->Context);
    DokanFileInfo->Context = 0;
  }
  return 0;
}

static int __stdcall WinCleanup(const WCHAR *FileName,
                                PDOKAN_FILE_INFO DokanFileInfo) {
  DbgPrint(L"WinCleanup\nFileName: %s\n", FileName);
  WCHAR filePath[MAX_PATH];
  GetFilePath(filePath, FileName);
  std::string relPathStr(WstrToStr(FileName));
  // WCHAR DokanPath[MAX_PATH];
  // GetDokanFilePath(DokanPath, FileName);
  bool encrypt_ = false;
  std::list<ULONG64>::iterator it;
  for (it = to_encrypt_.begin(); it != to_encrypt_.end(); ++it) {
    if (*it == DokanFileInfo->Context) {
      encrypt_ = true;
      to_encrypt_.erase(it);
      break;
    }
  }
  if (DokanFileInfo->Context) {
    CloseHandle((HANDLE)DokanFileInfo->Context);
    DokanFileInfo->Context = 0;
    if (DokanFileInfo->DeleteOnClose) {
      if (DokanFileInfo->IsDirectory) {
        RemoveDirectory(filePath);
      } else {
        DeleteFile(filePath);
      }
    }
    if (relPathStr == "\\" || relPathStr == "/" )
      return 0;
    if (encrypt_) {
      if (maidsafe::ClientController::getInstance()->write(relPathStr) != 0) {
        DbgPrint("In WinCleanup, Encryption failed.\n");
        return -errno;
      } else {
        DbgPrint("In WinCleanup, Encryption succeeded.\n");
      }
    }
//    if (!to_delete_.size())
//      return 0;
//    bool delete_ = false;
//    for (std::list<std::string>::iterator dit = to_delete_.begin();
//        dit != to_delete_.end(); ++dit) {
//      if (*dit == relPathStr) {
//        to_delete_.erase(dit);
//        delete_ = true;
//        break;
//      }
//    }
//    if (!delete_)
//      return 0;
//    for (std::list<std::string>::iterator dit = to_delete_.begin();
//        dit != to_delete_.end(); ++dit) {
//      if (*dit == relPathStr)
//        return 0;
//    }
//    if (fs::is_directory(filePath))
//      return 0;
//    //  printf("Removing %s\n", WstrToStr(filePath).c_str());
//    //  fs::remove(filePath);
    return 0;
  } else {
//    return fs::is_directory(filePath) ? 0 : -1;
    return -1;
  }
  return 0;
}

static int __stdcall WinReadFile(const WCHAR *FileName,
                                 LPVOID Buffer,
                                 DWORD BufferLength,
                                 LPDWORD ReadLength,
                                 LONGLONG Offset,
                                 PDOKAN_FILE_INFO DokanFileInfo) {
  DbgPrint(L"WinReadFile\nFileName: %s\n", FileName);
  WCHAR   filePath[MAX_PATH];
  HANDLE   handle = (HANDLE)DokanFileInfo->Context;
  ULONG   offset = (ULONG)Offset;
  BOOL   opened = FALSE;
  GetFilePath(filePath, FileName);
  if (!handle || handle == INVALID_HANDLE_VALUE) {
    handle = CreateFile(filePath,
                        GENERIC_READ,
                        FILE_SHARE_READ,
                        NULL,
                        OPEN_EXISTING,
                        0,
                        NULL);
    if (handle == INVALID_HANDLE_VALUE) {
      DbgPrint("In WinReadFile, handle == INVALID_HANDLE_VALUE\n");
      DWORD error = GetLastError();
      DbgPrint(L"In WinReadFile, error = %lu\n\n", error);
      return -1;
    }
    opened = TRUE;
  }
  if (SetFilePointer(handle, offset, NULL, FILE_BEGIN) == 0xFFFFFFFF) {
    DbgPrint(L"In WinReadFile, seek error, offset = %d\n\n", offset);
    if (opened)
      CloseHandle(handle);
    return -1;
  }
  if (!ReadFile(handle, Buffer, BufferLength, ReadLength, NULL)) {
    DbgPrint(L"In WinReadFile, read error = %u, buffer length = %d, read length"
             L" = %d\n\n",
             GetLastError(),
             BufferLength,
             *ReadLength);
    if (opened)
      CloseHandle(handle);
    return -1;
  } else {
    DbgPrint(L"In WinReadFile, read %d, offset %d\n", *ReadLength, offset);
  }
  if (opened)
    CloseHandle(handle);
//  DokanResetTimeout(1000 * 30, DokanFileInfo);
//  Sleep(1000 * 20);
  return 0;
}

static int __stdcall WinWriteFile(const WCHAR *FileName,
                                  LPCVOID Buffer,
                                  DWORD NumberOfBytesToWrite,
                                  LPDWORD NumberOfBytesWritten,
                                  LONGLONG Offset,
                                  PDOKAN_FILE_INFO DokanFileInfo) {
  DbgPrint(L"WinWriteFile\nFileName: %s\n", FileName);
  WCHAR filePath[MAX_PATH];
  HANDLE handle = (HANDLE)DokanFileInfo->Context;
  ULONG offset = (ULONG)Offset;
  BOOL opened = FALSE;
  GetFilePath(filePath, FileName);
  //  reopen the file
  if (!handle || handle == INVALID_HANDLE_VALUE) {
      // DbgPrint(L"\t\tinvalid handle, cleanuped?\n");
    handle = CreateFile(filePath,
                        GENERIC_WRITE,
                        FILE_SHARE_WRITE,
                        NULL,
                        OPEN_EXISTING,
                        0,
                        NULL);
    if (handle == INVALID_HANDLE_VALUE) {
      DbgPrint("In WinWriteFile, handle == INVALID_HANDLE_VALUE\n");
#ifdef DEBUG
      DWORD error = GetLastError();
      DbgPrint(L"In WinWriteFile, error = %lu\n\n", error);
#endif
      return -1;
    }
    opened = TRUE;
  }

  if (DokanFileInfo->WriteToEndOfFile) {
    if (SetFilePointer(handle, 0, NULL, FILE_END) == INVALID_SET_FILE_POINTER) {
      DbgPrint(L"In WinWriteFile, seek error, offset = EOF, error = %d\n",
               GetLastError());
      return -1;
    }
  } else if (SetFilePointer(handle, offset, NULL, FILE_BEGIN) ==
             INVALID_SET_FILE_POINTER) {
    DbgPrint("In WinWriteFile, SetFilePointer == INVALID_SET_FILE_POINTER\n");
#ifdef DEBUG
    DWORD error = GetLastError();
    DbgPrint(L"In WinWriteFile, error = %lu\n\n", error);
#endif
    return -1;
  }
  if (!WriteFile(handle,
                 Buffer,
                 NumberOfBytesToWrite,
                 NumberOfBytesWritten,
                 NULL)) {
    DbgPrint("In WinWriteFile, failed WriteFile\n");
    return -1;
  }
  //  close the file when it is reopened
  if (opened)
    CloseHandle(handle);
  std::list<ULONG64>::reverse_iterator rit;
  for (rit = to_encrypt_.rbegin(); rit != to_encrypt_.rend(); ++rit) {
    if (*rit == DokanFileInfo->Context)
      return 0;
  }
  to_encrypt_.push_back(DokanFileInfo->Context);
  return 0;
}

static int __stdcall WinFlushFileBuffers(const WCHAR *FileName,
                                         PDOKAN_FILE_INFO DokanFileInfo) {
  DbgPrint(L"WinFlushFileBuffers\nFileName: %s\n", FileName);
  WCHAR filePath[MAX_PATH];
  HANDLE handle = (HANDLE)DokanFileInfo->Context;
  GetFilePath(filePath, FileName);
  if (!handle || handle == INVALID_HANDLE_VALUE)
    return 0;
  if (!FlushFileBuffers(handle))
    return -1;
  return 0;
}

static int __stdcall WinGetFileInformation(
    const WCHAR *FileName,
    LPBY_HANDLE_FILE_INFORMATION HandleFileInformation,
    PDOKAN_FILE_INFO DokanFileInfo) {
  DbgPrint(L"WinGetFileInformation\nFileName: %s\n", FileName);
  WCHAR filePath[MAX_PATH];
  HANDLE handle = (HANDLE)DokanFileInfo->Context;
  BOOL opened = FALSE;
  GetFilePath(filePath, FileName);
  std::string relPathStr(WstrToStr(FileName));
  if (!handle || handle == INVALID_HANDLE_VALUE) {
    //  If CreateDirectory returned FILE_ALREADY_EXISTS and
    //  it is called with FILE_OPEN_IF, that handle must be opened.
    DbgPrint("In WinGetFileInfo, handle == INVALID_HANDLE_VALUE\n");
#ifdef DEBUG
    DWORD error = GetLastError();
    DbgPrint(L"In WinGetFileInfo, error = %lu\n\n", error);
#endif
    handle = CreateFile(
      filePath,
      0,
      FILE_SHARE_READ,
      NULL,
      OPEN_EXISTING,
      FILE_FLAG_BACKUP_SEMANTICS,
      NULL);
    if (handle == INVALID_HANDLE_VALUE) {
      DbgPrint("In WinGetFileInfo, NEW handle == INVALID_HANDLE_VALUE\n");
#ifdef DEBUG
      error = GetLastError();
      DbgPrint(L"In WinGetFileInfo, error = %lu\n\n", error);
#endif
      return -1;
    }
    opened = TRUE;
  }
  if (!GetFileInformationByHandle(handle, HandleFileInformation)) {
    // FileName is a root directory
    // in this case, FindFirstFile can't get directory information
    if (relPathStr == "\\" || relPathStr == "/") {
      HandleFileInformation->dwFileAttributes = GetFileAttributes(filePath);
    } else {
      maidsafe::MetaDataMap mdm;
      std::string ser_mdm;
      WIN32_FIND_DATAW find;
      ZeroMemory(&find, sizeof(WIN32_FIND_DATAW));
      handle = FindFirstFile(filePath, &find);
      if (handle == INVALID_HANDLE_VALUE) {
        DbgPrint("In WinGetFileInfo, 1st filehandle == INVALID_HANDLE_VALUE\n");
#ifdef DEBUG
        DWORD error = GetLastError();
        DbgPrint(L"In WinGetFileInfo, error = %lu\n\n", error);
#endif
        return -1;
      }
      if (maidsafe::ClientController::getInstance()->getattr(relPathStr,
                                                             ser_mdm)) {
        DbgPrint("In WinGetFileInfo, getattr failed\n");
        return -1;
      }
      mdm.ParseFromString(ser_mdm);
      if (mdm.type() == maidsafe::EMPTY_FILE ||
          mdm.type() == maidsafe::REGULAR_FILE ||
          mdm.type() == maidsafe::SMALL_FILE) {
        HandleFileInformation->dwFileAttributes = find.dwFileAttributes;
        // HandleFileInformation->dwFileAttributes = 32;
            // find.dwFileAttributes;
        HandleFileInformation->ftCreationTime =
            GetFileTime(mdm.creation_time());  // find.ftCreationTime;
        HandleFileInformation->ftLastAccessTime =
            GetFileTime(mdm.last_access());  // find.ftLastWriteTime;
        HandleFileInformation->ftLastWriteTime =
            GetFileTime(mdm.last_modified());  // find.ftLastWriteTime;
        HandleFileInformation->nFileSizeHigh =
            mdm.file_size_high();  // find.nFileSizeHigh;
        HandleFileInformation->nFileSizeLow =
            mdm.file_size_low();  // find.nFileSizeLow;

        DbgPrint("In WinGetFileInfo, FindFiles OK\n");
      } else if (mdm.type() == maidsafe::EMPTY_DIRECTORY ||
                 mdm.type() == maidsafe::DIRECTORY) {
      HandleFileInformation->dwFileAttributes = find.dwFileAttributes;
        // HandleFileInformation->dwFileAttributes = 16;
            // find.dwFileAttributes;
        HandleFileInformation->ftCreationTime =
            GetFileTime(mdm.creation_time());  // find.ftCreationTime;
        HandleFileInformation->ftLastAccessTime =
            GetFileTime(mdm.last_access());  // find.ftLastWriteTime;
        HandleFileInformation->ftLastWriteTime =
            GetFileTime(mdm.last_modified());  // find.ftLastWriteTime;
        HandleFileInformation->nFileSizeHigh = 0;  // find.nFileSizeHigh;
        HandleFileInformation->nFileSizeLow = 0;  // find.nFileSizeLow;
        DokanFileInfo->IsDirectory = TRUE;

        DbgPrint("In WinGetFileInfo, FindFiles OK\n");
      }
      FindClose(handle);
    }
  }
  if (opened)
    CloseHandle(handle);
  return 0;
}

static int __stdcall WinFindFiles(const WCHAR *FileName,
                                  PFillFindData FillFindData,
                                  PDOKAN_FILE_INFO DokanFileInfo) {
  DbgPrint(L"WinFindFiles\nFileName: %s\n", FileName);
  WCHAR filePath[MAX_PATH];
  WIN32_FIND_DATAW findData;
  PWCHAR yenStar = const_cast<PWCHAR>(L"\\*");
  int count = 0;
  GetFilePath(filePath, FileName);
  std::string relPathStr(WstrToStr(FileName));
  wcscat(filePath, yenStar);
  std::map<std::string, maidsafe::ItemType> children;
  maidsafe::ClientController::getInstance()->readdir(relPathStr, children);
  while (!children.empty()) {
    std::string s = children.begin()->first;
    maidsafe::ItemType ityp = children.begin()->second;
    maidsafe::MetaDataMap mdm;
    std::string ser_mdm;
    fs::path path_(relPathStr);
    path_ /= s;
    if (maidsafe::ClientController::getInstance()->getattr(path_.string(),
                                                           ser_mdm)) {
      DbgPrint("In WinFindFiles, getattr failed\n");
      return -1;
    }
    mdm.ParseFromString(ser_mdm);
    const char *charpath(s.c_str());
      memset(&findData, 0, sizeof(WIN32_FIND_DATAW));
    if (ityp == maidsafe::DIRECTORY || ityp == maidsafe::EMPTY_DIRECTORY) {
      findData.dwFileAttributes = FILE_ATTRIBUTE_DIRECTORY;
      findData.ftCreationTime = GetFileTime(mdm.creation_time());
      findData.ftLastAccessTime = GetFileTime(mdm.last_access());
      findData.ftLastWriteTime = GetFileTime(mdm.last_modified());
      findData.nFileSizeHigh = mdm.file_size_high();
      findData.nFileSizeLow = mdm.file_size_low();
      // findData.cFileName[ MAX_PATH ];
      MultiByteToWideChar(CP_ACP,
                          0,
                          charpath,
                          strlen(charpath) + 1,
                          findData.cFileName,
                          MAX_PATH);

      DbgPrint(L"\tchild: %s\ttype: %i\n", findData.cFileName, ityp);
      findData.cAlternateFileName[ 14 ] = NULL;
      // create children directories if they don't exist
      std::string root_dir(WstrToStr(RootDirectory));
      fs::path sub_dir(root_dir);
      sub_dir /= path_;
      if (!fs::exists(sub_dir)) {
        try {
          fs::create_directories(sub_dir);
        }
        catch(const std::exception &e) {
          DbgPrint("In WinFindFiles, %s\n", e.what());
          DWORD error = GetLastError();
          DbgPrint(L"In WinFindFiles, error = %lu\n\n", error);
          return error * -1;
        }
      }
    } else {
      findData.dwFileAttributes = FILE_ATTRIBUTE_NORMAL;
      findData.ftCreationTime = GetFileTime(mdm.creation_time());
      findData.ftLastAccessTime = GetFileTime(mdm.last_access());
      findData.ftLastWriteTime = GetFileTime(mdm.last_modified());
      findData.nFileSizeHigh = mdm.file_size_high();
      findData.nFileSizeLow = mdm.file_size_low();
      // findData.cFileName[MAX_PATH];
      MultiByteToWideChar(CP_ACP,
                          0,
                          charpath,
                          strlen(charpath) + 1,
                          findData.cFileName,
                          MAX_PATH);

      DbgPrint(L"\tchild: %s\ttype: %i\n", findData.cFileName, ityp);
      findData.cAlternateFileName[ 14 ] = NULL;
    }
    children.erase(children.begin());
    FillFindData(&findData, DokanFileInfo);
    count++;
  }
  return 0;
}

static int __stdcall WinDeleteFile(const WCHAR *FileName, PDOKAN_FILE_INFO) {
  DbgPrint(L"WinDeleteFile\nFileName: %s\n", FileName);
  WCHAR filePath[MAX_PATH];
  // HANDLE handle = (HANDLE)DokanFileInfo->Context;
  GetFilePath(filePath, FileName);
  std::string relPathStr(WstrToStr(FileName));
  if (to_delete_.size()) {
    for (std::list<std::string>::iterator dit = to_delete_.begin();
         dit != to_delete_.end();
         ++dit) {
      if (*dit == relPathStr) {
        to_delete_.erase(dit);
        break;
      }
    }
  }
  DbgPrint("In WinDeleteFile, after erasing %s from to_delete_ list.\n",
         relPathStr.c_str());
  bool gui_private_share_(false);
  if (maidsafe::ClientController::getInstance()->ReadOnly(relPathStr,
      gui_private_share_))
    return -5;

  if (maidsafe::ClientController::getInstance()->unlink(relPathStr) != 0) {
    DbgPrint("In WinDeleteFile, unlink failed\n");
    // return -errno;
  }
  return 0;
}

static int __stdcall WinDeleteDirectory(const WCHAR *FileName,
                                        PDOKAN_FILE_INFO) {
  DbgPrint(L"WinDeleteDirectory\nFileName: %s\n", FileName);
  WCHAR filePath[MAX_PATH];
  HANDLE hFind;
  WIN32_FIND_DATAW findData;
  ULONG fileLen;
  ZeroMemory(filePath, sizeof(filePath));
  GetFilePath(filePath, FileName);
  std::string relPathStr(WstrToStr(FileName));
  fileLen = wcslen(filePath);
  if (filePath[fileLen-1] != L'\\') {
    filePath[fileLen++] = L'\\';
  }
  filePath[fileLen] = L'*';
  hFind = FindFirstFile(filePath, &findData);
  while (hFind != INVALID_HANDLE_VALUE) {
    if (wcscmp(findData.cFileName, L"..") != 0 &&
        wcscmp(findData.cFileName, L".") != 0) {
      FindClose(hFind);
      DbgPrint(L"In WinDeleteDirectory, Directory is not empty: %s\n",
               findData.cFileName);
      return -static_cast<int>(ERROR_DIR_NOT_EMPTY);
    }
    if (!FindNextFile(hFind, &findData)) {
      break;
    }
  }
  FindClose(hFind);
  if (GetLastError() == ERROR_NO_MORE_FILES) {
    if (maidsafe::ClientController::getInstance()->rmdir(relPathStr) != 0) {
      DbgPrint("In WinDeleteDirectory, rmdir failed\n");
      return -145;
    } else {
      return 0;
    }
  } else {
    return -1;
  }
//    std::map<std::string, maidsafe::ItemType> children;
//    if (maidsafe::ClientController::getInstance()->readdir(relPathStr,
//                                                           children))
//      return -errno;
//    DbgPrint("In WinDeleteDirectory, Directory %s has %i children.\n\n\n",
//           relPathStr.c_str(),
//           children.size());
//    if (children.size()) {
//      DbgPrint("In WinDeleteDirectory, children.size() != 0\n");
//      DbgPrint(L"In WinDeleteDirectory, error = 145\n");
//      return -145;
//    }
//
//    bool gui_private_share_(false);
//    if (maidsafe::ClientController::getInstance()->ReadOnly(relPathStr,
//        gui_private_share_))
//      return -5;
//
//    if (!RemoveDirectory(filePath)) {
//      DbgPrint("In WinDeleteDirectory, RemoveDirectory failed\n");
//      DWORD error = GetLastError();
//      DbgPrint(L"In WinDeleteDirectory, error = %lu\n\n", error);
//      return error * -1;
//    }
//    if (maidsafe::ClientController::getInstance()->rmdir(relPathStr) != 0) {
//      DbgPrint("In WinDeleteDirectory, rmdir failed\n");
//      return -errno;
//    }
//    return 0;
}

static int __stdcall WinMoveFile(const WCHAR *FileName,
                                 const WCHAR *NewFileName,
                                 BOOL ReplaceIfExisting,
                                 PDOKAN_FILE_INFO DokanFileInfo) {
  DbgPrint(L"WinMovefile\nFileName: %s\n", FileName);
  WCHAR filePath[MAX_PATH];
  WCHAR newFilePath[MAX_PATH];
  BOOL status;
  GetFilePath(filePath, FileName);
  GetFilePath(newFilePath, NewFileName);
  std::string o_path(WstrToStr(FileName));
  std::string n_path(WstrToStr(NewFileName));
  if (DokanFileInfo->Context) {
    //  should close? or rename at closing?
    CloseHandle((HANDLE)DokanFileInfo->Context);
    DokanFileInfo->Context = 0;
  }

  bool gui_private_share(false);
  if (maidsafe::ClientController::getInstance()->ReadOnly(n_path,
      gui_private_share))
    return -5;

  if (maidsafe::ClientController::getInstance()->rename(o_path, n_path) != 0)
    return -errno;
  if (ReplaceIfExisting) {
    status = MoveFileEx(filePath, newFilePath, MOVEFILE_REPLACE_EXISTING);
  } else {
    status = MoveFile(filePath, newFilePath);
  }
  if (status == FALSE) {
    DWORD error = GetLastError();
    DbgPrint(L"In WinMoveFile, MoveFile failed status = %d, code = %lu\n",
             status, error);
    return -static_cast<int>(error);
  }
  //  Need to move file in list of files needing deleted after cleanup.
  DbgPrint("In WinMoveFile, files for deletion: ");
  if (!to_delete_.size())
    return status == TRUE ? 0 : -1;
  for (std::list<std::string>::iterator dit = to_delete_.begin();
       dit != to_delete_.end();
       ++dit) {
    if (*dit == o_path) {
      to_delete_.erase(dit);
      to_delete_.insert(dit, n_path);
      break;
    }
  }
  return status ? 0 : -1;
}

static int __stdcall WinLockFile(const WCHAR *FileName,
                                 LONGLONG ByteOffset,
                                 LONGLONG Length,
                                 PDOKAN_FILE_INFO DokanFileInfo) {
  DbgPrint(L"WinLockFile\nFileName: %s\n", FileName);
  WCHAR filePath[MAX_PATH];
  HANDLE handle;
  LARGE_INTEGER offset;
  LARGE_INTEGER length;
  GetFilePath(filePath, FileName);
  handle = (HANDLE)DokanFileInfo->Context;
  if (!handle || handle == INVALID_HANDLE_VALUE) {
    DbgPrint("In WinLockFile, handle == INVALID_HANDLE_VALUE\n");
    return -1;
  }
  length.QuadPart = Length;
  offset.QuadPart = ByteOffset;
  if (LockFile(handle,
               offset.HighPart,
               offset.LowPart,
               length.HighPart,
               length.LowPart)) {
    return 0;
  } else {
    DbgPrint("In WinLockFile, LockFile failed\n");
    return -1;
  }
  return 0;
}

static int __stdcall WinSetEndOfFile(const WCHAR *FileName,
                                     LONGLONG ByteOffset,
                                     PDOKAN_FILE_INFO DokanFileInfo) {
  DbgPrint(L"WinSetEndofFile\nFileName: %s\n", FileName);
  WCHAR filePath[MAX_PATH];
  HANDLE handle;
  LARGE_INTEGER offset;
  GetFilePath(filePath, FileName);
  handle = (HANDLE)DokanFileInfo->Context;
  if (!handle || handle == INVALID_HANDLE_VALUE) {
    DbgPrint("In WinSetEndOfFile, handle == INVALID_HANDLE_VALUE\n");
    return -1;
  }
  offset.QuadPart = ByteOffset;
  if (!SetFilePointerEx(handle, offset, NULL, FILE_BEGIN)) {
    DbgPrint("In WinSetEndOfFile, SetFilePointerEx failed\n");
    DWORD error = GetLastError();
    DbgPrint(L"In WinSetEndOfFile, error = %lu\n\n", error);
    return error * -1;
  }
  if (!SetEndOfFile(handle)) {
    DbgPrint("In WinSetEndOfFile, SetEndOfFile failed\n");
    DWORD error = GetLastError();
    DbgPrint(L"In WinSetEndOfFile, error = %lu\n\n", error);
    return error * -1;
  }
  return 0;
}

static int __stdcall WinSetAllocationSize(const WCHAR *FileName,
                                          LONGLONG AllocSize,
                                          PDOKAN_FILE_INFO DokanFileInfo) {
  DbgPrint(L"WinSetAllocationSize\nFileName: %s\n", FileName);
  WCHAR filePath[MAX_PATH];
  HANDLE handle;
  LARGE_INTEGER fileSize;
  GetFilePath(filePath, FileName);
  handle = (HANDLE)DokanFileInfo->Context;
  if (!handle || handle == INVALID_HANDLE_VALUE) {
    DbgPrint("In WinSetAllocationSize, handle == INVALID_HANDLE_VALUE\n");
    return -1;
  }
  if (GetFileSizeEx(handle, &fileSize)) {
    if (AllocSize < fileSize.QuadPart) {
      fileSize.QuadPart = AllocSize;
      if (!SetFilePointerEx(handle, fileSize, NULL, FILE_BEGIN)) {
        DbgPrint("In WinSetAllocationSize, SetFilePointer error: %ld",
                 GetLastError());
        DbgPrint(", offfset = %s\n\n",
                 boost::lexical_cast<std::string>(AllocSize).c_str());
        return GetLastError() * -1;
      }
      if (!SetEndOfFile(handle)) {
        DbgPrint("In WinSetAllocationSize, SetEndOfFile failed\n");
        DWORD error = GetLastError();
        DbgPrint(L"In WinSetAllocationSize, error = %lu\n\n", error);
        return error * -1;
      }
    }
  } else {
    DWORD error = GetLastError();
    DbgPrint(L"In WinSetAllocationSize, error = %lu\n\n", error);
    return error * -1;
  }
  return 0;
}

static int __stdcall WinSetFileAttributes(const WCHAR *FileName,
                                          DWORD FileAttributes,
                                          PDOKAN_FILE_INFO) {
  DbgPrint(L"WinSetFileAttributes\nFileName: %s\n", FileName);
  WCHAR filePath[MAX_PATH];
  GetFilePath(filePath, FileName);
  if (!SetFileAttributes(filePath, FileAttributes)) {
    DbgPrint("In WinSetFileAttributes, SetFileAttributes failed\n");
    DWORD error = GetLastError();
    DbgPrint(L"In WinSetFileAttributes, error = %lu\n\n", error);
    return error * -1;
  }
  return 0;
}

static int __stdcall WinSetFileTime(const WCHAR *FileName,
                                    CONST FILETIME *CreationTime,
                                    CONST FILETIME *LastAccessTime,
                                    CONST FILETIME *LastWriteTime,
                                    PDOKAN_FILE_INFO DokanFileInfo) {
  DbgPrint(L"WinSetFileTime\nFileName: %s\n", FileName);
  WCHAR   filePath[MAX_PATH];
  HANDLE   handle;
  GetFilePath(filePath, FileName);
  handle = (HANDLE)DokanFileInfo->Context;
  if (!handle || handle == INVALID_HANDLE_VALUE) {
    DbgPrint("In WinSetFileTime, handle == INVALID_HANDLE_VALUE\n");
    return -1;
  }
  if (!SetFileTime(handle, CreationTime, LastAccessTime, LastWriteTime)) {
    DbgPrint("In WinSetFileTime, SetFileAttributes failed\n");
    DWORD error = GetLastError();
    DbgPrint(L"In WinSetFileTime, error = %lu\n\n", error);
    return error * -1;
  }
  return 0;
}

static int __stdcall WinUnlockFile(const WCHAR *FileName,
                                   LONGLONG ByteOffset,
                                   LONGLONG Length,
                                   PDOKAN_FILE_INFO DokanFileInfo) {
  DbgPrint(L"WinUnLockFile\nFileName: %s\n", FileName);
  WCHAR filePath[MAX_PATH];
  HANDLE handle;
  LARGE_INTEGER length;
  LARGE_INTEGER offset;
  GetFilePath(filePath, FileName);
  handle = (HANDLE)DokanFileInfo->Context;
  if (!handle || handle == INVALID_HANDLE_VALUE) {
    DbgPrint("In WinUnLockFile, handle == INVALID_HANDLE_VALUE\n");
    return -1;
  }
  length.QuadPart = Length;
  offset.QuadPart = ByteOffset;
  if (UnlockFile(handle,
                 offset.HighPart,
                 offset.LowPart,
                 length.HighPart,
                 length.LowPart)) {
    return 0;
  } else {
    DbgPrint("In WinUnlockFile, UnlockFile failed\n");
    return -1;
  }
  return 0;
}

static int __stdcall WinGetFileSecurity(
    const WCHAR *FileName,
    PSECURITY_INFORMATION SecurityInformation,
    PSECURITY_DESCRIPTOR SecurityDescriptor,
    ULONG BufferLength,
    PULONG LengthNeeded,
    PDOKAN_FILE_INFO DokanFileInfo) {
  DbgPrint(L"GetFileSecurity %s\n", FileName);
  HANDLE handle;
  WCHAR filePath[MAX_PATH];
  GetFilePath(filePath, FileName);
  handle = (HANDLE)DokanFileInfo->Context;
  if (!handle || handle == INVALID_HANDLE_VALUE) {
    DbgPrint(L"\tinvalid handle\n\n");
    return -1;
  }
  if (!GetUserObjectSecurity(handle, SecurityInformation, SecurityDescriptor,
      BufferLength, LengthNeeded)) {
    int error = GetLastError();
    if (error == ERROR_INSUFFICIENT_BUFFER) {
      DbgPrint(L"  GetUserObjectSecurity failed: ERROR_INSUFFICIENT_BUFFER\n");
      return error * -1;
    } else {
      DbgPrint(L"  GetUserObjectSecurity failed: %d\n", error);
      return -1;
    }
  }
  return 0;
}

static int __stdcall WinSetFileSecurity(
    const WCHAR *FileName,
    PSECURITY_INFORMATION SecurityInformation,
    PSECURITY_DESCRIPTOR SecurityDescriptor,
    ULONG,
    PDOKAN_FILE_INFO DokanFileInfo) {
  DbgPrint(L"SetFileSecurity %s\n", FileName);
  HANDLE handle;
  WCHAR filePath[MAX_PATH];
  GetFilePath(filePath, FileName);
  handle = (HANDLE)DokanFileInfo->Context;
  if (!handle || handle == INVALID_HANDLE_VALUE) {
    DbgPrint(L"\tinvalid handle\n\n");
    return -1;
  }
  if (!SetUserObjectSecurity(handle, SecurityInformation, SecurityDescriptor)) {
    int error = GetLastError();
    DbgPrint(L"  SetUserObjectSecurity failed: %d\n", error);
    return -1;
  }
  return 0;
}

static int __stdcall WinGetVolumeInformation(LPWSTR VolumeNameBuffer,
                                             DWORD,
                                             LPDWORD VolumeSerialNumber,
                                             LPDWORD MaximumComponentLength,
                                             LPDWORD FileSystemFlags,
                                             LPWSTR FileSystemNameBuffer,
                                             DWORD,
                                             PDOKAN_FILE_INFO) {
  std::string public_username =
      maidsafe::SessionSingleton::getInstance()->PublicUsername();
  if (public_username.empty()) {
    wcscpy(VolumeNameBuffer, L"maidsafe");
  } else {
    std::string volume_name = public_username + "'s maidsafe";
    std::vector<WCHAR> s(MAX_PATH);
    MultiByteToWideChar(CP_ACP, 0, volume_name.c_str(), volume_name.length(),
        &s[0], MAX_PATH);
    std::wstring w_volume_name = &s[0];
    wcscpy(VolumeNameBuffer, w_volume_name.c_str());
  }
  *VolumeSerialNumber = 0x19831116;
  *MaximumComponentLength = 256;
  *FileSystemFlags = FILE_CASE_SENSITIVE_SEARCH |
                     FILE_CASE_PRESERVED_NAMES |
                     FILE_SUPPORTS_REMOTE_STORAGE |
                     FILE_UNICODE_ON_DISK |
                     FILE_PERSISTENT_ACLS;

  wcscpy(FileSystemNameBuffer, L"maidsafe drive");
  return 0;
}

static int __stdcall WinUnmount(PDOKAN_FILE_INFO) {
  DbgPrint(L"\tUnmount\n");
  return 0;
}

static void CallMount(char drive) {
  DbgPrint("In CallMount()\n");
  int status;
  PDOKAN_OPERATIONS Dokan_Operations =
      (PDOKAN_OPERATIONS)malloc(sizeof(DOKAN_OPERATIONS));
  PDOKAN_OPTIONS Dokan_Options =
      (PDOKAN_OPTIONS)malloc(sizeof(DOKAN_OPTIONS));

  ZeroMemory(Dokan_Options, sizeof(DOKAN_OPTIONS));

  maidsafe::SessionSingleton *ss = maidsafe::SessionSingleton::getInstance();
  std::string msHome(file_system::MaidsafeHomeDir(ss->SessionName()).string());
//   // repace '/' with '\\'
//   for (std::string::iterator it=msHome.begin(); it != msHome.end(); it++){
//     if ((*it) == '/')
//       msHome.replace(it, it+1, "\\");
//   }
  mbstowcs(RootDirectory, msHome.c_str(), msHome.size());
  DbgPrint("msHome= %s\n", msHome.c_str());
  DbgPrint(L"RootDirectory: %ls\n", RootDirectory);
#ifdef DEBUG
  printf("msHome= %s\n", msHome.c_str());
  wprintf(L"RootDirectory: %ls\n", RootDirectory);
#endif

  WCHAR mount_point[MAX_PATH];
  GetMountPoint(drive, mount_point);
  Dokan_Options->MountPoint = mount_point;
  Dokan_Options->ThreadCount = 3;
#ifdef DEBUG
  Dokan_Options->Options |= DOKAN_OPTION_DEBUG;
//  Dokan_Options->Options |= DOKAN_OPTION_STDERR;
#endif
//  Dokan_Options->Options |= DOKAN_OPTION_KEEP_ALIVE;
//  Dokan_Options->Options |= DOKAN_OPTION_NETWORK;
//  Dokan_Options->Options |= DOKAN_OPTION_REMOVABLE;

  ZeroMemory(Dokan_Operations, sizeof(DOKAN_OPERATIONS));
  Dokan_Operations->CreateFile = WinCreateFile;
  Dokan_Operations->OpenDirectory = WinOpenDirectory;
  Dokan_Operations->CreateDirectory = WinCreateDirectory;
  Dokan_Operations->Cleanup = WinCleanup;
  Dokan_Operations->CloseFile = WinCloseFile;
  Dokan_Operations->ReadFile = WinReadFile;
  Dokan_Operations->WriteFile = WinWriteFile;
  Dokan_Operations->FlushFileBuffers = WinFlushFileBuffers;
  Dokan_Operations->GetFileInformation = WinGetFileInformation;
  Dokan_Operations->FindFiles = WinFindFiles;
  Dokan_Operations->FindFilesWithPattern = NULL;
  Dokan_Operations->SetFileAttributes = WinSetFileAttributes;
  Dokan_Operations->SetFileTime = WinSetFileTime;
  Dokan_Operations->DeleteFile = WinDeleteFile;
  Dokan_Operations->DeleteDirectory = WinDeleteDirectory;
  Dokan_Operations->MoveFile = WinMoveFile;
  Dokan_Operations->SetEndOfFile = WinSetEndOfFile;
  Dokan_Operations->SetAllocationSize = WinSetAllocationSize;
  Dokan_Operations->LockFile = WinLockFile;
  Dokan_Operations->UnlockFile = WinUnlockFile;
  Dokan_Operations->GetFileSecurity = WinGetFileSecurity;
  Dokan_Operations->SetFileSecurity = WinSetFileSecurity;
  Dokan_Operations->GetDiskFreeSpace = NULL;
  Dokan_Operations->GetVolumeInformation = WinGetVolumeInformation;
  Dokan_Operations->Unmount = WinUnmount;

  status = DokanMain(Dokan_Options, Dokan_Operations);
  switch (status) {
    case DOKAN_SUCCESS:
      break;
    case DOKAN_ERROR:
#ifdef DEBUG
      printf("Dokan Error\n");
#endif
      break;
    case DOKAN_DRIVE_LETTER_ERROR:
#ifdef DEBUG
      printf("Dokan Bad Drive letter\n");
#endif
      break;
    case DOKAN_DRIVER_INSTALL_ERROR:
#ifdef DEBUG
      printf("Dokan Can't install driver\n");
#endif
      break;
    case DOKAN_START_ERROR:
#ifdef DEBUG
      printf("Dokan Driver has something wrong\n");
#endif
      break;
    case DOKAN_MOUNT_ERROR:
#ifdef DEBUG
      printf("Dokan Can't assign a drive letter\n");
#endif
      break;
    case DOKAN_MOUNT_POINT_ERROR:
#ifdef DEBUG
      printf("Dokan Mount point error\n");
#endif
      break;
    default:
#ifdef DEBUG
      printf("Dokan Unknown error: %d\n", status);
#endif
      break;
  }
  free(Dokan_Options);
  free(Dokan_Operations);
  maidsafe::SessionSingleton::getInstance()->SetMounted(1);
}

void Mount(char drive) {
  boost::thread thrd(CallMount, drive);
  std::string mounted_drive(1, drive);
  mounted_drive += ":";
  try {
    while (!fs::exists(mounted_drive)) {
      boost::this_thread::sleep(boost::posix_time::milliseconds(50));
    }
    maidsafe::SessionSingleton::getInstance()->SetMounted(0);
#ifdef DEBUG
    printf("Dokan mounted drive at %s\n", mounted_drive.c_str());
#endif
  }
  catch(const std::exception &e) {
#ifdef DEBUG
    printf("Dokan failed to mounted drive at %s\n%s\n",
           mounted_drive.c_str(), e.what());
#endif
  }
}

bool UnMount(char drive) {
  WCHAR mount_point[MAX_PATH];
  GetMountPoint(drive, mount_point);
  return DokanUnmount(mount_point);
}

}  // namespace fs_w_fuse
