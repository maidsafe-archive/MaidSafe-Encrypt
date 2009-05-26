/*
* ============================================================================
*
* Copyright 2009 maidsafe.net limited
*
* Description:  Windows service to run a vault

* Version:      1.0
* Created:      2009-04-12-03.38.39
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

#include <windows.h>
#include <stdio.h>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <string>
#include "maidsafe/vault/vaultdaemon.h"

#define LOGFILE "VaultService.txt"
const int kSleepTime = 10000;  // milliseconds

int WriteToLog(char* str) {
  FILE* log;
  log = fopen(LOGFILE, "a+");
  if (log == NULL)
    return -1;
  fprintf(log, "%s\n", str);
  fclose(log);
  return 0;
}

int WriteToLog(std::string str) {
  FILE* log;
  log = fopen(LOGFILE, "a+");
  if (log == NULL)
    return -1;
  fprintf(log, "%s\n", str.c_str());
  fclose(log);
  return 0;
}

SERVICE_STATUS ServiceStatus;
SERVICE_STATUS_HANDLE hStatus;

void ServiceMain();
void ControlHandler(DWORD request);
int InitService();

int main() {
  const size_t kMax(8);
  wchar_t service_name_[kMax];
  mbstowcs(service_name_, "PDVault", kMax);
  SERVICE_TABLE_ENTRY ServiceTable[2];
  ServiceTable[0].lpServiceName = service_name_;
  ServiceTable[0].lpServiceProc = (LPSERVICE_MAIN_FUNCTION)ServiceMain;
  ServiceTable[1].lpServiceName = NULL;
  ServiceTable[1].lpServiceProc = NULL;
  // Start the control dispatcher thread for our service
  StartServiceCtrlDispatcher(ServiceTable);
  return 0;
}


// Service initialization
int InitService() {
  std::string message = "PDVault service starting.";
  return(WriteToLog(message));
}


void ServiceMain() {
  int error;
  ServiceStatus.dwServiceType = SERVICE_WIN32;
  ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
  ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP |
                                     SERVICE_ACCEPT_SHUTDOWN;
  ServiceStatus.dwWin32ExitCode = 0;
  ServiceStatus.dwServiceSpecificExitCode = 0;
  ServiceStatus.dwCheckPoint = 0;
  ServiceStatus.dwWaitHint = 0;

  const size_t kMax = 8;
  wchar_t service_name_[kMax];
  mbstowcs(service_name_, "PDVault", kMax);
  hStatus = RegisterServiceCtrlHandler(service_name_,
                                       (LPHANDLER_FUNCTION)ControlHandler);
  if (hStatus == (SERVICE_STATUS_HANDLE)0)
    // Registering Control Handler failed
    return;

  // Initialize Service
  error = InitService();
  if (error) {
    // Initialization failed
    ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    ServiceStatus.dwWin32ExitCode = -1;
    SetServiceStatus(hStatus, &ServiceStatus);
    return;
  }
  // We report the running status to SCM.
  ServiceStatus.dwCurrentState = SERVICE_RUNNING;
  SetServiceStatus(hStatus, &ServiceStatus);

  // Start the vault by instantiating a VaultDaemon
  maidsafe_vault::VaultDaemon vault_daemon_(0);

  // The worker loop of a service
  while (ServiceStatus.dwCurrentState == SERVICE_RUNNING) {
//    // This checks that logfile is consistently writeable
//    char buffer[2];
//    snprintf(buffer, sizeof(buffer), ".");
//    int result = WriteToLog(buffer);
//    if (result) {
//      ServiceStatus.dwCurrentState = SERVICE_STOPPED;
//      ServiceStatus.dwWin32ExitCode = -1;
//      SetServiceStatus(hStatus, &ServiceStatus);
//      return;
//    }
    vault_daemon_.Status();
    Sleep(kSleepTime);
  }
  return;
}

void ControlHandler(DWORD request) {
  std::string message = "PDVault service stopping.";
  switch (request) {
    case SERVICE_CONTROL_STOP:
      WriteToLog(message);
      ServiceStatus.dwWin32ExitCode = 0;
      ServiceStatus.dwCurrentState = SERVICE_STOPPED;
      SetServiceStatus(hStatus, &ServiceStatus);
      return;
    case SERVICE_CONTROL_SHUTDOWN:
      WriteToLog(message);
      ServiceStatus.dwWin32ExitCode = 0;
      ServiceStatus.dwCurrentState = SERVICE_STOPPED;
      SetServiceStatus(hStatus, &ServiceStatus);
      return;
    default:
      break;
  }
  // Report current status
  SetServiceStatus(hStatus, &ServiceStatus);
  return;
}


