/* Copyright (c) 2009 maidsafe.net limited
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.
    * Neither the name of the maidsafe.net limited nor the names of its
    contributors may be used to endorse or promote products derived from this
    software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef BASE_CONFIG_H_
#define BASE_CONFIG_H_


#if defined(linux) || defined(__linux) || defined(__linux__) || \
  defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) || \
  defined(__DragonFly__) || defined(sun) || defined(__sun) || \
  defined(__sgi) || defined(__hpux) || defined(__BEOS__) || \
  defined(__IBMCPP__) || defined(_AIX) || defined(__QNXNTO__) || \
  defined(unix) || defined(_XOPEN_SOURCE) || defined(_POSIX_SOURCE)

#define MAIDSAFE_POSIX

// will we support this?  thoughts?
#elif defined(__CYGWIN__)
//  cygwin is not win32:
#define MAIDSAFE_POSIX

#elif defined(_WIN32) || defined(__WIN32__) || defined(WIN32) || \
  defined(_WIN32_WINNT) || defined(NTDDI_VERSION) || defined(_WIN32_WINDOWS)
//  Microsoft Windows:
#define MAIDSAFE_WIN32


#elif defined(macintosh) || defined(__APPLE__) || defined(__APPLE_CC__)
//  MacOS
#define MAIDSAFE_APPLE
#endif  // platform detect

#endif  // BASE_CONFIG_H_
