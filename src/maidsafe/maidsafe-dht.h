/*Copyright (c) 2009 maidsafe.net limited
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
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
OF THE POSSIBILITY OF SUCH DAMAGE.
*/
#ifndef MAIDSAFE-DHT_H_INCLUDED
#define MAIDSAFE-DHT_H_INCLUDED
/*
* This is the API for maidsafe-dht and is the only program access
* for developers. The config.h file included is where configuration
* may be saved. You MUST link the maidsafe-dht library !
*/
#include "config.h"
// Forward declarations for library
int StartListening(port);
trans::localport()
//internal declerations
bool message_rec(std::string msg, int ip);


//actual API 
//Transport
int LocalPort() {return trans::localport(); } // XXXX is declared above
LocalIP()
  ExternalPort()
  External_IP()
//test


//RPC


//Kademlia


//callbacks section 
// link our callback funtions to lower level 
bool LostNet();
bool ChangedIP();




#endif // MAIDSAFE-DHT_H_INCLUDED
