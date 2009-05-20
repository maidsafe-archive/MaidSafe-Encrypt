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


/*******************************************************************************
 * This file defines all constants used by the maidsafe-dht library.  It also  *
 * contains forward declarations and enumerations required by the library.     *
 *                                                                             *
 * NOTE: These settings and functions WILL be amended or deleted in future     *
 * releases until this notice is removed.                                      *
 ******************************************************************************/

#ifndef MAIDSAFE_MAIDSAFE_DHT_CONFIG_H_
#define MAIDSAFE_MAIDSAFE_DHT_CONFIG_H_


#if defined (__WIN32__) || defined (__MINGW__)
#include <winsock2.h>
#include <iphlpapi.h>
#else  // apple and POSIX
#include <unistd.h>
#include <netdb.h>
#include <net/if.h>  // must be before ifaddrs.h
#include <sys/ioctl.h>
// # include <net/route.h>  // not using this for the moment
#include <sys/socket.h>  // included in apple's net/route.h
#include <sys/types.h>  // included in apple's net/route.h
#include <ifaddrs.h>  // used for old implementation of LocalIPPort() remove
                      // when new soln impmltd.
//  // do we need these?
//  #include <arpa/inet.h>
//  #include <netinet/in.h>
//  #include <errno.h>
#endif

#include <boost/asio.hpp>
#include <boost/cstdint.hpp>
#include <boost/function.hpp>
#include <boost/mp_math/mp_int.hpp>
#include <boost/thread/recursive_mutex.hpp>
#include <boost/thread/thread.hpp>
#include <boost/shared_ptr.hpp>
#include <cryptopp/hex.h>
#include <stdint.h>
#include <google/protobuf/service.h>
#include <google/protobuf/message.h>

#include <algorithm>
#include <string>
#include <vector>

/*******************************************************************************
 * KADEMLIA LAYER                                                              *
 ******************************************************************************/
namespace kad {

// KADEMLIA CONSTANTS

// The size of DHT keys and node IDs in bytes.
const int kKeySizeBytes = 64;

// Kademlia constant k which defines the size of each "k-bucket" and the number
// of nodes upon which a given <key,value> is stored.
const boost::uint16_t K = 16;

// The parallel level of search iterations.
const int kAlpha = 3;

// The number of replies required in a search iteration to allow the next
// iteration to begin.
const int kBeta = 1;

// The frequency (in seconds) of the refresh routine.
const int kRefreshTime = 3600;  // 1 hour

// The frequency (in seconds) of the <key,value> republish routine.
const int kRepublishTime = 43200;  // 12 hours

// The duration (in seconds) after which a given <key,value> is deleted locally.
const int kExpireTime = kRepublishTime+3600;

// Kademlia RPC timeout duration (in milliseconds).
const int kRpcTimeout = 7000;

// RPC result constants.
const std::string kRpcResultSuccess("T");
const std::string kRpcResultFailure("F");
// TODO(Fraser#5#): 2009-05-15 - Make these bools

// Defines whether or not an existing local <key,value> database should be
// reused (true) or overwritten (false) on initialisation of the datastore.
const bool kReuseDatabase = false;

// The ratio of k successful individual kad store RPCs to yield overall success.
const double kMinSuccessfulPecentageStore = 0.75;

// The number of failed RPCs tolerated before a contact is removed from the
// k-bucket.
const boost::uint16_t kFailedRpc = 0;

// The maximum number of bootstrap contacts allowed in the .kadconfig file.
const int kMaxBootstrapContacts = 10000;

// Signature used to sign anonymous RPC requests.
const std::string kAnonymousSignedRequest("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");  // NOLINT


// KADEMLIA ENUMERATIONS, DATA TYPE DEFINITIONS, AND FORWARD DECLARATIONS
enum KBucketExitCode { SUCCEED, FULL, FAIL };
enum node_type { CLIENT, VAULT };
enum connect_to_node { LOCAL, REMOTE, UNKNOWN };
enum remote_find_method { FIND_NODE, FIND_VALUE, BOOTSTRAP };
typedef boost::mp_math::mp_int<> BigInt;
class KNodeImpl;
class KadRpcs;

class Contact {
// This class contains information on a single remote contact
 public:
  Contact(const std::string &node_id,
          const std::string &host_ip,
          const boost::uint16_t &host_port,
          const std::string &local_ip,
          const boost::uint16_t &local_port,
          const std::string &rendezvous_ip,
          const boost::uint16_t &rendezvous_port);
  Contact(const std::string &node_id,
          const std::string &host_ip,
          const boost::uint16_t &host_port);
  Contact(const std::string &node_id,
          const std::string &host_ip,
          const boost::uint16_t &host_port,
          const std::string &local_ip,
          const boost::uint16_t &local_port);
  Contact();
  // copy ctor
  Contact(const Contact&rhs);
  // Test whether this contact is equal to another according node id or (ip,
  // port)
  bool operator == (const Contact &other);
  bool operator != (const Contact &other);
  Contact& operator=(const Contact &other) {  // clone the content from another
    this->node_id_ = other.node_id_;
    this->host_ip_ = other.host_ip_;
    this->host_port_ = other.host_port_;
    this->failed_rpc_ = other.failed_rpc_;
    this->rendezvous_ip_ = other.rendezvous_ip_;
    this->rendezvous_port_ = other.rendezvous_port_;
    this->last_seen_ = other.last_seen_;
    this->local_ip_ = other.local_ip_;
    this->local_port_ = other.local_port_;
    return *this;
  }
  bool SerialiseToString(std::string *ser_output);
  bool ParseFromString(const std::string &data);
  inline const std::string& node_id() const { return node_id_; }
  inline const std::string& host_ip() const { return host_ip_; }
  inline boost::uint16_t host_port() const { return host_port_; }
  inline boost::uint16_t failed_rpc() const { return failed_rpc_; }
  inline void IncreaseFailed_RPC() { ++failed_rpc_; }
  const std::string& rendezvous_ip() const { return rendezvous_ip_; }
  boost::uint16_t rendezvous_port() const { return rendezvous_port_; }
  std::string ToString();
  inline boost::uint64_t last_seen() const { return last_seen_; }
  inline void set_last_seen(boost::uint64_t last_seen) {
    last_seen_ = last_seen;
  }
  inline const std::string& local_ip() const { return local_ip_; }
  inline boost::uint16_t local_port() const { return local_port_; }
 private:
  std::string node_id_;
  std::string host_ip_;
  boost::uint16_t host_port_;
  boost::uint16_t failed_rpc_;
  std::string rendezvous_ip_;
  boost::uint16_t rendezvous_port_;
  boost::uint64_t last_seen_;
  std::string local_ip_;
  boost::uint16_t local_port_;
};

class ContactInfo;
}  // namespace kad



/*******************************************************************************
 * BASE LAYER - FREE FUNCTIONS FOR USE IN ALL LAYERS                           *
 ******************************************************************************/
namespace base {

// Data type definition for general callback functions.
typedef boost::function<void(const std::string&)> callback_func_type;

// Data type definition for RPC callback functions.
typedef boost::function<void(const std::string&, const std::string &)>
    rpc_callback_func;

typedef boost::recursive_mutex::scoped_lock pd_scoped_lock;
// TODO(Fraser#5#): 2009-05-16 - remove this typedef & associated .hpp #include

// Convert from int to string.
std::string itos(int value);

// Convert from string to int.
int stoi(std::string value);

// Encode a string to hex.
bool encode_to_hex(const std::string &value, std::string &result);
// TODO(Fraser#5#): 2009-05-16 - Amend &result to pass by pointer.

// Decode a string from hex.
bool decode_from_hex(const std::string &value, std::string &result);
// TODO(Fraser#5#): 2009-05-16 - Amend &result to pass by pointer.

// Return the number of seconds since 1st January 1970.
boost::uint32_t get_epoch_time();

// Return the number of milliseconds since 1st January 1970.
boost::uint64_t get_epoch_milliseconds();

// Return the number of nanoseconds since 1st January 1970.
boost::uint64_t get_epoch_nanoseconds();

// Convert an IP in decimal dotted format to IPv4
std::string inet_atob(const std::string &dec_ip);

// Convert an IPv4 to decimal dotted format
std::string inet_btoa(const std::string &ipv4);

// Generate a (transaction) id between 1 & 2147483646 inclusive.
boost::uint32_t generate_next_transaction_id(boost::uint32_t id);

// Convert an internet network address into dotted string format.
void inet_ntoa(boost::uint32_t addr, char *ipbuf);

// Convert a dotted string format internet address into Ipv4 format.
boost::uint32_t inet_aton(const char * buf);

// Return a list of network interfaces in the format of "address, adapter name".
void get_net_interfaces(std::vector<struct device_struct> *alldevices);

// Return the first local network interface found.
bool get_local_address(boost::asio::ip::address *local_address);

// Generate a 32bit signed integer
// Use this function if receiving it in a variable that is int or int32_t
// or if before assinging to a signed int variable you are doing a modulo op
int32_t random_32bit_integer();

// Generate a 32bit unsigned integer
// Use this one if receiving it in a variable that is unsigned int or uint32_t
uint32_t random_32bit_uinteger();

// Generate a random string.
std::string RandomString(int length);

struct device_struct {
  device_struct() : ip_address(), interface_("") {}
  boost::asio::ip::address ip_address;
  std::string interface_;
};

// Get a random sample of N elements of a container(vector, list, set)
// Usage:
// random_sample(container.begin(), container.end(), result.begin(), N)
template <class ForwardIterator, class OutputIterator>
    OutputIterator random_sample_n(ForwardIterator begin,
                                   ForwardIterator end,
                                   OutputIterator result,
                                   int N) {
  int remaining = std::distance(begin, end);

  // To avoid clashing of Visual Studio's min macro
  #ifdef __MSVC__
    int m = min(N, remaining);
  #else
    int m = std::min(N, remaining);
  #endif
  while (m > 0) {
    if (static_cast<int>((random_32bit_uinteger() % remaining)) < m) {
      *result = *begin;
      ++result;
      --m;
    }
    --remaining;
    ++begin;
  }
  return result;
}

class CallLaterTimer;
}  // namespace base



/*******************************************************************************
 * RPC INTERFACE                                                               *
 ******************************************************************************/
namespace rpcprotocol {

// RPC CONSTANTS

// Maximum port number.
const int kMaxPort = 65535;

// Minimum port number.
const int kMinPort = 5000;

// RPC timeout duration (in milliseconds).
const int kRpcTimeout = 7000;  // 7 seconds

// RPC result constants.
const std::string kStartTransportSuccess("T");
const std::string kStartTransportFailure("F");
// TODO(Fraser#5#): 2009-05-16 - Make these bools


// RPC ENUMERATIONS, DATA TYPE DEFINITIONS, AND FORWARD DECLARATIONS
struct RpcInfo;
struct PendingReq;
class RpcMessage;
class ChannelManagerImpl;
class ControllerImpl;
class ChannelImpl;
class ChannelManager;
class Controller;
class Channel;
}  // namespace rpcprotocol



namespace transport {
class Transport;
}  // namespace transport

#endif  // MAIDSAFE_MAIDSAFE_DHT_CONFIG_H_
