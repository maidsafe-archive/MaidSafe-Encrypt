/*
 * copyright 2008 maidsafe.net limited
 * The following source code is property of maidsafe.net limited and
 * is not meant for external use. The use of this code is governed
 * by the license file LICENSE.TXT found in the root of this directory and also
 * on www.maidsafe.net.
 *
 * You are not free to copy, amend or otherwise use this source code without
 * explicit written permission of the board of directors of maidsafe.net
 */
#include <gtest/gtest.h>
#include <string>
#include <iostream>
#include <sstream>
#include <list>
#include "network/communication.h"
#include "base/config.h"
#include "base/utils.h"
#include "protobuf/callback_messages.pb.h"

using boost::asio::ip::udp;

class FakeCallback {
  public:
  FakeCallback() : result() {}
  void CallbackFunc(const std::string& res) {
    result.ParseFromString(res);
  }
  void Reset() {
    result.Clear();
  }
  net::NetStartResult result;
};

class FakeTransport {
    public:
  FakeTransport() : received_messages(), remote_addresses() {}
  void DatagramReceived(unsigned char* datagram, int len, \
    udp::endpoint *remote_addr) {
    std::string msg(reinterpret_cast<char*>(datagram), len);
    received_messages.push_back(msg);
    remote_addresses.push_back(*remote_addr);
  }
  std::list<std::string> received_messages;
  std::list<udp::endpoint> remote_addresses;
  FakeTransport(const FakeTransport &) : received_messages(), remote_addresses()
   {}
  FakeTransport &operator=(const FakeTransport &) { return *this; }
};

inline void wait_result(FakeCallback *cb, boost::recursive_mutex* mutex) {
  while (1) {
    {
      base::pd_scoped_lock guard(*mutex);
      if (cb->result.has_result())
        return;
    }
    base::sleep(0.005);
  }
}

class NetTest : public testing::Test {};


TEST_F(NetTest, BEH_NET_GetExternalIPAddress) {
  boost::asio::io_service io_service;
  boost::recursive_mutex mutex;
  base::CallLaterTimer timer(&mutex);
  FakeTransport transport;
  net::Communication node(boost::bind(&FakeTransport::DatagramReceived,
    &transport, _1, _2, _3), &io_service, &timer, &mutex);
  FakeCallback cb;
  node.NetStart(63001, boost::bind(&FakeCallback::CallbackFunc, &cb, _1));
  wait_result(&cb, &mutex);
  ASSERT_EQ(net::kNetResultSuccess, cb.result.result()) <<
    "Failed to start the node";
  udp::endpoint *external_addr = node.external_addr();
  ASSERT_FALSE(external_addr == NULL);
  std::cout << "Got external IP address: " << *external_addr << std::endl;
  // make sure it is not a bogus address
  ASSERT_NE("0.", external_addr->address().to_string().substr(0, 2));
  ASSERT_NE("127.", external_addr->address().to_string().substr(0, 4));
  ASSERT_TRUE(node.NetStop()) <<"Failed to stop the node";
}

TEST_F(NetTest, FUNC_NET_CommunicatingByUsingExternalIPAddress) {
  // start two nodes
  boost::asio::io_service io_service1;
  boost::recursive_mutex mutex1;
  base::CallLaterTimer timer1(&mutex1);
  FakeTransport transport1;
  net::Communication node1(boost::bind(&FakeTransport::DatagramReceived,
    &transport1, _1, _2, _3), &io_service1, &timer1, &mutex1);
  FakeCallback cb1;
  node1.NetStart(63001, boost::bind(&FakeCallback::CallbackFunc, &cb1, _1));
  wait_result(&cb1, &mutex1);
  ASSERT_EQ(net::kNetResultSuccess, cb1.result.result()) <<
    "Failed to start the node";
  udp::endpoint *external_addr1 = node1.external_addr();
  ASSERT_FALSE(external_addr1 == NULL);
  std::cout << "Got external IP address for node1: " << *external_addr1 \
    << std::endl;
  boost::asio::io_service io_service2;
  boost::recursive_mutex mutex2;
  base::CallLaterTimer timer2(&mutex2);
  FakeTransport transport2;
  net::Communication node2(boost::bind(&FakeTransport::DatagramReceived,
    &transport2, _1, _2, _3), &io_service2, &timer2, &mutex2);
  FakeCallback cb2;
  node2.NetStart(63002, boost::bind(&FakeCallback::CallbackFunc, &cb2, _1));
  wait_result(&cb2, &mutex2);
  ASSERT_EQ(net::kNetResultSuccess, cb2.result.result()) <<
    "Failed to start the node";
  udp::endpoint *external_addr2 = node2.external_addr();
  ASSERT_FALSE(external_addr2 == NULL);
  std::cout << "Got external IP address for node2: " <<
    *external_addr2 << std::endl;
  // send a packet from node1 to node2
  unsigned char test_packet[47] = \
    "thequickbrownfoxjumpedoverthelazydog0123456789";
  std::size_t payload_length = 46;
  node1.SendPacket(external_addr2, test_packet, payload_length);
  base::sleep(1);
  // check whether node2 has received the packet or not
  ASSERT_TRUE(transport2.received_messages.size() == 1);
  ASSERT_EQ(std::string(reinterpret_cast<char*>(test_packet), payload_length)\
    , transport2.received_messages.front());
  ASSERT_TRUE(transport2.remote_addresses.size() == 1);
  ASSERT_TRUE((*external_addr1) == transport2.remote_addresses.front());
  ASSERT_TRUE(node1.NetStop()) <<"Failed to stop the node1";
  ASSERT_TRUE(node2.NetStop()) <<"Failed to stop the node2";
}
/*
TEST_F(NetTest, FUNC_NET_STUNMappingKeepAlive){
  boost::asio::io_service io_service1;
  boost::recursive_mutex mutex1;
  base::CallLaterTimer timer1(&mutex1);
  FakeTransport transport1;
  net::Communication node1(boost::bind(&FakeTransport::DatagramReceived, &transport1, _1, _2, _3), \
      &io_service1, &timer1, &mutex1);
  FakeCallback cb1;
  // start node 1
  node1.NetStart(63001, boost::bind(&FakeCallback::CallbackFunc, &cb1, _1));
  wait_result(cb1, &mutex1);
  ASSERT_EQ(net::kNetResultSuccess, cb1.result["result"].string()) << "Failed to start the node";
  udp::endpoint *external_addr1 = node1.external_addr();
  ASSERT_FALSE(external_addr1==NULL);
  std::cout << "Node 1 IP address: " << *external_addr1 << std::endl;
  boost::asio::io_service io_service2;
  boost::recursive_mutex mutex2;
  base::CallLaterTimer timer2(&mutex2);
  FakeTransport transport2;
  net::Communication node2(boost::bind(&FakeTransport::DatagramReceived, &transport2, _1, _2, _3), \
      &io_service2, &timer2, &mutex2);
  FakeCallback cb2;
  // start node 2
  node2.NetStart(63002, boost::bind(&FakeCallback::CallbackFunc, &cb2, _1));
  wait_result(cb2, &mutex2);
  ASSERT_EQ(net::kNetResultSuccess, cb2.result["result"].string()) << "Failed to start the node";
  udp::endpoint *external_addr2 = node2.external_addr();
  ASSERT_FALSE(external_addr2==NULL);
  std::cout << "Node 2 IP address: " << *external_addr2 << std::endl;
  // send a packet from node1 to node2
  unsigned char test_packet[47] = "thequickbrownfoxjumpedoverthelazydog0123456789";
  std::size_t payload_length = 46;
  std::cout << "Sleep 10 minutes, wait..." << std::endl;
  // sleep for 10 mins (checks that keepalive keeps NAT mapping active
  base::sleep(10*60);
  // send packet from node 1 to node 2
  node1.SendPacket(external_addr2, test_packet, payload_length);
  base::sleep(1);
  // check whether node2 has received the packet or not
  ASSERT_TRUE(transport2.received_messages.size()==1);
  ASSERT_EQ(std::string((char*)test_packet, payload_length), transport2.received_messages.front());
  ASSERT_TRUE(transport2.remote_addresses.size()==1);
  ASSERT_TRUE((*external_addr1) == transport2.remote_addresses.front());
  ASSERT_TRUE(node1.NetStop()) <<"Failed to stop the node1";
  ASSERT_TRUE(node2.NetStop()) <<"Failed to stop the node2";
}

TEST_F(NetTest, FUNC_NET_STUNNoTimeout){
// sends data at a shorter interval than the keep-alive timer countdown
// so no STUN server pings will occur because the connection is active (doesn't time out)

// start two nodes
  boost::asio::io_service io_service1;
  boost::recursive_mutex mutex1;
  base::CallLaterTimer timer1(&mutex1);
  FakeTransport transport1;
  net::Communication node1(boost::bind(&FakeTransport::DatagramReceived, &transport1, _1, _2, _3), \
      &io_service1, &timer1, &mutex1);
  FakeCallback cb1;
  node1.NetStart(63001, boost::bind(&FakeCallback::CallbackFunc, &cb1, _1));
  wait_result(cb1, &mutex1);
  ASSERT_EQ(net::kNetResultSuccess, cb1.result["result"].string()) << "Failed to start the node";
  udp::endpoint *external_addr1 = node1.external_addr();
  ASSERT_FALSE(external_addr1==NULL);

  boost::asio::io_service io_service2;
  boost::recursive_mutex mutex2;
  base::CallLaterTimer timer2(&mutex2);
  FakeTransport transport2;
  net::Communication node2(boost::bind(&FakeTransport::DatagramReceived, &transport2, _1, _2, _3), \
      &io_service2, &timer2, &mutex2);
  FakeCallback cb2;
  node2.NetStart(63002, boost::bind(&FakeCallback::CallbackFunc, &cb2, _1));
  wait_result(cb2, &mutex2);
  ASSERT_EQ(net::kNetResultSuccess, cb2.result["result"].string()) << "Failed to start the node";
  udp::endpoint *external_addr2 = node2.external_addr();
  ASSERT_FALSE(external_addr2==NULL);

  // send a packet from node1 to node2
  std::string test_packet_str = base::RandomString(500);
  unsigned char *test_packet = (unsigned char*)(test_packet_str.c_str());
  std::size_t payload_length = 500;
  // unsigned char test_packet[21] = "STARTPACKET123456789";
  // std::size_t payload_length = 20;
  // send data from node1 to node 2 and vice versa every 5 seconds
  for ( int i=0; i<100; i++ ){
    ASSERT_TRUE(node2.SendPacket(external_addr1, test_packet, payload_length)) << "send packet failed";

    ASSERT_TRUE(node1.SendPacket(external_addr2, test_packet, payload_length)) << "send packet failed";
    base::sleep(5);
  }
  // check that node2 has received at least 90% of the packets
  ASSERT_TRUE(transport2.received_messages.size()>90) << \
  "less than 90% of messages received";
  std::cout << "number of messages received: " << transport2.received_messages.size() << std::endl;
  ASSERT_TRUE(transport2.remote_addresses.size()>90) << \
  "less than 90% of remote addresses not correctly parsed from incomming packets";
  std::cout << "number of addresses logged: " << transport2.remote_addresses.size() << std::endl;
  ASSERT_EQ(transport2.received_messages.size(), transport2.remote_addresses.size());
  std::list<udp::endpoint>::iterator addr_it;
  std::list<std::string>::iterator packet_it;


  for ( packet_it=transport2.received_messages.begin(); packet_it!=transport2.received_messages.end(); packet_it++ ){
    ASSERT_EQ(std::string((char*)test_packet, payload_length), *packet_it) << \
    "sent payload doesn't match received payload";
  }

  for ( addr_it=transport2.remote_addresses.begin(); addr_it!=transport2.remote_addresses.end(); addr_it++ ){
    ASSERT_TRUE((*external_addr1) == *addr_it) << \
    "reported senders address(embedded in packet) doesn't match actual senders address";
  }

  ASSERT_TRUE(node1.NetStop()) <<"Failed to stop the node1";
  ASSERT_TRUE(node2.NetStop()) <<"Failed to stop the node2";
}
*/
TEST_F(NetTest, FUNC_NET_SendInvalidMessage) {
  // try to send 3 invalid messages of length 1700, 1500 and 1487
  // Max payload length is 1486
  boost::asio::io_service io_service1;
  boost::recursive_mutex mutex1;
  base::CallLaterTimer timer1(&mutex1);
  FakeTransport transport1;
  net::Communication node1(boost::bind(&FakeTransport::DatagramReceived,
    &transport1, _1, _2, _3), &io_service1, &timer1, &mutex1);
  FakeCallback cb1;
  // start node 1
  node1.NetStart(63001, boost::bind(&FakeCallback::CallbackFunc, &cb1, _1));
  wait_result(&cb1, &mutex1);
  ASSERT_EQ(net::kNetResultSuccess, cb1.result.result()) << \
    "Failed to start the node";
  udp::endpoint *external_addr1 = node1.external_addr();
  ASSERT_FALSE(external_addr1 == NULL);
  std::cout << "Got external IP address for node1: " << \
    *external_addr1 << std::endl;
  boost::asio::io_service io_service2;
  boost::recursive_mutex mutex2;
  base::CallLaterTimer timer2(&mutex2);
  FakeTransport transport2;
  net::Communication node2(boost::bind(&FakeTransport::DatagramReceived, \
    &transport2, _1, _2, _3), &io_service2, &timer2, &mutex2);
  FakeCallback cb2;
  // start node 2
  node2.NetStart(63002, boost::bind(&FakeCallback::CallbackFunc, &cb2, _1));
  wait_result(&cb2, &mutex2);
  ASSERT_EQ(net::kNetResultSuccess, cb2.result.result()) << \
    "Failed to start the node";
  udp::endpoint *external_addr2 = node2.external_addr();
  ASSERT_FALSE(external_addr2 == NULL);
  std::cout << "Got external IP address for node2: " << \
    *external_addr2 << std::endl;
  // try to send an invalid packet of size 1700 from node1 to node2
  unsigned char *test_packet = reinterpret_cast<unsigned char*>(\
    const_cast<char*>(base::RandomString(1700).c_str()));
  std::size_t payload_length = 1700;
  ASSERT_FALSE(node1.SendPacket(external_addr2, test_packet, payload_length)) \
    << "invalid packet send returned successfully";
  base::sleep(1);
  // check that node2 has not received the packet
  ASSERT_TRUE(transport2.received_messages.size() == 0);
  ASSERT_TRUE(transport2.remote_addresses.size() == 0);
  // try to send an invalid packet of size 1500 from node1 to node2
  unsigned char *test_packet2 = reinterpret_cast<unsigned char*> \
    (const_cast<char *>(base::RandomString(1500).c_str()));
  std::size_t payload_length2 = 1500;
  ASSERT_FALSE(node1.SendPacket(external_addr2, test_packet2, \
    payload_length2)) << "invalid packet send returned successfully";
  base::sleep(1);
  // check that node2 has not received the packet
  ASSERT_TRUE(transport2.received_messages.size() == 0);
  ASSERT_TRUE(transport2.remote_addresses.size() == 0);
  // try to send an invalid packet of size 1487 from node1 to node2
  unsigned char *test_packet3 = reinterpret_cast<unsigned char*> \
    (const_cast<char*>(base::RandomString(1487).c_str()));
  std::size_t payload_length3 = 1487;
  ASSERT_FALSE(node1.SendPacket(external_addr2, test_packet3, \
    payload_length3)) << "invalid packet send returned successfully";
  base::sleep(1);
  // check that node2 has not received the packet
  ASSERT_TRUE(transport2.received_messages.size() == 0);
  ASSERT_TRUE(transport2.remote_addresses.size() == 0);

  ASSERT_TRUE(node1.NetStop()) <<"Failed to stop the node1";
  ASSERT_TRUE(node2.NetStop()) <<"Failed to stop the node2";
}

TEST_F(NetTest, BEH_NET_NetStopTwice) {
  boost::asio::io_service io_service1;
  boost::recursive_mutex mutex1;
  base::CallLaterTimer timer1(&mutex1);
  FakeTransport transport1;
  net::Communication node1(boost::bind(&FakeTransport::DatagramReceived,
    &transport1, _1, _2, _3), &io_service1, &timer1, &mutex1);
  FakeCallback cb1;
  // start node 1
  node1.NetStart(63001, boost::bind(&FakeCallback::CallbackFunc, &cb1, _1));
  wait_result(&cb1, &mutex1);
  ASSERT_EQ(net::kNetResultSuccess, cb1.result.result()) << \
    "Failed to start the node";
  ASSERT_TRUE(node1.NetStop()) <<"Failed to stop node1";
  ASSERT_FALSE(node1.NetStop()) <<\
    "netstop (second call) succeded when it should have failed";
}

TEST_F(NetTest, FUNC_NET_Send100Messages) {
  // start two nodes
  boost::asio::io_service io_service1;
  boost::recursive_mutex mutex1;
  base::CallLaterTimer timer1(&mutex1);
  FakeTransport transport1;
  net::Communication node1(boost::bind(&FakeTransport::DatagramReceived, \
    &transport1, _1, _2, _3), &io_service1, &timer1, &mutex1);
  FakeCallback cb1;
  node1.NetStart(63001, boost::bind(&FakeCallback::CallbackFunc, &cb1, _1));
  wait_result(&cb1, &mutex1);
  ASSERT_EQ(net::kNetResultSuccess, cb1.result.result()) << \
    "Failed to start the node";
  udp::endpoint *external_addr1 = node1.external_addr();
  ASSERT_FALSE(external_addr1 == NULL);
  boost::asio::io_service io_service2;
  boost::recursive_mutex mutex2;
  base::CallLaterTimer timer2(&mutex2);
  FakeTransport transport2;
  net::Communication node2(boost::bind(&FakeTransport::DatagramReceived, \
    &transport2, _1, _2, _3), &io_service2, &timer2, &mutex2);
  FakeCallback cb2;
  node2.NetStart(63002, boost::bind(&FakeCallback::CallbackFunc, &cb2, _1));
  wait_result(&cb2, &mutex2);
  ASSERT_EQ(net::kNetResultSuccess, cb2.result.result()) <<\
    "Failed to start the node";
  udp::endpoint *external_addr2 = node2.external_addr();
  ASSERT_FALSE(external_addr2 == NULL);
  // send a packet from node1 to node2
  std::string test_packet_str = base::RandomString(500);
  unsigned char *test_packet = reinterpret_cast<unsigned char*> \
    (const_cast<char*>(test_packet_str.c_str()));
  std::size_t payload_length = 500;
  // unsigned char test_packet[21] = "STARTPACKET123456789";
  // std::size_t payload_length = 20;
  for (int i = 0; i < 100; i++) {
    ASSERT_TRUE(node1.SendPacket(external_addr2, test_packet, \
      payload_length)) << "send packet failed";
    base::sleep(0.01);
  }
  // check that node2 has received at least 90% of the packets
  ASSERT_GT(transport2.received_messages.size(), 90) << \
  "less than 90% of messages received";
  std::cout << "number of messages received: " << \
    transport2.received_messages.size() << std::endl;
  ASSERT_GT(transport2.remote_addresses.size(), 90) << \
  "less than 90% of remote addresses not correctly parsed from inc. packets";
  std::cout << "number of addresses logged: " << \
    transport2.remote_addresses.size() << std::endl;
  ASSERT_EQ(transport2.received_messages.size(), \
    transport2.remote_addresses.size());
  std::list<udp::endpoint>::iterator addr_it;
  std::list<std::string>::iterator packet_it;
  for (packet_it = transport2.received_messages.begin(); \
    packet_it != transport2.received_messages.end(); packet_it++ ) {
    ASSERT_EQ(std::string(reinterpret_cast<char*>(test_packet), \
      payload_length), *packet_it) << \
      "sent payload doesn't match received payload";
  }
  for (addr_it = transport2.remote_addresses.begin(); \
    addr_it != transport2.remote_addresses.end(); addr_it++ ) {
    ASSERT_TRUE((*external_addr1) == *addr_it) << \
    "reported senders address(embedded in packet) doesn't match " << \
    "actual senders address";
  }
  ASSERT_TRUE(node1.NetStop()) <<"Failed to stop the node1";
  ASSERT_TRUE(node2.NetStop()) <<"Failed to stop the node2";
}
