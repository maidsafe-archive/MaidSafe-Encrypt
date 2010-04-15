/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Description:  Functional test for Clientbufferpackethandler
* Version:      1.0
* Created:      2010-04-14-10.09.29
* Revision:     none
* Compiler:     gcc
* Author:       Team
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

#include <gtest/gtest.h>
#include <boost/bind.hpp>
#include <boost/shared_ptr.hpp>
#include <maidsafe/maidsafe-dht_config.h>
#include <maidsafe/transport-api.h>
#include <maidsafe/transportudt.h>
#include "maidsafe/client/imconnectionhandler.h"
#include "protobuf/packet.pb.h"

class TestIMHandler : public testing::Test {
 public:
   TestIMHandler() : trans(new transport::TransportUDT), trans_hndlr(),
                     im_hdlr(),trans_id(0), port(0), ip(), msgs_rec(),
                     msgs_sent(), new_conn_accepted(), ext_conn_id(),
                     new_conn_trans_id() {
     boost::asio::ip::address addr;
     base::get_local_address(&addr);
     ip = addr.to_string();
   }
   void SetUp() {
     trans_hndlr.Register(trans.get(), &trans_id);
     ASSERT_TRUE(trans_hndlr.RegisterOnSend(boost::bind(&TestIMHandler::SendNotifier,
        this, _1, _2)));
     ASSERT_TRUE(trans_hndlr.RegisterOnServerDown(boost::bind(
        &TestIMHandler::OnServerDown, this, _1, _2, _3)));
     ASSERT_TRUE(trans_hndlr.RegisterOnMessage(boost::bind(
        &maidsafe::IMConnectionHandler::OnMessageArrive, &im_hdlr, _1, _2, _3,
        _4)));
     ASSERT_EQ(0, trans_hndlr.Start(0, trans_id));
     port = trans_hndlr.listening_port(trans_id);
     ASSERT_FALSE(trans->is_stopped());
   }
   void TearDown() {
     im_hdlr.Stop();
     trans_hndlr.Stop(trans_id);
   }
 protected:
  boost::shared_ptr<transport::Transport> trans;
  transport::TransportHandler trans_hndlr;
  maidsafe::IMConnectionHandler im_hdlr;
  boost::int16_t trans_id, port;
  std::string ip;
  std::string msgs_rec, msgs_sent;
  boost::uint32_t new_conn_accepted, ext_conn_id;
  boost::int16_t new_conn_trans_id;
 public:
  void SendNotifier(const boost::uint32_t&, const bool&) {
  }
  void OnServerDown(const bool&, const std::string&, const boost::uint16_t&) {
  }
  void NewMsgNotifier(const std::string &msg) {
    msgs_rec = msg;
  }
  void NewConnMsg(const boost::int16_t &t_id, const boost::uint32_t &c_id,
      const std::string &msg) {
    new_conn_accepted = c_id;
    new_conn_trans_id = t_id;
    msgs_rec = msg;
  }
  void UDTTransMsgArrived(const std::string &msg, const boost::uint32_t &id,
      const boost::int16_t&, const float&) {
    msgs_sent = msg;
    ext_conn_id = id;
  }
};

TEST_F(TestIMHandler, BEH_MAID_IMHdlrNotStarted) {
  maidsafe::new_connection_notifier conn_not;
  maidsafe::new_message_notifier msg_not;
  ASSERT_EQ(maidsafe::kFailedToStartHandler, im_hdlr.Start(&trans_hndlr,
      msg_not, conn_not));
  ASSERT_EQ(maidsafe::kHandlerNotStarted, im_hdlr.AddConnection(1, 1));
  ASSERT_EQ(maidsafe::kHandlerNotStarted, im_hdlr.CloseConnection(1, 1));
  ASSERT_EQ(maidsafe::kHandlerNotStarted, im_hdlr.CloseConnections(1));
  ASSERT_EQ(maidsafe::kHandlerNotStarted, im_hdlr.SendMessage(1, 1, "hello"));
  maidsafe::EndPoint endpoint;
  endpoint.add_ip(ip);
  endpoint.add_ip(ip);
  endpoint.add_ip("");
  endpoint.add_port(8888);
  endpoint.add_port(8888);
  endpoint.add_port(0);
  boost::uint32_t new_conn;
  ASSERT_EQ(maidsafe::kHandlerNotStarted, im_hdlr.CreateConnection(trans_id,
      endpoint, &new_conn));
}

TEST_F(TestIMHandler, BEH_MAID_IMHdlrSendMessage) {
  ASSERT_EQ(maidsafe::kSuccess, im_hdlr.Start(&trans_hndlr,
      boost::bind(&TestIMHandler::NewMsgNotifier, this, _1),
      boost::bind(&TestIMHandler::NewConnMsg, this, _1, _2, _3)));
  ASSERT_EQ(maidsafe::kHandlerAlreadyStarted, im_hdlr.Start(&trans_hndlr,
      boost::bind(&TestIMHandler::NewMsgNotifier, this, _1),
      boost::bind(&TestIMHandler::NewConnMsg, this, _1, _2, _3)));
  transport::TransportUDT udt_trans;
  ASSERT_TRUE(udt_trans.RegisterOnSend(boost::bind(&TestIMHandler::SendNotifier,
        this, _1, _2)));
  ASSERT_TRUE(udt_trans.RegisterOnServerDown(boost::bind(
        &TestIMHandler::OnServerDown, this, _1, _2, _3)));
  ASSERT_TRUE(udt_trans.RegisterOnMessage(boost::bind(
        &TestIMHandler::UDTTransMsgArrived, this, _1, _2, _3,
        _4)));
  ASSERT_EQ(0, udt_trans.Start(0));
  boost::uint16_t udt_port(udt_trans.listening_port());
  maidsafe::EndPoint endpoint;
  endpoint.add_ip(ip);
  endpoint.add_ip(ip);
  endpoint.add_ip("");
  endpoint.add_port(udt_port);
  endpoint.add_port(udt_port);
  endpoint.add_port(0);
  boost::uint32_t new_conn;
  ASSERT_EQ(maidsafe::kConnectionNotExists, im_hdlr.SendMessage(1, 1, "hello"));
  ASSERT_EQ(maidsafe::kSuccess, im_hdlr.CreateConnection(trans_id,
      endpoint, &new_conn));
  std::string msg("Hello World!!");
  ASSERT_EQ(maidsafe::kSuccess, im_hdlr.SendMessage(trans_id, new_conn, msg));
  boost::this_thread::sleep(boost::posix_time::seconds(2));
  ASSERT_EQ(msg, msgs_sent);
  ASSERT_EQ(maidsafe::kSuccess, im_hdlr.CloseConnection(trans_id, new_conn));
  udt_trans.Stop();
}

TEST_F(TestIMHandler, BEH_MAID_IMHdlrConnTimeout) {
  ASSERT_EQ(maidsafe::kSuccess, im_hdlr.Start(&trans_hndlr,
      boost::bind(&TestIMHandler::NewMsgNotifier, this, _1),
      boost::bind(&TestIMHandler::NewConnMsg, this, _1, _2, _3)));
  transport::TransportUDT udt_trans;
  ASSERT_TRUE(udt_trans.RegisterOnSend(boost::bind(&TestIMHandler::SendNotifier,
        this, _1, _2)));
  ASSERT_TRUE(udt_trans.RegisterOnServerDown(boost::bind(
        &TestIMHandler::OnServerDown, this, _1, _2, _3)));
  ASSERT_TRUE(udt_trans.RegisterOnMessage(boost::bind(
        &TestIMHandler::UDTTransMsgArrived, this, _1, _2, _3,
        _4)));
  ASSERT_EQ(0, udt_trans.Start(0));
  boost::uint16_t udt_port(udt_trans.listening_port());
  maidsafe::EndPoint endpoint;
  endpoint.add_ip(ip);
  endpoint.add_ip(ip);
  endpoint.add_ip("");
  endpoint.add_port(udt_port);
  endpoint.add_port(udt_port);
  endpoint.add_port(0);
  boost::uint32_t new_conn;
  ASSERT_EQ(maidsafe::kSuccess, im_hdlr.CreateConnection(trans_id,
      endpoint, &new_conn));
  boost::this_thread::sleep(boost::posix_time::seconds(
      maidsafe::kConnectionTimeout + 1));
  ASSERT_EQ(maidsafe::kConnectionNotExists,
      im_hdlr.SendMessage(trans_id, new_conn, "abcd"));
  ASSERT_EQ(maidsafe::kConnectionNotExists,
      im_hdlr.CloseConnection(trans_id, new_conn));
  udt_trans.Stop();
}

TEST_F(TestIMHandler, BEH_MAID_IMHdlrResetConnTimeout) {
  ASSERT_EQ(maidsafe::kSuccess, im_hdlr.Start(&trans_hndlr,
      boost::bind(&TestIMHandler::NewMsgNotifier, this, _1),
      boost::bind(&TestIMHandler::NewConnMsg, this, _1, _2, _3)));
  transport::TransportUDT udt_trans;
  ASSERT_TRUE(udt_trans.RegisterOnSend(boost::bind(&TestIMHandler::SendNotifier,
        this, _1, _2)));
  ASSERT_TRUE(udt_trans.RegisterOnServerDown(boost::bind(
        &TestIMHandler::OnServerDown, this, _1, _2, _3)));
  ASSERT_TRUE(udt_trans.RegisterOnMessage(boost::bind(
        &TestIMHandler::UDTTransMsgArrived, this, _1, _2, _3,
        _4)));
  ASSERT_EQ(0, udt_trans.Start(0));
  boost::uint16_t udt_port(udt_trans.listening_port());
  maidsafe::EndPoint endpoint;
  endpoint.add_ip(ip);
  endpoint.add_ip(ip);
  endpoint.add_ip("");
  endpoint.add_port(udt_port);
  endpoint.add_port(udt_port);
  endpoint.add_port(0);
  boost::uint32_t new_conn;
  ASSERT_EQ(maidsafe::kSuccess, im_hdlr.CreateConnection(trans_id,
      endpoint, &new_conn));
  boost::this_thread::sleep(boost::posix_time::seconds(
      maidsafe::kConnectionTimeout - 1));
  std::string msg("Hello World!!");
  ASSERT_EQ(maidsafe::kSuccess, im_hdlr.SendMessage(trans_id, new_conn, msg));
  boost::this_thread::sleep(boost::posix_time::seconds(
      maidsafe::kConnectionTimeout - 1));
  ASSERT_EQ(msg, msgs_sent);
  msg = "Goodbye";
  ASSERT_EQ(maidsafe::kSuccess, im_hdlr.SendMessage(trans_id, new_conn, msg));
  boost::this_thread::sleep(boost::posix_time::seconds(2));
  std::string reply_msg("See you");
  udt_trans.Send(reply_msg, ext_conn_id, false);
  boost::this_thread::sleep(boost::posix_time::seconds(
      maidsafe::kConnectionTimeout - 3));
  ASSERT_EQ(maidsafe::kSuccess, im_hdlr.CloseConnection(trans_id, new_conn));
  ASSERT_EQ(msg, msgs_sent);
  ASSERT_EQ(reply_msg, msgs_rec);
  udt_trans.Stop();
}

TEST_F(TestIMHandler, BEH_MAID_IMHdlrRemotePeerClosesConnection) {
  ASSERT_EQ(maidsafe::kSuccess, im_hdlr.Start(&trans_hndlr,
      boost::bind(&TestIMHandler::NewMsgNotifier, this, _1),
      boost::bind(&TestIMHandler::NewConnMsg, this, _1, _2, _3)));
  transport::TransportUDT udt_trans;
  ASSERT_TRUE(udt_trans.RegisterOnSend(boost::bind(&TestIMHandler::SendNotifier,
        this, _1, _2)));
  ASSERT_TRUE(udt_trans.RegisterOnServerDown(boost::bind(
        &TestIMHandler::OnServerDown, this, _1, _2, _3)));
  ASSERT_TRUE(udt_trans.RegisterOnMessage(boost::bind(
        &TestIMHandler::UDTTransMsgArrived, this, _1, _2, _3,
        _4)));
  ASSERT_EQ(0, udt_trans.Start(0));
  boost::uint16_t udt_port(udt_trans.listening_port());
  maidsafe::EndPoint endpoint;
  endpoint.add_ip(ip);
  endpoint.add_ip(ip);
  endpoint.add_ip("");
  endpoint.add_port(udt_port);
  endpoint.add_port(udt_port);
  endpoint.add_port(0);
  boost::uint32_t new_conn;
  ASSERT_EQ(maidsafe::kSuccess, im_hdlr.CreateConnection(trans_id,
      endpoint, &new_conn));
  boost::this_thread::sleep(boost::posix_time::seconds(
      maidsafe::kConnectionTimeout - 1));
  std::string msg("Hello World!!");
  ASSERT_EQ(maidsafe::kSuccess, im_hdlr.SendMessage(trans_id, new_conn, msg));
  boost::this_thread::sleep(boost::posix_time::seconds(2));
  ASSERT_EQ(msg, msgs_sent);
  udt_trans.CloseConnection(ext_conn_id);
  msg = "Goodbye";
  boost::this_thread::sleep(boost::posix_time::seconds(2));
  ASSERT_EQ(maidsafe::kConnectionDown,
      im_hdlr.SendMessage(trans_id, new_conn, msg));
  ASSERT_NE(msg, msgs_sent);
  ASSERT_EQ(maidsafe::kConnectionNotExists,
      im_hdlr.CloseConnection(trans_id, new_conn));
  udt_trans.Stop();
}

TEST_F(TestIMHandler, BEH_MAID_IMHdlrAcceptConnection) {
  ASSERT_EQ(maidsafe::kSuccess, im_hdlr.Start(&trans_hndlr,
      boost::bind(&TestIMHandler::NewMsgNotifier, this, _1),
      boost::bind(&TestIMHandler::NewConnMsg, this, _1, _2, _3)));
  transport::TransportUDT udt_trans;
  ASSERT_TRUE(udt_trans.RegisterOnSend(boost::bind(&TestIMHandler::SendNotifier,
        this, _1, _2)));
  ASSERT_TRUE(udt_trans.RegisterOnServerDown(boost::bind(
        &TestIMHandler::OnServerDown, this, _1, _2, _3)));
  ASSERT_TRUE(udt_trans.RegisterOnMessage(boost::bind(
        &TestIMHandler::UDTTransMsgArrived, this, _1, _2, _3,
        _4)));
  ASSERT_EQ(0, udt_trans.Start(0));

  boost::uint32_t id(0);
  ASSERT_EQ(0, udt_trans.ConnectToSend(ip, port, "", 0, "", 0, true, &id));
  std::string msg("Hello");
  ASSERT_EQ(0, udt_trans.Send(msg, id, false));
  boost::this_thread::sleep(boost::posix_time::seconds(2));
  ASSERT_EQ(msg, msgs_rec);
  ASSERT_NE(0, new_conn_accepted);
  ASSERT_EQ(maidsafe::kConnectionNotExists,
      im_hdlr.CloseConnection(trans_id, new_conn_accepted));
  ASSERT_EQ(maidsafe::kSuccess,
      im_hdlr.AddConnection(trans_id, new_conn_accepted));
  msg = "Goodbye";
  ASSERT_EQ(maidsafe::kSuccess,
      im_hdlr.SendMessage(trans_id, new_conn_accepted, msg));
  boost::this_thread::sleep(boost::posix_time::seconds(2));
  ASSERT_EQ(msg, msgs_sent);
  ASSERT_EQ(maidsafe::kSuccess,
      im_hdlr.CloseConnection(trans_id, new_conn_accepted));
  udt_trans.Stop();
}

TEST_F(TestIMHandler, FUNC_MAID_IMHdlrMultipleConnections) {
  ASSERT_EQ(maidsafe::kSuccess, im_hdlr.Start(&trans_hndlr,
      boost::bind(&TestIMHandler::NewMsgNotifier, this, _1),
      boost::bind(&TestIMHandler::NewConnMsg, this, _1, _2, _3)));
  transport::TransportUDT udt_trans1, udt_trans2;
  ASSERT_TRUE(udt_trans1.RegisterOnSend(boost::bind(&TestIMHandler::SendNotifier,
        this, _1, _2)));
  ASSERT_TRUE(udt_trans1.RegisterOnServerDown(boost::bind(
        &TestIMHandler::OnServerDown, this, _1, _2, _3)));
  ASSERT_TRUE(udt_trans1.RegisterOnMessage(boost::bind(
        &TestIMHandler::UDTTransMsgArrived, this, _1, _2, _3,
        _4)));
  ASSERT_EQ(0, udt_trans1.Start(0));
  ASSERT_TRUE(udt_trans2.RegisterOnSend(boost::bind(&TestIMHandler::SendNotifier,
        this, _1, _2)));
  ASSERT_TRUE(udt_trans2.RegisterOnServerDown(boost::bind(
        &TestIMHandler::OnServerDown, this, _1, _2, _3)));
  ASSERT_TRUE(udt_trans2.RegisterOnMessage(boost::bind(
        &TestIMHandler::UDTTransMsgArrived, this, _1, _2, _3,
        _4)));
  ASSERT_EQ(0, udt_trans2.Start(0));
  boost::uint16_t port2 (udt_trans2.listening_port());
  maidsafe::EndPoint endpoint;
  endpoint.add_ip(ip);
  endpoint.add_ip(ip);
  endpoint.add_ip("");
  endpoint.add_port(port2);
  endpoint.add_port(port2);
  endpoint.add_port(0);
  boost::uint32_t new_conn;
  ASSERT_EQ(maidsafe::kSuccess, im_hdlr.CreateConnection(trans_id,
      endpoint, &new_conn));

  boost::uint32_t id;
  ASSERT_EQ(0, udt_trans1.ConnectToSend(ip, port, "", 0, "", 0, true, &id));
  std::string msg("Hello -- from node1");
  ASSERT_EQ(0, udt_trans1.Send(msg, id, false));
  boost::this_thread::sleep(boost::posix_time::seconds(2));
  ASSERT_EQ(msg, msgs_rec);
  boost::uint32_t conn_to_node1 = new_conn_accepted;
  ASSERT_EQ(maidsafe::kSuccess,
      im_hdlr.AddConnection(trans_id, conn_to_node1));

  msg = "Hello node2!!";
  ASSERT_EQ(maidsafe::kSuccess, im_hdlr.SendMessage(trans_id, new_conn, msg));
  boost::this_thread::sleep(boost::posix_time::seconds(2));
  ASSERT_EQ(msg, msgs_sent);
  boost::uint32_t conn_hdlr_to_node2 = ext_conn_id;

  msg = "Hello node1";
  ASSERT_EQ(maidsafe::kSuccess,
      im_hdlr.SendMessage(trans_id, conn_to_node1, msg));
  boost::this_thread::sleep(boost::posix_time::seconds(2));
  ASSERT_EQ(msg, msgs_sent);

  msg = "Hello Handler -- from node2";
  ASSERT_EQ(0, udt_trans2.Send(msg, conn_hdlr_to_node2, false));
  boost::this_thread::sleep(boost::posix_time::seconds(2));
  ASSERT_EQ(msg, msgs_rec);
  boost::this_thread::sleep(boost::posix_time::seconds(
      maidsafe::kConnectionTimeout - 3));
  ASSERT_EQ(maidsafe::kConnectionNotExists,
      im_hdlr.CloseConnection(trans_id, conn_to_node1));

  msg = "Goodbye";
  ASSERT_EQ(maidsafe::kSuccess,
      im_hdlr.SendMessage(trans_id, new_conn, msg));
  boost::this_thread::sleep(boost::posix_time::seconds(2));
  ASSERT_EQ(msg, msgs_sent);
  ASSERT_EQ(maidsafe::kSuccess,
      im_hdlr.CloseConnection(trans_id, new_conn));

  udt_trans1.Stop();
  udt_trans2.Stop();
}
