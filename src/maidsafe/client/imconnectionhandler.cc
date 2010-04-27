/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Description:  Singleton class which controls all maidsafe client operations
* Version:      1.0
* Created:      2010-04-13
* Revision:     none
* Compiler:     gcc
* Author:
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

#include <boost/bind.hpp>
#include <utility>
#include "maidsafe/client/imconnectionhandler.h"
#include "protobuf/packet.pb.h"

namespace maidsafe {

void dummy_timeout_func(const boost::system::error_code &) {
}

IMConnectionHandler::IMConnectionHandler() : connections_(),
                                             transport_handler_(NULL),
                                             message_notifier_(),
                                             conn_notifier_(),
                                             started_(false),
                                             connections_mutex_(),
                                             worker_(),
                                             io_(),
                                             strand_(io_),
                                             timer_(io_),
                                             send_finished_() {
  timer_.expires_at(boost::posix_time::pos_infin);
}

ReturnCode IMConnectionHandler::Start(transport::TransportHandler *trans_hdler,
      new_message_notifier msg_notifier,
      new_connection_notifier conn_notifier) {
  if (msg_notifier.empty() || conn_notifier.empty() || trans_hdler == NULL)
    return kFailedToStartHandler;
  if (started_)
    return kHandlerAlreadyStarted;
  transport_handler_ = trans_hdler;
  message_notifier_ = msg_notifier;
  conn_notifier_ = conn_notifier;
  timer_.async_wait(strand_.wrap(boost::bind(&dummy_timeout_func, _1)));
  worker_.reset(new boost::thread(boost::bind(
      &boost::asio::io_service::run, &io_)));
  started_ = true;
  return kSuccess;
}

void IMConnectionHandler::Stop() {
  if (!started_)
    return;
  io_.stop();
  worker_->join();
  {
    boost::mutex::scoped_lock guard(connections_mutex_);
    connections_container::iterator it = connections_.begin();
    for (; it != connections_.begin(); ++it) {
      transport_handler_->CloseConnection(it->conn_id, it->trans_id);
    }
    connections_.clear();
  }
}

ReturnCode IMConnectionHandler::AddConnection(const boost::int16_t &trans_id,
      const boost::uint32_t &conn_id) {
  if (!started_)
    return kHandlerNotStarted;
  connection_info conn_info(io_, trans_id, conn_id);
  std::pair<connections_container::iterator, bool> p;
  {
    boost::mutex::scoped_lock guard(connections_mutex_);
    p = connections_.insert(conn_info);
  }
  if (p.second) {
    conn_info.timer->expires_from_now(boost::posix_time::seconds(
        kConnectionTimeout));
    conn_info.timer->async_wait(strand_.wrap(boost::bind(
        &IMConnectionHandler::ConnectionTimesOut, this, trans_id, conn_id,
        _1)));
    return kSuccess;
  }
  return kConnectionAlreadyExists;
}

ReturnCode IMConnectionHandler::CreateConnection(
      const boost::int16_t &trans_id, const EndPoint &endpoint,
      boost::uint32_t *conn_id) {
  if (!started_)
    return kHandlerNotStarted;
  if (!transport_handler_->ConnectToSend(endpoint.ip(0), endpoint.port(0),
      endpoint.ip(1), endpoint.port(1), endpoint.ip(2), endpoint.port(2), true,
      conn_id, trans_id)) {
    connection_info conn_info(io_, trans_id, *conn_id);
    {
      boost::mutex::scoped_lock guard(connections_mutex_);
      connections_.insert(conn_info);
    }
    conn_info.timer->expires_from_now(boost::posix_time::seconds(
        kConnectionTimeout));
    conn_info.timer->async_wait(strand_.wrap(boost::bind(
        &IMConnectionHandler::ConnectionTimesOut, this, trans_id,
        *conn_id, _1)));
    return kSuccess;
  }
  return kFailedToConnect;
}

ReturnCode IMConnectionHandler::CloseConnection(const boost::int16_t &trans_id,
      const boost::uint32_t &conn_id) {
  if (!started_)
    return kHandlerNotStarted;
  connections_container::iterator it = connections_.find(
      boost::make_tuple(trans_id, conn_id));
  transport_handler_->CloseConnection(conn_id, trans_id);
  boost::mutex::scoped_lock guard(connections_mutex_);
  if (it == connections_.end()) {
    return kConnectionNotExists;
  }
  boost::shared_ptr<boost::asio::deadline_timer> timer(it->timer);
  connections_.erase(it);
  timer->cancel();
  return kSuccess;
}

ReturnCode IMConnectionHandler::SendMessage(const boost::int16_t &trans_id,
      const boost::uint32_t &conn_id, const std::string &msg) {
  if (!started_)
    return kHandlerNotStarted;
  boost::mutex::scoped_lock guard(connections_mutex_);
  connections_container::iterator it = connections_.find(
      boost::make_tuple(trans_id, conn_id));
  if (it == connections_.end()) {
    return kConnectionNotExists;
  }
  bool timer_restarted = false;
  if (!transport_handler_->Send(msg, conn_id, false, trans_id)) {
    connection_info info;
    info.trans_id = it->trans_id;
    info.conn_id = it->conn_id;
    info.restart_timer = true;
    info.timer = it->timer;
    connections_.replace(it, info);
    info.timer->expires_from_now(
        boost::posix_time::seconds(kConnectionTimeout));
    info.timer->async_wait(strand_.wrap(boost::bind(
        &IMConnectionHandler::ConnectionTimesOut, this, trans_id,
        conn_id, _1)));
    while (!timer_restarted) {
      send_finished_.wait(guard);
      connections_container::iterator it1 = connections_.find(
        boost::make_tuple(trans_id, conn_id));
      timer_restarted = !(it->restart_timer);

    }

    return kSuccess;
  } else {
    connections_.erase(it);
    return kConnectionDown;
  }
}

void IMConnectionHandler::OnMessageArrive(const std::string &msg,
      const boost::uint32_t &conn_id, const boost::int16_t &trans_id,
      const double&) {
  if (!started_)
    return;
  connections_container::iterator it = connections_.find(
      boost::make_tuple(trans_id, conn_id));
  if (it == connections_.end()) {
    conn_notifier_(trans_id, conn_id, msg);
  } else {
    {
      connection_info info;
      boost::mutex::scoped_lock guard(connections_mutex_);
      info.trans_id = it->trans_id;
      info.conn_id = it->conn_id;
      info.timer = it->timer;
      info.restart_timer = true;
      info.timer->expires_from_now(
          boost::posix_time::seconds(kConnectionTimeout));
      connections_.replace(it, info);
      info.timer->async_wait(strand_.wrap(boost::bind(
          &IMConnectionHandler::ConnectionTimesOut, this, trans_id,
          conn_id, _1)));
    }
    message_notifier_(msg);
  }
}

void IMConnectionHandler::ConnectionTimesOut(const boost::int16_t &trans_id,
      const boost::uint32_t &conn_id, const boost::system::error_code &ec) {
  if (!started_)
    return;
  boost::mutex::scoped_lock guard(connections_mutex_);
  connections_container::iterator it = connections_.find(
      boost::make_tuple(trans_id, conn_id));
  if (it == connections_.end())
    return;
  if (ec && it->restart_timer) {
    connection_info info;
    info.trans_id = it->trans_id;
    info.conn_id = it->conn_id;
    info.timer = it->timer;
    connections_.replace(it, info);
    send_finished_.notify_all();
  } else {
    connections_.erase(it);
    transport_handler_->CloseConnection(conn_id, trans_id);
  }
}

ReturnCode IMConnectionHandler::CloseConnections(
      const boost::int16_t &trans_id) {
  if (!started_)
    return kHandlerNotStarted;
  boost::mutex::scoped_lock guard(connections_mutex_);
  connections_container::index<t_trans_id>::type& indx =
      connections_.get<t_trans_id>();
  connections_container::index<t_trans_id>::type::iterator l_limit =
      indx.lower_bound(trans_id);
  connections_container::index<t_trans_id>::type::iterator u_limit =
      indx.upper_bound(trans_id + 1);
  for (connections_container::index<t_trans_id>::type::iterator it = l_limit;
       it != u_limit; ++it) {
    transport_handler_->CloseConnection(it->conn_id, trans_id);
    it->timer->cancel();
  }
  indx.erase(l_limit, u_limit);
  return kSuccess;
}
}

