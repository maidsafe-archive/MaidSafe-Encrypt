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

#ifndef MAIDSAFE_CLIENT_IMCONNECTIONHANDLER_H_
#define MAIDSAFE_CLIENT_IMCONNECTIONHANDLER_H_

#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/identity.hpp>
#include <boost/multi_index/member.hpp>
#include <boost/multi_index/composite_key.hpp>
#include <boost/cstdint.hpp>
#include <boost/function.hpp>
#include <boost/thread.hpp>
#include <boost/asio.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/shared_ptr.hpp>

#include <maidsafe/transport/transporthandler-api.h>
#include <string>

#include "maidsafe/common/returncodes.h"

namespace maidsafe {

class EndPoint;

typedef boost::function<void(const std::string&)> new_message_notifier;
typedef boost::function<void(const boost::int16_t&, const boost::uint32_t&,
    const std::string&)> new_connection_notifier;

const boost::uint8_t kConnectionTimeout = 60;  // 60 seconds

struct connection_info {
  connection_info(boost::asio::io_service &io) : trans_id(0), conn_id(0),  // NOLINT
      restart_timer(false), timer(new boost::asio::deadline_timer(io)) {}
  connection_info(boost::asio::io_service &io, const boost::uint16_t &t_id,
      const boost::uint32_t & c_id) : trans_id(t_id), conn_id(c_id),
      restart_timer(false), timer(new boost::asio::deadline_timer(io)) {}
  connection_info() : trans_id(0), conn_id(0), restart_timer(false), timer() {}
  boost::uint16_t trans_id;
  boost::uint32_t conn_id;
  bool restart_timer;
  boost::shared_ptr<boost::asio::deadline_timer> timer;
};

// Tags
struct t_trans_conn_pair;
struct t_trans_id;

typedef boost::multi_index::multi_index_container<
  connection_info,
  boost::multi_index::indexed_by<
    boost::multi_index::ordered_unique<
      boost::multi_index::tag<t_trans_conn_pair>,
      boost::multi_index::composite_key<
        connection_info,
        BOOST_MULTI_INDEX_MEMBER(connection_info, boost::uint16_t, trans_id),
        BOOST_MULTI_INDEX_MEMBER(connection_info, boost::uint32_t, conn_id)
      >
    >,
    boost::multi_index::ordered_non_unique<
      boost::multi_index::tag<t_trans_id>,
      BOOST_MULTI_INDEX_MEMBER(connection_info, boost::uint32_t, conn_id)
    >
  >
> connections_container;

class IMConnectionHandler {
 public:
  IMConnectionHandler();
  ReturnCode Start(transport::TransportHandler *trans_hdler,
      new_message_notifier msg_notifier, new_connection_notifier conn_notifier);
  void Stop();
  ReturnCode AddConnection(const boost::int16_t &trans_id,
      const boost::uint32_t &conn_id);
  ReturnCode CreateConnection(const boost::int16_t &trans_id,
      const EndPoint &endpoint, boost::uint32_t *conn_id);
  ReturnCode SendMessage(const boost::int16_t &trans_id,
      const boost::uint32_t &conn_id, const std::string &msg);
  ReturnCode CloseConnection(const boost::int16_t &trans_id,
      const boost::uint32_t &conn_id);
  ReturnCode CloseConnections(const boost::int16_t &trans_id);
  void OnMessageArrive(const std::string &msg, const boost::uint32_t &conn_id,
      const boost::int16_t &trans_id, const double &rtt);
 private:
  void ConnectionTimesOut(const boost::int16_t &trans_id,
      const boost::uint32_t &conn_id, const boost::system::error_code &ec);
  connections_container connections_;
  transport::TransportHandler *transport_handler_;
  new_message_notifier message_notifier_;
  new_connection_notifier conn_notifier_;
  bool started_;
  boost::mutex connections_mutex_;
  boost::shared_ptr<boost::thread> worker_;
  boost::asio::io_service io_;
  boost::asio::strand strand_;
  boost::asio::deadline_timer timer_;
  boost::condition_variable send_finished_;
};

}  // namespace maidsafe

#endif  // MAIDSAFE_CLIENT_IMCONNECTIONHANDLER_H_
