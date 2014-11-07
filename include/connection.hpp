﻿//
// Copyright (C) 2013 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#pragma once

#include <set>

#include <boost/noncopyable.hpp>
#include <boost/logic/tribool.hpp>
#include <boost/tuple/tuple.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/progress.hpp>
#include <boost/tokenizer.hpp>
#include <boost/bind.hpp>
#include <boost/asio.hpp>
using boost::asio::ip::tcp;
#include <boost/date_time.hpp>
using namespace boost::posix_time;

#include "logging.hpp"

namespace av_router {

	class server;
	class connection_manager;
	class connection
		: public boost::enable_shared_from_this<connection>
		, public boost::noncopyable
	{
	public:
		explicit connection(boost::asio::io_service& io, server& serv, connection_manager* connection_man);
		~connection();

	public:
		void start();
		void stop();
		tcp::socket& socket();

	private:
		void close();

		void handle_read_header(const boost::system::error_code& error, std::size_t bytes_transferred);
		void handle_read_body(const boost::system::error_code& error, std::size_t bytes_transferred);

	private:
		boost::asio::io_service& m_io_service;
		server& m_server;
		tcp::socket m_socket;
		connection_manager* m_connection_manager;
		boost::asio::streambuf m_request;
		boost::asio::streambuf m_response;
		bool m_abort;
	};

	typedef boost::shared_ptr<connection> connection_ptr;
	class connection_manager
		: private boost::noncopyable
	{
	public:
		/// Add the specified connection to the manager and start it.
		void start(connection_ptr c)
		{
			boost::mutex::scoped_lock l(m_mutex);
			m_connections.insert(c);
			c->start();
		}

		/// Stop the specified connection.
		void stop(connection_ptr c)
		{
			boost::mutex::scoped_lock l(m_mutex);
			if (m_connections.find(c) != m_connections.end())
				m_connections.erase(c);
			c->stop();
		}

		/// Stop all connections.
		void stop_all()
		{
			boost::mutex::scoped_lock l(m_mutex);
			std::for_each(m_connections.begin(), m_connections.end(),
				boost::bind(&connection::stop, _1));
			m_connections.clear();
		}

	private:
		boost::mutex m_mutex;
		std::set<connection_ptr> m_connections;
	};
}
