﻿//
// Copyright (C) 2013 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#pragma once

#include <set>
#include <deque>

#include <boost/noncopyable.hpp>
#include <boost/any.hpp>
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
#include <boost/function.hpp>

#include "logging.hpp"

namespace av_router {

	class router_server;
	class connection_manager;
	class connection
		: public boost::enable_shared_from_this<connection>
		, public boost::noncopyable
	{
	public:
		explicit connection(boost::asio::io_service& io, router_server& serv, connection_manager* connection_man);
		~connection();

	public:
		void start();
		void stop();

		tcp::socket& socket();
		router_server& server(){return m_server;};

		// 消息发送接口, 消息必须是encode编码后的字符串, 支持回调.
		typedef boost::function<void(const boost::system::error_code&)> write_handler;
		void write_msg(const std::string& msg, const write_handler& handler = write_handler());

		// 当前连接属性获取或设置.
		boost::any property(const std::string& prop);
		void property(const std::string& prop, const boost::any& value);

	private:
		void close();

		void handle_read_header(const boost::system::error_code& error, std::size_t bytes_transferred);
		void handle_read_body(const boost::system::error_code& error, std::size_t bytes_transferred);
		void handle_write(const boost::system::error_code& error);

		void do_write(std::string msg, write_handler handler);

	private:
		boost::asio::io_service& m_io_service;
		router_server& m_server;
		tcp::socket m_socket;
		connection_manager* m_connection_manager;
		boost::asio::streambuf m_request;
		boost::asio::streambuf m_response;
		struct message
		{
			std::string msg;
			write_handler handler;
		};
		typedef std::deque<message> write_queue;
		write_queue m_write_queue;
		std::map<std::string, boost::any> m_connection_propertys;
		bool m_abort;
	};

	typedef boost::shared_ptr<connection> connection_ptr;
	typedef boost::weak_ptr<connection> connection_weak_ptr;
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
