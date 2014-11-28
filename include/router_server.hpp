//
// Copyright (C) 2013 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#pragma once

#include <unordered_map>
#include <boost/noncopyable.hpp>
#include <boost/thread.hpp>

#include "serialization.hpp"
#include "io_service_pool.hpp"
#include "connection.hpp"

namespace av_router {

	typedef boost::function<bool(google::protobuf::Message*, connection_ptr, connection_manager&)> message_callback;
	typedef std::unordered_map<std::string, message_callback> message_callback_table;

	typedef boost::function<void(int type, connection_ptr, connection_manager&)> connection_callback;
	typedef std::unordered_map<std::string, connection_callback> connection_callback_table;

	class router_server
		: public boost::noncopyable
	{
		friend class connection;
	public:
		explicit router_server(io_service_pool& ios, unsigned short port, std::string address = "0.0.0.0");
		~router_server();

	public:
		// 启动或停止.
		void start();
		void stop();

		// 添加或删除消息处理模块.
		bool add_message_process_moudle(const std::string& name, message_callback cb);
		bool del_message_process_moudle(const std::string& name);

		// 添加或删除 connection 对象的创建撤销事件通知
		bool add_connection_process_moudle(const std::string& name, connection_callback cb);
		bool del_connection_process_moudle(const std::string& name);

	private:
		// 处理客户连接.
		void handle_accept(const boost::system::error_code& error);
		// 滴哒.
		void on_tick(const boost::system::error_code& error);

		// 调用name所对应的消息处理模块.
		bool do_message(google::protobuf::Message*, connection_ptr);
		void do_connection_notify(int type, connection_ptr conn);

		// 开始的具体实现.
		void start_impl();
		// 继续定时器.
		void continue_timer();

	private:
		io_service_pool& m_io_service_pool;
		boost::asio::io_service& m_io_service;
		boost::asio::ip::tcp::acceptor m_acceptor;
		boost::asio::deadline_timer m_timer;
		connection_ptr m_connection;
		connection_manager m_connection_manager;
		boost::shared_mutex m_message_callback_mtx;
		boost::shared_mutex m_connection_callback_mtx;
		message_callback_table m_message_callbacks;
		connection_callback_table m_connection_callbacks;
	};

}
