//
// Copyright (C) 2013 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#pragma once

#include "server.hpp"
#include "serialization.hpp"

struct dh_st;
typedef struct dh_st DH;

namespace av_router {

	class database;
	class login_moudle
	{
	public:
		login_moudle(av_router::io_service_pool&);
		~login_moudle();

	public:
		void quit();

		void process_login_message(google::protobuf::Message*, connection_ptr, connection_manager&, database&);
		void process_hello_message(google::protobuf::Message*, connection_ptr, connection_manager&, database&);

	private:
		void on_tick(const boost::system::error_code& error);
		void continue_timer();

	private:
		av_router::io_service_pool& m_io_service_pool;
		boost::asio::deadline_timer m_timer;
		struct login_state
		{
			enum state {
				hello,
				succeed,
			};
			state status;
		};
		std::map<ptrdiff_t, login_state> m_log_state;
	};

}
