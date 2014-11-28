//
// Copyright (C) 2013 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#pragma once

#include <openssl/x509.h>

#include "router_server.hpp"
#include "serialization.hpp"

struct dh_st;
typedef struct dh_st DH;

namespace av_router {

	class database;
	class login_moudle
	{
	public:
		login_moudle(io_service_pool&, database&, X509* root_ca_cert);
		~login_moudle();

	public:
		void quit();

		bool process_login_message(google::protobuf::Message*, connection_ptr, connection_manager&);
		bool process_hello_message(google::protobuf::Message*, connection_ptr, connection_manager&);

	private:
		void on_tick(const boost::system::error_code& error);
		void continue_timer();

	private:
		io_service_pool& m_io_service_pool;
		database& m_database;
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
		X509* m_root_ca_cert;
	};

}
