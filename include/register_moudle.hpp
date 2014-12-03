//
// Copyright (C) 2013 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#pragma once

#include <boost/optional.hpp>

#include <openssl/x509.h>

#include "http_server.hpp"
#include "router_server.hpp"
#include "serialization.hpp"

namespace av_router {

	class database;
	class register_moudle
	{
	public:
		register_moudle(av_router::io_service_pool& io_pool, av_router::database& db);
		~register_moudle();

	public: // for HTTPD
		void availability_check_httpd(const request&, http_connection_ptr, http_connection_manager&);

	public:
		bool availability_check(google::protobuf::Message*, connection_ptr, connection_manager&);
		bool user_register(google::protobuf::Message*, connection_ptr, connection_manager&);

	protected:
		void proto_write_user_register_response(int, boost::optional<std::string>, connection_ptr, bool);

	private:
		av_router::io_service_pool& m_io_service_pool;
		database& m_database;
	};

}
