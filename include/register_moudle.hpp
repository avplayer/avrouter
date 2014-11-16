//
// Copyright (C) 2013 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#pragma once

#include <boost/optional.hpp>

#include <openssl/x509.h>

#include "server.hpp"
#include "serialization.hpp"

namespace av_router {

	class database;
	class register_moudle
	{
	public:
		register_moudle(io_service_pool&, database&);
		~register_moudle();

	public:
		void availability_check(google::protobuf::Message*, connection_ptr, connection_manager&);
		void user_register(google::protobuf::Message*, connection_ptr, connection_manager&);

	protected:
		void proto_write_user_register_response(int result_code, boost::optional<std::string> cert, connection_ptr);

	private:
		av_router::io_service_pool& m_io_service_pool;
		database& m_database;
	};

}
