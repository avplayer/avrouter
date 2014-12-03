//
// Copyright (C) 2013 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#pragma once

#include "router_server.hpp"
#include "serialization.hpp"

struct dh_st;
typedef struct dh_st DH;

namespace proto {
	class agmp;
	class av_address;
}

namespace av_router {

	class ca_moudle
	{
	public:
		ca_moudle(av_router::io_service_pool&);
		~ca_moudle();

	public:
		void connection_notify(int type, connection_ptr, connection_manager&);
		bool process_ca_announce(google::protobuf::Message*, connection_ptr, connection_manager&);
		bool process_csr_request(google::protobuf::Message*, connection_ptr, connection_manager&);

	private:
		av_router::io_service_pool& m_io_service_poll;

		connection_weak_ptr m_ca_connection;
	};
}
