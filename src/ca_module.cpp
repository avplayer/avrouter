#include <boost/any.hpp>

#include "ca_module.hpp"
#include "packet.pb.h"

#include <openssl/dh.h>
#include <openssl/aes.h>

#include "avpacket.hpp"

namespace av_router {

	ca_moudle::ca_moudle(io_service_pool& io_poll)
		: m_io_service_poll(io_poll)
	{
	}

	ca_moudle::~ca_moudle()
	{}

	void ca_moudle::connection_notify(int type, connection_ptr connection, connection_manager&)
	{
	}

	bool ca_moudle::process_ca_announce(google::protobuf::Message*, connection_ptr con, connection_manager&)
	{
		// TODO检查 ca
		m_ca_connection = con;
	}

	bool ca_moudle::process_csr_request(google::protobuf::Message* msg, connection_ptr connection, connection_manager&)
	{
		auto ca_con = m_ca_connection.lock();
		if (ca_con)
		{
			ca_con->write_msg(encode(*msg));
			return true;
		}
		return false;
	}
}
