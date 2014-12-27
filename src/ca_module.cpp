#include <boost/any.hpp>

#include "ca_module.hpp"
#include "packet.pb.h"
#include "ca.pb.h"
#include "user.pb.h"

#include <openssl/dh.h>
#include <openssl/aes.h>

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
		// TODO检查 ca.
		m_ca_connection = con;
		return true;
	}

	bool ca_moudle::process_csr_request(google::protobuf::Message* msg, connection_ptr connection, connection_manager&)
	{
		boost::lock_guard<boost::mutex> l(m_mutex);
		auto ca_con = m_ca_connection.lock();
		if (ca_con)
		{
			// 存入待回复表.
			ca_con->write_msg(encode(*msg));

			auto csr_request = dynamic_cast<proto::ca::csr_request*>(msg);
			m_user_cons.insert(std::make_pair(csr_request->fingerprint(), connection));
			return true;
		}
		return false;
	}

	bool ca_moudle::process_csr_result(google::protobuf::Message* msg, connection_ptr, connection_manager&)
	{
		auto csr_reslt = dynamic_cast<proto::ca::csr_result*>(msg);

		auto fingerprint = csr_reslt->fingerprint();

		boost::lock_guard<boost::mutex> l(m_mutex);
		auto res_it = m_user_cons.find(fingerprint);
		if (res_it != m_user_cons.end())
		{
			proto::user_register_result register_result;
			register_result.set_result((proto::user_register_result::user_register_result_code)(int)csr_reslt->result());
			register_result.set_cert(csr_reslt->cert());
			res_it->second->write_msg(encode(register_result));
			m_user_cons.erase(res_it);
		}
		return true;
	}

}
