#include "database.hpp"
#include "register_moudle.hpp"
#include "user.pb.h"
#include "ca.pb.h"

#include <future>
#include <boost/regex.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/format.hpp>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

namespace av_router {

	register_moudle::register_moudle(io_service_pool& io_pool, database& db)
		: m_io_service_pool(io_pool)
		, m_database(db)
	{}

	register_moudle::~register_moudle()
	{}

	bool register_moudle::availability_check(google::protobuf::Message* msg, connection_ptr connection, connection_manager&)
	{
		proto::username_availability_check* availabile = dynamic_cast<proto::username_availability_check*>(msg);
		if (!availabile || availabile->user_name().empty())
			return false;
		m_database.availability_check(availabile->user_name(),
			[this, connection](bool result)
			{
				// 检查用户名是否可以注册, 如果可以注册, 则返回可以的消息.
				proto::username_availability_result register_result;
				if (result)
				{
					register_result.set_result(proto::username_availability_result::NAME_AVAILABLE);
					LOG_DBG << "register, name available!";
				}
				else
				{
					register_result.set_result(proto::username_availability_result::NAME_TAKEN);
					LOG_DBG << "register, name taken!";
				}
				std::string response = encode(register_result);
				connection->write_msg(response);
			}
		);
		return true;
	}

	// HTTP 版本, 大同小异, 只是返回的不是 protobuf 消息, 而是 json 格式的消息
	void register_moudle::availability_check_httpd(const request& req, http_connection_ptr conn, http_connection_manager&)
	{
		std::string user_name;
		// TODO 添加实现.
		LOG_DBG << "register_moudle::availability_check_httpd called";
		LOG_DBG << req.body;

		http_form request_parameter(req.body, req["content-type"]);
		user_name = request_parameter["username"];

		m_database.availability_check(user_name,
		[conn](int result)
		{
			// TODO 返回 json 数据.
			auto body = boost::str(boost::format("{\"code\" : \"%d\"}") % result);
			conn->write_response(body);
		});
	}

	bool register_moudle::user_register(google::protobuf::Message* msg, connection_ptr connection, connection_manager&)
	{
		proto::user_register* register_msg = dynamic_cast<proto::user_register*>(msg);
		if (!register_msg || register_msg->user_name().empty())
			return false;

		// TODO 检查 CSR 证书是否有伪造.
		auto in = (const unsigned char *)register_msg->csr().data();
		std::string rsa_pubkey = register_msg->rsa_pubkey();
		std::shared_ptr<X509_REQ> csr(d2i_X509_REQ(NULL, &in, static_cast<long>(register_msg->csr().length())), X509_REQ_free);
		in = (const unsigned char *)rsa_pubkey.data();
		std::shared_ptr<RSA> user_rsa_pubkey(d2i_RSA_PUBKEY(NULL, &in, static_cast<long>(rsa_pubkey.length())), RSA_free);
		std::shared_ptr<EVP_PKEY> user_EVP_PKEY_pubkey(EVP_PKEY_new(), EVP_PKEY_free);
		EVP_PKEY_set1_RSA(user_EVP_PKEY_pubkey.get(), user_rsa_pubkey.get());

		// 失败了.
		if (X509_REQ_verify(csr.get(), user_EVP_PKEY_pubkey.get()) <= 0)
		{
			proto_write_user_register_response(proto::user_register_result::REGISTER_FAILED_CSR_VERIFY_FAILURE, boost::optional<std::string>(), connection, false);
			return false;
		}

		LOG_INFO << "csr fine, start registering";

		// 确定是合法的 CSR 证书, 接着数据库内插
		std::string user_name = register_msg->user_name();
		std::string csr_der_string = register_msg->csr();
		m_database.register_user(user_name, rsa_pubkey, register_msg->mail_address(), register_msg->cell_phone(),
			[=](bool result)
			{
				LOG_INFO << "database fine : " << result;

				// 插入成功了, 那就立马签名出证书来
				if(result)
				{
					LOG_INFO << "now send csr to peter";

					std::string rsa_figureprint;

					rsa_figureprint.resize(20);

					SHA1((unsigned char*)rsa_pubkey.data(), rsa_pubkey.length(), (unsigned char*) &rsa_figureprint[0]);

					proto::ca::csr_request csr_request;
					csr_request.set_csr(csr_der_string);
					csr_request.set_fingerprint(rsa_figureprint);

					// TODO call to packet forwarder to send request to avca

				}
				else
				{
					LOG_INFO << "db op failed, register stoped";
					proto_write_user_register_response(proto::user_register_result::REGISTER_FAILED_NAME_TAKEN, boost::optional<std::string>(), connection, false);
				}
			}
		);

		return true;
	}

	void register_moudle::proto_write_user_register_response(int result_code, boost::optional<std::string> cert, connection_ptr connection, bool result)
	{
		proto::user_register_result register_result;
		register_result.set_result(static_cast<proto::user_register_result::user_register_result_code>(result_code));
		if (cert.is_initialized())
		{
			register_result.set_cert(cert.value());
		}
		connection->write_msg(encode(register_result));
	}

}
