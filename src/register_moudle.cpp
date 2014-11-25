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

	namespace detail {

		template<class AsyncStream>
		static google::protobuf::Message* async_read_protobuf_message(AsyncStream& stream, boost::asio::yield_context yield_context)
		{
			boost::system::error_code ec;

			std::string buf;
			buf.resize(4);
			boost::asio::async_read(stream, boost::asio::buffer(&buf[0], 4), yield_context[ec]);
			if (ec)
			{
				LOG_ERR << "async read ca.avplayer.org packet header, error: " << ec.message();
				return nullptr;
			}

			uint32_t pktlen = ntohl(*(uint32_t*)(buf.data()));
			if (pktlen >= 10000)
				return nullptr;

			buf.resize(pktlen + 4);
			boost::asio::async_read(stream, boost::asio::buffer(&buf[4], pktlen), yield_context[ec]);
			if (ec)
			{
				LOG_ERR << "async read ca.avplayer.org packet body, error: " << ec.message();
				return nullptr;
			}

			return decode(buf);
		}

		// NOTE: 看上去很复杂, 不过这个是暂时的, 因为稍后会用大兽模式, 与 CA 建立长连接来处理
		// 而不是像现在这样使用短连接+轮询.
		template<class Handler>
		static void async_send_csr_coro(boost::asio::io_service& io, std::string csr, std::string rsa_fingerprint, Handler handler, boost::asio::yield_context yield_context)
		{
			boost::system::error_code ec;
			tcp::socket sock(io);

			// 解析ca.avplayer.org
			tcp::resolver resolver(io);
			auto endpoint_it = resolver.async_resolve(tcp::resolver::query("ca.avplayer.org", "8086"), yield_context[ec]);
			if (ec)
			{
				LOG_ERR << "resolver ca.avplayer.org failed, error: " << ec.message();
				return;
			}

			// 连接到ca.avplayer.org:8086
			boost::asio::async_connect(sock, endpoint_it, yield_context[ec]);
			if (ec)
			{
				LOG_ERR << "async connect to ca.avplayer.org failed, error: " << ec.message();
				return;
			}

			proto::ca::csr_push csr_push;
			csr_push.set_csr(csr);

			// 发送push_csr请求.
			boost::asio::async_write(sock, boost::asio::buffer(encode(csr_push)), yield_context[ec]);
			if (ec)
			{
				LOG_ERR << "async write push_csr to ca.avplayer.org failed, error: " << ec.message();
				return;
			}

			bool push_ready = false;
			// 等待 push_ok
			do {
				std::shared_ptr<google::protobuf::Message> msg(async_read_protobuf_message(sock, yield_context));
				if (msg && msg->GetTypeName() == "proto.ca.push_ok")
				{
					for (const std::string& fingerprint : dynamic_cast<proto::ca::push_ok*>(msg.get())->fingerprints())
					{
						if (fingerprint == rsa_fingerprint)
							push_ready = true;
					}
				}
			} while (false);

			if (!push_ready)
			{
				io.post(std::bind(handler, -1, std::string()));
				return;
			}

			boost::asio::deadline_timer timer(io);
			std::atomic<bool> can_read(false);

			boost::asio::async_read(sock, boost::asio::null_buffers(),
				[&can_read](boost::system::error_code ec, std::size_t)
				{
					can_read = !ec;
				});

			// 十秒后取消读取.
			timer.expires_from_now(boost::posix_time::seconds(10));
			timer.async_wait(yield_context[ec]);
			if (ec)
			{
				LOG_ERR << "async timer wait error: " << ec.message();
				return;
			}

			// 每秒轮询一次 pull_cert
			// 只轮询 10 次, 这样要求 10s 内给出结果.
			for (int i = 0; i < 10 && !can_read; i++)
			{
				proto::ca::cert_pull cert_pull;
				cert_pull.set_fingerprint(rsa_fingerprint);
				boost::asio::async_write(sock, boost::asio::buffer(encode(csr_push)), yield_context[ec]);
				if (ec)
				{
					LOG_ERR << "async write csr_push to ca.avplayer.org failed, error: " << ec.message();
					return;
				}
				boost::asio::deadline_timer timer(io);
				timer.expires_from_now(boost::posix_time::seconds(1));
				timer.async_wait(yield_context[ec]);
				if (ec)
				{
					LOG_ERR << "async timer wait error: " << ec.message();
					return;
				}
			}
			timer.cancel(ec);

			if (can_read)
			{
				// 返回 cert.
				std::shared_ptr<google::protobuf::Message> msg(async_read_protobuf_message(sock, yield_context));

				if (msg && msg->GetTypeName() == "proto.ca.cert_push" && dynamic_cast<proto::ca::cert_push*>(msg.get())->fingerprint() == rsa_fingerprint)
				{
					io.post(std::bind(handler, 0, dynamic_cast<proto::ca::cert_push*>(msg.get())->cert()));
				}
			}

			io.post(std::bind(handler, 1, std::string()));
		}

		// 暂时的嘛, 等 CA 签名服务器写好了, 这个就可以删了.
		template<class Handler>
		static void async_send_csr(boost::asio::io_service& io, std::string csr, std::string rsa_figureprint, Handler handler)
		{
			// 开协程, 否则编程太麻烦了, 不是么?
			boost::asio::spawn(io, boost::bind(detail::async_send_csr_coro<Handler>, boost::ref(io), csr, rsa_figureprint, handler, _1));
		}

	} // namespace detail


	register_moudle::register_moudle(io_service_pool& io_pool, database& db)
		: m_io_service_pool(io_pool)
		, m_database(db)
	{}

	register_moudle::~register_moudle()
	{}

	void register_moudle::availability_check(google::protobuf::Message* msg, connection_ptr connection, connection_manager&)
	{
		proto::username_availability_check* availabile = dynamic_cast<proto::username_availability_check*>(msg);
		if (!availabile || availabile->user_name().empty())
			return;
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


		m_database.availability_check(user_name, [conn](int result){
			// TODO 返回 json 数据
			auto body = boost::str(boost::format("{\"code\" : \"%d\"}") % result);
			conn->write_response(body);
		});
	}

	void register_moudle::user_register(google::protobuf::Message* msg, connection_ptr connection, connection_manager&)
	{
		proto::user_register* register_msg = dynamic_cast<proto::user_register*>(msg);
		if (!register_msg || register_msg->user_name().empty())
			return;

		// TODO 检查 CSR 证书是否有伪造
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
			return;
		}

		LOG_INFO << "csr fine, start registering";

		// 确定是合法的 CSR 证书, 接着数据库内插
		std::string user_name = register_msg->user_name();
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

					std::shared_ptr<BIO> bio(BIO_new(BIO_s_mem()), BIO_free);
					PEM_write_bio_X509_REQ(bio.get(), csr.get());

					unsigned char* PEM_CSR = NULL;
					auto PEM_CSR_LEN = BIO_get_mem_data(bio.get(), &PEM_CSR);
					std::string pem_csr((char*)PEM_CSR, PEM_CSR_LEN);

					LOG_DBG << pem_csr;

					detail::async_send_csr(m_io_service_pool.get_io_service(), pem_csr, rsa_figureprint,
					[=](int result, std::string cert)
					{
						LOG_INFO << "csr sended";

						if (result == 0)
						{
							// 将 CERT 存入数据库, 向用户返回可以马上登录!
							m_database.update_user_cert(user_name, cert, boost::bind(&register_moudle::proto_write_user_register_response, this,
								proto::user_register_result::REGISTER_SUCCEED, boost::optional<std::string>(cert), connection, _1));
						}
						else if (result == 1)
						{
							// 注册成功, CERT 等待.
							proto_write_user_register_response(proto::user_register_result::REGISTER_SUCCEED_PENDDING_CERT, boost::optional<std::string>(), connection, true);
						}
						else
						{
							//  回滚数据库.
							m_database.delete_user(user_name, boost::bind(&register_moudle::proto_write_user_register_response, this,
								proto::user_register_result::REGISTER_FAILED_CA_DOWN, boost::optional<std::string>(), connection, _1));
						}
					});
				}
				else
				{
					LOG_INFO << "db op failed, register stoped";
					proto_write_user_register_response(proto::user_register_result::REGISTER_FAILED_NAME_TAKEN, boost::optional<std::string>(), connection, false);
				}
			}
		);
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
