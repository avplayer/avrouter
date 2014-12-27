#include "database.hpp"
#include <boost/thread/future.hpp>
#include <boost/thread.hpp>
#include "logging.hpp"

#include <libpq-fe.h>
#include <soci-backend.h>
#include <postgresql/soci-postgresql.h>

namespace av_router {

	static const std::string db_name = "avim";
	static const std::string db_user_table = "avim_user";

	static std::string pg_escape_bytea(const soci::session& ses, const std::string bytea)
	{
		auto pgcon = dynamic_cast<soci::postgresql_session_backend*>(
			const_cast<soci::session&>(ses).get_backend())->conn_;
		std::size_t escaped_len = 0;
		std::shared_ptr<unsigned char> escaped_chars;
		escaped_chars.reset(PQescapeByteaConn(pgcon, (const uint8_t*)bytea.data(), bytea.length(), &escaped_len), PQfreemem);
		return std::string((const char*)escaped_chars.get(), escaped_len);
	}

	database::database(boost::asio::io_service& io, soci::connection_pool& db_pool)
		: m_io_service(io)
		, m_db_pool(db_pool)
	{
		boost::async(boost::launch::async,
			[this]()
			{
				soci::session ses(m_db_pool);
				try
				{
					// 检查数据库是否存在, 如果不存在, 则创建数据库.
					ses << "CREATE DATABASE " << db_name;
				}
				catch (soci::soci_error const& err)
				{
					LOG_ERR << err.what();
				}
				try
				{
					// 在这里创建数据表!
					ses << "CREATE TABLE " << db_user_table <<
						"(user_id text NOT NULL,"	// 用户id, 必填.
						"mail text,"				// mail, 可选.
						"phone text,"				// 电话, 可选.
						"cert bytea,"					// 证书信息, 可选.
						"public_key bytea NOT NULL,"	// 公钥信息, 必填.
						"private_key bytea,"		// 私钥, 可选.
						"allow boolean,"			// 是否允许登陆.
						"CONSTRAINT avim_user_pkey PRIMARY KEY(user_id)"
						")"
						"WITH("
						"OIDS = FALSE"
						");"
						"ALTER TABLE avim_user "
						"OWNER TO postgres;";
				}
				catch (soci::soci_error const& err)
				{
					LOG_ERR << err.what();
				}
				// ...
			}
		);
	}

	database::~database()
	{}

	void database::availability_check(const std::string& user_id, result_handler handler)
	{
		boost::async(boost::launch::async,
			[this, user_id, handler]()
			{
				// 在这里检查数据库中是否存在这个用户名, 检查到的话, 调用对应的handler.
				std::string user;
				soci::indicator user_name_indicator;

				soci::session ses(m_db_pool);
				try
				{
					ses << "SELECT user_id FROM avim_user WHERE user_id = :name", soci::use(user_id), soci::into(user, user_name_indicator);
				}
				catch (soci::soci_error const& err)
				{
					LOG_ERR << err.what();
					m_io_service.post(boost::bind(handler, false));
					return;
				}
				if (!ses.got_data() || user_name_indicator != soci::i_ok)
				{
					m_io_service.post(boost::bind(handler, true));
					return;
				}
				m_io_service.post(boost::bind(handler, false));
			}
		);
	}

	void database::register_user(std::string user_id, std::string pubkey, std::string email, std::string telephone, result_handler handler)
	{
		boost::async(boost::launch::async,
			[user_id, pubkey, email, telephone, handler, this]()
			{
				// 在这里检查数据库中是否存在这个用户名, 检查到的话, 调用对应的handler.
				std::string user;
				soci::indicator user_name_indicator;

				soci::session ses(m_db_pool);
				try
				{
					// 检查名字没占用, 然后插入个新的
					ses << "SELECT user_id FROM avim_user WHERE user_id = :name", soci::use(user_id), soci::into(user, user_name_indicator);
					if (ses.got_data() && user_name_indicator == soci::i_ok)
					{
						m_io_service.post(boost::bind(handler, false));
						return;
					}
					// 插入数据库
					ses << "INSERT INTO avim_user (user_id, public_key, mail, phone) VALUES (:name, :pubkey, :email , :phone)"
						, soci::use(user_id), soci::use(pg_escape_bytea(ses, pubkey)), soci::use(email), soci::use(telephone);

					m_io_service.post(boost::bind(handler, true));
					return;
				}
				catch (soci::soci_error const& err)
				{
					LOG_ERR << err.what();
					m_io_service.post(boost::bind(handler, false));
					return;
				}

				m_io_service.post(boost::bind(handler, false));
			}
		);
	}

	void database::delete_user(const std::string& user_id, database::result_handler handler)
	{
		boost::async(boost::launch::async,
			[=]()
			{
				// 在这里检查数据库中是否存在这个用户名, 检查到的话, 调用对应的handler.
				soci::session ses(m_db_pool);
				try
				{
					// 检查名字没占用, 然后插入个新的, 必须是个原子操作
					ses << "DELETE FROM avim_user WHERE user_id = :name", soci::use(user_id);
					m_io_service.post(boost::bind(handler, true));
					return;
				}
				catch (soci::soci_error const& err)
				{
					LOG_ERR << err.what();
					m_io_service.post(boost::bind(handler, false));
					return;
				}
			}
		);
	}

	void database::update_user_cert(const std::string& user_id, const std::string& cert, database::result_handler handler)
	{
		boost::async(boost::launch::async,
			[=]()
			{
				// 在这里检查数据库中是否存在这个用户名, 检查到的话, 调用对应的handler.
				soci::session ses(m_db_pool);
				try
				{
					std::string cert_escapted = pg_escape_bytea(ses, cert);
					// 检查名字没占用, 然后插入个新的, 必须是个原子操作
					ses << "UPDATE avim_user SET cert = :cert WHERE user_id = :name", soci::use(cert_escapted), soci::use(user_id);
					m_io_service.post(boost::bind(handler, true));
					return;
				}
				catch (soci::soci_error const& err)
				{
					LOG_ERR << err.what();
					m_io_service.post(boost::bind(handler, false));
					return;
				}
			}
		);
	}

}
