#include <iostream>

#include <boost/program_options.hpp>
namespace po = boost::program_options;

#include "database.hpp"
#include "io_service_pool.hpp"
#include "login_moudle.hpp"
#include "register_moudle.hpp"
#include "forward_moudle.hpp"
#include "router_server.hpp"
#include "http_server.hpp"
#include "ca_module.hpp"

// 测试数据库.
#include <soci.h>
#include <soci-config.h>
#include <session.h>
#include <connection-pool.h>
#include <postgresql/soci-postgresql.h>

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

using namespace av_router;

static void terminator(io_service_pool& ios, router_server& serv, login_moudle& login)
{
	login.quit();
	serv.stop();
	ios.stop();
}

// 定义在 root_ca.cpp.
extern const char* avim_root_ca_certificate_string;

int main(int argc, char** argv)
{
	OpenSSL_add_all_algorithms();
	try
	{
		unsigned short server_port = 0;
		unsigned short http_port = 0;
		int num_threads = 0;
		int pool_size = 0;
		std::string db_server;
		std::string db_port;
		std::string db_user;
		std::string db_password;
		std::string db_name;
		std::string db_timeout;
		std::string db_application_name;
		std::string key_filename, cert_filename;

		po::options_description desc("options");
		desc.add_options()
			("help,h", "help message")
			("version", "current avrouter version")
			("port", po::value<unsigned short>(&server_port)->default_value(24950), "avrouter listen port")
			("httpport", po::value<unsigned short>(&http_port)->default_value(24951), "http RPC listen port")
			("thread", po::value<int>(&num_threads)->default_value(boost::thread::hardware_concurrency()), "threads")
			("pool", po::value<int>(&pool_size)->default_value(32), "connection pool size")
			("db_server", po::value<std::string>(&db_server)->default_value("127.0.0.1"), "postresql database server addr")
			("db_port", po::value<std::string>(&db_port)->default_value("4321"), "postresql database server port")
			("db_user", po::value<std::string>(&db_user)->default_value("postgres"), "postresql database server user")
			("db_password", po::value<std::string>(&db_password)->default_value("avrouter"), "postresql database server password")
			("db_name", po::value<std::string>(&db_name)->default_value("avim"), "postresql database name")
			("db_timeout", po::value<std::string>(&db_timeout)->default_value("3"), "postresql database timeout")
			("db_application_name", po::value<std::string>(&db_application_name)->default_value("3"), "postresql database application_name")
			;

		po::variables_map vm;
		po::store(po::parse_command_line(argc, argv, desc), vm);
		po::notify(vm);

		if (vm.count("help"))
		{
			std::cout << desc << "\n";
			return 0;
		}

		// 组合连接串.
		std::string connection_string = "hostaddr = \'" + db_server + "' "
			"port = '" + db_port + "' "
			"user = '" + db_user + "' "
			"password = '" + db_password + "' "
			"dbname = '" + db_name + "' "
			"connect_timeout = '" + db_timeout + "' "
			"application_name = '" + db_application_name + "'";

		// 指定个数据库并发链接.
		soci::connection_pool db_pool(pool_size);

		try
		{
			// 创建数据库连接池.
			for (size_t i = 0; i != pool_size; ++i)
			{
				soci::session& sql = db_pool.at(i);
				// 直接指定数据库后端, 避免寻找dll而失败, 这里指定为postgresql数据库后端.
				sql.open(soci::postgresql, connection_string);
			}
		}
		catch (soci::soci_error& ec)
		{
			LOG_ERR << "create database connection pool failed, error: " << ec.what();
		}

		boost::shared_ptr<BIO> bp(BIO_new_mem_buf((void*)avim_root_ca_certificate_string, strlen(avim_root_ca_certificate_string)), BIO_free);
		boost::shared_ptr<X509> root_cert(PEM_read_bio_X509(bp.get(), 0, 0, 0), X509_free);
		bp.reset();

		// 指定线程并发数.
		io_service_pool io_pool(num_threads);
		// 创建服务器.
		router_server router_serv(io_pool, server_port);
		// 创建 http 服务器.
		http_server http_serv(io_pool, http_port);

		database async_database(io_pool.get_io_service(), db_pool);

		// 创建登陆处理模块.
		login_moudle moudle_login(io_pool, async_database, root_cert.get());
		forward_moudle forward_packet(io_pool);
		register_moudle moudle_register(io_pool, async_database);
		ca_moudle module_ca(io_pool);

		// 添加注册模块处理.
		router_serv.add_message_process_moudle("proto.username_availability_check",
			boost::bind(&register_moudle::availability_check, &moudle_register, _1, _2, _3));
		router_serv.add_message_process_moudle("proto.user_register",
			boost::bind(&register_moudle::user_register, &moudle_register, _1, _2, _3));

		// 添加登陆处理模块.
		router_serv.add_message_process_moudle("proto.client_hello", boost::bind(&login_moudle::process_hello_message, &moudle_login, _1, _2, _3));
		router_serv.add_message_process_moudle("proto.login", boost::bind(&login_moudle::process_login_message, &moudle_login, _1, _2, _3));

		// 添加包的转发处理模块.
		router_serv.add_message_process_moudle("proto.avpacket", boost::bind(&forward_moudle::process_packet, &forward_packet, _1, _2, _3));
		router_serv.add_connection_process_moudle("proto.avpacket", boost::bind(&forward_moudle::connection_notify, &forward_packet, _1, _2, _3));

		router_serv.add_message_process_moudle("proto.ca.ca_announce", boost::bind(&ca_moudle::process_ca_announce, &module_ca, _1, _2, _3));
		router_serv.add_message_process_moudle("proto.ca.csr_request", boost::bind(&ca_moudle::process_csr_request, &module_ca, _1, _2, _3));

		// 启动服务器.
		router_serv.start();

		// 愚弄傻逼, 让他们以为服务器是 jsp 的.
		http_serv.add_uri_handler("/username_availability_check.jsp", bind(&register_moudle::availability_check_httpd, &moudle_register, _1, _2, _3));
		// 启动 HTTPD
		http_serv.start();

		// Ctrl+c异步处理退出.
		boost::asio::signal_set terminator_signal(io_pool.get_io_service());
		terminator_signal.add(SIGINT);
		terminator_signal.add(SIGTERM);
#if defined(SIGQUIT)
		terminator_signal.add(SIGQUIT);
#endif // defined(SIGQUIT)
		terminator_signal.async_wait(boost::bind(&terminator, boost::ref(io_pool), boost::ref(router_serv), boost::ref(moudle_login)));

		// 开始启动整个系统事件循环.
		io_pool.run();
	}
	catch (std::exception& e)
	{
		LOG_ERR << "main exception: " << e.what();
		return -1;
	}
	return 0;
}
