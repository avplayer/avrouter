﻿#include <boost/bind.hpp>
#include <boost/date_time.hpp>
using namespace boost::posix_time;

#include "http_server.hpp"

namespace av_router {

	http_server::http_server(io_service_pool& ios, unsigned short port, std::string address /*= "0.0.0.0"*/)
		: m_io_service_pool(ios)
		, m_io_service(ios.get_io_service())
		, m_acceptor(m_io_service)
		, m_is_listen(false)
		, m_timer(m_io_service)
	{
		boost::asio::ip::tcp::resolver resolver(m_io_service);
		std::ostringstream port_string;
		port_string.imbue(std::locale("C"));
		port_string << port;
		boost::system::error_code ignore_ec;
		boost::asio::ip::tcp::resolver::query query(address, port_string.str());
		boost::asio::ip::tcp::resolver::iterator endpoint_iterator = resolver.resolve(query, ignore_ec);
		if (ignore_ec)
		{
			LOG_ERR << "HTTP Server bind address, DNS resolve failed: " << ignore_ec.message() << ", address: " << address;
			return;
		}
		boost::asio::ip::tcp::endpoint endpoint = *endpoint_iterator;
		m_acceptor.open(endpoint.protocol(), ignore_ec);
		if (ignore_ec)
		{
			LOG_ERR << "HTTP Server open protocol failed: " << ignore_ec.message();
			return;
		}
		m_acceptor.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true), ignore_ec);
		if (ignore_ec)
		{
			LOG_ERR << "HTTP Server set option failed: " << ignore_ec.message();
			return;
		}
		m_acceptor.bind(endpoint, ignore_ec);
		if (ignore_ec)
		{
			LOG_ERR << "HTTP Server bind failed: " << ignore_ec.message() << ", address: " << address;
			return;
		}
		m_acceptor.listen(boost::asio::socket_base::max_connections, ignore_ec);
		if (ignore_ec)
		{
			LOG_ERR << "HTTP Server listen failed: " << ignore_ec.message();
			return;
		}
		m_is_listen = true;
		m_timer.expires_from_now(seconds(1));
		m_timer.async_wait(boost::bind(&http_server::on_tick, this, boost::asio::placeholders::error));
	}

	http_server::~http_server()
	{}

	void http_server::start()
	{
		if (!m_is_listen) return;
		m_connection = boost::make_shared<http_connection>(boost::ref(m_io_service_pool.get_io_service()), &m_connection_manager);
		m_acceptor.async_accept(m_connection->socket(), boost::bind(&http_server::handle_accept, this, boost::asio::placeholders::error));
	}

	void http_server::stop()
	{
		m_acceptor.close();
		m_connection_manager.stop_all();
		boost::system::error_code ignore_ec;
		m_timer.cancel(ignore_ec);
	}

	void http_server::handle_accept(const boost::system::error_code& error)
	{
		if (!m_acceptor.is_open() || error)
		{
			if (error)
				LOG_ERR << "http_server::handle_accept, error: " << error.message();
			return;
		}

		m_connection_manager.start(m_connection);

		m_connection = boost::make_shared<http_connection>(boost::ref(m_io_service_pool.get_io_service()), &m_connection_manager);
		m_acceptor.async_accept(m_connection->socket(), boost::bind(&http_server::handle_accept, this, boost::asio::placeholders::error));
	}

	void http_server::on_tick(const boost::system::error_code& error)
	{
		if (error) return;

		m_connection_manager.tick();

		m_timer.expires_from_now(seconds(1));
		m_timer.async_wait(boost::bind(&http_server::on_tick, this, boost::asio::placeholders::error));
	}

}
