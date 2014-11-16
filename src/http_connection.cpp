﻿#include "http_connection.hpp"
#include "escape_string.hpp"
#include "io_service_pool.hpp"
#include "logging.hpp"
#include "http_server.hpp"

namespace av_router {

	http_connection::http_connection(boost::asio::io_service& io, http_server& serv, http_connection_manager* connection_man)
		: m_io_service(io)
		, m_server(serv)
		, m_socket(io)
		, m_connection_manager(connection_man)
		, m_abort(false)
	{}

	http_connection::~http_connection()
	{
		LOG_DBG << "destruct http connection!";
	}

	void http_connection::start()
	{
		m_request.consume(m_request.size());
		m_abort = false;

		boost::system::error_code ignore_ec;
		m_socket.set_option(tcp::no_delay(true), ignore_ec);
		if (ignore_ec)
			LOG_ERR << "http_connection::start, Set option to nodelay, error message :" << ignore_ec.message();

		boost::asio::async_read_until(m_socket, m_request, "\r\n\r\n",
			boost::bind(&http_connection::handle_read_headers,
				shared_from_this(),
				boost::asio::placeholders::error,
				boost::asio::placeholders::bytes_transferred
			)
		);
	}

	void http_connection::stop()
	{
		boost::system::error_code ignore_ec;
		m_abort = true;
		m_socket.close(ignore_ec);
	}

	tcp::socket& http_connection::socket()
	{
		return m_socket;
	}

	void http_connection::handle_read_headers(const boost::system::error_code& error, std::size_t bytes_transferred)
	{
		// 出错处理.
		if (error || m_abort)
		{
			m_connection_manager->stop(shared_from_this());
			return;
		}

		// 复制http头缓冲区.
		std::vector<char> buffer;
		buffer.resize(m_request.size() + 1);
		buffer[m_request.size()] = 0;
		m_request.sgetn(&buffer[0], m_request.size());

		boost::tribool result;
		boost::tie(result, boost::tuples::ignore) = m_request_parser.parse(m_http_request, buffer.begin(), buffer.end());
		if (!result || result == boost::indeterminate)
		{
			// 断开.
			m_connection_manager->stop(shared_from_this());
			return;
		}
		m_request.consume(bytes_transferred);

		m_http_request.normalise();

		if (m_http_request.method == "post")
		{
			// NOTE: 限制 body 的大小到 64KiB
			auto content_length = m_http_request.content_length;
			if (content_length == 0 || content_length >= 65536)
			{
				// 断开, POST 必须要有 content_length
				// 暴力断开没事, 首先浏览器不会发这种垃圾请求
				// 第二, 如果在 nginx 后面, 暴力断开 nginx 会返回 503 错误
				m_connection_manager->stop(shared_from_this());
				return;
			}

			// 读取 body
			boost::asio::async_read(m_socket, m_request, boost::asio::transfer_exactly(content_length),
				boost::bind(&http_connection::handle_read_body,
					shared_from_this(),
					boost::asio::placeholders::error,
					boost::asio::placeholders::bytes_transferred
				)
			);
		}
		else
		{
			m_server.handle_request(m_http_request, shared_from_this());

			if (m_http_request.keep_alive)
			{
				// 继续读取下一个请求.
				boost::asio::async_read_until(m_socket, m_request, "\r\n\r\n",
					boost::bind(&http_connection::handle_read_headers,
						shared_from_this(),
						boost::asio::placeholders::error,
						boost::asio::placeholders::bytes_transferred
					)
				);
			}
		}
	}

	void http_connection::handle_read_body(const boost::system::error_code& error, std::size_t bytes_transferred)
	{
		// 出错处理.
		if (error || m_abort)
		{
			m_connection_manager->stop(shared_from_this());
			return;
		}

		m_http_request.body.resize(bytes_transferred);
		m_request.sgetn(&m_http_request.body[0], bytes_transferred);

		m_server.handle_request(m_http_request, shared_from_this());

		if (m_http_request.keep_alive)
		{
			// 继续读取下一个请求.
			boost::asio::async_read_until(m_socket, m_request, "\r\n\r\n",
				boost::bind(&http_connection::handle_read_headers,
					shared_from_this(),
					boost::asio::placeholders::error,
					boost::asio::placeholders::bytes_transferred
				)
			);
		}
	}

	void http_connection::handle_write_http(const boost::system::error_code& error, std::size_t bytes_transferred)
	{
		// 出错处理.
		if (error || m_abort)
		{
			m_connection_manager->stop(shared_from_this());
			return;
		}

		BOOST_ASSERT(m_response.size() == 0);

		boost::asio::async_write(m_socket, m_response,
			boost::bind(&http_connection::handle_write_http,
				shared_from_this(),
				boost::asio::placeholders::error,
				boost::asio::placeholders::bytes_transferred
			)
		);
	}
}
