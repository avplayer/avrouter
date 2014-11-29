#include <boost/smart_ptr.hpp>
#include <boost/any.hpp>
#include "router_server.hpp"
#include "connection.hpp"
#include "logging.hpp"
#include "serialization.hpp"

namespace av_router {

	connection::connection(boost::asio::io_service& io, router_server& serv, connection_manager* connection_man)
		: m_io_service(io)
		, m_server(serv)
		, m_socket(io)
		, m_connection_manager(connection_man)
		, m_abort(false)
	{
	}

	connection::~connection()
	{
		LOG_DBG << "destruct connection: " << this;
	}

	void connection::start()
	{
		LOG_DBG << "start the connection: " << this;

		m_response.consume(m_response.size());
		m_abort = false;

		boost::system::error_code ignore_ec;
		m_socket.set_option(tcp::no_delay(true), ignore_ec);
		if (ignore_ec)
			LOG_ERR << "connection::start, Set option to nodelay, error message :" << ignore_ec.message();

		m_server.do_connection_notify(0, shared_from_this());

		boost::asio::async_read(m_socket, m_response, boost::asio::transfer_exactly(4),
			boost::bind(&connection::handle_read_header,
				shared_from_this(),
				boost::asio::placeholders::error,
				boost::asio::placeholders::bytes_transferred
			)
		);
	}

	void connection::stop()
	{
		m_server.do_connection_notify(1, shared_from_this());
		boost::system::error_code ignore_ec;
		m_abort = true;
		m_socket.close(ignore_ec);
	}

	tcp::socket& connection::socket()
	{
		return m_socket;
	}

	void connection::close()
	{
		m_connection_manager->stop(shared_from_this());
	}

	void connection::handle_read_header(const boost::system::error_code& error, std::size_t bytes_transferred)
	{
		// 出错处理.
		if (error || m_abort)
		{
			close();
			return;
		}

		// 复制出来,避免影响m_response中接收到的数据, 也就4个字节.
		boost::asio::streambuf tempbuf;
		boost::asio::buffer_copy(tempbuf.prepare(m_response.size()), m_response.data());
		tempbuf.commit(m_response.size());

		// 获得包长度, 转为主机字节序.
		int packet_length = 0;
		tempbuf.sgetn(reinterpret_cast<char*>(&packet_length), sizeof(packet_length));
		packet_length = ntohl(packet_length);

		if (packet_length > 64 * 1024) // 过大的数据包, 此客户端有问题, 果然断开.
		{
			close();
			return;
		}

		// 继续读取packet_length长度的数据.
		boost::asio::async_read(m_socket, m_response, boost::asio::transfer_exactly(packet_length),
			boost::bind(&connection::handle_read_body,
				shared_from_this(),
				boost::asio::placeholders::error,
				boost::asio::placeholders::bytes_transferred
			)
		);
	}

	void connection::handle_read_body(const boost::system::error_code& error, std::size_t bytes_transferred)
	{
		// 出错处理.
		if (error || m_abort)
		{
			close();
			return;
		}

		// 读取到body并处理.
		int packet_length = static_cast<int>(bytes_transferred + 4);
		std::string message;
		message.resize(packet_length);
		m_response.sgetn(&message[0], packet_length);
		m_response.consume(packet_length);

		// 解析包.
		google::protobuf::Message* msg = decode(message);
		if (!msg)
		{
			close();
			return;
		}
		boost::scoped_ptr<google::protobuf::Message> defer(msg);

		LOG_DBG << this << " recv: " << msg->GetTypeName();

		// 处理这个消息.
		if (!m_server.do_message(msg, shared_from_this()))
			return;

		// 继续下一个消息头读取.
		boost::asio::async_read(m_socket, m_response, boost::asio::transfer_exactly(4),
			boost::bind(&connection::handle_read_header,
				shared_from_this(),
				boost::asio::placeholders::error,
				boost::asio::placeholders::bytes_transferred
			)
		);

	}

	void connection::handle_write(const boost::system::error_code& error)
	{
		// 通知writr完成.
		m_write_queue.front().handler(error);

		if (!error)
		{
			m_write_queue.pop_front();
			if (!m_write_queue.empty())
			{
				boost::asio::async_write(m_socket,
					boost::asio::buffer(m_write_queue.front().msg.data(),
					m_write_queue.front().msg.length()),
					boost::bind(&connection::handle_write,
					shared_from_this(),
					boost::asio::placeholders::error
					)
				);
			}
		}
		else
		{
			close();
		}
	}

	void connection::write_msg(const std::string& msg, const msg_handler& handler)
	{
		m_io_service.post(boost::bind(&connection::do_write, shared_from_this(), msg,handler));
	}

	void connection::do_write(std::string msg, msg_handler handler)
	{
		bool write_in_progress = !m_write_queue.empty();
		msg_pack_t pack = { msg, handler };
		m_write_queue.push_back(pack);
		if (!write_in_progress)
		{
			boost::asio::async_write(m_socket,
				boost::asio::buffer(m_write_queue.front().msg.data(),
				m_write_queue.front().msg.length()),
				boost::bind(&connection::handle_write,
				shared_from_this(),
				boost::asio::placeholders::error
				)
			);
		}

	}

	boost::any connection::retrive_module_private(const std::string& module_name)
	{
		return m_module_private_info_ptrs[module_name];
	}

	void connection::store_module_private(const std::string& module_name, const boost::any& ptr)
	{
		m_module_private_info_ptrs[module_name] = ptr;
	}

}
