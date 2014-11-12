﻿#include "database.hpp"
#include "login_moudle.hpp"
#include "user.pb.h"

#include <openssl/dh.h>
#include <openssl/aes.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>

inline std::string RSA_public_encrypt(RSA * rsa, const std::string & from)
{
	std::string result;
	const int keysize = RSA_size(rsa);
	std::vector<unsigned char> block(keysize);
	const int chunksize = keysize  - RSA_PKCS1_PADDING_SIZE;
	int inputlen = from.length();

	for(int i = 0 ; i < inputlen; i+= chunksize)
	{
		auto resultsize = RSA_public_encrypt(std::min(chunksize, inputlen - i), (uint8_t*) &from[i],  &block[0], (RSA*) rsa, RSA_PKCS1_PADDING);
		result.append((char*)block.data(), resultsize);
	}
	return result;
}

inline std::string RSA_private_decrypt(RSA * rsa, const std::string & from)
{
	std::string result;
	const int keysize = RSA_size(rsa);
	std::vector<unsigned char> block(keysize);

	for(int i = 0 ; i < from.length(); i+= keysize)
	{
		auto resultsize = RSA_private_decrypt(std::min<int>(keysize, from.length() - i), (uint8_t*) &from[i],  &block[0], rsa, RSA_PKCS1_PADDING);
		result.append((char*)block.data(), resultsize);
	}
	return result;
}

inline std::string RSA_private_encrypt(RSA * rsa, const std::string & from)
{
	std::string result;
	const int keysize = RSA_size(rsa);
	std::vector<unsigned char> block(keysize);
	const int chunksize = keysize  - RSA_PKCS1_PADDING_SIZE;
	int inputlen = from.length();

	for(int i = 0 ; i < from.length(); i+= chunksize)
	{
		int flen = std::min<int>(chunksize, inputlen - i);

		std::fill(block.begin(),block.end(), 0);

		auto resultsize = RSA_private_encrypt(
			flen,
			(uint8_t*) &from[i],
			&block[0],
			rsa,
			RSA_PKCS1_PADDING
		);
		result.append((char*)block.data(), resultsize);
	}
	return result;
}

inline std::string RSA_public_decrypt(RSA * rsa, const std::string & from)
{
	std::string result;
	const int keysize = RSA_size(rsa);
	std::vector<unsigned char> block(keysize);

	int inputlen = from.length();

	for(int i = 0 ; i < from.length(); i+= keysize)
	{
		int flen = std::min(keysize, inputlen - i);

		auto resultsize = RSA_public_decrypt(
			flen,
			(uint8_t*) &from[i],
			&block[0],
			rsa,
			RSA_PKCS1_PADDING
		);
		result.append((char*)block.data(), resultsize);
	}
	return result;
}

namespace av_router {

	login_moudle::login_moudle(av_router::io_service_pool& io_poll)
		: m_io_service_pool(io_poll)
		, m_timer(io_poll.get_io_service())
	{
		continue_timer();
	}

	login_moudle::~login_moudle()
	{}

	void login_moudle::process_login_message(google::protobuf::Message* msg, connection_ptr connection, connection_manager&, database&)
	{
		proto::login* login = dynamic_cast<proto::login*>(msg);
		std::map<ptrdiff_t, login_state>::iterator iter = m_log_state.find(reinterpret_cast<ptrdiff_t>(connection.get()));
		if (iter == m_log_state.end())
			return;

		std::string login_check_key = boost::any_cast<std::string>(
			connection->retrive_module_private("login_check_key"));

		const unsigned char * in = (unsigned char *) login->user_cert().data();

		boost::shared_ptr<X509> user_cert(d2i_X509(NULL, &in , login->user_cert().length()), X509_free);
		connection->store_module_private("user_cert", user_cert);

		// TODO 首先验证用户的证书


		// 证书验证通过后, 用用户的公钥解密 encryped_radom_key 然后比较是否是 login_check_key
		// 如果是, 那么此次就不是冒名登录

		// 接着到数据库查询是否阻止登录, 是不是帐号没钱了不给登录了 etc

		auto evPkey = X509_get_pubkey(user_cert.get());
		auto user_rsa_pubkey = EVP_PKEY_get1_RSA(evPkey);
		EVP_PKEY_free(evPkey);

		auto decrypted_key = RSA_public_decrypt(user_rsa_pubkey, login->encryped_radom_key());
		RSA_free(user_rsa_pubkey);

		proto::login_result result;
		if(decrypted_key == login_check_key)
		{
			// 登陆成功.
			login_state& state = iter->second;
			state.status = login_state::succeed;

			result.set_result(proto::login_result::LOGIN_SUCCEED);
		}
		else
		{
			// 登录失败
			result.set_result(proto::login_result::PUBLIC_KEY_MISMATCH);
		}

		std::string response = encode(result);
		connection->write_msg(response);
	}

	void login_moudle::process_hello_message(google::protobuf::Message* hellomsg, connection_ptr connection, connection_manager&, database&)
	{
		proto::client_hello* client_hello = dynamic_cast<proto::client_hello*>(hellomsg);
		login_state& state = m_log_state[reinterpret_cast<ptrdiff_t>(connection.get())];
		state.status = login_state::hello;

		std::vector<uint8_t> shared_key;
		DH* dh = DH_new();
		unsigned char bin_key[512] = { 0 };

		// 生成随机数然后返回 m_dh->p ，让客户端去算共享密钥.
		DH_generate_parameters_ex(dh, 64, DH_GENERATOR_5, NULL);
		dh->g = BN_bin2bn((const unsigned char *)client_hello->random_g().data(), client_hello->random_g().length(), dh->g);
		dh->p = BN_bin2bn((const unsigned char *)client_hello->random_p().data(), client_hello->random_p().length(), dh->p);

		DH_generate_key(dh);

		proto::server_hello server_hello;
		server_hello.set_servername("avrouter");
		server_hello.set_version(001);
		server_hello.set_random_pub_key((const void*)bin_key, BN_bn2bin(dh->pub_key, bin_key));
		server_hello.set_server_av_address("router@avplayer.org");

		shared_key.resize(DH_size(dh));
		BIGNUM* client_pubkey = BN_bin2bn((const unsigned char *)client_hello->random_pub_key().data(), client_hello->random_pub_key().length(), NULL);
		DH_compute_key(&shared_key[0], client_pubkey, dh);
		BN_free(client_pubkey);
		DH_free(dh);

		std::string key;
		char buf[16] = { 0 };
		for (int i = 0; i < shared_key.size(); ++i)
		{
			sprintf(buf, "%x%x", (shared_key[i] >> 4) & 0xf, shared_key[i] & 0xf);
			key += buf;
		}

		LOG_DBG << "key: " << key;
		std::string response = encode(server_hello);

		connection->store_module_private("symmetickey", shared_key);
		connection->store_module_private("login_check_key", server_hello.random_pub_key());

		// 发回消息.
		connection->write_msg(response);
	}

	void login_moudle::on_tick(const boost::system::error_code& error)
	{
		if (error)
			return;

		continue_timer();
	}

	void login_moudle::continue_timer()
	{
		m_timer.expires_from_now(seconds(1));
		m_timer.async_wait(boost::bind(&login_moudle::on_tick, this, boost::asio::placeholders::error));
	}

	void login_moudle::quit()
	{
		boost::system::error_code ignore_ec;
		m_timer.cancel(ignore_ec);
	}

}
