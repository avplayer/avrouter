#include "database.hpp"
#include "login_moudle.hpp"
#include "user.pb.h"

#include <openssl/dh.h>
#include <openssl/aes.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>


namespace av_router {

	inline std::string RSA_public_decrypt(RSA * rsa, const std::string & from)
	{
		const int keysize = RSA_size(rsa);
		const int inputlen = static_cast<int>(from.length());

		std::vector<unsigned char> block(keysize);
		std::string result;

		for (int i = 0; i < from.length(); i += keysize)
		{
			int flen = std::min(keysize, inputlen - i);
			auto resultsize = RSA_public_decrypt(flen, (uint8_t*)&from[i], &block[0], rsa, RSA_PKCS1_PADDING);
			result.append((char*)block.data(), resultsize);
		}
		return result;
	}

	class cert_validater
		: boost::noncopyable
	{
	public:
		cert_validater(X509* ca)
		{
			m_store = X509_STORE_new();

			X509_STORE_add_cert(m_store, ca);
			X509_STORE_set_default_paths(m_store);
		}

		~cert_validater()
		{
			X509_STORE_free(m_store);
		}

		bool operator()(X509* cert)
		{
			return verity(cert);
		}

		bool verity(X509* cert)
		{
			boost::shared_ptr<X509_STORE_CTX> storeCtx(X509_STORE_CTX_new(), X509_STORE_CTX_free);
			X509_STORE_CTX_init(storeCtx.get(), m_store, cert, NULL);
			X509_STORE_CTX_set_flags(storeCtx.get(), X509_V_FLAG_CB_ISSUER_CHECK);
			return X509_verify_cert(storeCtx.get()) ? true : false;
		}

	private:
		X509_STORE* m_store;
	};


	login_moudle::login_moudle(io_service_pool& io_pool, database& db, X509* root_ca_cert)
		: m_io_service_pool(io_pool)
		, m_database(db)
		, m_timer(io_pool.get_io_service())
		, m_root_ca_cert(root_ca_cert)
	{
		continue_timer();
	}

	login_moudle::~login_moudle()
	{}

	bool login_moudle::process_login_message(google::protobuf::Message* msg, connection_ptr connection, connection_manager&)
	{
		proto::login* login = dynamic_cast<proto::login*>(msg);
		std::map<ptrdiff_t, login_state>::iterator iter = m_log_state.find(reinterpret_cast<ptrdiff_t>(connection.get()));
		if (iter == m_log_state.end())
			return false;

		std::string login_check_key = boost::any_cast<std::string>(connection->retrive_module_private("login_check_key"));

		const unsigned char* in = (unsigned char*)login->user_cert().data();

		boost::shared_ptr<X509> user_cert(d2i_X509(NULL, &in, static_cast<long>(login->user_cert().length())), X509_free);
		connection->store_module_private("user_cert", user_cert);

		unsigned char* common_name_ptr = NULL;
		auto cert_name = X509_get_subject_name(user_cert.get());
		auto cert_entry = X509_NAME_get_entry(cert_name, X509_NAME_get_index_by_NID(cert_name, NID_commonName, 0));
		ASN1_STRING* entry_data = X509_NAME_ENTRY_get_data(cert_entry);
		auto strlengh = ASN1_STRING_to_UTF8(&common_name_ptr, entry_data);
		std::string common_name((char*)common_name_ptr, strlengh);
		OPENSSL_free(common_name_ptr);
		LOG_DBG << "CN: " << common_name;

		// 首先验证用户的证书
		bool user_cert_valid = cert_validater(m_root_ca_cert)(user_cert.get());

		// 证书验证通过后, 用用户的公钥解密 encryped_radom_key 然后比较是否是 login_check_key
		// 如果是, 那么此次就不是冒名登录.
		auto evp_key = X509_get_pubkey(user_cert.get());
		auto user_rsa_pubkey = EVP_PKEY_get1_RSA(evp_key);
		EVP_PKEY_free(evp_key);

		auto decrypted_key = RSA_public_decrypt(user_rsa_pubkey, login->encryped_radom_key());
		RSA_free(user_rsa_pubkey);
		bool user_rsa_key_valid = (decrypted_key == login_check_key);

		proto::login_result result;

		// TODO 接着到数据库查询是否阻止登录, 是不是帐号没钱了不给登录了 etc
		if(user_cert_valid && user_rsa_key_valid)
		{
			// 登陆成功.
			login_state& state = iter->second;
			state.status = login_state::succeed;

			result.set_result(proto::login_result::LOGIN_SUCCEED);

			// 记录登录用户名
			connection->store_module_private("user_name", common_name);
		}
		else
		{
			// 登录失败
			result.set_result(proto::login_result::PUBLIC_KEY_MISMATCH);
		}

		std::string response = encode(result);
		connection->write_msg(response);
		return true;
	}

	bool login_moudle::process_hello_message(google::protobuf::Message* hellomsg, connection_ptr connection, connection_manager&)
	{
		proto::client_hello* client_hello = dynamic_cast<proto::client_hello*>(hellomsg);
		login_state& state = m_log_state[reinterpret_cast<ptrdiff_t>(connection.get())];
		state.status = login_state::hello;

		std::vector<uint8_t> shared_key;
		DH* dh = DH_new();
		unsigned char bin_key[512] = { 0 };

		// 生成随机数然后返回 m_dh->p ，让客户端去算共享密钥.
		DH_generate_parameters_ex(dh, 64, DH_GENERATOR_5, NULL);
		dh->g = BN_bin2bn((const unsigned char *)client_hello->random_g().data(), static_cast<long>(client_hello->random_g().length()), dh->g);
		dh->p = BN_bin2bn((const unsigned char *)client_hello->random_p().data(), static_cast<long>(client_hello->random_p().length()), dh->p);

		DH_generate_key(dh);

		proto::server_hello server_hello;
		server_hello.set_servername("avrouter");
		server_hello.set_version(001);
		int size = BN_bn2bin(dh->pub_key, bin_key);
		server_hello.set_random_pub_key(static_cast<const void*>(bin_key), size);
		server_hello.set_server_av_address("router@avplayer.org");

		shared_key.resize(DH_size(dh));
		BIGNUM* client_pubkey = BN_bin2bn((const unsigned char *)client_hello->random_pub_key().data(), static_cast<long>(client_hello->random_pub_key().length()), NULL);
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
		return true;
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
