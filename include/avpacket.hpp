#pragma once

/*
 * this file contains helper utilities to create avpacket
 */
#include <memory>
#include <openssl/rsa.h>
#include "packet.pb.h"

inline proto::avpacket create_agmp_message_noroutetohost(const proto::av_address& reportee, const proto::av_address& report_to, const proto::av_address& reporter)
{
	proto::agmp agmp;
	agmp.mutable_noroutetohost()->mutable_host()->CopyFrom(reportee);
	proto::avpacket returnpkt;
	returnpkt.mutable_dest()->CopyFrom(report_to);
	returnpkt.mutable_src()->CopyFrom(reporter);
	returnpkt.mutable_upperlayerpotocol()->assign("agmp");
	returnpkt.set_time_to_live(1);
	returnpkt.mutable_payload()->assign(agmp.SerializeAsString());
	return returnpkt;
}

inline proto::avpacket create_agmp_message_ttlout(const proto::av_address& reportee, const proto::av_address& report_to, const proto::av_address& reporter)
{
	proto::agmp agmp;
	agmp.mutable_ttlout()->mutable_host()->CopyFrom(reportee);
	proto::avpacket returnpkt;
	returnpkt.mutable_dest()->CopyFrom(report_to);
	returnpkt.mutable_src()->CopyFrom(reporter);
	returnpkt.mutable_upperlayerpotocol()->assign("agmp");
	returnpkt.set_time_to_live(1);
	returnpkt.mutable_payload()->assign(agmp.SerializeAsString());
	return returnpkt;
}

namespace detail{

	/*
	* 顾名思义，这个是简单 RSA , c++ 封装，专门对付 openssl 烂接口烂源码烂文档这种弱智库的
	*/

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

}

inline std::string encrypt_payload_for_avim(const std::string& payload, std::shared_ptr<RSA> reciver, std::shared_ptr<RSA> sender)
{
	// 第一次加密
	std::string first_pubencode = detail::RSA_public_encrypt(reciver.get(), payload);
	// 第二次签名
	std::string second_sign = detail::RSA_private_encrypt(sender.get(), first_pubencode);

	return second_sign;
}

inline std::string decrypt_payload_from_avim(const std::string& payload, std::shared_ptr<RSA> reciver, std::shared_ptr<RSA> sender)
{
	// 第一阶段解密，先使用发送者的公钥解密
	std::string stage1decypted = detail::RSA_public_decrypt(sender.get(), payload);
	// 第二阶段解密，用自己的私钥解密
	auto data = detail::RSA_private_decrypt(reciver.get(), stage1decypted);
	return data;
}

inline proto::avpacket create_message_from_payload(const proto::av_address& dest, const proto::av_address& src, const std::string& payload)
{
	proto::avpacket returnpkt;
	returnpkt.set_time_to_live(2);
	returnpkt.mutable_dest()->CopyFrom(dest);
	returnpkt.mutable_src()->CopyFrom(src);
	returnpkt.mutable_upperlayerpotocol()->assign("avim");
	returnpkt.mutable_payload()->assign(payload);
	return returnpkt;
}

