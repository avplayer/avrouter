#pragma once

/*
 * this file contains helper utilities to create avpacket
 */

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

