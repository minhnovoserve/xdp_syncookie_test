#ifndef __COMMON_XDP_H
#define __COMMON_XDP_H
enum xdp_packet_type{
	xdp_udp_ntp = 0,
	xdp_udp_ntp_ipv6,
	xdp_udp_dns,
	xdp_udp_dns_ipv6,
	xdp_udp_quic,
	xdp_udp_quic_ipv6,
	xdp_udp_unknown,
	xdp_udp_unknown_ipv6,
	xdp_tcp_http,
	xdp_tcp_http_ipv6,
	xdp_tcp_https,
	xdp_tcp_https_ipv6,
	xdp_tcp_dns,
	xdp_tcp_dns_ipv6,
	xdp_tcp_unknown,
	xdp_tcp_unknown_ipv6,
	xdp_icmp,
	xdp_icmp_ipv6,
	xdp_ip,
	xdp_ipv6,
	xdp_unknown

};
enum reasons{
	no_rule = 0,
	not_ip,
	drop_fragment,
	blocked_subnet,
	invalid_packet_saddr_eq_daddr,
	invalid_port,
	poor_dns_query,
	ntp_query,
	server_server_connection,
	alt_http,
	block_iptv,
	invalid_icmp
};
struct pack_stat{
    __u8 action;
    __u8 xdp_type;
    __u64 num;
	__u8 reason;
};
#endif