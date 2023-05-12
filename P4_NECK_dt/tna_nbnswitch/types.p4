#ifndef _P4_TYPES_
#define _P4_TYPES_

// ----------------------------------------------------------------------------
// Common protocols/types
//-----------------------------------------------------------------------------
#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_ARP  0x0806
#define ETHERTYPE_QINQ 0x88a8
#define ETHERTYPE_VLAN_STAG 0x88a8
#define ETHERTYPE_VLAN 0x8100
#define ETHERTYPE_IPV6 0x86dd

/*
header vlan_tag_h {
    bit<3> pcp;
    bit<1> dei;
    vlan_id_t    vid;
    ether_type_t ether_type;
}
*/

#define IP_PROTOCOLS_ICMP   1
#define IP_PROTOCOLS_IGMP   2
#define IP_PROTOCOLS_IPV4   4
#define IP_PROTOCOLS_TCP    6
#define IP_PROTOCOLS_UDP    17
#define IP_PROTOCOLS_IPV6   41
#define IP_PROTOCOLS_ICMPV6 58

#define VLAN_DEPTH 2

// ----------------------------------------------------------------------------
// Common types
//-----------------------------------------------------------------------------


//-----------------------------------------------------------------------------
// Other Metadata Definitions
//-----------------------------------------------------------------------------

// Ingress metadata
struct ingress_metadata_t {
    bit<1> do_ing_mirroring;
    MirrorId_t ing_mir_ses;
    pkt_type_t pkt_type;
    bit<16> ingress_port;
    bit<8> traffic_type;
}

// Egress metadata
struct egress_metadata_t {
}

header mirror_h {
    pkt_type_t  pkt_type;
    bit<16> ingress_port;
    bit<8> traffic_type;
}

@flexible
header mirror_bridged_metadata_h {
    pkt_type_t pkt_type;
    bit<16> ingress_port;
    bit<8> traffic_type;
}

struct header_t {
    ethernet_h ethernet;
    //vlan_tag_h vlan_tag;
    vlan_tag_h[VLAN_DEPTH] vlan_tag;
    ipv4_h ipv4;
    ipv4_option_h ipv4_option;
    ipv6_h ipv6;
    arp_h arp;
    udp_h udp;
    icmp_h icmp;
    tcp_h tcp;
}

struct digest_a_t {
    bit<16> port;
    bit<3> AVC_pcp;
    bit<1> AVC_dei;
    vlan_id_t AVC_vid;
    bit<3> CVC_pcp;
    bit<1> CVC_dei;
    vlan_id_t CVC_vid;
    mac_addr_t dst_mac;
    mac_addr_t src_mac;
    ipv4_addr_t dst_ip;
    ipv4_addr_t src_ip;
}

struct empty_header_t {}

struct empty_metadata_t {}

#endif /* _P4_TYPES_ */
