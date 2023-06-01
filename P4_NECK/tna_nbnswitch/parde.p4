#include "headers.p4"
#include "types.p4"
#include "util.p4"


// ---------------------------------------------------------------------------
// Ingress Parser
// ---------------------------------------------------------------------------
parser IngressParser(
    packet_in                        pkt,
    out header_t                     hdr,
    out ingress_metadata_t           ig_md,
    out ingress_intrinsic_metadata_t ig_intr_md) {

    TofinoIngressParser() tofino_parser;

    state start {
        tofino_parser.apply(pkt, ig_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            ETHERTYPE_IPV6 : accept;
            ETHERTYPE_ARP : parse_arp;
            ETHERTYPE_VLAN: parse_vlan;
            ETHERTYPE_QINQ : parse_vlan;
            default : accept;
        }
    }

    state parse_vlan {
        pkt.extract(hdr.vlan_tag.next);
        transition select(hdr.vlan_tag.last.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            ETHERTYPE_IPV6 : accept;
            ETHERTYPE_ARP : parse_arp;
            ETHERTYPE_VLAN : parse_vlan;
            default : accept;
        }
    }


    state parse_arp {
        pkt.extract(hdr.arp);
        transition accept;
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition accept;

    }

}

// ---------------------------------------------------------------------------
// Ingress Deparser
// ---------------------------------------------------------------------------
control IngressDeparser(
    packet_out                                   pkt,
    inout header_t                               hdr,
    in ingress_metadata_t                        ig_md,
    in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
    Digest<digest_a_t>() digest_a;
    apply {
        if (ig_dprsr_md.digest_type == 1) {
            digest_a.pack({ig_md.ingress_port,
            hdr.vlan_tag[0].pcp, hdr.vlan_tag[0].dei, hdr.vlan_tag[0].vid,
            hdr.vlan_tag[1].pcp, hdr.vlan_tag[1].dei, hdr.vlan_tag[1].vid,
            hdr.ethernet.dst_addr, hdr.ethernet.src_addr, hdr.ipv4.dst_addr, hdr.ipv4.src_addr});
        }

        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.vlan_tag[0]);
        pkt.emit(hdr.vlan_tag[1]);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.ipv4_option);
        pkt.emit(hdr.ipv6);
        pkt.emit(hdr.arp);
        pkt.emit(hdr.udp);
        pkt.emit(hdr.icmp);
        pkt.emit(hdr.tcp);
    }
}

// ---------------------------------------------------------------------------
// Egress parser
// ---------------------------------------------------------------------------
parser EgressParser(
    packet_in                       pkt,
    out header_t                    hdr,
    out egress_metadata_t           eg_md,
    out egress_intrinsic_metadata_t eg_intr_md) {

    TofinoEgressParser() tofino_parser;

    state start {
        tofino_parser.apply(pkt, eg_intr_md);
        transition accept;
    }

}

// ---------------------------------------------------------------------------
// Egress Deparser
// ---------------------------------------------------------------------------
control EgressDeparser(
    packet_out                                  pkt,
    inout header_t                              hdr,
    in egress_metadata_t                        eg_md,
    in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {

    apply {
        pkt.emit(hdr);
    }

}
