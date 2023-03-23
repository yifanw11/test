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
            ETHERTYPE_VLAN: parse_vlan_avc;
            default : accept;
        }
    }

    state parse_vlan_avc {
        pkt.extract(hdr.vlan_dual_tag);
        transition select(hdr.vlan_dual_tag.ether_type_ctag) {
            ETHERTYPE_IPV4 : parse_ipv4;
            ETHERTYPE_IPV6 : accept;
            ETHERTYPE_ARP : parse_arp;
            default : accept;
        }
    }

    //state parse_vlan_cvc {
    //    pkt.extract(hdr.vlan_tag);
    //    transition select(hdr.vlan_tag.ether_type) {
    //        ETHERTYPE_IPV4 : parse_ipv4;
    //        ETHERTYPE_IPV6 : accept;
    //        ETHERTYPE_ARP : parse_arp;
    //        default : accept;
    //   }
    //}

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
    Mirror() mirror; // mirror发生在deparser
    apply {
        if (ig_dprsr_md.mirror_type == MIRROR_TYPE_I2E) {
            mirror.emit<mirror_h>(ig_md.ing_mir_ses, {ig_md.pkt_type,ig_md.ingress_port,ig_md.traffic_type});
        }

        //pkt.emit(hdr) sends the packet out. 只有egress port没有pkt.emit的话, packet是无法发出的.
        pkt.emit(hdr);
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
