#include <core.p4>
#include <tna.p4>
#include "const.p4"
#include "parde.p4"
//const.p4定义: ingress_metadata_t ig_md包含:
// 1. traffic_type(即traffic_t, 0/1/2/3)
// 2. do_ing_mirroring(0/1, 1 means mirrored)
// 3. ing_mir_ses
// 4. pkt_type
// 5. ingress_port

// 其中, pkt_type有3种possible values:
// const pkt_type_t PKT_TYPE_NORMAL = 1;
// const pkt_type_t PKT_TYPE_MIRROR = 2;
// const pkt_type_t PKT_TYPE_CLOUD_ARP = 3;

//另外, do_ing_mirroring


// ---------------------------------------------------------------------------
// Ingress control block
// ---------------------------------------------------------------------------
control Ingress(
    inout header_t                                  hdr,
    inout ingress_metadata_t                        ig_md,
    in ingress_intrinsic_metadata_t                 ig_intr_md,
    in ingress_intrinsic_metadata_from_parser_t     ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t       ig_tm_md) {


    bit<32> temp_ip;
    bool dst_cloud;
    bool cloud_enabled;

    // 定义direct counters
    @name(".counter_ing")
    DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) counter_ing;

    @name(".counter_egr")
    DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) counter_egr;

    @name(".counter_cloud_ing")
    DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) counter_cloud_ing;

    @name(".counter_cloud_egr")
    DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) counter_cloud_egr;

    @name(".drop")
    action drop() {
        ig_dprsr_md.drop_ctl = 0x1;
        exit;
    }

    @name(".nop")
    action nop(){}


    @name(".unk_source")
    action unk_source(){
        ig_md.traffic_type = UNKNOWN;
    }

    //在action中counter.count()
    @name(".hit_counting_table_ing")
    action hit_counting_table_ing(){
        counter_ing.count();
    }

    @name(".hit_counting_table_egr")
    action hit_counting_table_egr(){
        counter_egr.count();
    }

    @name(".hit_counting_table_cloud_ing")
    action hit_counting_table_cloud_ing(){
        counter_cloud_ing.count();
    }

    @name(".hit_counting_table_cloud_egr")
    action hit_counting_table_cloud_egr(){
        counter_cloud_egr.count();
    }

    // 看traffic是来自USER还是RSP还是CLOUD
    // traffic type有4种:
    // const bit<2> USER = 0;
    // const bit<2> RSP = 1;
    // const bit<2> CLOUD = 2;
    // UNKNOWN = 3
    @name(".detect_source")
    action detect_source(bit<2> traffic){
        ig_md.traffic_type = (bit<8>)traffic;
    }

    @name(".set_egr_port")
    action set_egr_port(PortId_t dst_port) {
        ig_tm_md.ucast_egress_port = dst_port;
    }


    // when access to cloud, need to strip vlan tag
    // when cloud to access, need to add vlan tag


    @name(".set_src_mac")
    action set_src_mac(mac_addr_t src_mac) {
        hdr.ethernet.src_addr = src_mac;
    }

    @name(".set_dst_mac")
    action set_dst_mac(mac_addr_t dst_mac) {
        hdr.ethernet.dst_addr = dst_mac;
    }

    // cloud_enabled是个global variable. bool cloud_enabled;
    @name(".set_cloud_access")
    action set_cloud_access() {
        cloud_enabled = true;
    }

    @name(".no_access")
    action no_access() {
        cloud_enabled = false;
    }

    // dst_cloud是个global variable. bool dst_cloud;
    @name(".invalid_cloud_dst")
    action invalid_cloud_dst() {
        dst_cloud = false;
    }

    @name(".valid_cloud_dst")
    action valid_cloud_dst() {
        dst_cloud = true;
    }


    //当subscriber src MAC, src IP, ingress port有一项unknown的时候,
    //需要mirror packet然后send back to control plane for MAC learning
    // const mirror_type_t MIRROR_TYPE_I2E = 1;
    // const mirror_type_t MIRROR_TYPE_E2E = 2;
    // MIRROR_TYPE_E2E = 2的packet在deparser会被mirror
    action unknown_source () {
        ig_md.do_ing_mirroring = 1;
        ig_md.ing_mir_ses = (bit<10>)ig_intr_md.ingress_port;
        ig_dprsr_md.mirror_type = MIRROR_TYPE_I2E;
        ig_md.pkt_type = PKT_TYPE_MIRROR;
        ig_md.ingress_port = (bit<16>)ig_intr_md.ingress_port;
    }

    // provide switch MAC to clouds
    action cloud_arp () {
        ig_tm_md.ucast_egress_port = ig_intr_md.ingress_port;
        hdr.arp.spa_addr = hdr.arp.tpa_addr;
        // tpa: target protocol address, 即之前存的temp_ip(sender protocol address)
        hdr.arp.tpa_addr = temp_ip;
        hdr.arp.tha_addr = hdr.arp.sha_addr;
        hdr.arp.sha_addr = P4_SWITCH_MAC;
        hdr.arp.opcode = (bit<16>)2;
        hdr.ethernet.dst_addr = hdr.ethernet.src_addr;
        hdr.ethernet.src_addr = P4_SWITCH_MAC;
    }


    // rsp port routing table
    // e.g. packets arriving at the RSP port(simple downstream).
    @name(".port_forward")
    table port_forward {
        key = {
            // custom_ig_md.l4_dst_port是ip header中的dst port, 而ig_intr_md.ingress_port是switch的internal port
            ig_intr_md.ingress_port : exact @name("ingress_port");
        }
        actions = {
            set_egr_port;
            @defaultonly nop;
        }
        const default_action = nop;
    }


    @name(".counting_table_ing")
    table counting_table_ing {
         key = {
            ig_intr_md.ingress_port : exact @name("ingress_port_count");
        }
        actions = {
            hit_counting_table_ing;
            @defaultonly nop;
        }
        const default_action = nop;
        // associate direct counter with this table
        counters = counter_ing;
     }

    @name(".counting_table_egr")
    table counting_table_egr {
         key = {
            ig_tm_md.ucast_egress_port : exact @name("egress_port_count");
        }
        actions = {
            hit_counting_table_egr;
            @defaultonly nop;
        }
        const default_action = nop;
        counters = counter_egr;
     }

    @name(".counting_table_cloud_ing")
    table counting_table_cloud_ing {
         key = {
            ig_intr_md.ingress_port : exact @name("ingress_port_count");
        }
        actions = {
            hit_counting_table_cloud_ing;
            @defaultonly nop;
        }
        const default_action = nop;
        counters = counter_cloud_ing;
     }

    @name(".counting_table_cloud_egr")
    table counting_table_cloud_egr {
         key = {
            ig_tm_md.ucast_egress_port : exact @name("egress_port_count");
        }
        actions = {
            hit_counting_table_cloud_egr;
            @defaultonly nop;
        }
        const default_action = nop;
        counters = counter_cloud_egr;
     }

    // port_type table用于set traffic_t metadata based on ingress port. 但是什么port有什么traffic_t是control plane的logic.
    // traffic_t 有3种:
    // const bit<2> USER = 0;
    // const bit<2> RSP = 1;
    // const bit<2> CLOUD = 2;
    @name(".port_type")
    table port_type {
        key = {
            ig_intr_md.ingress_port : exact @name("ingress_port_type");
        }
        actions = {
            detect_source;
            unk_source;
        }
        const default_action = unk_source;
    }

    //AVC CVC tag in front end, but we use ip prefix to see if subscriber has cloud access
    @name(".cloud_access")
    table cloud_access {
        key = {
            hdr.ipv4.src_addr : lpm @name("src_ip");
        }
        actions = {
            set_cloud_access;
            no_access;
        }
        //设置default action使得所有没有match的packet都default进行no_access action
        const default_action = no_access;
    }


    // When cloud sends packets to user, check if source IP is a valid cloud,
    // if not, drop packet.
    @name(".cloud_validity")
    table cloud_validity {
        key = {
            hdr.ipv4.src_addr : lpm @name("src_ip");
        }
        actions = {
            nop;
            drop;
        }
        const default_action = drop;
    }


    // Don't want cloud response to go to unauthorised subscribers
    @name(".reverse_cloud_access")
    table reverse_cloud_access {
        key = {
            hdr.ipv4.dst_addr : lpm @name("dst_ip_access");
        }
        actions = {
            // set and reset variable + if(cloud_enabled)或drop/nop哪个更好?
            set_cloud_access;
            no_access;
        }
        const default_action = no_access;
    }

    // cloud port and access port routing table,
    // 当packet来自access时, set egress port to be appropriate cloud port based on dest cloud IP.
    // 若dst cloud IP不是valid cloud address的话, set egress port as RSP port. 但这个逻辑在control plane处理
    // 当packet来自cloud时, set egress port to be appropriate access port based on dest access IP.
    @name(".ipv4_forward")
    table ipv4_forward {
        key = {
            hdr.ipv4.dst_addr: lpm @name("dst_ip");
        }
        actions = {
            set_egr_port;
            nop;
        }
        const default_action = nop;
    }

    // This table is used to check if user is sending to a cloud, if not, then it sends to RSP BNG
    // Also used for counting # of cloud packets, if valid_cloud_dst, invoke counting_table_cloud_egr table
    @name(".check_dst_cloud")
    table check_dst_cloud {
        key = {
            hdr.ipv4.dst_addr: lpm @name("cloud_dst_ip");
        }
        actions = {
            valid_cloud_dst;
            invalid_cloud_dst;
        }
        const default_action = invalid_cloud_dst;
    }

    @name(".update_src_mac")
    table update_src_mac {
        key = {
            hdr.ipv4.dst_addr: lpm @name("src_ip_mac");
        }
        actions = {
            set_src_mac;
            nop;
        }
        const default_action = nop;
    }

    @name(".update_dst_mac")
    table update_dst_mac {
        key = {
            hdr.ipv4.dst_addr: lpm @name("dst_ip_mac");
        }
        actions = {
            set_dst_mac;
            nop;
        }
        const default_action = nop;
    }

    // learn_mac learn的是both subscriber和RSP的MAC
    @name(".learned_sources_user")
    table learned_sources_user {
        key = {
            hdr.ipv4.src_addr: exact @name("known_ipv4");
            hdr.ethernet.src_addr : exact @name("known_mac");
            ig_intr_md.ingress_port : exact @name("known_ingress_port");

        }
        actions = {
            // do nothing if user is known
            nop;
            // mirror and do MAC learn if user is unknown
            unknown_source;
        }
        const default_action = unknown_source;
    }

    // 收到response from RSP to subscribers的时候, 也要learn RSP的MAC
    @name(".learned_sources_rsp")
    table learned_sources_rsp {
        key = {
            hdr.ipv4.dst_addr: exact @name("known_ipv4_rsp");
            hdr.ethernet.src_addr : exact @name("known_mac_rsp");
            ig_intr_md.ingress_port : exact @name("known_ingress_port_rsp");

        }
        actions = {
            nop;
            unknown_source;
        }
        const default_action = unknown_source;
    }

    // cloud询问switch的MAC address
    // arp_ip就是swicth的IP address, needs to be provided by control plane
    // packet will egress on the same port that it was ingressed
    @name(".arp_response")
    table arp_response {
        key = {
            // tpa: target protocol address, 即arp索求MAC address的ip address
            hdr.arp.tpa_addr: exact @name("arp_ip");
        }
        actions = {
            nop;
            cloud_arp;
        }
        const default_action = nop;
    }


    //swicth需要forward host ARP request and RSP BNG ARP response
    @name(".arp_forward")
    table arp_forward {
        key = {
            // tpa: target protocol address, 即arp索求MAC address的ip address
            hdr.arp.spa_addr: exact @name("arp_spa_ip");
            hdr.arp.tpa_addr: exact @name("arp_tpa_ip");
        }
        actions = {
            set_egr_port;
            nop;
        }
        const default_action = nop;
    }


    //packet通过这样的方式来pipeline通过多个match action tables.
    apply {
        ig_dprsr_md.digest_type = 1;
        ig_md.ingress_port = (bit<16>) ig_intr_md.ingress_port;

        counting_table_ing.apply();
        counting_table_cloud_ing.apply();
        port_type.apply();

        if (ig_md.traffic_type == USER) {
            // Handles ARP requests from user to RSP
            // either dst cloud or dst RSP, ARP all go to RSP
            if ((hdr.ethernet.ether_type == ETHERTYPE_ARP || hdr.vlan_tag[1].ether_type == ETHERTYPE_ARP)) {
                port_forward.apply();
            }
            // Handles direct cloud connectivity
            else{
                // if going to the cloud(previous ipv4_forward no match), check user's cloud access
                cloud_access.apply();
                // check if the destination is a cloud IP address
                check_dst_cloud.apply();
                // route to the cloud
                if (dst_cloud){
                    //strip VLAN tag for eligible direct cloud traffic
                    hdr.vlan_tag[0].setInvalid();
                    hdr.vlan_tag[1].setInvalid();
                    hdr.ethernet.ether_type = ETHERTYPE_IPV4;

                    update_src_mac.apply();
                    update_dst_mac.apply();
                    ipv4_forward.apply();
                }
                // default forward to RSP BNG
                else {
                    port_forward.apply();
                }
            }
        }

        else if (ig_md.traffic_type == RSP){
            // Handles ARP responses from RSP to user and normal downstream traffic from RSP(same subnet so MAC change not applicable)
            port_forward.apply();
        }

        else if (ig_md.traffic_type == CLOUD){
            // Handles ARP requests from Cloud to switch
            if ((hdr.ethernet.ether_type == ETHERTYPE_ARP || hdr.vlan_tag[1].ether_type == ETHERTYPE_ARP)) {
                arp_response.apply();
                // sets egress port to the same as the ingress port
                port_forward.apply();
            }
            // Handles normal downstream traffic from Cloud, off net so MAC change needed
            else{
                // populate vlan c-tag
                hdr.vlan_tag[0].pcp = NBN_AVC_PCP;
                hdr.vlan_tag[0].dei = NBN_AVC_DEI;
                hdr.vlan_tag[0].vid = NBN_AVC_VLAN_ID;
                hdr.vlan_tag[0].ether_type = ETHERTYPE_VLAN;

                // populate vlan s-tag
                hdr.vlan_tag[1].pcp = NBN_CVC_PCP;
                hdr.vlan_tag[1].dei = NBN_CVC_DEI;
                hdr.vlan_tag[1].vid = NBN_CVC_VLAN_ID;
                hdr.vlan_tag[1].ether_type = ETHERTYPE_IPV4;

                // Mark ethertype as vlan
                hdr.ethernet.ether_type = ETHERTYPE_VLAN;

                // insert vlan tags
                hdr.vlan_tag[0].setValid();
                hdr.vlan_tag[1].setValid();

                // Drop packets to users that don't have direct cloud connectivity
                reverse_cloud_access.apply();
                #if (cloud_enabled == true) {
                    update_src_mac.apply();
                    update_dst_mac.apply();
                    ipv4_forward.apply();
                #}
            }
        }

        counting_table_egr.apply();
        counting_table_cloud_egr.apply();
    }
}




// ---------------------------------------------------------------------------
// Egress control block
// ---------------------------------------------------------------------------
control Egress(
    inout header_t                                    hdr,
    inout egress_metadata_t                           eg_md,
    in    egress_intrinsic_metadata_t                 eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t     eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t    eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t eg_oport_md) {

    apply {}

}


// ---------------------------------------------------------------------------------------
// main package block
// note that the Pipeline must be named "pipe" for the P4Runtime shell scripts to work
// ---------------------------------------------------------------------------------------

Pipeline(
    IngressParser(),
    Ingress(),
    IngressDeparser(),
    EgressParser(),
    Egress(),
    EgressDeparser()
) pipe;

// instantiate the package Switch with a single pipeline
Switch(pipe) main;


