# This script inserts the entries that the NORDIC app will not insert (because there is no MAC learning)
# # In main_grpc.py these entries are also inserted


import logging
import os
import bfruntime_pb2 as bfruntime_pb2
import client as gc
import yaml
import threading
import time
import ipaddress


logger = logging.getLogger('bfrtpython.' + __name__)
if not len(logger.handlers):
    logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.INFO)
binary_name = "tofino"
client_id = 0
device_id = 0
sde_install = '/home/yifan/Intel/bf-sde-9.6.0/install'
# sde_install = os.environ["SDE_INSTALL"]
base_pick_path = sde_install + "/" + "share/" + binary_name + "pd"
base_put_path = "/home/yifan/forwarding_configs"
logger.debug("\nbase_pick_path=%s \nbase_put_path=%s", base_pick_path, base_put_path)


def create_path_bf_rt(base_path, p4_name_to_use):
    return base_path + "/" + p4_name_to_use + "/bf-rt.json"


def create_path_context(base_path, p4_name_to_use, profile_name):
    return base_path + "/" + p4_name_to_use + "/" + profile_name + "/context.json"


def create_path_tofino(base_path, p4_name_to_use, profile_name):
    return base_path + "/" + p4_name_to_use + "/" + profile_name + "/" + binary_name + ".bin"


def set_fwd_pipeline(p4_name, profile_name, interface):
    logger.info("Sending verify and warm_init_begin and warm_init_end for %s", p4_name)
    p4_name_to_put = p4_name_to_pick = p4_name
    profile_name_to_put = profile_name_to_pick = profile_name
    pipe_scope = [0, 1, 2, 3]
    action = bfruntime_pb2.SetForwardingPipelineConfigRequest.VERIFY_AND_WARM_INIT_BEGIN_AND_END
    profile_info = gc.ProfileInfo(profile_name_to_put,
                                  create_path_context(base_pick_path, p4_name_to_pick, profile_name_to_pick),
                                  create_path_tofino(base_pick_path, p4_name_to_pick, profile_name_to_pick),
                                  pipe_scope)
    forwarding_config = gc.ForwardingConfig(p4_name_to_put,
                                            create_path_bf_rt(base_pick_path, p4_name_to_pick),
                                            [profile_info])
    success = interface.send_set_forwarding_pipeline_config_request(
        action,
        base_put_path,
        [forwarding_config]
    )

    if not success:
        raise RuntimeError("SetForwardingPipelineRequest failed")


# 1-12 access
# 13 - 18 cloud
# 19 - 30 RSP
# $DEV_PORT is D_P in the switch CLI
def configure_ports(port_table):
    target = gc.Target()
    # Access User - port 1/0 *TX 10G
    port_table.entry_add(
    target,
    [port_table.make_key([gc.KeyTuple('$DEV_PORT', 132)])],#This means an exact match
    [port_table.make_data([gc.DataTuple('$SPEED', str_val="BF_SPEED_10G"),
                           gc.DataTuple('$FEC', str_val="BF_FEC_TYP_NONE"),
                           gc.DataTuple('$PORT_ENABLE', bool_val=True),
                           gc.DataTuple('$PORT_DIR', str_val="PM_PORT_DIR_DEFAULT"),
                           gc.DataTuple('$AUTO_NEGOTIATION', str_val="PM_AN_FORCE_DISABLE")])]
    )

    # RSP BNG - port 2/0 *TX 10G
    port_table.entry_add(
        target,
        [port_table.make_key([gc.KeyTuple('$DEV_PORT', 140)])],#This means an exact match
        [port_table.make_data([gc.DataTuple('$SPEED', str_val="BF_SPEED_10G"),
                               gc.DataTuple('$FEC', str_val="BF_FEC_TYP_NONE"),
                               gc.DataTuple('$PORT_ENABLE', bool_val=True),
                               gc.DataTuple('$PORT_DIR', str_val="PM_PORT_DIR_DEFAULT"),
                               gc.DataTuple('$AUTO_NEGOTIATION', str_val="PM_AN_FORCE_DISABLE")])]
        )

    # direct cloud - port 5/0 *TX 10G
    port_table.entry_add(
        target,
        [port_table.make_key([gc.KeyTuple('$DEV_PORT', 164)])],#This means an exact match
        [port_table.make_data([gc.DataTuple('$SPEED', str_val="BF_SPEED_10G"),
                               gc.DataTuple('$FEC', str_val="BF_FEC_TYP_NONE"),
                               gc.DataTuple('$PORT_ENABLE', bool_val=True),
                               gc.DataTuple('$PORT_DIR', str_val="PM_PORT_DIR_DEFAULT"),
                               gc.DataTuple('$AUTO_NEGOTIATION', str_val="PM_AN_FORCE_DISABLE")])]
        )

    #  - port 21/0 *TX and RX 25G
    port_table.entry_add(
        target,
        [port_table.make_key([gc.KeyTuple('$DEV_PORT', 36)])],#This means an exact match
        [port_table.make_data([gc.DataTuple('$SPEED', str_val="BF_SPEED_25G"),
                               gc.DataTuple('$FEC', str_val="BF_FEC_TYP_NONE"),
                               gc.DataTuple('$PORT_ENABLE', bool_val=True),
                               gc.DataTuple('$PORT_DIR', str_val="PM_PORT_DIR_DEFAULT"),
                               gc.DataTuple('$AUTO_NEGOTIATION', str_val="PM_AN_FORCE_DISABLE")])]
        )

    #  - port 22/0 *TX and RX 25G
    port_table.entry_add(
        target,
        [port_table.make_key([gc.KeyTuple('$DEV_PORT', 44)])],#This means an exact match
        [port_table.make_data([gc.DataTuple('$SPEED', str_val="BF_SPEED_25G"),
                               gc.DataTuple('$FEC', str_val="BF_FEC_TYP_NONE"),
                               gc.DataTuple('$PORT_ENABLE', bool_val=True),
                               gc.DataTuple('$PORT_DIR', str_val="PM_PORT_DIR_DEFAULT"),
                               gc.DataTuple('$AUTO_NEGOTIATION', str_val="PM_AN_FORCE_DISABLE")])]
        )

    return target


def port_type_add_entry(target, table, ing_port, traffic_type):
    table.entry_add(
        target,
        [table.make_key(
            [gc.KeyTuple('ingress_port_type', ing_port)])],
        [table.make_data(
            [gc.DataTuple('traffic', traffic_type)],
            'detect_source')])


# function to add entry into port_forward table
def port_forward_add_entry(target, table, ing_port, egr_port):
    table.entry_add(
        target,
        [table.make_key(
            [gc.KeyTuple('ingress_port', ing_port)])],
        [table.make_data(
            [gc.DataTuple('dst_port', egr_port)],
            'set_egr_port')])


def arp_forward_add_entry(target, table, ing_port, egr_port):
    table.entry_add(
        target,
        [table.make_key(
            [gc.KeyTuple('ingress_port', ing_port)])],
        [table.make_data(
            [gc.DataTuple('dst_port', egr_port)],
            'set_egr_port')])


## this function is an old way of writing port_forward_add_entry()
# def port_forward_add_entry(target, _BfRtInfo_object, table_name, key, data):
#     port_forward_table = _BfRtInfo_object.table_get(table_name)
#     key_list = [port_forward_table.make_key([gc.KeyTuple('ingress_port', key)])]
#     data_list = [port_forward_table.make_data([gc.DataTuple('dst_port', data)],
#                                              "set_egr_port")]
#     port_forward_table.entry_add(target, key_list, data_list)


# function to manipulate cloud_access table
def cloud_access_add_entry(target, table, src_ip, prefix_len):
    table.info.key_field_annotation_add("src_ip", "ipv4")
    key_list = [table.make_key([gc.KeyTuple("src_ip", src_ip, prefix_len=prefix_len)])]
    data_list = [table.make_data([], "set_cloud_access")]
    table.entry_add(target, key_list, data_list)


def cloud_validity_add_entry(target, table, src_ip, prefix_len):
    table.info.key_field_annotation_add("src_ip", "ipv4")
    key_list = [table.make_key([gc.KeyTuple("src_ip", src_ip, prefix_len=prefix_len)])]
    data_list = [table.make_data([], "nop")]
    table.entry_add(target, key_list, data_list)


def reverse_cloud_access_add_entry(target, table, dst_ip, prefix_len):
    table.info.key_field_annotation_add("dst_ip_access", "ipv4")
    key_list = [table.make_key([gc.KeyTuple("dst_ip_access", dst_ip, prefix_len=prefix_len)])]
    data_list = [table.make_data([], "set_cloud_access")]
    table.entry_add(target, key_list, data_list)


def check_dst_cloud_add_entry(target, table, dst_ip, prefix_len):
    table.info.key_field_annotation_add("cloud_dst_ip", "ipv4")
    key_list = [table.make_key([gc.KeyTuple("cloud_dst_ip", dst_ip, prefix_len=prefix_len)])]
    data_list = [table.make_data([], "valid_cloud_dst")]
    table.entry_add(target, key_list, data_list)


# function to manipulate ipv4_forward table
def ipv4_forward_add_entry(target, table, dst_ip, prefix_len, dst_port):
    table.info.key_field_annotation_add("dst_ip", "ipv4")
    key_list = [table.make_key([gc.KeyTuple("dst_ip", dst_ip, prefix_len=prefix_len)])]
    data_list = [table.make_data([gc.DataTuple('dst_port', dst_port)], "set_egr_port")]
    table.entry_add(target, key_list, data_list)


def update_src_mac_add_entry(target, table, dst_ip, prefix_len, src_mac):
    # ipv4: make_data can accept string of format "10.12.14.16".
    # mac: make_data can accept string of format "4f:3d:2c:1a:00:ff"
    table.info.key_field_annotation_add("src_ip_mac", "ipv4")
    table.info.data_field_annotation_add("src_mac", "set_src_mac", "mac")
    key_list = [table.make_key([gc.KeyTuple("src_ip_mac", dst_ip, prefix_len=prefix_len)])]
    data_list = [table.make_data([gc.DataTuple('src_mac', src_mac)], "set_src_mac")]
    table.entry_add(target, key_list, data_list)


def update_dst_mac_add_entry(target, table, dst_ip, prefix_len, dst_mac):
    table.info.key_field_annotation_add("dst_ip_mac", "ipv4")
    table.info.data_field_annotation_add("dst_mac", "set_dst_mac", "mac")
    key_list = [table.make_key([gc.KeyTuple("dst_ip_mac", dst_ip, prefix_len=prefix_len)])]
    data_list = [table.make_data([gc.DataTuple('dst_mac', dst_mac)], "set_dst_mac")]
    table.entry_add(target, key_list, data_list)


def arp_response_add_entry(target, table, dst_virtual_ip):
    table.info.key_field_annotation_add('arp_ip', 'ipv4')
    table.entry_add(
        target,
        [table.make_key(
            [gc.KeyTuple('arp_ip', dst_virtual_ip)])],
        [table.make_data([], 'cloud_arp')])


def arp_forward_add_entry(target, table, src_ip, dst_ip, egr_port):
    table.info.key_field_annotation_add('arp_spa_ip', 'ipv4')
    table.info.key_field_annotation_add('arp_tpa_ip', 'ipv4')
    table.entry_add(
        target,
        [table.make_key(
            [gc.KeyTuple('arp_spa_ip', src_ip),
             gc.KeyTuple('arp_tpa_ip', dst_ip)])],
        [table.make_data(
            [gc.DataTuple('dst_port', egr_port)],
            'set_egr_port')])


def counting_table_ing_add_entry(target, table, ing_port, c_bytes=0, c_pkts=0):
    table.entry_add(
        target,
        [table.make_key(
            [gc.KeyTuple('ingress_port_count', ing_port)])],
        [table.make_data(
            [gc.DataTuple('$COUNTER_SPEC_BYTES', c_pkts),
             gc.DataTuple('$COUNTER_SPEC_PKTS', c_bytes)],
            'hit_counting_table_ing')])


def counting_table_ing_get_entry(target, table, ing_port):
    resp = table.entry_get(target,
                           [table.make_key([gc.KeyTuple('ingress_port_count', ing_port)])],
                           {"from_hw": True},
                           table.make_data([gc.DataTuple("$COUNTER_SPEC_BYTES"),
                                            gc.DataTuple("$COUNTER_SPEC_PKTS")],
                                           'hit_counting_table_ing', get=True)
                           )
    return resp


def counting_table_egr_add_entry(target, table, egr_port, c_bytes=0, c_pkts=0):
    table.entry_add(
        target,
        [table.make_key(
            [gc.KeyTuple('egress_port_count', egr_port)])],
        [table.make_data(
            [gc.DataTuple('$COUNTER_SPEC_BYTES', c_pkts),
             gc.DataTuple('$COUNTER_SPEC_PKTS', c_bytes)],
            'hit_counting_table_egr')])


def counting_table_egr_get_entry(target, table, egr_port):
    resp = table.entry_get(target,
                           [table.make_key([gc.KeyTuple('egress_port_count', egr_port)])],
                           {"from_hw": True},
                           table.make_data([gc.DataTuple("$COUNTER_SPEC_BYTES"),
                                            gc.DataTuple("$COUNTER_SPEC_PKTS")],
                                           'hit_counting_table_egr', get=True)
                           )
    return resp


def counting_table_ing_cld_add_entry(target, table, ing_port, c_bytes=0, c_pkts=0):
    key_list = [table.make_key([gc.KeyTuple('ingress_port_count', ing_port)])]
    data_list = [
        table.make_data([gc.DataTuple('$COUNTER_SPEC_BYTES', c_pkts), gc.DataTuple('$COUNTER_SPEC_PKTS', c_bytes)],
                        'hit_counting_table_cloud_ing')]
    resp = table.entry_add(target, key_list, data_list)
    return resp


def counting_table_egr_cld_add_entry(target, table, egr_port, c_bytes=0, c_pkts=0):
    key_list = [table.make_key([gc.KeyTuple('egress_port_count', egr_port)])]
    data_list = [
        table.make_data([gc.DataTuple('$COUNTER_SPEC_BYTES', c_pkts), gc.DataTuple('$COUNTER_SPEC_PKTS', c_bytes)],
                        'hit_counting_table_cloud_egr')]
    resp = table.entry_add(target, key_list, data_list)
    return resp


def read_counter(resp):
    data_dict = next(resp)[0].to_dict()
    print(data_dict)
    recv_pkts = data_dict["$COUNTER_SPEC_PKTS"]
    print(recv_pkts)
    recv_bytes = data_dict["$COUNTER_SPEC_BYTES"]
    print(recv_bytes)


# This function clears all entries of a table in one go
def clear_table_entry(target, _BfRtInfo_object, table_name):
    table = _BfRtInfo_object.table_get(table_name)
    table.entry_clear(target)


# Current use case built specifically for exact_match_table
def insert_table_entry(target, _BfRtInfo_object, table_name, five_tuple):
    table = _BfRtInfo_object.table_get(table_name)

    key_list = [table.make_key([gc.KeyTuple("src", five_tuple["srcIP"]),
                                gc.KeyTuple("dst", five_tuple["dstIP"]),
                                gc.KeyTuple("srcPort", five_tuple["srcPort"]),
                                gc.KeyTuple("dstPort", five_tuple["dstPort"]),
                                gc.KeyTuple("proto", five_tuple["proto"])
                                ])]
    data_list = [table.make_data([], "drop")]
    table.entry_add(target, key_list, data_list)


# Current use case built specifically for exact_match_table
def delete_table_entry(target, _BfRtInfo_object, table_name, five_tuple):
    table = _BfRtInfo_object.table_get(table_name)

    key_list = [table.make_key([gc.KeyTuple("src", five_tuple["srcIP"]),
                                gc.KeyTuple("dst", five_tuple["dstIP"]),
                                gc.KeyTuple("srcPort", five_tuple["srcPort"]),
                                gc.KeyTuple("dstPort", five_tuple["dstPort"]),
                                gc.KeyTuple("proto", five_tuple["proto"])
                                ])]
    table.entry_del(target, key_list)


def get_p4info_from_yaml(filename):
    logging.debug('Reading {} file'.format(filename))
    try:
        with open(filename, 'r') as stream:
            print("Loaded", filename)
            yaml_data = yaml.load(stream, Loader=yaml.FullLoader)
    except yaml.YAMLError as exc:
        logging.critical("Error in yaml file {} {}".format(filename, exc))
    return yaml_data


def read_digest(bfrt_info, interface, cloud_ip_prefix):
    while True:
        try:
            time.sleep(1)
            learn_filter = bfrt_info.learn_get("digest_a")
            learn_filter.info.data_field_annotation_add("src_mac", "mac")
            learn_filter.info.data_field_annotation_add("dst_mac", "mac")
            learn_filter.info.data_field_annotation_add("src_ip", "ipv4")
            learn_filter.info.data_field_annotation_add("dst_ip", "ipv4")
            digest = interface.digest_get()
        except Exception as e:
            print(e)
            print("No digest received...")
        else:
            #print("Digest received!")
            #recv_target = digest.target
            #print(recv_target)

            data_list = learn_filter.make_data_list(digest)
            data_dict = data_list[0].to_dict()

            #if "port" in data_dict:
                #port = data_dict["port"]
                #if (port==164):
                    #print(data_dict)
 
                #if ipaddress.ip_address(dst_ip) in ipaddress.ip_network(cloud_ip_prefix + '/24'):
                    #print(data_dict)
                #else:
                    #pass
            #else:
                #pass

            print(data_dict)


def match_forward_src_lpm_add_entry(target, table, src_ip, prefix_len, dst_ip, egr_port):
    table.info.key_field_annotation_add('src_ip', 'ipv4')
    table.info.key_field_annotation_add('dst_ip', 'ipv4')
    table.entry_add(
        target,
        [table.make_key(
            [gc.KeyTuple("src_ip", src_ip, prefix_len=prefix_len), gc.KeyTuple("dst_ip", dst_ip)])],
        [table.make_data(
            [gc.DataTuple('dst_port', egr_port)],
            'set_egr_port')])


def match_forward_dst_lpm_add_entry(target, table, src_ip, dst_ip, prefix_len, egr_port):
    table.info.key_field_annotation_add('src_ip', 'ipv4')
    table.info.key_field_annotation_add('dst_ip', 'ipv4')
    table.entry_add(
        target,
        [table.make_key(
            [gc.KeyTuple("src_ip", src_ip), gc.KeyTuple("dst_ip", dst_ip, prefix_len=prefix_len)])],
        [table.make_data(
            [gc.DataTuple('dst_port', egr_port)],
            'set_egr_port')])


def main():
    config = get_p4info_from_yaml('NECK_manual_conf.yaml')
    grpc_addr = config["grpc_addr"]
    p4_name = "tna_nbnswitch"
    profile_name = "pipe"

    # Subscribe.Notifications.enable_learn_notifications
    notification = gc.Notifications(True, False, False)

    interface = gc.ClientInterface(grpc_addr, client_id, device_id, notifications=notification)
    set_fwd_pipeline(p4_name, profile_name, interface)
    interface.bind_pipeline_config(p4_name)

    bfrt_info = interface.bfrt_info_get(p4_name)
    port_table = bfrt_info.table_get("$PORT")
    target = configure_ports(port_table)


    port_type_table = bfrt_info.table_get("pipe.port_type")
    # Access ports
    # 31/2
    port_type_add_entry(target, port_type_table, config["switch_host_port"], 0)

    # Cloud ports
    # 31/0
    port_type_add_entry(target, port_type_table, config["switch_cloud_port"], 2)

    # RSP port
    # 30/0
    port_type_add_entry(target, port_type_table, config["switch_RSP_port"], 1)

    # ---------USER(ARP) ----------
    # ARP requests from user to RSP
    # Also forward access to cloud via RSP(if no cloud access)
    port_forward_table = bfrt_info.table_get("pipe.port_forward")
    port_forward_add_entry(target, port_forward_table, config["switch_host_port"], config["switch_RSP_port"])

    # RSP downstream to host1
    # Did not add RSP to host2, because RSP port and host port is 1-1
    port_forward_add_entry(target, port_forward_table, config["switch_RSP_port"], config["switch_host_port"])

    # ---------USER(ip layer packets) ----------
    # USER to cloud: cloud_access
    # Check if user has direct cloud access - user to cloud
    cloud_access_table = bfrt_info.table_get("pipe.cloud_access")
    cloud_access_add_entry(target, cloud_access_table, config["host_ip_prefix"], 24)

    # Check if destination cloud is valid
    check_dst_cloud_table = bfrt_info.table_get("pipe.check_dst_cloud")
    check_dst_cloud_add_entry(target, check_dst_cloud_table, config["cloud_ip_prefix"], 24)

    # Check if user has direct cloud access(dest IP subnet) - cloud back to user
    reverse_cloud_access_table = bfrt_info.table_get("pipe.reverse_cloud_access")
    reverse_cloud_access_add_entry(target, reverse_cloud_access_table, config["host_ip_prefix"], 24)

    update_src_mac_table = bfrt_info.table_get("pipe.update_src_mac")
    # Both switch MAC
    update_src_mac_add_entry(target, update_src_mac_table, config["cloud_ip_prefix"], 24, config["switch_mac"])

    update_dst_mac_table = bfrt_info.table_get("pipe.update_dst_mac")
    # Cloud 1 ens11f0 MAC
    update_dst_mac_add_entry(target, update_dst_mac_table, config["cloud_ip_prefix"], 24, config["cloud_mac"])

    # Access port to Cloud: ipv4_forward
    # +++ipv4_forward_table = bfrt_info.table_get("pipe.ipv4_forward")
    # cloud 1: 31/0 = 128
    # +++ipv4_forward_add_entry(target, ipv4_forward_table, config["cloud_ip_prefix"], 24, config["switch_cloud_port"])

    # ---------ClOUD ----------
    # arp requests from cloud
    arp_response_table = bfrt_info.table_get("pipe.arp_response")
    arp_response_add_entry(target, arp_response_table, config["switch_virtual_ip"])

    # Handles cloud arp response where the egress port is set to the same as the ingress port
    port_forward_add_entry(target, port_forward_table, config["switch_cloud_port"], config["switch_cloud_port"])

    # Cloud 1 ens11f0 MAC
    update_src_mac_add_entry(target, update_src_mac_table, config["host_ip"], 24, config["cloud_mac"])

    # Host MAC address should be learned, currently hardcoded!!!
    # Host 1 ens11f0 MAC
    update_dst_mac_add_entry(target, update_dst_mac_table, config["host_ip"], 24, config["host_mac"])

    # Cloud port to Access: ipv4_forward
    # Handles normal downstream traffic from Cloud
    # +++ipv4_forward_add_entry(target, ipv4_forward_table, config["host_ip"], 24, config["switch_host_port"])

    # ---------Counter ----------
    counting_table_ing_table = bfrt_info.table_get("pipe.counting_table_ing")
    counting_table_ing_add_entry(target, counting_table_ing_table, config["switch_host_port"], c_bytes=0, c_pkts=0)
    counting_table_ing_add_entry(target, counting_table_ing_table, config["switch_RSP_port"], c_bytes=0, c_pkts=0)

    counting_table_egr_table = bfrt_info.table_get("pipe.counting_table_egr")
    counting_table_egr_add_entry(target, counting_table_egr_table, config["switch_host_port"], c_bytes=0, c_pkts=0)
    counting_table_egr_add_entry(target, counting_table_egr_table, config["switch_RSP_port"], c_bytes=0, c_pkts=0)

    # ---------Cloud Counter ----------
    counting_table_cld_ing_table = bfrt_info.table_get("pipe.counting_table_cloud_ing")
    counting_table_ing_cld_add_entry(target, counting_table_cld_ing_table, config["switch_cloud_port"], c_bytes=0,
                                     c_pkts=0)

    counting_table_cld_egr_table = bfrt_info.table_get("pipe.counting_table_cloud_egr")
    counting_table_egr_cld_add_entry(target, counting_table_cld_egr_table, config["switch_cloud_port"], c_bytes=0,
                                     c_pkts=0)
  
    match_forward_table = bfrt_info.table_get("pipe.match_forward")
    # match_forward_src_lpm_add_entry(target, match_forward_table, config["host_ip"], 24, config["cloud_ip"], 36)
    match_forward_dst_lpm_add_entry(target, match_forward_table, config["cloud_ip"], config["host_ip"], 24, 36)

    digest_reader = threading.Thread(target=read_digest, args=(bfrt_info, interface, config["cloud_ip_prefix"],))
    digest_reader.start()

if __name__ == '__main__':
    main()
