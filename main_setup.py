import logging
import os
import bfruntime_pb2 as bfruntime_pb2
import client as gc

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
    binary_name = "tofino"
    base_pick_path = sde_install + "/" + "share/" + binary_name + "pd"
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
    # Access User - port 1/0 *TX 25G
    port_table.entry_add(
    target,
    [port_table.make_key([gc.KeyTuple('$DEV_PORT', 132)])],#This means an exact match
    [port_table.make_data([gc.DataTuple('$SPEED', str_val="BF_SPEED_10G"),
                           gc.DataTuple('$FEC', str_val="BF_FEC_TYP_NONE"),
                           gc.DataTuple('$PORT_ENABLE', bool_val=True),
                           gc.DataTuple('$PORT_DIR', str_val="PM_PORT_DIR_DEFAULT"),
                           gc.DataTuple('$AUTO_NEGOTIATION', str_val="PM_AN_FORCE_DISABLE")])]
    )

    # RSP BNG - port 2/0 *TX 25G
    port_table.entry_add(
        target,
        [port_table.make_key([gc.KeyTuple('$DEV_PORT', 140)])],#This means an exact match
        [port_table.make_data([gc.DataTuple('$SPEED', str_val="BF_SPEED_10G"),
                               gc.DataTuple('$FEC', str_val="BF_FEC_TYP_NONE"),
                               gc.DataTuple('$PORT_ENABLE', bool_val=True),
                               gc.DataTuple('$PORT_DIR', str_val="PM_PORT_DIR_DEFAULT"),
                               gc.DataTuple('$AUTO_NEGOTIATION', str_val="PM_AN_FORCE_DISABLE")])]
        )

    # direct cloud - port 5/0 *TX 25G
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



def main():
    grpc_addr = "10.0.59.166:50052"
    p4_name = "tna_nbnswitch"
    profile_name = "pipe"

    interface = gc.ClientInterface(grpc_addr, client_id, device_id)
    set_fwd_pipeline(p4_name, profile_name, interface)
    interface.bind_pipeline_config(p4_name)

    bfrt_info = interface.bfrt_info_get(p4_name)
    port_table = bfrt_info.table_get("$PORT")
    target = configure_ports(port_table)



if __name__ == '__main__':
    main()
