// Constants to help with static flow entries and troubleshooting
const bit<8> USER = 0;
const bit<8> RSP = 1;
const bit<8> CLOUD = 2;
const bit<8> BGP = 3;
const bit<8> UNKNOWN = 4;

typedef bit<3> mirror_type_t;
typedef bit<8>  pkt_type_t;

const mirror_type_t MIRROR_TYPE_I2E = 1;
const mirror_type_t MIRROR_TYPE_E2E = 2;
const pkt_type_t PKT_TYPE_NORMAL = 1;
const pkt_type_t PKT_TYPE_MIRROR = 2;
const pkt_type_t PKT_TYPE_CLOUD_ARP = 3;


//P4_SWITCH_MAC is used for cloud_arp action
// change P4_SWITCH_MAC
// todo change P4_SWITCH_MAC and potentially make it dynamic
const bit<48> P4_SWITCH_MAC = 622693826712;