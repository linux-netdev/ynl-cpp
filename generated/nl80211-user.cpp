// SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause)
/* Do not edit directly, auto-generated from: */
/*	 */
/* YNL-GEN user source */

#include "nl80211-user.hpp"

#include <array>

#include <linux/nl80211.h>

#include <linux/genetlink.h>

namespace ynl_cpp {

/* Enums */
static constexpr std::array<std::string_view,
                            NL80211_CMD_GET_PROTOCOL_FEATURES + 1>
    nl80211_op_strmap = []() {
      std::array<std::string_view, NL80211_CMD_GET_PROTOCOL_FEATURES + 1> arr{};
      arr[3] = "get-wiphy";
      arr[7] = "get-interface";
      arr[NL80211_CMD_GET_PROTOCOL_FEATURES] = "get-protocol-features";
      return arr;
    }();

std::string_view nl80211_op_str(int op) {
  if (op < 0 || op >= (int)(nl80211_op_strmap.size()))
    return "";
  return nl80211_op_strmap[op];
}

static constexpr std::array<std::string_view, 155 + 1> nl80211_commands_strmap =
    []() {
      std::array<std::string_view, 155 + 1> arr{};
      arr[0] = "unspec";
      arr[1] = "get-wiphy";
      arr[2] = "set-wiphy";
      arr[3] = "new-wiphy";
      arr[4] = "del-wiphy";
      arr[5] = "get-interface";
      arr[6] = "set-interface";
      arr[7] = "new-interface";
      arr[8] = "del-interface";
      arr[9] = "get-key";
      arr[10] = "set-key";
      arr[11] = "new-key";
      arr[12] = "del-key";
      arr[13] = "get-beacon";
      arr[14] = "set-beacon";
      arr[15] = "new-beacon";
      arr[16] = "del-beacon";
      arr[17] = "get-station";
      arr[18] = "set-station";
      arr[19] = "new-station";
      arr[20] = "del-station";
      arr[21] = "get-mpath";
      arr[22] = "set-mpath";
      arr[23] = "new-mpath";
      arr[24] = "del-mpath";
      arr[25] = "set-bss";
      arr[26] = "set-reg";
      arr[27] = "req-set-reg";
      arr[28] = "get-mesh-config";
      arr[29] = "set-mesh-config";
      arr[30] = "set-mgmt-extra-ie";
      arr[31] = "get-reg";
      arr[32] = "get-scan";
      arr[33] = "trigger-scan";
      arr[34] = "new-scan-results";
      arr[35] = "scan-aborted";
      arr[36] = "reg-change";
      arr[37] = "authenticate";
      arr[38] = "associate";
      arr[39] = "deauthenticate";
      arr[40] = "disassociate";
      arr[41] = "michael-mic-failure";
      arr[42] = "reg-beacon-hint";
      arr[43] = "join-ibss";
      arr[44] = "leave-ibss";
      arr[45] = "testmode";
      arr[46] = "connect";
      arr[47] = "roam";
      arr[48] = "disconnect";
      arr[49] = "set-wiphy-netns";
      arr[50] = "get-survey";
      arr[51] = "new-survey-results";
      arr[52] = "set-pmksa";
      arr[53] = "del-pmksa";
      arr[54] = "flush-pmksa";
      arr[55] = "remain-on-channel";
      arr[56] = "cancel-remain-on-channel";
      arr[57] = "set-tx-bitrate-mask";
      arr[58] = "register-action";
      arr[59] = "action";
      arr[60] = "action-tx-status";
      arr[61] = "set-power-save";
      arr[62] = "get-power-save";
      arr[63] = "set-cqm";
      arr[64] = "notify-cqm";
      arr[65] = "set-channel";
      arr[66] = "set-wds-peer";
      arr[67] = "frame-wait-cancel";
      arr[68] = "join-mesh";
      arr[69] = "leave-mesh";
      arr[70] = "unprot-deauthenticate";
      arr[71] = "unprot-disassociate";
      arr[72] = "new-peer-candidate";
      arr[73] = "get-wowlan";
      arr[74] = "set-wowlan";
      arr[75] = "start-sched-scan";
      arr[76] = "stop-sched-scan";
      arr[77] = "sched-scan-results";
      arr[78] = "sched-scan-stopped";
      arr[79] = "set-rekey-offload";
      arr[80] = "pmksa-candidate";
      arr[81] = "tdls-oper";
      arr[82] = "tdls-mgmt";
      arr[83] = "unexpected-frame";
      arr[84] = "probe-client";
      arr[85] = "register-beacons";
      arr[86] = "unexpected-4-addr-frame";
      arr[87] = "set-noack-map";
      arr[88] = "ch-switch-notify";
      arr[89] = "start-p2p-device";
      arr[90] = "stop-p2p-device";
      arr[91] = "conn-failed";
      arr[92] = "set-mcast-rate";
      arr[93] = "set-mac-acl";
      arr[94] = "radar-detect";
      arr[95] = "get-protocol-features";
      arr[96] = "update-ft-ies";
      arr[97] = "ft-event";
      arr[98] = "crit-protocol-start";
      arr[99] = "crit-protocol-stop";
      arr[100] = "get-coalesce";
      arr[101] = "set-coalesce";
      arr[102] = "channel-switch";
      arr[103] = "vendor";
      arr[104] = "set-qos-map";
      arr[105] = "add-tx-ts";
      arr[106] = "del-tx-ts";
      arr[107] = "get-mpp";
      arr[108] = "join-ocb";
      arr[109] = "leave-ocb";
      arr[110] = "ch-switch-started-notify";
      arr[111] = "tdls-channel-switch";
      arr[112] = "tdls-cancel-channel-switch";
      arr[113] = "wiphy-reg-change";
      arr[114] = "abort-scan";
      arr[115] = "start-nan";
      arr[116] = "stop-nan";
      arr[117] = "add-nan-function";
      arr[118] = "del-nan-function";
      arr[119] = "change-nan-config";
      arr[120] = "nan-match";
      arr[121] = "set-multicast-to-unicast";
      arr[122] = "update-connect-params";
      arr[123] = "set-pmk";
      arr[124] = "del-pmk";
      arr[125] = "port-authorized";
      arr[126] = "reload-regdb";
      arr[127] = "external-auth";
      arr[128] = "sta-opmode-changed";
      arr[129] = "control-port-frame";
      arr[130] = "get-ftm-responder-stats";
      arr[131] = "peer-measurement-start";
      arr[132] = "peer-measurement-result";
      arr[133] = "peer-measurement-complete";
      arr[134] = "notify-radar";
      arr[135] = "update-owe-info";
      arr[136] = "probe-mesh-link";
      arr[137] = "set-tid-config";
      arr[138] = "unprot-beacon";
      arr[139] = "control-port-frame-tx-status";
      arr[140] = "set-sar-specs";
      arr[141] = "obss-color-collision";
      arr[142] = "color-change-request";
      arr[143] = "color-change-started";
      arr[144] = "color-change-aborted";
      arr[145] = "color-change-completed";
      arr[146] = "set-fils-aad";
      arr[147] = "assoc-comeback";
      arr[148] = "add-link";
      arr[149] = "remove-link";
      arr[150] = "add-link-sta";
      arr[151] = "modify-link-sta";
      arr[152] = "remove-link-sta";
      arr[153] = "set-hw-timestamp";
      arr[154] = "links-removed";
      arr[155] = "set-tid-to-link-mapping";
      return arr;
    }();

std::string_view nl80211_commands_str(nl80211_commands value) {
  if (value < 0 || value >= (int)(nl80211_commands_strmap.size()))
    return "";
  return nl80211_commands_strmap[value];
}

static constexpr std::array<std::string_view, 31 + 1>
    nl80211_feature_flags_strmap = []() {
      std::array<std::string_view, 31 + 1> arr{};
      arr[0] = "sk-tx-status";
      arr[1] = "ht-ibss";
      arr[2] = "inactivity-timer";
      arr[3] = "cell-base-reg-hints";
      arr[4] = "p2p-device-needs-channel";
      arr[5] = "sae";
      arr[6] = "low-priority-scan";
      arr[7] = "scan-flush";
      arr[8] = "ap-scan";
      arr[9] = "vif-txpower";
      arr[10] = "need-obss-scan";
      arr[11] = "p2p-go-ctwin";
      arr[12] = "p2p-go-oppps";
      arr[13] = "reserved";
      arr[14] = "advertise-chan-limits";
      arr[15] = "full-ap-client-state";
      arr[16] = "userspace-mpm";
      arr[17] = "active-monitor";
      arr[18] = "ap-mode-chan-width-change";
      arr[19] = "ds-param-set-ie-in-probes";
      arr[20] = "wfa-tpc-ie-in-probes";
      arr[21] = "quiet";
      arr[22] = "tx-power-insertion";
      arr[23] = "ackto-estimation";
      arr[24] = "static-smps";
      arr[25] = "dynamic-smps";
      arr[26] = "supports-wmm-admission";
      arr[27] = "mac-on-create";
      arr[28] = "tdls-channel-switch";
      arr[29] = "scan-random-mac-addr";
      arr[30] = "sched-scan-random-mac-addr";
      arr[31] = "no-random-mac-addr";
      return arr;
    }();

std::string_view nl80211_feature_flags_str(nl80211_feature_flags value) {
  value = (nl80211_feature_flags)(ffs(value) - 1);
  if (value < 0 || value >= (int)(nl80211_feature_flags_strmap.size()))
    return "";
  return nl80211_feature_flags_strmap[value];
}

static constexpr std::array<std::string_view, 3 + 1>
    nl80211_channel_type_strmap = []() {
      std::array<std::string_view, 3 + 1> arr{};
      arr[0] = "no-ht";
      arr[1] = "ht20";
      arr[2] = "ht40minus";
      arr[3] = "ht40plus";
      return arr;
    }();

std::string_view nl80211_channel_type_str(nl80211_channel_type value) {
  if (value < 0 || value >= (int)(nl80211_channel_type_strmap.size()))
    return "";
  return nl80211_channel_type_strmap[value];
}

static constexpr std::array<std::string_view, 0 + 1>
    nl80211_protocol_features_strmap = []() {
      std::array<std::string_view, 0 + 1> arr{};
      arr[0] = "split-wiphy-dump";
      return arr;
    }();

std::string_view
nl80211_protocol_features_str(nl80211_protocol_features value) {
  value = (nl80211_protocol_features)(ffs(value) - 1);
  if (value < 0 || value >= (int)(nl80211_protocol_features_strmap.size()))
    return "";
  return nl80211_protocol_features_strmap[value];
}

/* Policies */
static std::array<ynl_policy_attr, NL80211_IFTYPE_MAX + 1>
    nl80211_supported_iftypes_policy = []() {
      std::array<ynl_policy_attr, NL80211_IFTYPE_MAX + 1> arr{};
      arr[NL80211_IFTYPE_ADHOC].name = "adhoc";
      arr[NL80211_IFTYPE_ADHOC].type = YNL_PT_FLAG;
      arr[NL80211_IFTYPE_STATION].name = "station";
      arr[NL80211_IFTYPE_STATION].type = YNL_PT_FLAG;
      arr[NL80211_IFTYPE_AP].name = "ap";
      arr[NL80211_IFTYPE_AP].type = YNL_PT_FLAG;
      arr[NL80211_IFTYPE_AP_VLAN].name = "ap-vlan";
      arr[NL80211_IFTYPE_AP_VLAN].type = YNL_PT_FLAG;
      arr[NL80211_IFTYPE_WDS].name = "wds";
      arr[NL80211_IFTYPE_WDS].type = YNL_PT_FLAG;
      arr[NL80211_IFTYPE_MONITOR].name = "monitor";
      arr[NL80211_IFTYPE_MONITOR].type = YNL_PT_FLAG;
      arr[NL80211_IFTYPE_MESH_POINT].name = "mesh-point";
      arr[NL80211_IFTYPE_MESH_POINT].type = YNL_PT_FLAG;
      arr[NL80211_IFTYPE_P2P_CLIENT].name = "p2p-client";
      arr[NL80211_IFTYPE_P2P_CLIENT].type = YNL_PT_FLAG;
      arr[NL80211_IFTYPE_P2P_GO].name = "p2p-go";
      arr[NL80211_IFTYPE_P2P_GO].type = YNL_PT_FLAG;
      arr[NL80211_IFTYPE_P2P_DEVICE].name = "p2p-device";
      arr[NL80211_IFTYPE_P2P_DEVICE].type = YNL_PT_FLAG;
      arr[NL80211_IFTYPE_OCB].name = "ocb";
      arr[NL80211_IFTYPE_OCB].type = YNL_PT_FLAG;
      arr[NL80211_IFTYPE_NAN].name = "nan";
      arr[NL80211_IFTYPE_NAN].type = YNL_PT_FLAG;
      return arr;
    }();

struct ynl_policy_nest nl80211_supported_iftypes_nest = {
    .max_attr = static_cast<unsigned int>(NL80211_IFTYPE_MAX),
    .table = nl80211_supported_iftypes_policy.data(),
};

static std::array<ynl_policy_attr, MAX_NL80211_WOWLAN_TRIG + 1>
    nl80211_wowlan_triggers_attrs_policy = []() {
      std::array<ynl_policy_attr, MAX_NL80211_WOWLAN_TRIG + 1> arr{};
      arr[NL80211_WOWLAN_TRIG_ANY].name = "any";
      arr[NL80211_WOWLAN_TRIG_ANY].type = YNL_PT_FLAG;
      arr[NL80211_WOWLAN_TRIG_DISCONNECT].name = "disconnect";
      arr[NL80211_WOWLAN_TRIG_DISCONNECT].type = YNL_PT_FLAG;
      arr[NL80211_WOWLAN_TRIG_MAGIC_PKT].name = "magic-pkt";
      arr[NL80211_WOWLAN_TRIG_MAGIC_PKT].type = YNL_PT_FLAG;
      arr[NL80211_WOWLAN_TRIG_PKT_PATTERN].name = "pkt-pattern";
      arr[NL80211_WOWLAN_TRIG_PKT_PATTERN].type = YNL_PT_FLAG;
      arr[NL80211_WOWLAN_TRIG_GTK_REKEY_SUPPORTED].name = "gtk-rekey-supported";
      arr[NL80211_WOWLAN_TRIG_GTK_REKEY_SUPPORTED].type = YNL_PT_FLAG;
      arr[NL80211_WOWLAN_TRIG_GTK_REKEY_FAILURE].name = "gtk-rekey-failure";
      arr[NL80211_WOWLAN_TRIG_GTK_REKEY_FAILURE].type = YNL_PT_FLAG;
      arr[NL80211_WOWLAN_TRIG_EAP_IDENT_REQUEST].name = "eap-ident-request";
      arr[NL80211_WOWLAN_TRIG_EAP_IDENT_REQUEST].type = YNL_PT_FLAG;
      arr[NL80211_WOWLAN_TRIG_4WAY_HANDSHAKE].name = "4way-handshake";
      arr[NL80211_WOWLAN_TRIG_4WAY_HANDSHAKE].type = YNL_PT_FLAG;
      arr[NL80211_WOWLAN_TRIG_RFKILL_RELEASE].name = "rfkill-release";
      arr[NL80211_WOWLAN_TRIG_RFKILL_RELEASE].type = YNL_PT_FLAG;
      arr[NL80211_WOWLAN_TRIG_WAKEUP_PKT_80211].name = "wakeup-pkt-80211";
      arr[NL80211_WOWLAN_TRIG_WAKEUP_PKT_80211].type = YNL_PT_FLAG;
      arr[NL80211_WOWLAN_TRIG_WAKEUP_PKT_80211_LEN].name =
          "wakeup-pkt-80211-len";
      arr[NL80211_WOWLAN_TRIG_WAKEUP_PKT_80211_LEN].type = YNL_PT_FLAG;
      arr[NL80211_WOWLAN_TRIG_WAKEUP_PKT_8023].name = "wakeup-pkt-8023";
      arr[NL80211_WOWLAN_TRIG_WAKEUP_PKT_8023].type = YNL_PT_FLAG;
      arr[NL80211_WOWLAN_TRIG_WAKEUP_PKT_8023_LEN].name = "wakeup-pkt-8023-len";
      arr[NL80211_WOWLAN_TRIG_WAKEUP_PKT_8023_LEN].type = YNL_PT_FLAG;
      arr[NL80211_WOWLAN_TRIG_TCP_CONNECTION].name = "tcp-connection";
      arr[NL80211_WOWLAN_TRIG_TCP_CONNECTION].type = YNL_PT_FLAG;
      arr[NL80211_WOWLAN_TRIG_WAKEUP_TCP_MATCH].name = "wakeup-tcp-match";
      arr[NL80211_WOWLAN_TRIG_WAKEUP_TCP_MATCH].type = YNL_PT_FLAG;
      arr[NL80211_WOWLAN_TRIG_WAKEUP_TCP_CONNLOST].name = "wakeup-tcp-connlost";
      arr[NL80211_WOWLAN_TRIG_WAKEUP_TCP_CONNLOST].type = YNL_PT_FLAG;
      arr[NL80211_WOWLAN_TRIG_WAKEUP_TCP_NOMORETOKENS].name =
          "wakeup-tcp-nomoretokens";
      arr[NL80211_WOWLAN_TRIG_WAKEUP_TCP_NOMORETOKENS].type = YNL_PT_FLAG;
      arr[NL80211_WOWLAN_TRIG_NET_DETECT].name = "net-detect";
      arr[NL80211_WOWLAN_TRIG_NET_DETECT].type = YNL_PT_FLAG;
      arr[NL80211_WOWLAN_TRIG_NET_DETECT_RESULTS].name = "net-detect-results";
      arr[NL80211_WOWLAN_TRIG_NET_DETECT_RESULTS].type = YNL_PT_FLAG;
      arr[NL80211_WOWLAN_TRIG_UNPROTECTED_DEAUTH_DISASSOC].name =
          "unprotected-deauth-disassoc";
      arr[NL80211_WOWLAN_TRIG_UNPROTECTED_DEAUTH_DISASSOC].type = YNL_PT_FLAG;
      return arr;
    }();

struct ynl_policy_nest nl80211_wowlan_triggers_attrs_nest = {
    .max_attr = static_cast<unsigned int>(MAX_NL80211_WOWLAN_TRIG),
    .table = nl80211_wowlan_triggers_attrs_policy.data(),
};

static std::array<ynl_policy_attr, NL80211_TXQ_STATS_MAX + 1>
    nl80211_txq_stats_attrs_policy = []() {
      std::array<ynl_policy_attr, NL80211_TXQ_STATS_MAX + 1> arr{};
      arr[NL80211_TXQ_STATS_BACKLOG_BYTES].name = "backlog-bytes";
      arr[NL80211_TXQ_STATS_BACKLOG_BYTES].type = YNL_PT_U32;
      arr[NL80211_TXQ_STATS_BACKLOG_PACKETS].name = "backlog-packets";
      arr[NL80211_TXQ_STATS_BACKLOG_PACKETS].type = YNL_PT_U32;
      arr[NL80211_TXQ_STATS_FLOWS].name = "flows";
      arr[NL80211_TXQ_STATS_FLOWS].type = YNL_PT_U32;
      arr[NL80211_TXQ_STATS_DROPS].name = "drops";
      arr[NL80211_TXQ_STATS_DROPS].type = YNL_PT_U32;
      arr[NL80211_TXQ_STATS_ECN_MARKS].name = "ecn-marks";
      arr[NL80211_TXQ_STATS_ECN_MARKS].type = YNL_PT_U32;
      arr[NL80211_TXQ_STATS_OVERLIMIT].name = "overlimit";
      arr[NL80211_TXQ_STATS_OVERLIMIT].type = YNL_PT_U32;
      arr[NL80211_TXQ_STATS_OVERMEMORY].name = "overmemory";
      arr[NL80211_TXQ_STATS_OVERMEMORY].type = YNL_PT_U32;
      arr[NL80211_TXQ_STATS_COLLISIONS].name = "collisions";
      arr[NL80211_TXQ_STATS_COLLISIONS].type = YNL_PT_U32;
      arr[NL80211_TXQ_STATS_TX_BYTES].name = "tx-bytes";
      arr[NL80211_TXQ_STATS_TX_BYTES].type = YNL_PT_U32;
      arr[NL80211_TXQ_STATS_TX_PACKETS].name = "tx-packets";
      arr[NL80211_TXQ_STATS_TX_PACKETS].type = YNL_PT_U32;
      arr[NL80211_TXQ_STATS_MAX_FLOWS].name = "max-flows";
      arr[NL80211_TXQ_STATS_MAX_FLOWS].type = YNL_PT_U32;
      return arr;
    }();

struct ynl_policy_nest nl80211_txq_stats_attrs_nest = {
    .max_attr = static_cast<unsigned int>(NL80211_TXQ_STATS_MAX),
    .table = nl80211_txq_stats_attrs_policy.data(),
};

static std::array<ynl_policy_attr, NUM_NL80211_ATTR + 1>
    nl80211_frame_type_attrs_policy = []() {
      std::array<ynl_policy_attr, NUM_NL80211_ATTR + 1> arr{};
      arr[NL80211_ATTR_FRAME_TYPE].name = "frame-type";
      arr[NL80211_ATTR_FRAME_TYPE].type = YNL_PT_U16;
      return arr;
    }();

struct ynl_policy_nest nl80211_frame_type_attrs_nest = {
    .max_attr = static_cast<unsigned int>(NUM_NL80211_ATTR),
    .table = nl80211_frame_type_attrs_policy.data(),
};

static std::array<ynl_policy_attr, MAX_NL80211_IFACE_LIMIT + 1>
    nl80211_iface_limit_attributes_policy = []() {
      std::array<ynl_policy_attr, MAX_NL80211_IFACE_LIMIT + 1> arr{};
      arr[NL80211_IFACE_LIMIT_MAX].name = "max";
      arr[NL80211_IFACE_LIMIT_MAX].type = YNL_PT_U32;
      arr[NL80211_IFACE_LIMIT_TYPES].name = "types";
      arr[NL80211_IFACE_LIMIT_TYPES].type = YNL_PT_NEST;
      arr[NL80211_IFACE_LIMIT_TYPES].nest = &nl80211_supported_iftypes_nest;
      return arr;
    }();

struct ynl_policy_nest nl80211_iface_limit_attributes_nest = {
    .max_attr = static_cast<unsigned int>(MAX_NL80211_IFACE_LIMIT),
    .table = nl80211_iface_limit_attributes_policy.data(),
};

static std::array<ynl_policy_attr, NL80211_SAR_ATTR_SPECS_MAX + 1>
    nl80211_sar_specs_policy = []() {
      std::array<ynl_policy_attr, NL80211_SAR_ATTR_SPECS_MAX + 1> arr{};
      arr[NL80211_SAR_ATTR_SPECS_POWER].name = "power";
      arr[NL80211_SAR_ATTR_SPECS_POWER].type = YNL_PT_U32;
      arr[NL80211_SAR_ATTR_SPECS_RANGE_INDEX].name = "range-index";
      arr[NL80211_SAR_ATTR_SPECS_RANGE_INDEX].type = YNL_PT_U32;
      arr[NL80211_SAR_ATTR_SPECS_START_FREQ].name = "start-freq";
      arr[NL80211_SAR_ATTR_SPECS_START_FREQ].type = YNL_PT_U32;
      arr[NL80211_SAR_ATTR_SPECS_END_FREQ].name = "end-freq";
      arr[NL80211_SAR_ATTR_SPECS_END_FREQ].type = YNL_PT_U32;
      return arr;
    }();

struct ynl_policy_nest nl80211_sar_specs_nest = {
    .max_attr = static_cast<unsigned int>(NL80211_SAR_ATTR_SPECS_MAX),
    .table = nl80211_sar_specs_policy.data(),
};

static std::array<ynl_policy_attr, NL80211_BITRATE_ATTR_MAX + 1>
    nl80211_bitrate_attrs_policy = []() {
      std::array<ynl_policy_attr, NL80211_BITRATE_ATTR_MAX + 1> arr{};
      arr[NL80211_BITRATE_ATTR_RATE].name = "rate";
      arr[NL80211_BITRATE_ATTR_RATE].type = YNL_PT_U32;
      arr[NL80211_BITRATE_ATTR_2GHZ_SHORTPREAMBLE].name = "2ghz-shortpreamble";
      arr[NL80211_BITRATE_ATTR_2GHZ_SHORTPREAMBLE].type = YNL_PT_FLAG;
      return arr;
    }();

struct ynl_policy_nest nl80211_bitrate_attrs_nest = {
    .max_attr = static_cast<unsigned int>(NL80211_BITRATE_ATTR_MAX),
    .table = nl80211_bitrate_attrs_policy.data(),
};

static std::array<ynl_policy_attr, NL80211_BAND_IFTYPE_ATTR_MAX + 1>
    nl80211_iftype_data_attrs_policy = []() {
      std::array<ynl_policy_attr, NL80211_BAND_IFTYPE_ATTR_MAX + 1> arr{};
      arr[NL80211_BAND_IFTYPE_ATTR_IFTYPES].name = "iftypes";
      arr[NL80211_BAND_IFTYPE_ATTR_IFTYPES].type = YNL_PT_BINARY;
      arr[NL80211_BAND_IFTYPE_ATTR_HE_CAP_MAC].name = "he-cap-mac";
      arr[NL80211_BAND_IFTYPE_ATTR_HE_CAP_MAC].type = YNL_PT_BINARY;
      arr[NL80211_BAND_IFTYPE_ATTR_HE_CAP_PHY].name = "he-cap-phy";
      arr[NL80211_BAND_IFTYPE_ATTR_HE_CAP_PHY].type = YNL_PT_BINARY;
      arr[NL80211_BAND_IFTYPE_ATTR_HE_CAP_MCS_SET].name = "he-cap-mcs-set";
      arr[NL80211_BAND_IFTYPE_ATTR_HE_CAP_MCS_SET].type = YNL_PT_BINARY;
      arr[NL80211_BAND_IFTYPE_ATTR_HE_CAP_PPE].name = "he-cap-ppe";
      arr[NL80211_BAND_IFTYPE_ATTR_HE_CAP_PPE].type = YNL_PT_BINARY;
      arr[NL80211_BAND_IFTYPE_ATTR_HE_6GHZ_CAPA].name = "he-6ghz-capa";
      arr[NL80211_BAND_IFTYPE_ATTR_HE_6GHZ_CAPA].type = YNL_PT_BINARY;
      arr[NL80211_BAND_IFTYPE_ATTR_VENDOR_ELEMS].name = "vendor-elems";
      arr[NL80211_BAND_IFTYPE_ATTR_VENDOR_ELEMS].type = YNL_PT_BINARY;
      arr[NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MAC].name = "eht-cap-mac";
      arr[NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MAC].type = YNL_PT_BINARY;
      arr[NL80211_BAND_IFTYPE_ATTR_EHT_CAP_PHY].name = "eht-cap-phy";
      arr[NL80211_BAND_IFTYPE_ATTR_EHT_CAP_PHY].type = YNL_PT_BINARY;
      arr[NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MCS_SET].name = "eht-cap-mcs-set";
      arr[NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MCS_SET].type = YNL_PT_BINARY;
      arr[NL80211_BAND_IFTYPE_ATTR_EHT_CAP_PPE].name = "eht-cap-ppe";
      arr[NL80211_BAND_IFTYPE_ATTR_EHT_CAP_PPE].type = YNL_PT_BINARY;
      return arr;
    }();

struct ynl_policy_nest nl80211_iftype_data_attrs_nest = {
    .max_attr = static_cast<unsigned int>(NL80211_BAND_IFTYPE_ATTR_MAX),
    .table = nl80211_iftype_data_attrs_policy.data(),
};

static std::array<ynl_policy_attr, NL80211_WMMR_MAX + 1>
    nl80211_wmm_attrs_policy = []() {
      std::array<ynl_policy_attr, NL80211_WMMR_MAX + 1> arr{};
      arr[NL80211_WMMR_CW_MIN].name = "cw-min";
      arr[NL80211_WMMR_CW_MIN].type = YNL_PT_U16;
      arr[NL80211_WMMR_CW_MAX].name = "cw-max";
      arr[NL80211_WMMR_CW_MAX].type = YNL_PT_U16;
      arr[NL80211_WMMR_AIFSN].name = "aifsn";
      arr[NL80211_WMMR_AIFSN].type = YNL_PT_U8;
      arr[NL80211_WMMR_TXOP].name = "txop";
      arr[NL80211_WMMR_TXOP].type = YNL_PT_U16;
      return arr;
    }();

struct ynl_policy_nest nl80211_wmm_attrs_nest = {
    .max_attr = static_cast<unsigned int>(NL80211_WMMR_MAX),
    .table = nl80211_wmm_attrs_policy.data(),
};

static std::array<ynl_policy_attr, NL80211_IFTYPE_MAX + 1>
    nl80211_iftype_attrs_policy = []() {
      std::array<ynl_policy_attr, NL80211_IFTYPE_MAX + 1> arr{};
      arr[NL80211_IFTYPE_UNSPECIFIED].name = "unspecified";
      arr[NL80211_IFTYPE_UNSPECIFIED].type = YNL_PT_NEST;
      arr[NL80211_IFTYPE_UNSPECIFIED].nest = &nl80211_frame_type_attrs_nest;
      arr[NL80211_IFTYPE_ADHOC].name = "adhoc";
      arr[NL80211_IFTYPE_ADHOC].type = YNL_PT_NEST;
      arr[NL80211_IFTYPE_ADHOC].nest = &nl80211_frame_type_attrs_nest;
      arr[NL80211_IFTYPE_STATION].name = "station";
      arr[NL80211_IFTYPE_STATION].type = YNL_PT_NEST;
      arr[NL80211_IFTYPE_STATION].nest = &nl80211_frame_type_attrs_nest;
      arr[NL80211_IFTYPE_AP].name = "ap";
      arr[NL80211_IFTYPE_AP].type = YNL_PT_NEST;
      arr[NL80211_IFTYPE_AP].nest = &nl80211_frame_type_attrs_nest;
      arr[NL80211_IFTYPE_AP_VLAN].name = "ap-vlan";
      arr[NL80211_IFTYPE_AP_VLAN].type = YNL_PT_NEST;
      arr[NL80211_IFTYPE_AP_VLAN].nest = &nl80211_frame_type_attrs_nest;
      arr[NL80211_IFTYPE_WDS].name = "wds";
      arr[NL80211_IFTYPE_WDS].type = YNL_PT_NEST;
      arr[NL80211_IFTYPE_WDS].nest = &nl80211_frame_type_attrs_nest;
      arr[NL80211_IFTYPE_MONITOR].name = "monitor";
      arr[NL80211_IFTYPE_MONITOR].type = YNL_PT_NEST;
      arr[NL80211_IFTYPE_MONITOR].nest = &nl80211_frame_type_attrs_nest;
      arr[NL80211_IFTYPE_MESH_POINT].name = "mesh-point";
      arr[NL80211_IFTYPE_MESH_POINT].type = YNL_PT_NEST;
      arr[NL80211_IFTYPE_MESH_POINT].nest = &nl80211_frame_type_attrs_nest;
      arr[NL80211_IFTYPE_P2P_CLIENT].name = "p2p-client";
      arr[NL80211_IFTYPE_P2P_CLIENT].type = YNL_PT_NEST;
      arr[NL80211_IFTYPE_P2P_CLIENT].nest = &nl80211_frame_type_attrs_nest;
      arr[NL80211_IFTYPE_P2P_GO].name = "p2p-go";
      arr[NL80211_IFTYPE_P2P_GO].type = YNL_PT_NEST;
      arr[NL80211_IFTYPE_P2P_GO].nest = &nl80211_frame_type_attrs_nest;
      arr[NL80211_IFTYPE_P2P_DEVICE].name = "p2p-device";
      arr[NL80211_IFTYPE_P2P_DEVICE].type = YNL_PT_NEST;
      arr[NL80211_IFTYPE_P2P_DEVICE].nest = &nl80211_frame_type_attrs_nest;
      arr[NL80211_IFTYPE_OCB].name = "ocb";
      arr[NL80211_IFTYPE_OCB].type = YNL_PT_NEST;
      arr[NL80211_IFTYPE_OCB].nest = &nl80211_frame_type_attrs_nest;
      arr[NL80211_IFTYPE_NAN].name = "nan";
      arr[NL80211_IFTYPE_NAN].type = YNL_PT_NEST;
      arr[NL80211_IFTYPE_NAN].nest = &nl80211_frame_type_attrs_nest;
      return arr;
    }();

struct ynl_policy_nest nl80211_iftype_attrs_nest = {
    .max_attr = static_cast<unsigned int>(NL80211_IFTYPE_MAX),
    .table = nl80211_iftype_attrs_policy.data(),
};

static std::array<ynl_policy_attr, MAX_NL80211_IFACE_COMB + 1>
    nl80211_if_combination_attributes_policy = []() {
      std::array<ynl_policy_attr, MAX_NL80211_IFACE_COMB + 1> arr{};
      arr[NL80211_IFACE_COMB_LIMITS].name = "limits";
      arr[NL80211_IFACE_COMB_LIMITS].type = YNL_PT_NEST;
      arr[NL80211_IFACE_COMB_LIMITS].nest =
          &nl80211_iface_limit_attributes_nest;
      arr[NL80211_IFACE_COMB_MAXNUM].name = "maxnum";
      arr[NL80211_IFACE_COMB_MAXNUM].type = YNL_PT_U32;
      arr[NL80211_IFACE_COMB_STA_AP_BI_MATCH].name = "sta-ap-bi-match";
      arr[NL80211_IFACE_COMB_STA_AP_BI_MATCH].type = YNL_PT_FLAG;
      arr[NL80211_IFACE_COMB_NUM_CHANNELS].name = "num-channels";
      arr[NL80211_IFACE_COMB_NUM_CHANNELS].type = YNL_PT_U32;
      arr[NL80211_IFACE_COMB_RADAR_DETECT_WIDTHS].name = "radar-detect-widths";
      arr[NL80211_IFACE_COMB_RADAR_DETECT_WIDTHS].type = YNL_PT_U32;
      arr[NL80211_IFACE_COMB_RADAR_DETECT_REGIONS].name =
          "radar-detect-regions";
      arr[NL80211_IFACE_COMB_RADAR_DETECT_REGIONS].type = YNL_PT_U32;
      arr[NL80211_IFACE_COMB_BI_MIN_GCD].name = "bi-min-gcd";
      arr[NL80211_IFACE_COMB_BI_MIN_GCD].type = YNL_PT_U32;
      return arr;
    }();

struct ynl_policy_nest nl80211_if_combination_attributes_nest = {
    .max_attr = static_cast<unsigned int>(MAX_NL80211_IFACE_COMB),
    .table = nl80211_if_combination_attributes_policy.data(),
};

static std::array<ynl_policy_attr, NL80211_SAR_ATTR_MAX + 1>
    nl80211_sar_attributes_policy = []() {
      std::array<ynl_policy_attr, NL80211_SAR_ATTR_MAX + 1> arr{};
      arr[NL80211_SAR_ATTR_TYPE].name = "type";
      arr[NL80211_SAR_ATTR_TYPE].type = YNL_PT_U32;
      arr[NL80211_SAR_ATTR_SPECS].name = "specs";
      arr[NL80211_SAR_ATTR_SPECS].type = YNL_PT_NEST;
      arr[NL80211_SAR_ATTR_SPECS].nest = &nl80211_sar_specs_nest;
      return arr;
    }();

struct ynl_policy_nest nl80211_sar_attributes_nest = {
    .max_attr = static_cast<unsigned int>(NL80211_SAR_ATTR_MAX),
    .table = nl80211_sar_attributes_policy.data(),
};

static std::array<ynl_policy_attr, NL80211_FREQUENCY_ATTR_MAX + 1>
    nl80211_frequency_attrs_policy = []() {
      std::array<ynl_policy_attr, NL80211_FREQUENCY_ATTR_MAX + 1> arr{};
      arr[NL80211_FREQUENCY_ATTR_FREQ].name = "freq";
      arr[NL80211_FREQUENCY_ATTR_FREQ].type = YNL_PT_U32;
      arr[NL80211_FREQUENCY_ATTR_DISABLED].name = "disabled";
      arr[NL80211_FREQUENCY_ATTR_DISABLED].type = YNL_PT_FLAG;
      arr[NL80211_FREQUENCY_ATTR_NO_IR].name = "no-ir";
      arr[NL80211_FREQUENCY_ATTR_NO_IR].type = YNL_PT_FLAG;
      arr[__NL80211_FREQUENCY_ATTR_NO_IBSS].name = "no-ibss";
      arr[__NL80211_FREQUENCY_ATTR_NO_IBSS].type = YNL_PT_FLAG;
      arr[NL80211_FREQUENCY_ATTR_RADAR].name = "radar";
      arr[NL80211_FREQUENCY_ATTR_RADAR].type = YNL_PT_FLAG;
      arr[NL80211_FREQUENCY_ATTR_MAX_TX_POWER].name = "max-tx-power";
      arr[NL80211_FREQUENCY_ATTR_MAX_TX_POWER].type = YNL_PT_U32;
      arr[NL80211_FREQUENCY_ATTR_DFS_STATE].name = "dfs-state";
      arr[NL80211_FREQUENCY_ATTR_DFS_STATE].type = YNL_PT_U32;
      arr[NL80211_FREQUENCY_ATTR_DFS_TIME].name = "dfs-time";
      arr[NL80211_FREQUENCY_ATTR_DFS_TIME].type = YNL_PT_BINARY;
      arr[NL80211_FREQUENCY_ATTR_NO_HT40_MINUS].name = "no-ht40-minus";
      arr[NL80211_FREQUENCY_ATTR_NO_HT40_MINUS].type = YNL_PT_BINARY;
      arr[NL80211_FREQUENCY_ATTR_NO_HT40_PLUS].name = "no-ht40-plus";
      arr[NL80211_FREQUENCY_ATTR_NO_HT40_PLUS].type = YNL_PT_BINARY;
      arr[NL80211_FREQUENCY_ATTR_NO_80MHZ].name = "no-80mhz";
      arr[NL80211_FREQUENCY_ATTR_NO_80MHZ].type = YNL_PT_BINARY;
      arr[NL80211_FREQUENCY_ATTR_NO_160MHZ].name = "no-160mhz";
      arr[NL80211_FREQUENCY_ATTR_NO_160MHZ].type = YNL_PT_BINARY;
      arr[NL80211_FREQUENCY_ATTR_DFS_CAC_TIME].name = "dfs-cac-time";
      arr[NL80211_FREQUENCY_ATTR_DFS_CAC_TIME].type = YNL_PT_BINARY;
      arr[NL80211_FREQUENCY_ATTR_INDOOR_ONLY].name = "indoor-only";
      arr[NL80211_FREQUENCY_ATTR_INDOOR_ONLY].type = YNL_PT_BINARY;
      arr[NL80211_FREQUENCY_ATTR_IR_CONCURRENT].name = "ir-concurrent";
      arr[NL80211_FREQUENCY_ATTR_IR_CONCURRENT].type = YNL_PT_BINARY;
      arr[NL80211_FREQUENCY_ATTR_NO_20MHZ].name = "no-20mhz";
      arr[NL80211_FREQUENCY_ATTR_NO_20MHZ].type = YNL_PT_BINARY;
      arr[NL80211_FREQUENCY_ATTR_NO_10MHZ].name = "no-10mhz";
      arr[NL80211_FREQUENCY_ATTR_NO_10MHZ].type = YNL_PT_BINARY;
      arr[NL80211_FREQUENCY_ATTR_WMM].name = "wmm";
      arr[NL80211_FREQUENCY_ATTR_WMM].type = YNL_PT_NEST;
      arr[NL80211_FREQUENCY_ATTR_WMM].nest = &nl80211_wmm_attrs_nest;
      arr[NL80211_FREQUENCY_ATTR_NO_HE].name = "no-he";
      arr[NL80211_FREQUENCY_ATTR_NO_HE].type = YNL_PT_BINARY;
      arr[NL80211_FREQUENCY_ATTR_OFFSET].name = "offset";
      arr[NL80211_FREQUENCY_ATTR_OFFSET].type = YNL_PT_U32;
      arr[NL80211_FREQUENCY_ATTR_1MHZ].name = "1mhz";
      arr[NL80211_FREQUENCY_ATTR_1MHZ].type = YNL_PT_BINARY;
      arr[NL80211_FREQUENCY_ATTR_2MHZ].name = "2mhz";
      arr[NL80211_FREQUENCY_ATTR_2MHZ].type = YNL_PT_BINARY;
      arr[NL80211_FREQUENCY_ATTR_4MHZ].name = "4mhz";
      arr[NL80211_FREQUENCY_ATTR_4MHZ].type = YNL_PT_BINARY;
      arr[NL80211_FREQUENCY_ATTR_8MHZ].name = "8mhz";
      arr[NL80211_FREQUENCY_ATTR_8MHZ].type = YNL_PT_BINARY;
      arr[NL80211_FREQUENCY_ATTR_16MHZ].name = "16mhz";
      arr[NL80211_FREQUENCY_ATTR_16MHZ].type = YNL_PT_BINARY;
      arr[NL80211_FREQUENCY_ATTR_NO_320MHZ].name = "no-320mhz";
      arr[NL80211_FREQUENCY_ATTR_NO_320MHZ].type = YNL_PT_BINARY;
      arr[NL80211_FREQUENCY_ATTR_NO_EHT].name = "no-eht";
      arr[NL80211_FREQUENCY_ATTR_NO_EHT].type = YNL_PT_BINARY;
      arr[NL80211_FREQUENCY_ATTR_PSD].name = "psd";
      arr[NL80211_FREQUENCY_ATTR_PSD].type = YNL_PT_BINARY;
      arr[NL80211_FREQUENCY_ATTR_DFS_CONCURRENT].name = "dfs-concurrent";
      arr[NL80211_FREQUENCY_ATTR_DFS_CONCURRENT].type = YNL_PT_BINARY;
      arr[NL80211_FREQUENCY_ATTR_NO_6GHZ_VLP_CLIENT].name =
          "no-6ghz-vlp-client";
      arr[NL80211_FREQUENCY_ATTR_NO_6GHZ_VLP_CLIENT].type = YNL_PT_BINARY;
      arr[NL80211_FREQUENCY_ATTR_NO_6GHZ_AFC_CLIENT].name =
          "no-6ghz-afc-client";
      arr[NL80211_FREQUENCY_ATTR_NO_6GHZ_AFC_CLIENT].type = YNL_PT_BINARY;
      arr[NL80211_FREQUENCY_ATTR_CAN_MONITOR].name = "can-monitor";
      arr[NL80211_FREQUENCY_ATTR_CAN_MONITOR].type = YNL_PT_BINARY;
      arr[NL80211_FREQUENCY_ATTR_ALLOW_6GHZ_VLP_AP].name = "allow-6ghz-vlp-ap";
      arr[NL80211_FREQUENCY_ATTR_ALLOW_6GHZ_VLP_AP].type = YNL_PT_BINARY;
      return arr;
    }();

struct ynl_policy_nest nl80211_frequency_attrs_nest = {
    .max_attr = static_cast<unsigned int>(NL80211_FREQUENCY_ATTR_MAX),
    .table = nl80211_frequency_attrs_policy.data(),
};

static std::array<ynl_policy_attr, NL80211_BAND_ATTR_MAX + 1>
    nl80211_band_attrs_policy = []() {
      std::array<ynl_policy_attr, NL80211_BAND_ATTR_MAX + 1> arr{};
      arr[NL80211_BAND_ATTR_FREQS].name = "freqs";
      arr[NL80211_BAND_ATTR_FREQS].type = YNL_PT_NEST;
      arr[NL80211_BAND_ATTR_FREQS].nest = &nl80211_frequency_attrs_nest;
      arr[NL80211_BAND_ATTR_RATES].name = "rates";
      arr[NL80211_BAND_ATTR_RATES].type = YNL_PT_NEST;
      arr[NL80211_BAND_ATTR_RATES].nest = &nl80211_bitrate_attrs_nest;
      arr[NL80211_BAND_ATTR_HT_MCS_SET].name = "ht-mcs-set";
      arr[NL80211_BAND_ATTR_HT_MCS_SET].type = YNL_PT_BINARY;
      arr[NL80211_BAND_ATTR_HT_CAPA].name = "ht-capa";
      arr[NL80211_BAND_ATTR_HT_CAPA].type = YNL_PT_U16;
      arr[NL80211_BAND_ATTR_HT_AMPDU_FACTOR].name = "ht-ampdu-factor";
      arr[NL80211_BAND_ATTR_HT_AMPDU_FACTOR].type = YNL_PT_U8;
      arr[NL80211_BAND_ATTR_HT_AMPDU_DENSITY].name = "ht-ampdu-density";
      arr[NL80211_BAND_ATTR_HT_AMPDU_DENSITY].type = YNL_PT_U8;
      arr[NL80211_BAND_ATTR_VHT_MCS_SET].name = "vht-mcs-set";
      arr[NL80211_BAND_ATTR_VHT_MCS_SET].type = YNL_PT_BINARY;
      arr[NL80211_BAND_ATTR_VHT_CAPA].name = "vht-capa";
      arr[NL80211_BAND_ATTR_VHT_CAPA].type = YNL_PT_U32;
      arr[NL80211_BAND_ATTR_IFTYPE_DATA].name = "iftype-data";
      arr[NL80211_BAND_ATTR_IFTYPE_DATA].type = YNL_PT_NEST;
      arr[NL80211_BAND_ATTR_IFTYPE_DATA].nest = &nl80211_iftype_data_attrs_nest;
      arr[NL80211_BAND_ATTR_EDMG_CHANNELS].name = "edmg-channels";
      arr[NL80211_BAND_ATTR_EDMG_CHANNELS].type = YNL_PT_BINARY;
      arr[NL80211_BAND_ATTR_EDMG_BW_CONFIG].name = "edmg-bw-config";
      arr[NL80211_BAND_ATTR_EDMG_BW_CONFIG].type = YNL_PT_BINARY;
      arr[NL80211_BAND_ATTR_S1G_MCS_NSS_SET].name = "s1g-mcs-nss-set";
      arr[NL80211_BAND_ATTR_S1G_MCS_NSS_SET].type = YNL_PT_BINARY;
      arr[NL80211_BAND_ATTR_S1G_CAPA].name = "s1g-capa";
      arr[NL80211_BAND_ATTR_S1G_CAPA].type = YNL_PT_BINARY;
      return arr;
    }();

struct ynl_policy_nest nl80211_band_attrs_nest = {
    .max_attr = static_cast<unsigned int>(NL80211_BAND_ATTR_MAX),
    .table = nl80211_band_attrs_policy.data(),
};

static std::array<ynl_policy_attr, NUM_NL80211_BANDS + 1>
    nl80211_wiphy_bands_policy = []() {
      std::array<ynl_policy_attr, NUM_NL80211_BANDS + 1> arr{};
      arr[NL80211_BAND_2GHZ].name = "2ghz";
      arr[NL80211_BAND_2GHZ].type = YNL_PT_NEST;
      arr[NL80211_BAND_2GHZ].nest = &nl80211_band_attrs_nest;
      arr[NL80211_BAND_5GHZ].name = "5ghz";
      arr[NL80211_BAND_5GHZ].type = YNL_PT_NEST;
      arr[NL80211_BAND_5GHZ].nest = &nl80211_band_attrs_nest;
      arr[NL80211_BAND_60GHZ].name = "60ghz";
      arr[NL80211_BAND_60GHZ].type = YNL_PT_NEST;
      arr[NL80211_BAND_60GHZ].nest = &nl80211_band_attrs_nest;
      arr[NL80211_BAND_6GHZ].name = "6ghz";
      arr[NL80211_BAND_6GHZ].type = YNL_PT_NEST;
      arr[NL80211_BAND_6GHZ].nest = &nl80211_band_attrs_nest;
      arr[NL80211_BAND_S1GHZ].name = "s1ghz";
      arr[NL80211_BAND_S1GHZ].type = YNL_PT_NEST;
      arr[NL80211_BAND_S1GHZ].nest = &nl80211_band_attrs_nest;
      arr[NL80211_BAND_LC].name = "lc";
      arr[NL80211_BAND_LC].type = YNL_PT_NEST;
      arr[NL80211_BAND_LC].nest = &nl80211_band_attrs_nest;
      return arr;
    }();

struct ynl_policy_nest nl80211_wiphy_bands_nest = {
    .max_attr = static_cast<unsigned int>(NUM_NL80211_BANDS),
    .table = nl80211_wiphy_bands_policy.data(),
};

static std::array<ynl_policy_attr, NUM_NL80211_ATTR + 1>
    nl80211_nl80211_attrs_policy = []() {
      std::array<ynl_policy_attr, NUM_NL80211_ATTR + 1> arr{};
      arr[NL80211_ATTR_WIPHY].name = "wiphy";
      arr[NL80211_ATTR_WIPHY].type = YNL_PT_U32;
      arr[NL80211_ATTR_WIPHY_NAME].name = "wiphy-name";
      arr[NL80211_ATTR_WIPHY_NAME].type = YNL_PT_NUL_STR;
      arr[NL80211_ATTR_IFINDEX].name = "ifindex";
      arr[NL80211_ATTR_IFINDEX].type = YNL_PT_U32;
      arr[NL80211_ATTR_IFNAME].name = "ifname";
      arr[NL80211_ATTR_IFNAME].type = YNL_PT_NUL_STR;
      arr[NL80211_ATTR_IFTYPE].name = "iftype";
      arr[NL80211_ATTR_IFTYPE].type = YNL_PT_U32;
      arr[NL80211_ATTR_MAC].name = "mac";
      arr[NL80211_ATTR_MAC].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_KEY_DATA].name = "key-data";
      arr[NL80211_ATTR_KEY_DATA].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_KEY_IDX].name = "key-idx";
      arr[NL80211_ATTR_KEY_IDX].type = YNL_PT_U8;
      arr[NL80211_ATTR_KEY_CIPHER].name = "key-cipher";
      arr[NL80211_ATTR_KEY_CIPHER].type = YNL_PT_U32;
      arr[NL80211_ATTR_KEY_SEQ].name = "key-seq";
      arr[NL80211_ATTR_KEY_SEQ].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_KEY_DEFAULT].name = "key-default";
      arr[NL80211_ATTR_KEY_DEFAULT].type = YNL_PT_FLAG;
      arr[NL80211_ATTR_BEACON_INTERVAL].name = "beacon-interval";
      arr[NL80211_ATTR_BEACON_INTERVAL].type = YNL_PT_U32;
      arr[NL80211_ATTR_DTIM_PERIOD].name = "dtim-period";
      arr[NL80211_ATTR_DTIM_PERIOD].type = YNL_PT_U32;
      arr[NL80211_ATTR_BEACON_HEAD].name = "beacon-head";
      arr[NL80211_ATTR_BEACON_HEAD].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_BEACON_TAIL].name = "beacon-tail";
      arr[NL80211_ATTR_BEACON_TAIL].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_STA_AID].name = "sta-aid";
      arr[NL80211_ATTR_STA_AID].type = YNL_PT_U16;
      arr[NL80211_ATTR_STA_FLAGS].name = "sta-flags";
      arr[NL80211_ATTR_STA_FLAGS].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_STA_LISTEN_INTERVAL].name = "sta-listen-interval";
      arr[NL80211_ATTR_STA_LISTEN_INTERVAL].type = YNL_PT_U16;
      arr[NL80211_ATTR_STA_SUPPORTED_RATES].name = "sta-supported-rates";
      arr[NL80211_ATTR_STA_SUPPORTED_RATES].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_STA_VLAN].name = "sta-vlan";
      arr[NL80211_ATTR_STA_VLAN].type = YNL_PT_U32;
      arr[NL80211_ATTR_STA_INFO].name = "sta-info";
      arr[NL80211_ATTR_STA_INFO].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_WIPHY_BANDS].name = "wiphy-bands";
      arr[NL80211_ATTR_WIPHY_BANDS].type = YNL_PT_NEST;
      arr[NL80211_ATTR_WIPHY_BANDS].nest = &nl80211_wiphy_bands_nest;
      arr[NL80211_ATTR_MNTR_FLAGS].name = "mntr-flags";
      arr[NL80211_ATTR_MNTR_FLAGS].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_MESH_ID].name = "mesh-id";
      arr[NL80211_ATTR_MESH_ID].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_STA_PLINK_ACTION].name = "sta-plink-action";
      arr[NL80211_ATTR_STA_PLINK_ACTION].type = YNL_PT_U8;
      arr[NL80211_ATTR_MPATH_NEXT_HOP].name = "mpath-next-hop";
      arr[NL80211_ATTR_MPATH_NEXT_HOP].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_MPATH_INFO].name = "mpath-info";
      arr[NL80211_ATTR_MPATH_INFO].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_BSS_CTS_PROT].name = "bss-cts-prot";
      arr[NL80211_ATTR_BSS_CTS_PROT].type = YNL_PT_U8;
      arr[NL80211_ATTR_BSS_SHORT_PREAMBLE].name = "bss-short-preamble";
      arr[NL80211_ATTR_BSS_SHORT_PREAMBLE].type = YNL_PT_U8;
      arr[NL80211_ATTR_BSS_SHORT_SLOT_TIME].name = "bss-short-slot-time";
      arr[NL80211_ATTR_BSS_SHORT_SLOT_TIME].type = YNL_PT_U8;
      arr[NL80211_ATTR_HT_CAPABILITY].name = "ht-capability";
      arr[NL80211_ATTR_HT_CAPABILITY].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_SUPPORTED_IFTYPES].name = "supported-iftypes";
      arr[NL80211_ATTR_SUPPORTED_IFTYPES].type = YNL_PT_NEST;
      arr[NL80211_ATTR_SUPPORTED_IFTYPES].nest =
          &nl80211_supported_iftypes_nest;
      arr[NL80211_ATTR_REG_ALPHA2].name = "reg-alpha2";
      arr[NL80211_ATTR_REG_ALPHA2].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_REG_RULES].name = "reg-rules";
      arr[NL80211_ATTR_REG_RULES].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_MESH_CONFIG].name = "mesh-config";
      arr[NL80211_ATTR_MESH_CONFIG].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_BSS_BASIC_RATES].name = "bss-basic-rates";
      arr[NL80211_ATTR_BSS_BASIC_RATES].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_WIPHY_TXQ_PARAMS].name = "wiphy-txq-params";
      arr[NL80211_ATTR_WIPHY_TXQ_PARAMS].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_WIPHY_FREQ].name = "wiphy-freq";
      arr[NL80211_ATTR_WIPHY_FREQ].type = YNL_PT_U32;
      arr[NL80211_ATTR_WIPHY_CHANNEL_TYPE].name = "wiphy-channel-type";
      arr[NL80211_ATTR_WIPHY_CHANNEL_TYPE].type = YNL_PT_U32;
      arr[NL80211_ATTR_KEY_DEFAULT_MGMT].name = "key-default-mgmt";
      arr[NL80211_ATTR_KEY_DEFAULT_MGMT].type = YNL_PT_FLAG;
      arr[NL80211_ATTR_MGMT_SUBTYPE].name = "mgmt-subtype";
      arr[NL80211_ATTR_MGMT_SUBTYPE].type = YNL_PT_U8;
      arr[NL80211_ATTR_IE].name = "ie";
      arr[NL80211_ATTR_IE].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_MAX_NUM_SCAN_SSIDS].name = "max-num-scan-ssids";
      arr[NL80211_ATTR_MAX_NUM_SCAN_SSIDS].type = YNL_PT_U8;
      arr[NL80211_ATTR_SCAN_FREQUENCIES].name = "scan-frequencies";
      arr[NL80211_ATTR_SCAN_FREQUENCIES].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_SCAN_SSIDS].name = "scan-ssids";
      arr[NL80211_ATTR_SCAN_SSIDS].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_GENERATION].name = "generation";
      arr[NL80211_ATTR_GENERATION].type = YNL_PT_U32;
      arr[NL80211_ATTR_BSS].name = "bss";
      arr[NL80211_ATTR_BSS].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_REG_INITIATOR].name = "reg-initiator";
      arr[NL80211_ATTR_REG_INITIATOR].type = YNL_PT_U8;
      arr[NL80211_ATTR_REG_TYPE].name = "reg-type";
      arr[NL80211_ATTR_REG_TYPE].type = YNL_PT_U8;
      arr[NL80211_ATTR_SUPPORTED_COMMANDS].name = "supported-commands";
      arr[NL80211_ATTR_SUPPORTED_COMMANDS].type = YNL_PT_U32;
      arr[NL80211_ATTR_FRAME].name = "frame";
      arr[NL80211_ATTR_FRAME].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_SSID].name = "ssid";
      arr[NL80211_ATTR_SSID].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_AUTH_TYPE].name = "auth-type";
      arr[NL80211_ATTR_AUTH_TYPE].type = YNL_PT_U32;
      arr[NL80211_ATTR_REASON_CODE].name = "reason-code";
      arr[NL80211_ATTR_REASON_CODE].type = YNL_PT_U16;
      arr[NL80211_ATTR_KEY_TYPE].name = "key-type";
      arr[NL80211_ATTR_KEY_TYPE].type = YNL_PT_U32;
      arr[NL80211_ATTR_MAX_SCAN_IE_LEN].name = "max-scan-ie-len";
      arr[NL80211_ATTR_MAX_SCAN_IE_LEN].type = YNL_PT_U16;
      arr[NL80211_ATTR_CIPHER_SUITES].name = "cipher-suites";
      arr[NL80211_ATTR_CIPHER_SUITES].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_FREQ_BEFORE].name = "freq-before";
      arr[NL80211_ATTR_FREQ_BEFORE].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_FREQ_AFTER].name = "freq-after";
      arr[NL80211_ATTR_FREQ_AFTER].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_FREQ_FIXED].name = "freq-fixed";
      arr[NL80211_ATTR_FREQ_FIXED].type = YNL_PT_FLAG;
      arr[NL80211_ATTR_WIPHY_RETRY_SHORT].name = "wiphy-retry-short";
      arr[NL80211_ATTR_WIPHY_RETRY_SHORT].type = YNL_PT_U8;
      arr[NL80211_ATTR_WIPHY_RETRY_LONG].name = "wiphy-retry-long";
      arr[NL80211_ATTR_WIPHY_RETRY_LONG].type = YNL_PT_U8;
      arr[NL80211_ATTR_WIPHY_FRAG_THRESHOLD].name = "wiphy-frag-threshold";
      arr[NL80211_ATTR_WIPHY_FRAG_THRESHOLD].type = YNL_PT_U32;
      arr[NL80211_ATTR_WIPHY_RTS_THRESHOLD].name = "wiphy-rts-threshold";
      arr[NL80211_ATTR_WIPHY_RTS_THRESHOLD].type = YNL_PT_U32;
      arr[NL80211_ATTR_TIMED_OUT].name = "timed-out";
      arr[NL80211_ATTR_TIMED_OUT].type = YNL_PT_FLAG;
      arr[NL80211_ATTR_USE_MFP].name = "use-mfp";
      arr[NL80211_ATTR_USE_MFP].type = YNL_PT_U32;
      arr[NL80211_ATTR_STA_FLAGS2].name = "sta-flags2";
      arr[NL80211_ATTR_STA_FLAGS2].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_CONTROL_PORT].name = "control-port";
      arr[NL80211_ATTR_CONTROL_PORT].type = YNL_PT_FLAG;
      arr[NL80211_ATTR_TESTDATA].name = "testdata";
      arr[NL80211_ATTR_TESTDATA].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_PRIVACY].name = "privacy";
      arr[NL80211_ATTR_PRIVACY].type = YNL_PT_FLAG;
      arr[NL80211_ATTR_DISCONNECTED_BY_AP].name = "disconnected-by-ap";
      arr[NL80211_ATTR_DISCONNECTED_BY_AP].type = YNL_PT_FLAG;
      arr[NL80211_ATTR_STATUS_CODE].name = "status-code";
      arr[NL80211_ATTR_STATUS_CODE].type = YNL_PT_U16;
      arr[NL80211_ATTR_CIPHER_SUITES_PAIRWISE].name = "cipher-suites-pairwise";
      arr[NL80211_ATTR_CIPHER_SUITES_PAIRWISE].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_CIPHER_SUITE_GROUP].name = "cipher-suite-group";
      arr[NL80211_ATTR_CIPHER_SUITE_GROUP].type = YNL_PT_U32;
      arr[NL80211_ATTR_WPA_VERSIONS].name = "wpa-versions";
      arr[NL80211_ATTR_WPA_VERSIONS].type = YNL_PT_U32;
      arr[NL80211_ATTR_AKM_SUITES].name = "akm-suites";
      arr[NL80211_ATTR_AKM_SUITES].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_REQ_IE].name = "req-ie";
      arr[NL80211_ATTR_REQ_IE].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_RESP_IE].name = "resp-ie";
      arr[NL80211_ATTR_RESP_IE].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_PREV_BSSID].name = "prev-bssid";
      arr[NL80211_ATTR_PREV_BSSID].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_KEY].name = "key";
      arr[NL80211_ATTR_KEY].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_KEYS].name = "keys";
      arr[NL80211_ATTR_KEYS].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_PID].name = "pid";
      arr[NL80211_ATTR_PID].type = YNL_PT_U32;
      arr[NL80211_ATTR_4ADDR].name = "4addr";
      arr[NL80211_ATTR_4ADDR].type = YNL_PT_U8;
      arr[NL80211_ATTR_SURVEY_INFO].name = "survey-info";
      arr[NL80211_ATTR_SURVEY_INFO].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_PMKID].name = "pmkid";
      arr[NL80211_ATTR_PMKID].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_MAX_NUM_PMKIDS].name = "max-num-pmkids";
      arr[NL80211_ATTR_MAX_NUM_PMKIDS].type = YNL_PT_U8;
      arr[NL80211_ATTR_DURATION].name = "duration";
      arr[NL80211_ATTR_DURATION].type = YNL_PT_U32;
      arr[NL80211_ATTR_COOKIE].name = "cookie";
      arr[NL80211_ATTR_COOKIE].type = YNL_PT_U64;
      arr[NL80211_ATTR_WIPHY_COVERAGE_CLASS].name = "wiphy-coverage-class";
      arr[NL80211_ATTR_WIPHY_COVERAGE_CLASS].type = YNL_PT_U8;
      arr[NL80211_ATTR_TX_RATES].name = "tx-rates";
      arr[NL80211_ATTR_TX_RATES].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_FRAME_MATCH].name = "frame-match";
      arr[NL80211_ATTR_FRAME_MATCH].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_ACK].name = "ack";
      arr[NL80211_ATTR_ACK].type = YNL_PT_FLAG;
      arr[NL80211_ATTR_PS_STATE].name = "ps-state";
      arr[NL80211_ATTR_PS_STATE].type = YNL_PT_U32;
      arr[NL80211_ATTR_CQM].name = "cqm";
      arr[NL80211_ATTR_CQM].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_LOCAL_STATE_CHANGE].name = "local-state-change";
      arr[NL80211_ATTR_LOCAL_STATE_CHANGE].type = YNL_PT_FLAG;
      arr[NL80211_ATTR_AP_ISOLATE].name = "ap-isolate";
      arr[NL80211_ATTR_AP_ISOLATE].type = YNL_PT_U8;
      arr[NL80211_ATTR_WIPHY_TX_POWER_SETTING].name = "wiphy-tx-power-setting";
      arr[NL80211_ATTR_WIPHY_TX_POWER_SETTING].type = YNL_PT_U32;
      arr[NL80211_ATTR_WIPHY_TX_POWER_LEVEL].name = "wiphy-tx-power-level";
      arr[NL80211_ATTR_WIPHY_TX_POWER_LEVEL].type = YNL_PT_U32;
      arr[NL80211_ATTR_TX_FRAME_TYPES].name = "tx-frame-types";
      arr[NL80211_ATTR_TX_FRAME_TYPES].type = YNL_PT_NEST;
      arr[NL80211_ATTR_TX_FRAME_TYPES].nest = &nl80211_iftype_attrs_nest;
      arr[NL80211_ATTR_RX_FRAME_TYPES].name = "rx-frame-types";
      arr[NL80211_ATTR_RX_FRAME_TYPES].type = YNL_PT_NEST;
      arr[NL80211_ATTR_RX_FRAME_TYPES].nest = &nl80211_iftype_attrs_nest;
      arr[NL80211_ATTR_FRAME_TYPE].name = "frame-type";
      arr[NL80211_ATTR_FRAME_TYPE].type = YNL_PT_U16;
      arr[NL80211_ATTR_CONTROL_PORT_ETHERTYPE].name = "control-port-ethertype";
      arr[NL80211_ATTR_CONTROL_PORT_ETHERTYPE].type = YNL_PT_FLAG;
      arr[NL80211_ATTR_CONTROL_PORT_NO_ENCRYPT].name =
          "control-port-no-encrypt";
      arr[NL80211_ATTR_CONTROL_PORT_NO_ENCRYPT].type = YNL_PT_FLAG;
      arr[NL80211_ATTR_SUPPORT_IBSS_RSN].name = "support-ibss-rsn";
      arr[NL80211_ATTR_SUPPORT_IBSS_RSN].type = YNL_PT_FLAG;
      arr[NL80211_ATTR_WIPHY_ANTENNA_TX].name = "wiphy-antenna-tx";
      arr[NL80211_ATTR_WIPHY_ANTENNA_TX].type = YNL_PT_U32;
      arr[NL80211_ATTR_WIPHY_ANTENNA_RX].name = "wiphy-antenna-rx";
      arr[NL80211_ATTR_WIPHY_ANTENNA_RX].type = YNL_PT_U32;
      arr[NL80211_ATTR_MCAST_RATE].name = "mcast-rate";
      arr[NL80211_ATTR_MCAST_RATE].type = YNL_PT_U32;
      arr[NL80211_ATTR_OFFCHANNEL_TX_OK].name = "offchannel-tx-ok";
      arr[NL80211_ATTR_OFFCHANNEL_TX_OK].type = YNL_PT_FLAG;
      arr[NL80211_ATTR_BSS_HT_OPMODE].name = "bss-ht-opmode";
      arr[NL80211_ATTR_BSS_HT_OPMODE].type = YNL_PT_U16;
      arr[NL80211_ATTR_KEY_DEFAULT_TYPES].name = "key-default-types";
      arr[NL80211_ATTR_KEY_DEFAULT_TYPES].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_MAX_REMAIN_ON_CHANNEL_DURATION].name =
          "max-remain-on-channel-duration";
      arr[NL80211_ATTR_MAX_REMAIN_ON_CHANNEL_DURATION].type = YNL_PT_U32;
      arr[NL80211_ATTR_MESH_SETUP].name = "mesh-setup";
      arr[NL80211_ATTR_MESH_SETUP].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_WIPHY_ANTENNA_AVAIL_TX].name = "wiphy-antenna-avail-tx";
      arr[NL80211_ATTR_WIPHY_ANTENNA_AVAIL_TX].type = YNL_PT_U32;
      arr[NL80211_ATTR_WIPHY_ANTENNA_AVAIL_RX].name = "wiphy-antenna-avail-rx";
      arr[NL80211_ATTR_WIPHY_ANTENNA_AVAIL_RX].type = YNL_PT_U32;
      arr[NL80211_ATTR_SUPPORT_MESH_AUTH].name = "support-mesh-auth";
      arr[NL80211_ATTR_SUPPORT_MESH_AUTH].type = YNL_PT_FLAG;
      arr[NL80211_ATTR_STA_PLINK_STATE].name = "sta-plink-state";
      arr[NL80211_ATTR_STA_PLINK_STATE].type = YNL_PT_U8;
      arr[NL80211_ATTR_WOWLAN_TRIGGERS].name = "wowlan-triggers";
      arr[NL80211_ATTR_WOWLAN_TRIGGERS].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_WOWLAN_TRIGGERS_SUPPORTED].name =
          "wowlan-triggers-supported";
      arr[NL80211_ATTR_WOWLAN_TRIGGERS_SUPPORTED].type = YNL_PT_NEST;
      arr[NL80211_ATTR_WOWLAN_TRIGGERS_SUPPORTED].nest =
          &nl80211_wowlan_triggers_attrs_nest;
      arr[NL80211_ATTR_SCHED_SCAN_INTERVAL].name = "sched-scan-interval";
      arr[NL80211_ATTR_SCHED_SCAN_INTERVAL].type = YNL_PT_U32;
      arr[NL80211_ATTR_INTERFACE_COMBINATIONS].name = "interface-combinations";
      arr[NL80211_ATTR_INTERFACE_COMBINATIONS].type = YNL_PT_NEST;
      arr[NL80211_ATTR_INTERFACE_COMBINATIONS].nest =
          &nl80211_if_combination_attributes_nest;
      arr[NL80211_ATTR_SOFTWARE_IFTYPES].name = "software-iftypes";
      arr[NL80211_ATTR_SOFTWARE_IFTYPES].type = YNL_PT_NEST;
      arr[NL80211_ATTR_SOFTWARE_IFTYPES].nest = &nl80211_supported_iftypes_nest;
      arr[NL80211_ATTR_REKEY_DATA].name = "rekey-data";
      arr[NL80211_ATTR_REKEY_DATA].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_MAX_NUM_SCHED_SCAN_SSIDS].name =
          "max-num-sched-scan-ssids";
      arr[NL80211_ATTR_MAX_NUM_SCHED_SCAN_SSIDS].type = YNL_PT_U8;
      arr[NL80211_ATTR_MAX_SCHED_SCAN_IE_LEN].name = "max-sched-scan-ie-len";
      arr[NL80211_ATTR_MAX_SCHED_SCAN_IE_LEN].type = YNL_PT_U16;
      arr[NL80211_ATTR_SCAN_SUPP_RATES].name = "scan-supp-rates";
      arr[NL80211_ATTR_SCAN_SUPP_RATES].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_HIDDEN_SSID].name = "hidden-ssid";
      arr[NL80211_ATTR_HIDDEN_SSID].type = YNL_PT_U32;
      arr[NL80211_ATTR_IE_PROBE_RESP].name = "ie-probe-resp";
      arr[NL80211_ATTR_IE_PROBE_RESP].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_IE_ASSOC_RESP].name = "ie-assoc-resp";
      arr[NL80211_ATTR_IE_ASSOC_RESP].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_STA_WME].name = "sta-wme";
      arr[NL80211_ATTR_STA_WME].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_SUPPORT_AP_UAPSD].name = "support-ap-uapsd";
      arr[NL80211_ATTR_SUPPORT_AP_UAPSD].type = YNL_PT_FLAG;
      arr[NL80211_ATTR_ROAM_SUPPORT].name = "roam-support";
      arr[NL80211_ATTR_ROAM_SUPPORT].type = YNL_PT_FLAG;
      arr[NL80211_ATTR_SCHED_SCAN_MATCH].name = "sched-scan-match";
      arr[NL80211_ATTR_SCHED_SCAN_MATCH].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_MAX_MATCH_SETS].name = "max-match-sets";
      arr[NL80211_ATTR_MAX_MATCH_SETS].type = YNL_PT_U8;
      arr[NL80211_ATTR_PMKSA_CANDIDATE].name = "pmksa-candidate";
      arr[NL80211_ATTR_PMKSA_CANDIDATE].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_TX_NO_CCK_RATE].name = "tx-no-cck-rate";
      arr[NL80211_ATTR_TX_NO_CCK_RATE].type = YNL_PT_FLAG;
      arr[NL80211_ATTR_TDLS_ACTION].name = "tdls-action";
      arr[NL80211_ATTR_TDLS_ACTION].type = YNL_PT_U8;
      arr[NL80211_ATTR_TDLS_DIALOG_TOKEN].name = "tdls-dialog-token";
      arr[NL80211_ATTR_TDLS_DIALOG_TOKEN].type = YNL_PT_U8;
      arr[NL80211_ATTR_TDLS_OPERATION].name = "tdls-operation";
      arr[NL80211_ATTR_TDLS_OPERATION].type = YNL_PT_U8;
      arr[NL80211_ATTR_TDLS_SUPPORT].name = "tdls-support";
      arr[NL80211_ATTR_TDLS_SUPPORT].type = YNL_PT_FLAG;
      arr[NL80211_ATTR_TDLS_EXTERNAL_SETUP].name = "tdls-external-setup";
      arr[NL80211_ATTR_TDLS_EXTERNAL_SETUP].type = YNL_PT_FLAG;
      arr[NL80211_ATTR_DEVICE_AP_SME].name = "device-ap-sme";
      arr[NL80211_ATTR_DEVICE_AP_SME].type = YNL_PT_U32;
      arr[NL80211_ATTR_DONT_WAIT_FOR_ACK].name = "dont-wait-for-ack";
      arr[NL80211_ATTR_DONT_WAIT_FOR_ACK].type = YNL_PT_FLAG;
      arr[NL80211_ATTR_FEATURE_FLAGS].name = "feature-flags";
      arr[NL80211_ATTR_FEATURE_FLAGS].type = YNL_PT_U32;
      arr[NL80211_ATTR_PROBE_RESP_OFFLOAD].name = "probe-resp-offload";
      arr[NL80211_ATTR_PROBE_RESP_OFFLOAD].type = YNL_PT_U32;
      arr[NL80211_ATTR_PROBE_RESP].name = "probe-resp";
      arr[NL80211_ATTR_PROBE_RESP].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_DFS_REGION].name = "dfs-region";
      arr[NL80211_ATTR_DFS_REGION].type = YNL_PT_U8;
      arr[NL80211_ATTR_DISABLE_HT].name = "disable-ht";
      arr[NL80211_ATTR_DISABLE_HT].type = YNL_PT_FLAG;
      arr[NL80211_ATTR_HT_CAPABILITY_MASK].name = "ht-capability-mask";
      arr[NL80211_ATTR_HT_CAPABILITY_MASK].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_NOACK_MAP].name = "noack-map";
      arr[NL80211_ATTR_NOACK_MAP].type = YNL_PT_U16;
      arr[NL80211_ATTR_INACTIVITY_TIMEOUT].name = "inactivity-timeout";
      arr[NL80211_ATTR_INACTIVITY_TIMEOUT].type = YNL_PT_U16;
      arr[NL80211_ATTR_RX_SIGNAL_DBM].name = "rx-signal-dbm";
      arr[NL80211_ATTR_RX_SIGNAL_DBM].type = YNL_PT_U32;
      arr[NL80211_ATTR_BG_SCAN_PERIOD].name = "bg-scan-period";
      arr[NL80211_ATTR_BG_SCAN_PERIOD].type = YNL_PT_U16;
      arr[NL80211_ATTR_WDEV].name = "wdev";
      arr[NL80211_ATTR_WDEV].type = YNL_PT_U64;
      arr[NL80211_ATTR_USER_REG_HINT_TYPE].name = "user-reg-hint-type";
      arr[NL80211_ATTR_USER_REG_HINT_TYPE].type = YNL_PT_U32;
      arr[NL80211_ATTR_CONN_FAILED_REASON].name = "conn-failed-reason";
      arr[NL80211_ATTR_CONN_FAILED_REASON].type = YNL_PT_U32;
      arr[NL80211_ATTR_AUTH_DATA].name = "auth-data";
      arr[NL80211_ATTR_AUTH_DATA].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_VHT_CAPABILITY].name = "vht-capability";
      arr[NL80211_ATTR_VHT_CAPABILITY].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_SCAN_FLAGS].name = "scan-flags";
      arr[NL80211_ATTR_SCAN_FLAGS].type = YNL_PT_U32;
      arr[NL80211_ATTR_CHANNEL_WIDTH].name = "channel-width";
      arr[NL80211_ATTR_CHANNEL_WIDTH].type = YNL_PT_U32;
      arr[NL80211_ATTR_CENTER_FREQ1].name = "center-freq1";
      arr[NL80211_ATTR_CENTER_FREQ1].type = YNL_PT_U32;
      arr[NL80211_ATTR_CENTER_FREQ2].name = "center-freq2";
      arr[NL80211_ATTR_CENTER_FREQ2].type = YNL_PT_U32;
      arr[NL80211_ATTR_P2P_CTWINDOW].name = "p2p-ctwindow";
      arr[NL80211_ATTR_P2P_CTWINDOW].type = YNL_PT_U8;
      arr[NL80211_ATTR_P2P_OPPPS].name = "p2p-oppps";
      arr[NL80211_ATTR_P2P_OPPPS].type = YNL_PT_U8;
      arr[NL80211_ATTR_LOCAL_MESH_POWER_MODE].name = "local-mesh-power-mode";
      arr[NL80211_ATTR_LOCAL_MESH_POWER_MODE].type = YNL_PT_U32;
      arr[NL80211_ATTR_ACL_POLICY].name = "acl-policy";
      arr[NL80211_ATTR_ACL_POLICY].type = YNL_PT_U32;
      arr[NL80211_ATTR_MAC_ADDRS].name = "mac-addrs";
      arr[NL80211_ATTR_MAC_ADDRS].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_MAC_ACL_MAX].name = "mac-acl-max";
      arr[NL80211_ATTR_MAC_ACL_MAX].type = YNL_PT_U32;
      arr[NL80211_ATTR_RADAR_EVENT].name = "radar-event";
      arr[NL80211_ATTR_RADAR_EVENT].type = YNL_PT_U32;
      arr[NL80211_ATTR_EXT_CAPA].name = "ext-capa";
      arr[NL80211_ATTR_EXT_CAPA].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_EXT_CAPA_MASK].name = "ext-capa-mask";
      arr[NL80211_ATTR_EXT_CAPA_MASK].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_STA_CAPABILITY].name = "sta-capability";
      arr[NL80211_ATTR_STA_CAPABILITY].type = YNL_PT_U16;
      arr[NL80211_ATTR_STA_EXT_CAPABILITY].name = "sta-ext-capability";
      arr[NL80211_ATTR_STA_EXT_CAPABILITY].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_PROTOCOL_FEATURES].name = "protocol-features";
      arr[NL80211_ATTR_PROTOCOL_FEATURES].type = YNL_PT_U32;
      arr[NL80211_ATTR_SPLIT_WIPHY_DUMP].name = "split-wiphy-dump";
      arr[NL80211_ATTR_SPLIT_WIPHY_DUMP].type = YNL_PT_FLAG;
      arr[NL80211_ATTR_DISABLE_VHT].name = "disable-vht";
      arr[NL80211_ATTR_DISABLE_VHT].type = YNL_PT_FLAG;
      arr[NL80211_ATTR_VHT_CAPABILITY_MASK].name = "vht-capability-mask";
      arr[NL80211_ATTR_VHT_CAPABILITY_MASK].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_MDID].name = "mdid";
      arr[NL80211_ATTR_MDID].type = YNL_PT_U16;
      arr[NL80211_ATTR_IE_RIC].name = "ie-ric";
      arr[NL80211_ATTR_IE_RIC].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_CRIT_PROT_ID].name = "crit-prot-id";
      arr[NL80211_ATTR_CRIT_PROT_ID].type = YNL_PT_U16;
      arr[NL80211_ATTR_MAX_CRIT_PROT_DURATION].name = "max-crit-prot-duration";
      arr[NL80211_ATTR_MAX_CRIT_PROT_DURATION].type = YNL_PT_U16;
      arr[NL80211_ATTR_PEER_AID].name = "peer-aid";
      arr[NL80211_ATTR_PEER_AID].type = YNL_PT_U16;
      arr[NL80211_ATTR_COALESCE_RULE].name = "coalesce-rule";
      arr[NL80211_ATTR_COALESCE_RULE].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_CH_SWITCH_COUNT].name = "ch-switch-count";
      arr[NL80211_ATTR_CH_SWITCH_COUNT].type = YNL_PT_U32;
      arr[NL80211_ATTR_CH_SWITCH_BLOCK_TX].name = "ch-switch-block-tx";
      arr[NL80211_ATTR_CH_SWITCH_BLOCK_TX].type = YNL_PT_FLAG;
      arr[NL80211_ATTR_CSA_IES].name = "csa-ies";
      arr[NL80211_ATTR_CSA_IES].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_CNTDWN_OFFS_BEACON].name = "cntdwn-offs-beacon";
      arr[NL80211_ATTR_CNTDWN_OFFS_BEACON].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_CNTDWN_OFFS_PRESP].name = "cntdwn-offs-presp";
      arr[NL80211_ATTR_CNTDWN_OFFS_PRESP].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_RXMGMT_FLAGS].name = "rxmgmt-flags";
      arr[NL80211_ATTR_RXMGMT_FLAGS].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_STA_SUPPORTED_CHANNELS].name = "sta-supported-channels";
      arr[NL80211_ATTR_STA_SUPPORTED_CHANNELS].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_STA_SUPPORTED_OPER_CLASSES].name =
          "sta-supported-oper-classes";
      arr[NL80211_ATTR_STA_SUPPORTED_OPER_CLASSES].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_HANDLE_DFS].name = "handle-dfs";
      arr[NL80211_ATTR_HANDLE_DFS].type = YNL_PT_FLAG;
      arr[NL80211_ATTR_SUPPORT_5_MHZ].name = "support-5-mhz";
      arr[NL80211_ATTR_SUPPORT_5_MHZ].type = YNL_PT_FLAG;
      arr[NL80211_ATTR_SUPPORT_10_MHZ].name = "support-10-mhz";
      arr[NL80211_ATTR_SUPPORT_10_MHZ].type = YNL_PT_FLAG;
      arr[NL80211_ATTR_OPMODE_NOTIF].name = "opmode-notif";
      arr[NL80211_ATTR_OPMODE_NOTIF].type = YNL_PT_U8;
      arr[NL80211_ATTR_VENDOR_ID].name = "vendor-id";
      arr[NL80211_ATTR_VENDOR_ID].type = YNL_PT_U32;
      arr[NL80211_ATTR_VENDOR_SUBCMD].name = "vendor-subcmd";
      arr[NL80211_ATTR_VENDOR_SUBCMD].type = YNL_PT_U32;
      arr[NL80211_ATTR_VENDOR_DATA].name = "vendor-data";
      arr[NL80211_ATTR_VENDOR_DATA].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_VENDOR_EVENTS].name = "vendor-events";
      arr[NL80211_ATTR_VENDOR_EVENTS].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_QOS_MAP].name = "qos-map";
      arr[NL80211_ATTR_QOS_MAP].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_MAC_HINT].name = "mac-hint";
      arr[NL80211_ATTR_MAC_HINT].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_WIPHY_FREQ_HINT].name = "wiphy-freq-hint";
      arr[NL80211_ATTR_WIPHY_FREQ_HINT].type = YNL_PT_U32;
      arr[NL80211_ATTR_MAX_AP_ASSOC_STA].name = "max-ap-assoc-sta";
      arr[NL80211_ATTR_MAX_AP_ASSOC_STA].type = YNL_PT_U32;
      arr[NL80211_ATTR_TDLS_PEER_CAPABILITY].name = "tdls-peer-capability";
      arr[NL80211_ATTR_TDLS_PEER_CAPABILITY].type = YNL_PT_U32;
      arr[NL80211_ATTR_SOCKET_OWNER].name = "socket-owner";
      arr[NL80211_ATTR_SOCKET_OWNER].type = YNL_PT_FLAG;
      arr[NL80211_ATTR_CSA_C_OFFSETS_TX].name = "csa-c-offsets-tx";
      arr[NL80211_ATTR_CSA_C_OFFSETS_TX].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_MAX_CSA_COUNTERS].name = "max-csa-counters";
      arr[NL80211_ATTR_MAX_CSA_COUNTERS].type = YNL_PT_U8;
      arr[NL80211_ATTR_TDLS_INITIATOR].name = "tdls-initiator";
      arr[NL80211_ATTR_TDLS_INITIATOR].type = YNL_PT_FLAG;
      arr[NL80211_ATTR_USE_RRM].name = "use-rrm";
      arr[NL80211_ATTR_USE_RRM].type = YNL_PT_FLAG;
      arr[NL80211_ATTR_WIPHY_DYN_ACK].name = "wiphy-dyn-ack";
      arr[NL80211_ATTR_WIPHY_DYN_ACK].type = YNL_PT_FLAG;
      arr[NL80211_ATTR_TSID].name = "tsid";
      arr[NL80211_ATTR_TSID].type = YNL_PT_U8;
      arr[NL80211_ATTR_USER_PRIO].name = "user-prio";
      arr[NL80211_ATTR_USER_PRIO].type = YNL_PT_U8;
      arr[NL80211_ATTR_ADMITTED_TIME].name = "admitted-time";
      arr[NL80211_ATTR_ADMITTED_TIME].type = YNL_PT_U16;
      arr[NL80211_ATTR_SMPS_MODE].name = "smps-mode";
      arr[NL80211_ATTR_SMPS_MODE].type = YNL_PT_U8;
      arr[NL80211_ATTR_OPER_CLASS].name = "oper-class";
      arr[NL80211_ATTR_OPER_CLASS].type = YNL_PT_U8;
      arr[NL80211_ATTR_MAC_MASK].name = "mac-mask";
      arr[NL80211_ATTR_MAC_MASK].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_WIPHY_SELF_MANAGED_REG].name = "wiphy-self-managed-reg";
      arr[NL80211_ATTR_WIPHY_SELF_MANAGED_REG].type = YNL_PT_FLAG;
      arr[NL80211_ATTR_EXT_FEATURES].name = "ext-features";
      arr[NL80211_ATTR_EXT_FEATURES].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_SURVEY_RADIO_STATS].name = "survey-radio-stats";
      arr[NL80211_ATTR_SURVEY_RADIO_STATS].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_NETNS_FD].name = "netns-fd";
      arr[NL80211_ATTR_NETNS_FD].type = YNL_PT_U32;
      arr[NL80211_ATTR_SCHED_SCAN_DELAY].name = "sched-scan-delay";
      arr[NL80211_ATTR_SCHED_SCAN_DELAY].type = YNL_PT_U32;
      arr[NL80211_ATTR_REG_INDOOR].name = "reg-indoor";
      arr[NL80211_ATTR_REG_INDOOR].type = YNL_PT_FLAG;
      arr[NL80211_ATTR_MAX_NUM_SCHED_SCAN_PLANS].name =
          "max-num-sched-scan-plans";
      arr[NL80211_ATTR_MAX_NUM_SCHED_SCAN_PLANS].type = YNL_PT_U32;
      arr[NL80211_ATTR_MAX_SCAN_PLAN_INTERVAL].name = "max-scan-plan-interval";
      arr[NL80211_ATTR_MAX_SCAN_PLAN_INTERVAL].type = YNL_PT_U32;
      arr[NL80211_ATTR_MAX_SCAN_PLAN_ITERATIONS].name =
          "max-scan-plan-iterations";
      arr[NL80211_ATTR_MAX_SCAN_PLAN_ITERATIONS].type = YNL_PT_U32;
      arr[NL80211_ATTR_SCHED_SCAN_PLANS].name = "sched-scan-plans";
      arr[NL80211_ATTR_SCHED_SCAN_PLANS].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_PBSS].name = "pbss";
      arr[NL80211_ATTR_PBSS].type = YNL_PT_FLAG;
      arr[NL80211_ATTR_BSS_SELECT].name = "bss-select";
      arr[NL80211_ATTR_BSS_SELECT].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_STA_SUPPORT_P2P_PS].name = "sta-support-p2p-ps";
      arr[NL80211_ATTR_STA_SUPPORT_P2P_PS].type = YNL_PT_U8;
      arr[NL80211_ATTR_PAD].name = "pad";
      arr[NL80211_ATTR_PAD].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_IFTYPE_EXT_CAPA].name = "iftype-ext-capa";
      arr[NL80211_ATTR_IFTYPE_EXT_CAPA].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_MU_MIMO_GROUP_DATA].name = "mu-mimo-group-data";
      arr[NL80211_ATTR_MU_MIMO_GROUP_DATA].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_MU_MIMO_FOLLOW_MAC_ADDR].name =
          "mu-mimo-follow-mac-addr";
      arr[NL80211_ATTR_MU_MIMO_FOLLOW_MAC_ADDR].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_SCAN_START_TIME_TSF].name = "scan-start-time-tsf";
      arr[NL80211_ATTR_SCAN_START_TIME_TSF].type = YNL_PT_U64;
      arr[NL80211_ATTR_SCAN_START_TIME_TSF_BSSID].name =
          "scan-start-time-tsf-bssid";
      arr[NL80211_ATTR_SCAN_START_TIME_TSF_BSSID].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_MEASUREMENT_DURATION].name = "measurement-duration";
      arr[NL80211_ATTR_MEASUREMENT_DURATION].type = YNL_PT_U16;
      arr[NL80211_ATTR_MEASUREMENT_DURATION_MANDATORY].name =
          "measurement-duration-mandatory";
      arr[NL80211_ATTR_MEASUREMENT_DURATION_MANDATORY].type = YNL_PT_FLAG;
      arr[NL80211_ATTR_MESH_PEER_AID].name = "mesh-peer-aid";
      arr[NL80211_ATTR_MESH_PEER_AID].type = YNL_PT_U16;
      arr[NL80211_ATTR_NAN_MASTER_PREF].name = "nan-master-pref";
      arr[NL80211_ATTR_NAN_MASTER_PREF].type = YNL_PT_U8;
      arr[NL80211_ATTR_BANDS].name = "bands";
      arr[NL80211_ATTR_BANDS].type = YNL_PT_U32;
      arr[NL80211_ATTR_NAN_FUNC].name = "nan-func";
      arr[NL80211_ATTR_NAN_FUNC].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_NAN_MATCH].name = "nan-match";
      arr[NL80211_ATTR_NAN_MATCH].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_FILS_KEK].name = "fils-kek";
      arr[NL80211_ATTR_FILS_KEK].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_FILS_NONCES].name = "fils-nonces";
      arr[NL80211_ATTR_FILS_NONCES].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_MULTICAST_TO_UNICAST_ENABLED].name =
          "multicast-to-unicast-enabled";
      arr[NL80211_ATTR_MULTICAST_TO_UNICAST_ENABLED].type = YNL_PT_FLAG;
      arr[NL80211_ATTR_BSSID].name = "bssid";
      arr[NL80211_ATTR_BSSID].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_SCHED_SCAN_RELATIVE_RSSI].name =
          "sched-scan-relative-rssi";
      arr[NL80211_ATTR_SCHED_SCAN_RELATIVE_RSSI].type = YNL_PT_U8;
      arr[NL80211_ATTR_SCHED_SCAN_RSSI_ADJUST].name = "sched-scan-rssi-adjust";
      arr[NL80211_ATTR_SCHED_SCAN_RSSI_ADJUST].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_TIMEOUT_REASON].name = "timeout-reason";
      arr[NL80211_ATTR_TIMEOUT_REASON].type = YNL_PT_U32;
      arr[NL80211_ATTR_FILS_ERP_USERNAME].name = "fils-erp-username";
      arr[NL80211_ATTR_FILS_ERP_USERNAME].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_FILS_ERP_REALM].name = "fils-erp-realm";
      arr[NL80211_ATTR_FILS_ERP_REALM].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_FILS_ERP_NEXT_SEQ_NUM].name = "fils-erp-next-seq-num";
      arr[NL80211_ATTR_FILS_ERP_NEXT_SEQ_NUM].type = YNL_PT_U16;
      arr[NL80211_ATTR_FILS_ERP_RRK].name = "fils-erp-rrk";
      arr[NL80211_ATTR_FILS_ERP_RRK].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_FILS_CACHE_ID].name = "fils-cache-id";
      arr[NL80211_ATTR_FILS_CACHE_ID].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_PMK].name = "pmk";
      arr[NL80211_ATTR_PMK].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_SCHED_SCAN_MULTI].name = "sched-scan-multi";
      arr[NL80211_ATTR_SCHED_SCAN_MULTI].type = YNL_PT_FLAG;
      arr[NL80211_ATTR_SCHED_SCAN_MAX_REQS].name = "sched-scan-max-reqs";
      arr[NL80211_ATTR_SCHED_SCAN_MAX_REQS].type = YNL_PT_U32;
      arr[NL80211_ATTR_WANT_1X_4WAY_HS].name = "want-1x-4way-hs";
      arr[NL80211_ATTR_WANT_1X_4WAY_HS].type = YNL_PT_FLAG;
      arr[NL80211_ATTR_PMKR0_NAME].name = "pmkr0-name";
      arr[NL80211_ATTR_PMKR0_NAME].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_PORT_AUTHORIZED].name = "port-authorized";
      arr[NL80211_ATTR_PORT_AUTHORIZED].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_EXTERNAL_AUTH_ACTION].name = "external-auth-action";
      arr[NL80211_ATTR_EXTERNAL_AUTH_ACTION].type = YNL_PT_U32;
      arr[NL80211_ATTR_EXTERNAL_AUTH_SUPPORT].name = "external-auth-support";
      arr[NL80211_ATTR_EXTERNAL_AUTH_SUPPORT].type = YNL_PT_FLAG;
      arr[NL80211_ATTR_NSS].name = "nss";
      arr[NL80211_ATTR_NSS].type = YNL_PT_U8;
      arr[NL80211_ATTR_ACK_SIGNAL].name = "ack-signal";
      arr[NL80211_ATTR_ACK_SIGNAL].type = YNL_PT_U32;
      arr[NL80211_ATTR_CONTROL_PORT_OVER_NL80211].name =
          "control-port-over-nl80211";
      arr[NL80211_ATTR_CONTROL_PORT_OVER_NL80211].type = YNL_PT_FLAG;
      arr[NL80211_ATTR_TXQ_STATS].name = "txq-stats";
      arr[NL80211_ATTR_TXQ_STATS].type = YNL_PT_NEST;
      arr[NL80211_ATTR_TXQ_STATS].nest = &nl80211_txq_stats_attrs_nest;
      arr[NL80211_ATTR_TXQ_LIMIT].name = "txq-limit";
      arr[NL80211_ATTR_TXQ_LIMIT].type = YNL_PT_U32;
      arr[NL80211_ATTR_TXQ_MEMORY_LIMIT].name = "txq-memory-limit";
      arr[NL80211_ATTR_TXQ_MEMORY_LIMIT].type = YNL_PT_U32;
      arr[NL80211_ATTR_TXQ_QUANTUM].name = "txq-quantum";
      arr[NL80211_ATTR_TXQ_QUANTUM].type = YNL_PT_U32;
      arr[NL80211_ATTR_HE_CAPABILITY].name = "he-capability";
      arr[NL80211_ATTR_HE_CAPABILITY].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_FTM_RESPONDER].name = "ftm-responder";
      arr[NL80211_ATTR_FTM_RESPONDER].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_FTM_RESPONDER_STATS].name = "ftm-responder-stats";
      arr[NL80211_ATTR_FTM_RESPONDER_STATS].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_TIMEOUT].name = "timeout";
      arr[NL80211_ATTR_TIMEOUT].type = YNL_PT_U32;
      arr[NL80211_ATTR_PEER_MEASUREMENTS].name = "peer-measurements";
      arr[NL80211_ATTR_PEER_MEASUREMENTS].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_AIRTIME_WEIGHT].name = "airtime-weight";
      arr[NL80211_ATTR_AIRTIME_WEIGHT].type = YNL_PT_U16;
      arr[NL80211_ATTR_STA_TX_POWER_SETTING].name = "sta-tx-power-setting";
      arr[NL80211_ATTR_STA_TX_POWER_SETTING].type = YNL_PT_U8;
      arr[NL80211_ATTR_STA_TX_POWER].name = "sta-tx-power";
      arr[NL80211_ATTR_STA_TX_POWER].type = YNL_PT_U16;
      arr[NL80211_ATTR_SAE_PASSWORD].name = "sae-password";
      arr[NL80211_ATTR_SAE_PASSWORD].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_TWT_RESPONDER].name = "twt-responder";
      arr[NL80211_ATTR_TWT_RESPONDER].type = YNL_PT_FLAG;
      arr[NL80211_ATTR_HE_OBSS_PD].name = "he-obss-pd";
      arr[NL80211_ATTR_HE_OBSS_PD].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_WIPHY_EDMG_CHANNELS].name = "wiphy-edmg-channels";
      arr[NL80211_ATTR_WIPHY_EDMG_CHANNELS].type = YNL_PT_U8;
      arr[NL80211_ATTR_WIPHY_EDMG_BW_CONFIG].name = "wiphy-edmg-bw-config";
      arr[NL80211_ATTR_WIPHY_EDMG_BW_CONFIG].type = YNL_PT_U8;
      arr[NL80211_ATTR_VLAN_ID].name = "vlan-id";
      arr[NL80211_ATTR_VLAN_ID].type = YNL_PT_U16;
      arr[NL80211_ATTR_HE_BSS_COLOR].name = "he-bss-color";
      arr[NL80211_ATTR_HE_BSS_COLOR].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_IFTYPE_AKM_SUITES].name = "iftype-akm-suites";
      arr[NL80211_ATTR_IFTYPE_AKM_SUITES].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_TID_CONFIG].name = "tid-config";
      arr[NL80211_ATTR_TID_CONFIG].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_CONTROL_PORT_NO_PREAUTH].name =
          "control-port-no-preauth";
      arr[NL80211_ATTR_CONTROL_PORT_NO_PREAUTH].type = YNL_PT_FLAG;
      arr[NL80211_ATTR_PMK_LIFETIME].name = "pmk-lifetime";
      arr[NL80211_ATTR_PMK_LIFETIME].type = YNL_PT_U32;
      arr[NL80211_ATTR_PMK_REAUTH_THRESHOLD].name = "pmk-reauth-threshold";
      arr[NL80211_ATTR_PMK_REAUTH_THRESHOLD].type = YNL_PT_U8;
      arr[NL80211_ATTR_RECEIVE_MULTICAST].name = "receive-multicast";
      arr[NL80211_ATTR_RECEIVE_MULTICAST].type = YNL_PT_FLAG;
      arr[NL80211_ATTR_WIPHY_FREQ_OFFSET].name = "wiphy-freq-offset";
      arr[NL80211_ATTR_WIPHY_FREQ_OFFSET].type = YNL_PT_U32;
      arr[NL80211_ATTR_CENTER_FREQ1_OFFSET].name = "center-freq1-offset";
      arr[NL80211_ATTR_CENTER_FREQ1_OFFSET].type = YNL_PT_U32;
      arr[NL80211_ATTR_SCAN_FREQ_KHZ].name = "scan-freq-khz";
      arr[NL80211_ATTR_SCAN_FREQ_KHZ].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_HE_6GHZ_CAPABILITY].name = "he-6ghz-capability";
      arr[NL80211_ATTR_HE_6GHZ_CAPABILITY].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_FILS_DISCOVERY].name = "fils-discovery";
      arr[NL80211_ATTR_FILS_DISCOVERY].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_UNSOL_BCAST_PROBE_RESP].name = "unsol-bcast-probe-resp";
      arr[NL80211_ATTR_UNSOL_BCAST_PROBE_RESP].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_S1G_CAPABILITY].name = "s1g-capability";
      arr[NL80211_ATTR_S1G_CAPABILITY].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_S1G_CAPABILITY_MASK].name = "s1g-capability-mask";
      arr[NL80211_ATTR_S1G_CAPABILITY_MASK].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_SAE_PWE].name = "sae-pwe";
      arr[NL80211_ATTR_SAE_PWE].type = YNL_PT_U8;
      arr[NL80211_ATTR_RECONNECT_REQUESTED].name = "reconnect-requested";
      arr[NL80211_ATTR_RECONNECT_REQUESTED].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_SAR_SPEC].name = "sar-spec";
      arr[NL80211_ATTR_SAR_SPEC].type = YNL_PT_NEST;
      arr[NL80211_ATTR_SAR_SPEC].nest = &nl80211_sar_attributes_nest;
      arr[NL80211_ATTR_DISABLE_HE].name = "disable-he";
      arr[NL80211_ATTR_DISABLE_HE].type = YNL_PT_FLAG;
      arr[NL80211_ATTR_OBSS_COLOR_BITMAP].name = "obss-color-bitmap";
      arr[NL80211_ATTR_OBSS_COLOR_BITMAP].type = YNL_PT_U64;
      arr[NL80211_ATTR_COLOR_CHANGE_COUNT].name = "color-change-count";
      arr[NL80211_ATTR_COLOR_CHANGE_COUNT].type = YNL_PT_U8;
      arr[NL80211_ATTR_COLOR_CHANGE_COLOR].name = "color-change-color";
      arr[NL80211_ATTR_COLOR_CHANGE_COLOR].type = YNL_PT_U8;
      arr[NL80211_ATTR_COLOR_CHANGE_ELEMS].name = "color-change-elems";
      arr[NL80211_ATTR_COLOR_CHANGE_ELEMS].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_MBSSID_CONFIG].name = "mbssid-config";
      arr[NL80211_ATTR_MBSSID_CONFIG].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_MBSSID_ELEMS].name = "mbssid-elems";
      arr[NL80211_ATTR_MBSSID_ELEMS].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_RADAR_BACKGROUND].name = "radar-background";
      arr[NL80211_ATTR_RADAR_BACKGROUND].type = YNL_PT_FLAG;
      arr[NL80211_ATTR_AP_SETTINGS_FLAGS].name = "ap-settings-flags";
      arr[NL80211_ATTR_AP_SETTINGS_FLAGS].type = YNL_PT_U32;
      arr[NL80211_ATTR_EHT_CAPABILITY].name = "eht-capability";
      arr[NL80211_ATTR_EHT_CAPABILITY].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_DISABLE_EHT].name = "disable-eht";
      arr[NL80211_ATTR_DISABLE_EHT].type = YNL_PT_FLAG;
      arr[NL80211_ATTR_MLO_LINKS].name = "mlo-links";
      arr[NL80211_ATTR_MLO_LINKS].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_MLO_LINK_ID].name = "mlo-link-id";
      arr[NL80211_ATTR_MLO_LINK_ID].type = YNL_PT_U8;
      arr[NL80211_ATTR_MLD_ADDR].name = "mld-addr";
      arr[NL80211_ATTR_MLD_ADDR].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_MLO_SUPPORT].name = "mlo-support";
      arr[NL80211_ATTR_MLO_SUPPORT].type = YNL_PT_FLAG;
      arr[NL80211_ATTR_MAX_NUM_AKM_SUITES].name = "max-num-akm-suites";
      arr[NL80211_ATTR_MAX_NUM_AKM_SUITES].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_EML_CAPABILITY].name = "eml-capability";
      arr[NL80211_ATTR_EML_CAPABILITY].type = YNL_PT_U16;
      arr[NL80211_ATTR_MLD_CAPA_AND_OPS].name = "mld-capa-and-ops";
      arr[NL80211_ATTR_MLD_CAPA_AND_OPS].type = YNL_PT_U16;
      arr[NL80211_ATTR_TX_HW_TIMESTAMP].name = "tx-hw-timestamp";
      arr[NL80211_ATTR_TX_HW_TIMESTAMP].type = YNL_PT_U64;
      arr[NL80211_ATTR_RX_HW_TIMESTAMP].name = "rx-hw-timestamp";
      arr[NL80211_ATTR_RX_HW_TIMESTAMP].type = YNL_PT_U64;
      arr[NL80211_ATTR_TD_BITMAP].name = "td-bitmap";
      arr[NL80211_ATTR_TD_BITMAP].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_PUNCT_BITMAP].name = "punct-bitmap";
      arr[NL80211_ATTR_PUNCT_BITMAP].type = YNL_PT_U32;
      arr[NL80211_ATTR_MAX_HW_TIMESTAMP_PEERS].name = "max-hw-timestamp-peers";
      arr[NL80211_ATTR_MAX_HW_TIMESTAMP_PEERS].type = YNL_PT_U16;
      arr[NL80211_ATTR_HW_TIMESTAMP_ENABLED].name = "hw-timestamp-enabled";
      arr[NL80211_ATTR_HW_TIMESTAMP_ENABLED].type = YNL_PT_FLAG;
      arr[NL80211_ATTR_EMA_RNR_ELEMS].name = "ema-rnr-elems";
      arr[NL80211_ATTR_EMA_RNR_ELEMS].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_MLO_LINK_DISABLED].name = "mlo-link-disabled";
      arr[NL80211_ATTR_MLO_LINK_DISABLED].type = YNL_PT_FLAG;
      arr[NL80211_ATTR_BSS_DUMP_INCLUDE_USE_DATA].name =
          "bss-dump-include-use-data";
      arr[NL80211_ATTR_BSS_DUMP_INCLUDE_USE_DATA].type = YNL_PT_FLAG;
      arr[NL80211_ATTR_MLO_TTLM_DLINK].name = "mlo-ttlm-dlink";
      arr[NL80211_ATTR_MLO_TTLM_DLINK].type = YNL_PT_U16;
      arr[NL80211_ATTR_MLO_TTLM_ULINK].name = "mlo-ttlm-ulink";
      arr[NL80211_ATTR_MLO_TTLM_ULINK].type = YNL_PT_U16;
      arr[NL80211_ATTR_ASSOC_SPP_AMSDU].name = "assoc-spp-amsdu";
      arr[NL80211_ATTR_ASSOC_SPP_AMSDU].type = YNL_PT_FLAG;
      arr[NL80211_ATTR_WIPHY_RADIOS].name = "wiphy-radios";
      arr[NL80211_ATTR_WIPHY_RADIOS].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_WIPHY_INTERFACE_COMBINATIONS].name =
          "wiphy-interface-combinations";
      arr[NL80211_ATTR_WIPHY_INTERFACE_COMBINATIONS].type = YNL_PT_BINARY;
      arr[NL80211_ATTR_VIF_RADIO_MASK].name = "vif-radio-mask";
      arr[NL80211_ATTR_VIF_RADIO_MASK].type = YNL_PT_U32;
      return arr;
    }();

struct ynl_policy_nest nl80211_nl80211_attrs_nest = {
    .max_attr = static_cast<unsigned int>(NUM_NL80211_ATTR),
    .table = nl80211_nl80211_attrs_policy.data(),
};

/* Common nested types */
int nl80211_supported_iftypes_parse(struct ynl_parse_arg *yarg,
                                    const struct nlattr *nested) {
  nl80211_supported_iftypes *dst = (nl80211_supported_iftypes *)yarg->data;
  const struct nlattr *attr;

  ynl_attr_for_each_nested(attr, nested) {
    unsigned int type = ynl_attr_type(attr);

    if (type == NL80211_IFTYPE_ADHOC) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_IFTYPE_STATION) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_IFTYPE_AP) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_IFTYPE_AP_VLAN) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_IFTYPE_WDS) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_IFTYPE_MONITOR) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_IFTYPE_MESH_POINT) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_IFTYPE_P2P_CLIENT) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_IFTYPE_P2P_GO) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_IFTYPE_P2P_DEVICE) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_IFTYPE_OCB) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_IFTYPE_NAN) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
    }
  }

  return 0;
}

int nl80211_wowlan_triggers_attrs_parse(struct ynl_parse_arg *yarg,
                                        const struct nlattr *nested) {
  nl80211_wowlan_triggers_attrs *dst =
      (nl80211_wowlan_triggers_attrs *)yarg->data;
  const struct nlattr *attr;

  ynl_attr_for_each_nested(attr, nested) {
    unsigned int type = ynl_attr_type(attr);

    if (type == NL80211_WOWLAN_TRIG_ANY) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_WOWLAN_TRIG_DISCONNECT) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_WOWLAN_TRIG_MAGIC_PKT) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_WOWLAN_TRIG_PKT_PATTERN) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_WOWLAN_TRIG_GTK_REKEY_SUPPORTED) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_WOWLAN_TRIG_GTK_REKEY_FAILURE) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_WOWLAN_TRIG_EAP_IDENT_REQUEST) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_WOWLAN_TRIG_4WAY_HANDSHAKE) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_WOWLAN_TRIG_RFKILL_RELEASE) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_WOWLAN_TRIG_WAKEUP_PKT_80211) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_WOWLAN_TRIG_WAKEUP_PKT_80211_LEN) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_WOWLAN_TRIG_WAKEUP_PKT_8023) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_WOWLAN_TRIG_WAKEUP_PKT_8023_LEN) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_WOWLAN_TRIG_TCP_CONNECTION) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_WOWLAN_TRIG_WAKEUP_TCP_MATCH) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_WOWLAN_TRIG_WAKEUP_TCP_CONNLOST) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_WOWLAN_TRIG_WAKEUP_TCP_NOMORETOKENS) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_WOWLAN_TRIG_NET_DETECT) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_WOWLAN_TRIG_NET_DETECT_RESULTS) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_WOWLAN_TRIG_UNPROTECTED_DEAUTH_DISASSOC) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
    }
  }

  return 0;
}

int nl80211_txq_stats_attrs_parse(struct ynl_parse_arg *yarg,
                                  const struct nlattr *nested) {
  nl80211_txq_stats_attrs *dst = (nl80211_txq_stats_attrs *)yarg->data;
  const struct nlattr *attr;

  ynl_attr_for_each_nested(attr, nested) {
    unsigned int type = ynl_attr_type(attr);

    if (type == NL80211_TXQ_STATS_BACKLOG_BYTES) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->backlog_bytes = (__u32)ynl_attr_get_u32(attr);
    } else if (type == NL80211_TXQ_STATS_BACKLOG_PACKETS) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->backlog_packets = (__u32)ynl_attr_get_u32(attr);
    } else if (type == NL80211_TXQ_STATS_FLOWS) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->flows = (__u32)ynl_attr_get_u32(attr);
    } else if (type == NL80211_TXQ_STATS_DROPS) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->drops = (__u32)ynl_attr_get_u32(attr);
    } else if (type == NL80211_TXQ_STATS_ECN_MARKS) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->ecn_marks = (__u32)ynl_attr_get_u32(attr);
    } else if (type == NL80211_TXQ_STATS_OVERLIMIT) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->overlimit = (__u32)ynl_attr_get_u32(attr);
    } else if (type == NL80211_TXQ_STATS_OVERMEMORY) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->overmemory = (__u32)ynl_attr_get_u32(attr);
    } else if (type == NL80211_TXQ_STATS_COLLISIONS) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->collisions = (__u32)ynl_attr_get_u32(attr);
    } else if (type == NL80211_TXQ_STATS_TX_BYTES) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->tx_bytes = (__u32)ynl_attr_get_u32(attr);
    } else if (type == NL80211_TXQ_STATS_TX_PACKETS) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->tx_packets = (__u32)ynl_attr_get_u32(attr);
    } else if (type == NL80211_TXQ_STATS_MAX_FLOWS) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->max_flows = (__u32)ynl_attr_get_u32(attr);
    }
  }

  return 0;
}

int nl80211_frame_type_attrs_parse(struct ynl_parse_arg *yarg,
                                   const struct nlattr *nested) {
  nl80211_frame_type_attrs *dst = (nl80211_frame_type_attrs *)yarg->data;
  const struct nlattr *attr;

  ynl_attr_for_each_nested(attr, nested) {
    unsigned int type = ynl_attr_type(attr);

    if (type == NL80211_ATTR_FRAME_TYPE) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->frame_type = (__u16)ynl_attr_get_u16(attr);
    }
  }

  return 0;
}

int nl80211_iface_limit_attributes_parse(struct ynl_parse_arg *yarg,
                                         const struct nlattr *nested,
                                         __u32 idx) {
  nl80211_iface_limit_attributes *dst =
      (nl80211_iface_limit_attributes *)yarg->data;
  const struct nlattr *attr;
  struct ynl_parse_arg parg;

  parg.ys = yarg->ys;

  dst->idx = idx;

  ynl_attr_for_each_nested(attr, nested) {
    unsigned int type = ynl_attr_type(attr);

    if (type == NL80211_IFACE_LIMIT_MAX) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->max = (__u32)ynl_attr_get_u32(attr);
    } else if (type == NL80211_IFACE_LIMIT_TYPES) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;

      parg.rsp_policy = &nl80211_supported_iftypes_nest;
      parg.data = &dst->types.emplace();
      if (nl80211_supported_iftypes_parse(&parg, attr))
        return YNL_PARSE_CB_ERROR;
    }
  }

  return 0;
}

int nl80211_sar_specs_parse(struct ynl_parse_arg *yarg,
                            const struct nlattr *nested, __u32 idx) {
  nl80211_sar_specs *dst = (nl80211_sar_specs *)yarg->data;
  const struct nlattr *attr;

  dst->idx = idx;

  ynl_attr_for_each_nested(attr, nested) {
    unsigned int type = ynl_attr_type(attr);

    if (type == NL80211_SAR_ATTR_SPECS_POWER) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->power = (__s32)ynl_attr_get_s32(attr);
    } else if (type == NL80211_SAR_ATTR_SPECS_RANGE_INDEX) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->range_index = (__u32)ynl_attr_get_u32(attr);
    } else if (type == NL80211_SAR_ATTR_SPECS_START_FREQ) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->start_freq = (__u32)ynl_attr_get_u32(attr);
    } else if (type == NL80211_SAR_ATTR_SPECS_END_FREQ) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->end_freq = (__u32)ynl_attr_get_u32(attr);
    }
  }

  return 0;
}

int nl80211_bitrate_attrs_parse(struct ynl_parse_arg *yarg,
                                const struct nlattr *nested, __u32 idx) {
  nl80211_bitrate_attrs *dst = (nl80211_bitrate_attrs *)yarg->data;
  const struct nlattr *attr;

  dst->idx = idx;

  ynl_attr_for_each_nested(attr, nested) {
    unsigned int type = ynl_attr_type(attr);

    if (type == NL80211_BITRATE_ATTR_RATE) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->rate = (__u32)ynl_attr_get_u32(attr);
    } else if (type == NL80211_BITRATE_ATTR_2GHZ_SHORTPREAMBLE) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
    }
  }

  return 0;
}

int nl80211_iftype_data_attrs_parse(struct ynl_parse_arg *yarg,
                                    const struct nlattr *nested, __u32 idx) {
  nl80211_iftype_data_attrs *dst = (nl80211_iftype_data_attrs *)yarg->data;
  const struct nlattr *attr;

  dst->idx = idx;

  ynl_attr_for_each_nested(attr, nested) {
    unsigned int type = ynl_attr_type(attr);

    if (type == NL80211_BAND_IFTYPE_ATTR_IFTYPES) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      unsigned int len = ynl_attr_data_len(attr);
      __u8 *data = (__u8 *)ynl_attr_data(attr);
      dst->iftypes.assign(data, data + len);
    } else if (type == NL80211_BAND_IFTYPE_ATTR_HE_CAP_MAC) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      unsigned int len = ynl_attr_data_len(attr);
      __u8 *data = (__u8 *)ynl_attr_data(attr);
      dst->he_cap_mac.assign(data, data + len);
    } else if (type == NL80211_BAND_IFTYPE_ATTR_HE_CAP_PHY) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      unsigned int len = ynl_attr_data_len(attr);
      __u8 *data = (__u8 *)ynl_attr_data(attr);
      dst->he_cap_phy.assign(data, data + len);
    } else if (type == NL80211_BAND_IFTYPE_ATTR_HE_CAP_MCS_SET) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      unsigned int len = ynl_attr_data_len(attr);
      __u8 *data = (__u8 *)ynl_attr_data(attr);
      dst->he_cap_mcs_set.assign(data, data + len);
    } else if (type == NL80211_BAND_IFTYPE_ATTR_HE_CAP_PPE) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      unsigned int len = ynl_attr_data_len(attr);
      __u8 *data = (__u8 *)ynl_attr_data(attr);
      dst->he_cap_ppe.assign(data, data + len);
    } else if (type == NL80211_BAND_IFTYPE_ATTR_HE_6GHZ_CAPA) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      unsigned int len = ynl_attr_data_len(attr);
      __u8 *data = (__u8 *)ynl_attr_data(attr);
      dst->he_6ghz_capa.assign(data, data + len);
    } else if (type == NL80211_BAND_IFTYPE_ATTR_VENDOR_ELEMS) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      unsigned int len = ynl_attr_data_len(attr);
      __u8 *data = (__u8 *)ynl_attr_data(attr);
      dst->vendor_elems.assign(data, data + len);
    } else if (type == NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MAC) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      unsigned int len = ynl_attr_data_len(attr);
      __u8 *data = (__u8 *)ynl_attr_data(attr);
      dst->eht_cap_mac.assign(data, data + len);
    } else if (type == NL80211_BAND_IFTYPE_ATTR_EHT_CAP_PHY) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      unsigned int len = ynl_attr_data_len(attr);
      __u8 *data = (__u8 *)ynl_attr_data(attr);
      dst->eht_cap_phy.assign(data, data + len);
    } else if (type == NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MCS_SET) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      unsigned int len = ynl_attr_data_len(attr);
      __u8 *data = (__u8 *)ynl_attr_data(attr);
      dst->eht_cap_mcs_set.assign(data, data + len);
    } else if (type == NL80211_BAND_IFTYPE_ATTR_EHT_CAP_PPE) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      unsigned int len = ynl_attr_data_len(attr);
      __u8 *data = (__u8 *)ynl_attr_data(attr);
      dst->eht_cap_ppe.assign(data, data + len);
    }
  }

  return 0;
}

int nl80211_wmm_attrs_parse(struct ynl_parse_arg *yarg,
                            const struct nlattr *nested, __u32 idx) {
  nl80211_wmm_attrs *dst = (nl80211_wmm_attrs *)yarg->data;
  const struct nlattr *attr;

  dst->idx = idx;

  ynl_attr_for_each_nested(attr, nested) {
    unsigned int type = ynl_attr_type(attr);

    if (type == NL80211_WMMR_CW_MIN) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->cw_min = (__u16)ynl_attr_get_u16(attr);
    } else if (type == NL80211_WMMR_CW_MAX) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->cw_max = (__u16)ynl_attr_get_u16(attr);
    } else if (type == NL80211_WMMR_AIFSN) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->aifsn = (__u8)ynl_attr_get_u8(attr);
    } else if (type == NL80211_WMMR_TXOP) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->txop = (__u16)ynl_attr_get_u16(attr);
    }
  }

  return 0;
}

int nl80211_iftype_attrs_parse(struct ynl_parse_arg *yarg,
                               const struct nlattr *nested) {
  nl80211_iftype_attrs *dst = (nl80211_iftype_attrs *)yarg->data;
  const struct nlattr *attr;
  struct ynl_parse_arg parg;

  parg.ys = yarg->ys;

  ynl_attr_for_each_nested(attr, nested) {
    unsigned int type = ynl_attr_type(attr);

    if (type == NL80211_IFTYPE_UNSPECIFIED) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;

      parg.rsp_policy = &nl80211_frame_type_attrs_nest;
      parg.data = &dst->unspecified.emplace();
      if (nl80211_frame_type_attrs_parse(&parg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_IFTYPE_ADHOC) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;

      parg.rsp_policy = &nl80211_frame_type_attrs_nest;
      parg.data = &dst->adhoc.emplace();
      if (nl80211_frame_type_attrs_parse(&parg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_IFTYPE_STATION) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;

      parg.rsp_policy = &nl80211_frame_type_attrs_nest;
      parg.data = &dst->station.emplace();
      if (nl80211_frame_type_attrs_parse(&parg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_IFTYPE_AP) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;

      parg.rsp_policy = &nl80211_frame_type_attrs_nest;
      parg.data = &dst->ap.emplace();
      if (nl80211_frame_type_attrs_parse(&parg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_IFTYPE_AP_VLAN) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;

      parg.rsp_policy = &nl80211_frame_type_attrs_nest;
      parg.data = &dst->ap_vlan.emplace();
      if (nl80211_frame_type_attrs_parse(&parg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_IFTYPE_WDS) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;

      parg.rsp_policy = &nl80211_frame_type_attrs_nest;
      parg.data = &dst->wds.emplace();
      if (nl80211_frame_type_attrs_parse(&parg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_IFTYPE_MONITOR) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;

      parg.rsp_policy = &nl80211_frame_type_attrs_nest;
      parg.data = &dst->monitor.emplace();
      if (nl80211_frame_type_attrs_parse(&parg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_IFTYPE_MESH_POINT) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;

      parg.rsp_policy = &nl80211_frame_type_attrs_nest;
      parg.data = &dst->mesh_point.emplace();
      if (nl80211_frame_type_attrs_parse(&parg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_IFTYPE_P2P_CLIENT) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;

      parg.rsp_policy = &nl80211_frame_type_attrs_nest;
      parg.data = &dst->p2p_client.emplace();
      if (nl80211_frame_type_attrs_parse(&parg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_IFTYPE_P2P_GO) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;

      parg.rsp_policy = &nl80211_frame_type_attrs_nest;
      parg.data = &dst->p2p_go.emplace();
      if (nl80211_frame_type_attrs_parse(&parg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_IFTYPE_P2P_DEVICE) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;

      parg.rsp_policy = &nl80211_frame_type_attrs_nest;
      parg.data = &dst->p2p_device.emplace();
      if (nl80211_frame_type_attrs_parse(&parg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_IFTYPE_OCB) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;

      parg.rsp_policy = &nl80211_frame_type_attrs_nest;
      parg.data = &dst->ocb.emplace();
      if (nl80211_frame_type_attrs_parse(&parg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_IFTYPE_NAN) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;

      parg.rsp_policy = &nl80211_frame_type_attrs_nest;
      parg.data = &dst->nan.emplace();
      if (nl80211_frame_type_attrs_parse(&parg, attr))
        return YNL_PARSE_CB_ERROR;
    }
  }

  return 0;
}

int nl80211_if_combination_attributes_parse(struct ynl_parse_arg *yarg,
                                            const struct nlattr *nested,
                                            __u32 idx) {
  nl80211_if_combination_attributes *dst =
      (nl80211_if_combination_attributes *)yarg->data;
  const struct nlattr *attr_limits;
  const struct nlattr *attr;
  struct ynl_parse_arg parg;
  unsigned int n_limits = 0;
  int i;

  parg.ys = yarg->ys;

  dst->idx = idx;
  if (dst->limits.size() > 0)
    return ynl_error_parse(
        yarg, "attribute already present (if-combination-attributes.limits)");

  ynl_attr_for_each_nested(attr, nested) {
    unsigned int type = ynl_attr_type(attr);

    if (type == NL80211_IFACE_COMB_LIMITS) {
      const struct nlattr *attr2;

      attr_limits = attr;
    } else if (type == NL80211_IFACE_COMB_MAXNUM) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->maxnum = (__u32)ynl_attr_get_u32(attr);
    } else if (type == NL80211_IFACE_COMB_STA_AP_BI_MATCH) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_IFACE_COMB_NUM_CHANNELS) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->num_channels = (__u32)ynl_attr_get_u32(attr);
    } else if (type == NL80211_IFACE_COMB_RADAR_DETECT_WIDTHS) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->radar_detect_widths = (__u32)ynl_attr_get_u32(attr);
    } else if (type == NL80211_IFACE_COMB_RADAR_DETECT_REGIONS) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->radar_detect_regions = (__u32)ynl_attr_get_u32(attr);
    } else if (type == NL80211_IFACE_COMB_BI_MIN_GCD) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->bi_min_gcd = (__u32)ynl_attr_get_u32(attr);
    }
  }

  if (n_limits) {
    dst->limits.resize(n_limits);
    i = 0;
    parg.rsp_policy = &nl80211_iface_limit_attributes_nest;
    ynl_attr_for_each_nested(attr, attr_limits) {
      parg.data = &dst->limits[i];
      if (nl80211_iface_limit_attributes_parse(&parg, attr,
                                               ynl_attr_type(attr)))
        return YNL_PARSE_CB_ERROR;
      i++;
    }
  }

  return 0;
}

int nl80211_sar_attributes_parse(struct ynl_parse_arg *yarg,
                                 const struct nlattr *nested) {
  nl80211_sar_attributes *dst = (nl80211_sar_attributes *)yarg->data;
  const struct nlattr *attr_specs;
  const struct nlattr *attr;
  struct ynl_parse_arg parg;
  unsigned int n_specs = 0;
  int i;

  parg.ys = yarg->ys;

  if (dst->specs.size() > 0)
    return ynl_error_parse(yarg,
                           "attribute already present (sar-attributes.specs)");

  ynl_attr_for_each_nested(attr, nested) {
    unsigned int type = ynl_attr_type(attr);

    if (type == NL80211_SAR_ATTR_TYPE) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->type = (__u32)ynl_attr_get_u32(attr);
    } else if (type == NL80211_SAR_ATTR_SPECS) {
      const struct nlattr *attr2;

      attr_specs = attr;
    }
  }

  if (n_specs) {
    dst->specs.resize(n_specs);
    i = 0;
    parg.rsp_policy = &nl80211_sar_specs_nest;
    ynl_attr_for_each_nested(attr, attr_specs) {
      parg.data = &dst->specs[i];
      if (nl80211_sar_specs_parse(&parg, attr, ynl_attr_type(attr)))
        return YNL_PARSE_CB_ERROR;
      i++;
    }
  }

  return 0;
}

int nl80211_frequency_attrs_parse(struct ynl_parse_arg *yarg,
                                  const struct nlattr *nested, __u32 idx) {
  nl80211_frequency_attrs *dst = (nl80211_frequency_attrs *)yarg->data;
  const struct nlattr *attr_wmm;
  const struct nlattr *attr;
  struct ynl_parse_arg parg;
  unsigned int n_wmm = 0;
  int i;

  parg.ys = yarg->ys;

  dst->idx = idx;
  if (dst->wmm.size() > 0)
    return ynl_error_parse(yarg,
                           "attribute already present (frequency-attrs.wmm)");

  ynl_attr_for_each_nested(attr, nested) {
    unsigned int type = ynl_attr_type(attr);

    if (type == NL80211_FREQUENCY_ATTR_FREQ) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->freq = (__u32)ynl_attr_get_u32(attr);
    } else if (type == NL80211_FREQUENCY_ATTR_DISABLED) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_FREQUENCY_ATTR_NO_IR) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == __NL80211_FREQUENCY_ATTR_NO_IBSS) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_FREQUENCY_ATTR_RADAR) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_FREQUENCY_ATTR_MAX_TX_POWER) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->max_tx_power = (__u32)ynl_attr_get_u32(attr);
    } else if (type == NL80211_FREQUENCY_ATTR_DFS_STATE) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->dfs_state = (__u32)ynl_attr_get_u32(attr);
    } else if (type == NL80211_FREQUENCY_ATTR_DFS_TIME) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      unsigned int len = ynl_attr_data_len(attr);
      __u8 *data = (__u8 *)ynl_attr_data(attr);
      dst->dfs_time.assign(data, data + len);
    } else if (type == NL80211_FREQUENCY_ATTR_NO_HT40_MINUS) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      unsigned int len = ynl_attr_data_len(attr);
      __u8 *data = (__u8 *)ynl_attr_data(attr);
      dst->no_ht40_minus.assign(data, data + len);
    } else if (type == NL80211_FREQUENCY_ATTR_NO_HT40_PLUS) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      unsigned int len = ynl_attr_data_len(attr);
      __u8 *data = (__u8 *)ynl_attr_data(attr);
      dst->no_ht40_plus.assign(data, data + len);
    } else if (type == NL80211_FREQUENCY_ATTR_NO_80MHZ) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      unsigned int len = ynl_attr_data_len(attr);
      __u8 *data = (__u8 *)ynl_attr_data(attr);
      dst->no_80mhz.assign(data, data + len);
    } else if (type == NL80211_FREQUENCY_ATTR_NO_160MHZ) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      unsigned int len = ynl_attr_data_len(attr);
      __u8 *data = (__u8 *)ynl_attr_data(attr);
      dst->no_160mhz.assign(data, data + len);
    } else if (type == NL80211_FREQUENCY_ATTR_DFS_CAC_TIME) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      unsigned int len = ynl_attr_data_len(attr);
      __u8 *data = (__u8 *)ynl_attr_data(attr);
      dst->dfs_cac_time.assign(data, data + len);
    } else if (type == NL80211_FREQUENCY_ATTR_INDOOR_ONLY) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      unsigned int len = ynl_attr_data_len(attr);
      __u8 *data = (__u8 *)ynl_attr_data(attr);
      dst->indoor_only.assign(data, data + len);
    } else if (type == NL80211_FREQUENCY_ATTR_IR_CONCURRENT) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      unsigned int len = ynl_attr_data_len(attr);
      __u8 *data = (__u8 *)ynl_attr_data(attr);
      dst->ir_concurrent.assign(data, data + len);
    } else if (type == NL80211_FREQUENCY_ATTR_NO_20MHZ) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      unsigned int len = ynl_attr_data_len(attr);
      __u8 *data = (__u8 *)ynl_attr_data(attr);
      dst->no_20mhz.assign(data, data + len);
    } else if (type == NL80211_FREQUENCY_ATTR_NO_10MHZ) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      unsigned int len = ynl_attr_data_len(attr);
      __u8 *data = (__u8 *)ynl_attr_data(attr);
      dst->no_10mhz.assign(data, data + len);
    } else if (type == NL80211_FREQUENCY_ATTR_WMM) {
      const struct nlattr *attr2;

      attr_wmm = attr;
    } else if (type == NL80211_FREQUENCY_ATTR_NO_HE) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      unsigned int len = ynl_attr_data_len(attr);
      __u8 *data = (__u8 *)ynl_attr_data(attr);
      dst->no_he.assign(data, data + len);
    } else if (type == NL80211_FREQUENCY_ATTR_OFFSET) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->offset = (__u32)ynl_attr_get_u32(attr);
    } else if (type == NL80211_FREQUENCY_ATTR_1MHZ) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      unsigned int len = ynl_attr_data_len(attr);
      __u8 *data = (__u8 *)ynl_attr_data(attr);
      dst->_1mhz.assign(data, data + len);
    } else if (type == NL80211_FREQUENCY_ATTR_2MHZ) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      unsigned int len = ynl_attr_data_len(attr);
      __u8 *data = (__u8 *)ynl_attr_data(attr);
      dst->_2mhz.assign(data, data + len);
    } else if (type == NL80211_FREQUENCY_ATTR_4MHZ) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      unsigned int len = ynl_attr_data_len(attr);
      __u8 *data = (__u8 *)ynl_attr_data(attr);
      dst->_4mhz.assign(data, data + len);
    } else if (type == NL80211_FREQUENCY_ATTR_8MHZ) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      unsigned int len = ynl_attr_data_len(attr);
      __u8 *data = (__u8 *)ynl_attr_data(attr);
      dst->_8mhz.assign(data, data + len);
    } else if (type == NL80211_FREQUENCY_ATTR_16MHZ) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      unsigned int len = ynl_attr_data_len(attr);
      __u8 *data = (__u8 *)ynl_attr_data(attr);
      dst->_16mhz.assign(data, data + len);
    } else if (type == NL80211_FREQUENCY_ATTR_NO_320MHZ) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      unsigned int len = ynl_attr_data_len(attr);
      __u8 *data = (__u8 *)ynl_attr_data(attr);
      dst->no_320mhz.assign(data, data + len);
    } else if (type == NL80211_FREQUENCY_ATTR_NO_EHT) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      unsigned int len = ynl_attr_data_len(attr);
      __u8 *data = (__u8 *)ynl_attr_data(attr);
      dst->no_eht.assign(data, data + len);
    } else if (type == NL80211_FREQUENCY_ATTR_PSD) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      unsigned int len = ynl_attr_data_len(attr);
      __u8 *data = (__u8 *)ynl_attr_data(attr);
      dst->psd.assign(data, data + len);
    } else if (type == NL80211_FREQUENCY_ATTR_DFS_CONCURRENT) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      unsigned int len = ynl_attr_data_len(attr);
      __u8 *data = (__u8 *)ynl_attr_data(attr);
      dst->dfs_concurrent.assign(data, data + len);
    } else if (type == NL80211_FREQUENCY_ATTR_NO_6GHZ_VLP_CLIENT) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      unsigned int len = ynl_attr_data_len(attr);
      __u8 *data = (__u8 *)ynl_attr_data(attr);
      dst->no_6ghz_vlp_client.assign(data, data + len);
    } else if (type == NL80211_FREQUENCY_ATTR_NO_6GHZ_AFC_CLIENT) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      unsigned int len = ynl_attr_data_len(attr);
      __u8 *data = (__u8 *)ynl_attr_data(attr);
      dst->no_6ghz_afc_client.assign(data, data + len);
    } else if (type == NL80211_FREQUENCY_ATTR_CAN_MONITOR) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      unsigned int len = ynl_attr_data_len(attr);
      __u8 *data = (__u8 *)ynl_attr_data(attr);
      dst->can_monitor.assign(data, data + len);
    } else if (type == NL80211_FREQUENCY_ATTR_ALLOW_6GHZ_VLP_AP) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      unsigned int len = ynl_attr_data_len(attr);
      __u8 *data = (__u8 *)ynl_attr_data(attr);
      dst->allow_6ghz_vlp_ap.assign(data, data + len);
    }
  }

  if (n_wmm) {
    dst->wmm.resize(n_wmm);
    i = 0;
    parg.rsp_policy = &nl80211_wmm_attrs_nest;
    ynl_attr_for_each_nested(attr, attr_wmm) {
      parg.data = &dst->wmm[i];
      if (nl80211_wmm_attrs_parse(&parg, attr, ynl_attr_type(attr)))
        return YNL_PARSE_CB_ERROR;
      i++;
    }
  }

  return 0;
}

int nl80211_band_attrs_parse(struct ynl_parse_arg *yarg,
                             const struct nlattr *nested) {
  nl80211_band_attrs *dst = (nl80211_band_attrs *)yarg->data;
  const struct nlattr *attr_iftype_data;
  const struct nlattr *attr_freqs;
  const struct nlattr *attr_rates;
  unsigned int n_iftype_data = 0;
  const struct nlattr *attr;
  struct ynl_parse_arg parg;
  unsigned int n_freqs = 0;
  unsigned int n_rates = 0;
  int i;

  parg.ys = yarg->ys;

  if (dst->freqs.size() > 0)
    return ynl_error_parse(yarg,
                           "attribute already present (band-attrs.freqs)");
  if (dst->iftype_data.size() > 0)
    return ynl_error_parse(
        yarg, "attribute already present (band-attrs.iftype-data)");
  if (dst->rates.size() > 0)
    return ynl_error_parse(yarg,
                           "attribute already present (band-attrs.rates)");

  ynl_attr_for_each_nested(attr, nested) {
    unsigned int type = ynl_attr_type(attr);

    if (type == NL80211_BAND_ATTR_FREQS) {
      const struct nlattr *attr2;

      attr_freqs = attr;
    } else if (type == NL80211_BAND_ATTR_RATES) {
      const struct nlattr *attr2;

      attr_rates = attr;
    } else if (type == NL80211_BAND_ATTR_HT_MCS_SET) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      unsigned int len = ynl_attr_data_len(attr);
      __u8 *data = (__u8 *)ynl_attr_data(attr);
      dst->ht_mcs_set.assign(data, data + len);
    } else if (type == NL80211_BAND_ATTR_HT_CAPA) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->ht_capa = (__u16)ynl_attr_get_u16(attr);
    } else if (type == NL80211_BAND_ATTR_HT_AMPDU_FACTOR) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->ht_ampdu_factor = (__u8)ynl_attr_get_u8(attr);
    } else if (type == NL80211_BAND_ATTR_HT_AMPDU_DENSITY) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->ht_ampdu_density = (__u8)ynl_attr_get_u8(attr);
    } else if (type == NL80211_BAND_ATTR_VHT_MCS_SET) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      unsigned int len = ynl_attr_data_len(attr);
      __u8 *data = (__u8 *)ynl_attr_data(attr);
      dst->vht_mcs_set.assign(data, data + len);
    } else if (type == NL80211_BAND_ATTR_VHT_CAPA) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->vht_capa = (__u32)ynl_attr_get_u32(attr);
    } else if (type == NL80211_BAND_ATTR_IFTYPE_DATA) {
      const struct nlattr *attr2;

      attr_iftype_data = attr;
    } else if (type == NL80211_BAND_ATTR_EDMG_CHANNELS) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      unsigned int len = ynl_attr_data_len(attr);
      __u8 *data = (__u8 *)ynl_attr_data(attr);
      dst->edmg_channels.assign(data, data + len);
    } else if (type == NL80211_BAND_ATTR_EDMG_BW_CONFIG) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      unsigned int len = ynl_attr_data_len(attr);
      __u8 *data = (__u8 *)ynl_attr_data(attr);
      dst->edmg_bw_config.assign(data, data + len);
    } else if (type == NL80211_BAND_ATTR_S1G_MCS_NSS_SET) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      unsigned int len = ynl_attr_data_len(attr);
      __u8 *data = (__u8 *)ynl_attr_data(attr);
      dst->s1g_mcs_nss_set.assign(data, data + len);
    } else if (type == NL80211_BAND_ATTR_S1G_CAPA) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      unsigned int len = ynl_attr_data_len(attr);
      __u8 *data = (__u8 *)ynl_attr_data(attr);
      dst->s1g_capa.assign(data, data + len);
    }
  }

  if (n_freqs) {
    dst->freqs.resize(n_freqs);
    i = 0;
    parg.rsp_policy = &nl80211_frequency_attrs_nest;
    ynl_attr_for_each_nested(attr, attr_freqs) {
      parg.data = &dst->freqs[i];
      if (nl80211_frequency_attrs_parse(&parg, attr, ynl_attr_type(attr)))
        return YNL_PARSE_CB_ERROR;
      i++;
    }
  }
  if (n_iftype_data) {
    dst->iftype_data.resize(n_iftype_data);
    i = 0;
    parg.rsp_policy = &nl80211_iftype_data_attrs_nest;
    ynl_attr_for_each_nested(attr, attr_iftype_data) {
      parg.data = &dst->iftype_data[i];
      if (nl80211_iftype_data_attrs_parse(&parg, attr, ynl_attr_type(attr)))
        return YNL_PARSE_CB_ERROR;
      i++;
    }
  }
  if (n_rates) {
    dst->rates.resize(n_rates);
    i = 0;
    parg.rsp_policy = &nl80211_bitrate_attrs_nest;
    ynl_attr_for_each_nested(attr, attr_rates) {
      parg.data = &dst->rates[i];
      if (nl80211_bitrate_attrs_parse(&parg, attr, ynl_attr_type(attr)))
        return YNL_PARSE_CB_ERROR;
      i++;
    }
  }

  return 0;
}

int nl80211_wiphy_bands_parse(struct ynl_parse_arg *yarg,
                              const struct nlattr *nested) {
  nl80211_wiphy_bands *dst = (nl80211_wiphy_bands *)yarg->data;
  const struct nlattr *attr;
  struct ynl_parse_arg parg;

  parg.ys = yarg->ys;

  ynl_attr_for_each_nested(attr, nested) {
    unsigned int type = ynl_attr_type(attr);

    if (type == NL80211_BAND_2GHZ) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;

      parg.rsp_policy = &nl80211_band_attrs_nest;
      parg.data = &dst->_2ghz.emplace();
      if (nl80211_band_attrs_parse(&parg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_BAND_5GHZ) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;

      parg.rsp_policy = &nl80211_band_attrs_nest;
      parg.data = &dst->_5ghz.emplace();
      if (nl80211_band_attrs_parse(&parg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_BAND_60GHZ) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;

      parg.rsp_policy = &nl80211_band_attrs_nest;
      parg.data = &dst->_60ghz.emplace();
      if (nl80211_band_attrs_parse(&parg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_BAND_6GHZ) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;

      parg.rsp_policy = &nl80211_band_attrs_nest;
      parg.data = &dst->_6ghz.emplace();
      if (nl80211_band_attrs_parse(&parg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_BAND_S1GHZ) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;

      parg.rsp_policy = &nl80211_band_attrs_nest;
      parg.data = &dst->s1ghz.emplace();
      if (nl80211_band_attrs_parse(&parg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_BAND_LC) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;

      parg.rsp_policy = &nl80211_band_attrs_nest;
      parg.data = &dst->lc.emplace();
      if (nl80211_band_attrs_parse(&parg, attr))
        return YNL_PARSE_CB_ERROR;
    }
  }

  return 0;
}

/* ============== NL80211_CMD_GET_WIPHY ============== */
/* NL80211_CMD_GET_WIPHY - do */
int nl80211_get_wiphy_rsp_parse(const struct nlmsghdr *nlh,
                                struct ynl_parse_arg *yarg) {
  const struct nlattr *attr_interface_combinations;
  const struct nlattr *attr_supported_commands;
  unsigned int n_interface_combinations = 0;
  unsigned int n_supported_commands = 0;
  nl80211_get_wiphy_rsp *dst;
  const struct nlattr *attr;
  struct ynl_parse_arg parg;
  int i;

  dst = (nl80211_get_wiphy_rsp *)yarg->data;
  parg.ys = yarg->ys;

  if (dst->interface_combinations.size() > 0)
    return ynl_error_parse(
        yarg,
        "attribute already present (nl80211-attrs.interface-combinations)");
  if (dst->supported_commands.size() > 0)
    return ynl_error_parse(
        yarg, "attribute already present (nl80211-attrs.supported-commands)");

  ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
    unsigned int type = ynl_attr_type(attr);

    if (type == NL80211_ATTR_BANDS) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->bands = (__u32)ynl_attr_get_u32(attr);
    } else if (type == NL80211_ATTR_CIPHER_SUITES) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      unsigned int len = ynl_attr_data_len(attr);
      __u8 *data = (__u8 *)ynl_attr_data(attr);
      dst->cipher_suites.assign(data, data + len);
    } else if (type == NL80211_ATTR_CONTROL_PORT_ETHERTYPE) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_ATTR_EXT_CAPA) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      unsigned int len = ynl_attr_data_len(attr);
      __u8 *data = (__u8 *)ynl_attr_data(attr);
      dst->ext_capa.assign(data, data + len);
    } else if (type == NL80211_ATTR_EXT_CAPA_MASK) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      unsigned int len = ynl_attr_data_len(attr);
      __u8 *data = (__u8 *)ynl_attr_data(attr);
      dst->ext_capa_mask.assign(data, data + len);
    } else if (type == NL80211_ATTR_EXT_FEATURES) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      unsigned int len = ynl_attr_data_len(attr);
      __u8 *data = (__u8 *)ynl_attr_data(attr);
      dst->ext_features.assign(data, data + len);
    } else if (type == NL80211_ATTR_FEATURE_FLAGS) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->feature_flags = (__u32)ynl_attr_get_u32(attr);
    } else if (type == NL80211_ATTR_GENERATION) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->generation = (__u32)ynl_attr_get_u32(attr);
    } else if (type == NL80211_ATTR_HT_CAPABILITY_MASK) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      unsigned int len = ynl_attr_data_len(attr);
      __u8 *data = (__u8 *)ynl_attr_data(attr);
      dst->ht_capability_mask.assign(data, data + len);
    } else if (type == NL80211_ATTR_INTERFACE_COMBINATIONS) {
      const struct nlattr *attr2;

      attr_interface_combinations = attr;
    } else if (type == NL80211_ATTR_MAC) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      unsigned int len = ynl_attr_data_len(attr);
      __u8 *data = (__u8 *)ynl_attr_data(attr);
      dst->mac.assign(data, data + len);
    } else if (type == NL80211_ATTR_MAX_CSA_COUNTERS) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->max_csa_counters = (__u8)ynl_attr_get_u8(attr);
    } else if (type == NL80211_ATTR_MAX_MATCH_SETS) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->max_match_sets = (__u8)ynl_attr_get_u8(attr);
    } else if (type == NL80211_ATTR_MAX_NUM_AKM_SUITES) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      unsigned int len = ynl_attr_data_len(attr);
      __u8 *data = (__u8 *)ynl_attr_data(attr);
      dst->max_num_akm_suites.assign(data, data + len);
    } else if (type == NL80211_ATTR_MAX_NUM_PMKIDS) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->max_num_pmkids = (__u8)ynl_attr_get_u8(attr);
    } else if (type == NL80211_ATTR_MAX_NUM_SCAN_SSIDS) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->max_num_scan_ssids = (__u8)ynl_attr_get_u8(attr);
    } else if (type == NL80211_ATTR_MAX_NUM_SCHED_SCAN_PLANS) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->max_num_sched_scan_plans = (__u32)ynl_attr_get_u32(attr);
    } else if (type == NL80211_ATTR_MAX_NUM_SCHED_SCAN_SSIDS) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->max_num_sched_scan_ssids = (__u8)ynl_attr_get_u8(attr);
    } else if (type == NL80211_ATTR_MAX_REMAIN_ON_CHANNEL_DURATION) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->max_remain_on_channel_duration = (__u32)ynl_attr_get_u32(attr);
    } else if (type == NL80211_ATTR_MAX_SCAN_IE_LEN) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->max_scan_ie_len = (__u16)ynl_attr_get_u16(attr);
    } else if (type == NL80211_ATTR_MAX_SCAN_PLAN_INTERVAL) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->max_scan_plan_interval = (__u32)ynl_attr_get_u32(attr);
    } else if (type == NL80211_ATTR_MAX_SCAN_PLAN_ITERATIONS) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->max_scan_plan_iterations = (__u32)ynl_attr_get_u32(attr);
    } else if (type == NL80211_ATTR_MAX_SCHED_SCAN_IE_LEN) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->max_sched_scan_ie_len = (__u16)ynl_attr_get_u16(attr);
    } else if (type == NL80211_ATTR_OFFCHANNEL_TX_OK) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_ATTR_RX_FRAME_TYPES) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;

      parg.rsp_policy = &nl80211_iftype_attrs_nest;
      parg.data = &dst->rx_frame_types.emplace();
      if (nl80211_iftype_attrs_parse(&parg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_ATTR_SAR_SPEC) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;

      parg.rsp_policy = &nl80211_sar_attributes_nest;
      parg.data = &dst->sar_spec.emplace();
      if (nl80211_sar_attributes_parse(&parg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_ATTR_SCHED_SCAN_MAX_REQS) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->sched_scan_max_reqs = (__u32)ynl_attr_get_u32(attr);
    } else if (type == NL80211_ATTR_SOFTWARE_IFTYPES) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;

      parg.rsp_policy = &nl80211_supported_iftypes_nest;
      parg.data = &dst->software_iftypes.emplace();
      if (nl80211_supported_iftypes_parse(&parg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_ATTR_SUPPORT_AP_UAPSD) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_ATTR_SUPPORTED_COMMANDS) {
      const struct nlattr *attr2;

      attr_supported_commands = attr;
    } else if (type == NL80211_ATTR_SUPPORTED_IFTYPES) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;

      parg.rsp_policy = &nl80211_supported_iftypes_nest;
      parg.data = &dst->supported_iftypes.emplace();
      if (nl80211_supported_iftypes_parse(&parg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_ATTR_TDLS_EXTERNAL_SETUP) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_ATTR_TDLS_SUPPORT) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_ATTR_TX_FRAME_TYPES) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;

      parg.rsp_policy = &nl80211_iftype_attrs_nest;
      parg.data = &dst->tx_frame_types.emplace();
      if (nl80211_iftype_attrs_parse(&parg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_ATTR_TXQ_LIMIT) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->txq_limit = (__u32)ynl_attr_get_u32(attr);
    } else if (type == NL80211_ATTR_TXQ_MEMORY_LIMIT) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->txq_memory_limit = (__u32)ynl_attr_get_u32(attr);
    } else if (type == NL80211_ATTR_TXQ_QUANTUM) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->txq_quantum = (__u32)ynl_attr_get_u32(attr);
    } else if (type == NL80211_ATTR_TXQ_STATS) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;

      parg.rsp_policy = &nl80211_txq_stats_attrs_nest;
      parg.data = &dst->txq_stats.emplace();
      if (nl80211_txq_stats_attrs_parse(&parg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_ATTR_VHT_CAPABILITY_MASK) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      unsigned int len = ynl_attr_data_len(attr);
      __u8 *data = (__u8 *)ynl_attr_data(attr);
      dst->vht_capability_mask.assign(data, data + len);
    } else if (type == NL80211_ATTR_WIPHY) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->wiphy = (__u32)ynl_attr_get_u32(attr);
    } else if (type == NL80211_ATTR_WIPHY_ANTENNA_AVAIL_RX) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->wiphy_antenna_avail_rx = (__u32)ynl_attr_get_u32(attr);
    } else if (type == NL80211_ATTR_WIPHY_ANTENNA_AVAIL_TX) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->wiphy_antenna_avail_tx = (__u32)ynl_attr_get_u32(attr);
    } else if (type == NL80211_ATTR_WIPHY_ANTENNA_RX) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->wiphy_antenna_rx = (__u32)ynl_attr_get_u32(attr);
    } else if (type == NL80211_ATTR_WIPHY_ANTENNA_TX) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->wiphy_antenna_tx = (__u32)ynl_attr_get_u32(attr);
    } else if (type == NL80211_ATTR_WIPHY_BANDS) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;

      parg.rsp_policy = &nl80211_wiphy_bands_nest;
      parg.data = &dst->wiphy_bands.emplace();
      if (nl80211_wiphy_bands_parse(&parg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_ATTR_WIPHY_COVERAGE_CLASS) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->wiphy_coverage_class = (__u8)ynl_attr_get_u8(attr);
    } else if (type == NL80211_ATTR_WIPHY_FRAG_THRESHOLD) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->wiphy_frag_threshold = (__u32)ynl_attr_get_u32(attr);
    } else if (type == NL80211_ATTR_WIPHY_NAME) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->wiphy_name.assign(ynl_attr_get_str(attr));
    } else if (type == NL80211_ATTR_WIPHY_RETRY_LONG) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->wiphy_retry_long = (__u8)ynl_attr_get_u8(attr);
    } else if (type == NL80211_ATTR_WIPHY_RETRY_SHORT) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->wiphy_retry_short = (__u8)ynl_attr_get_u8(attr);
    } else if (type == NL80211_ATTR_WIPHY_RTS_THRESHOLD) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->wiphy_rts_threshold = (__u32)ynl_attr_get_u32(attr);
    } else if (type == NL80211_ATTR_WOWLAN_TRIGGERS_SUPPORTED) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;

      parg.rsp_policy = &nl80211_wowlan_triggers_attrs_nest;
      parg.data = &dst->wowlan_triggers_supported.emplace();
      if (nl80211_wowlan_triggers_attrs_parse(&parg, attr))
        return YNL_PARSE_CB_ERROR;
    }
  }

  if (n_interface_combinations) {
    dst->interface_combinations.resize(n_interface_combinations);
    i = 0;
    parg.rsp_policy = &nl80211_if_combination_attributes_nest;
    ynl_attr_for_each_nested(attr, attr_interface_combinations) {
      parg.data = &dst->interface_combinations[i];
      if (nl80211_if_combination_attributes_parse(&parg, attr,
                                                  ynl_attr_type(attr)))
        return YNL_PARSE_CB_ERROR;
      i++;
    }
  }
  if (n_supported_commands) {
    dst->supported_commands.resize(n_supported_commands);
    i = 0;
    ynl_attr_for_each_nested(attr, attr_supported_commands) {
      dst->supported_commands[i] = ynl_attr_get_u32(attr);
      i++;
    }
  }

  return YNL_PARSE_CB_OK;
}

std::unique_ptr<nl80211_get_wiphy_rsp>
nl80211_get_wiphy(ynl_cpp::ynl_socket &ys, nl80211_get_wiphy_req &req) {
  struct ynl_req_state yrs = {
      .yarg =
          {
              .ys = ys,
          },
  };
  std::unique_ptr<nl80211_get_wiphy_rsp> rsp;
  struct nlmsghdr *nlh;
  int err;

  nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock *)ys)->family_id,
                            NL80211_CMD_GET_WIPHY, 1);
  ((struct ynl_sock *)ys)->req_policy = &nl80211_nl80211_attrs_nest;
  yrs.yarg.rsp_policy = &nl80211_nl80211_attrs_nest;

  if (req.wiphy.has_value())
    ynl_attr_put_u32(nlh, NL80211_ATTR_WIPHY, req.wiphy.value());
  if (req.wdev.has_value())
    ynl_attr_put_u64(nlh, NL80211_ATTR_WDEV, req.wdev.value());
  if (req.ifindex.has_value())
    ynl_attr_put_u32(nlh, NL80211_ATTR_IFINDEX, req.ifindex.value());

  rsp.reset(new nl80211_get_wiphy_rsp());
  yrs.yarg.data = rsp.get();
  yrs.cb = nl80211_get_wiphy_rsp_parse;
  yrs.rsp_cmd = 3;

  err = ynl_exec(ys, nlh, &yrs);
  if (err < 0)
    return nullptr;

  return rsp;
}

/* NL80211_CMD_GET_WIPHY - dump */
int nl80211_get_wiphy_rsp_dump_parse(const struct nlmsghdr *nlh,
                                     struct ynl_parse_arg *yarg) {
  const struct nlattr *attr_interface_combinations;
  const struct nlattr *attr_supported_commands;
  unsigned int n_interface_combinations = 0;
  unsigned int n_supported_commands = 0;
  nl80211_get_wiphy_rsp_dump *dst;
  const struct nlattr *attr;
  struct ynl_parse_arg parg;
  int i;

  dst = (nl80211_get_wiphy_rsp_dump *)yarg->data;
  parg.ys = yarg->ys;

  if (dst->interface_combinations.size() > 0)
    return ynl_error_parse(
        yarg,
        "attribute already present (nl80211-attrs.interface-combinations)");
  if (dst->supported_commands.size() > 0)
    return ynl_error_parse(
        yarg, "attribute already present (nl80211-attrs.supported-commands)");

  ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
    unsigned int type = ynl_attr_type(attr);

    if (type == NL80211_ATTR_BANDS) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->bands = (__u32)ynl_attr_get_u32(attr);
    } else if (type == NL80211_ATTR_CIPHER_SUITES) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      unsigned int len = ynl_attr_data_len(attr);
      __u8 *data = (__u8 *)ynl_attr_data(attr);
      dst->cipher_suites.assign(data, data + len);
    } else if (type == NL80211_ATTR_CONTROL_PORT_ETHERTYPE) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_ATTR_EXT_CAPA) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      unsigned int len = ynl_attr_data_len(attr);
      __u8 *data = (__u8 *)ynl_attr_data(attr);
      dst->ext_capa.assign(data, data + len);
    } else if (type == NL80211_ATTR_EXT_CAPA_MASK) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      unsigned int len = ynl_attr_data_len(attr);
      __u8 *data = (__u8 *)ynl_attr_data(attr);
      dst->ext_capa_mask.assign(data, data + len);
    } else if (type == NL80211_ATTR_EXT_FEATURES) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      unsigned int len = ynl_attr_data_len(attr);
      __u8 *data = (__u8 *)ynl_attr_data(attr);
      dst->ext_features.assign(data, data + len);
    } else if (type == NL80211_ATTR_FEATURE_FLAGS) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->feature_flags = (__u32)ynl_attr_get_u32(attr);
    } else if (type == NL80211_ATTR_GENERATION) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->generation = (__u32)ynl_attr_get_u32(attr);
    } else if (type == NL80211_ATTR_HT_CAPABILITY_MASK) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      unsigned int len = ynl_attr_data_len(attr);
      __u8 *data = (__u8 *)ynl_attr_data(attr);
      dst->ht_capability_mask.assign(data, data + len);
    } else if (type == NL80211_ATTR_INTERFACE_COMBINATIONS) {
      const struct nlattr *attr2;

      attr_interface_combinations = attr;
    } else if (type == NL80211_ATTR_MAC) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      unsigned int len = ynl_attr_data_len(attr);
      __u8 *data = (__u8 *)ynl_attr_data(attr);
      dst->mac.assign(data, data + len);
    } else if (type == NL80211_ATTR_MAX_CSA_COUNTERS) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->max_csa_counters = (__u8)ynl_attr_get_u8(attr);
    } else if (type == NL80211_ATTR_MAX_MATCH_SETS) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->max_match_sets = (__u8)ynl_attr_get_u8(attr);
    } else if (type == NL80211_ATTR_MAX_NUM_AKM_SUITES) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      unsigned int len = ynl_attr_data_len(attr);
      __u8 *data = (__u8 *)ynl_attr_data(attr);
      dst->max_num_akm_suites.assign(data, data + len);
    } else if (type == NL80211_ATTR_MAX_NUM_PMKIDS) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->max_num_pmkids = (__u8)ynl_attr_get_u8(attr);
    } else if (type == NL80211_ATTR_MAX_NUM_SCAN_SSIDS) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->max_num_scan_ssids = (__u8)ynl_attr_get_u8(attr);
    } else if (type == NL80211_ATTR_MAX_NUM_SCHED_SCAN_PLANS) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->max_num_sched_scan_plans = (__u32)ynl_attr_get_u32(attr);
    } else if (type == NL80211_ATTR_MAX_NUM_SCHED_SCAN_SSIDS) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->max_num_sched_scan_ssids = (__u8)ynl_attr_get_u8(attr);
    } else if (type == NL80211_ATTR_MAX_REMAIN_ON_CHANNEL_DURATION) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->max_remain_on_channel_duration = (__u32)ynl_attr_get_u32(attr);
    } else if (type == NL80211_ATTR_MAX_SCAN_IE_LEN) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->max_scan_ie_len = (__u16)ynl_attr_get_u16(attr);
    } else if (type == NL80211_ATTR_MAX_SCAN_PLAN_INTERVAL) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->max_scan_plan_interval = (__u32)ynl_attr_get_u32(attr);
    } else if (type == NL80211_ATTR_MAX_SCAN_PLAN_ITERATIONS) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->max_scan_plan_iterations = (__u32)ynl_attr_get_u32(attr);
    } else if (type == NL80211_ATTR_MAX_SCHED_SCAN_IE_LEN) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->max_sched_scan_ie_len = (__u16)ynl_attr_get_u16(attr);
    } else if (type == NL80211_ATTR_OFFCHANNEL_TX_OK) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_ATTR_RX_FRAME_TYPES) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;

      parg.rsp_policy = &nl80211_iftype_attrs_nest;
      parg.data = &dst->rx_frame_types.emplace();
      if (nl80211_iftype_attrs_parse(&parg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_ATTR_SAR_SPEC) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;

      parg.rsp_policy = &nl80211_sar_attributes_nest;
      parg.data = &dst->sar_spec.emplace();
      if (nl80211_sar_attributes_parse(&parg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_ATTR_SCHED_SCAN_MAX_REQS) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->sched_scan_max_reqs = (__u32)ynl_attr_get_u32(attr);
    } else if (type == NL80211_ATTR_SOFTWARE_IFTYPES) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;

      parg.rsp_policy = &nl80211_supported_iftypes_nest;
      parg.data = &dst->software_iftypes.emplace();
      if (nl80211_supported_iftypes_parse(&parg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_ATTR_SUPPORT_AP_UAPSD) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_ATTR_SUPPORTED_COMMANDS) {
      const struct nlattr *attr2;

      attr_supported_commands = attr;
    } else if (type == NL80211_ATTR_SUPPORTED_IFTYPES) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;

      parg.rsp_policy = &nl80211_supported_iftypes_nest;
      parg.data = &dst->supported_iftypes.emplace();
      if (nl80211_supported_iftypes_parse(&parg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_ATTR_TDLS_EXTERNAL_SETUP) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_ATTR_TDLS_SUPPORT) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_ATTR_TX_FRAME_TYPES) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;

      parg.rsp_policy = &nl80211_iftype_attrs_nest;
      parg.data = &dst->tx_frame_types.emplace();
      if (nl80211_iftype_attrs_parse(&parg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_ATTR_TXQ_LIMIT) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->txq_limit = (__u32)ynl_attr_get_u32(attr);
    } else if (type == NL80211_ATTR_TXQ_MEMORY_LIMIT) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->txq_memory_limit = (__u32)ynl_attr_get_u32(attr);
    } else if (type == NL80211_ATTR_TXQ_QUANTUM) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->txq_quantum = (__u32)ynl_attr_get_u32(attr);
    } else if (type == NL80211_ATTR_TXQ_STATS) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;

      parg.rsp_policy = &nl80211_txq_stats_attrs_nest;
      parg.data = &dst->txq_stats.emplace();
      if (nl80211_txq_stats_attrs_parse(&parg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_ATTR_VHT_CAPABILITY_MASK) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      unsigned int len = ynl_attr_data_len(attr);
      __u8 *data = (__u8 *)ynl_attr_data(attr);
      dst->vht_capability_mask.assign(data, data + len);
    } else if (type == NL80211_ATTR_WIPHY) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->wiphy = (__u32)ynl_attr_get_u32(attr);
    } else if (type == NL80211_ATTR_WIPHY_ANTENNA_AVAIL_RX) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->wiphy_antenna_avail_rx = (__u32)ynl_attr_get_u32(attr);
    } else if (type == NL80211_ATTR_WIPHY_ANTENNA_AVAIL_TX) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->wiphy_antenna_avail_tx = (__u32)ynl_attr_get_u32(attr);
    } else if (type == NL80211_ATTR_WIPHY_ANTENNA_RX) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->wiphy_antenna_rx = (__u32)ynl_attr_get_u32(attr);
    } else if (type == NL80211_ATTR_WIPHY_ANTENNA_TX) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->wiphy_antenna_tx = (__u32)ynl_attr_get_u32(attr);
    } else if (type == NL80211_ATTR_WIPHY_BANDS) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;

      parg.rsp_policy = &nl80211_wiphy_bands_nest;
      parg.data = &dst->wiphy_bands.emplace();
      if (nl80211_wiphy_bands_parse(&parg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_ATTR_WIPHY_COVERAGE_CLASS) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->wiphy_coverage_class = (__u8)ynl_attr_get_u8(attr);
    } else if (type == NL80211_ATTR_WIPHY_FRAG_THRESHOLD) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->wiphy_frag_threshold = (__u32)ynl_attr_get_u32(attr);
    } else if (type == NL80211_ATTR_WIPHY_NAME) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->wiphy_name.assign(ynl_attr_get_str(attr));
    } else if (type == NL80211_ATTR_WIPHY_RETRY_LONG) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->wiphy_retry_long = (__u8)ynl_attr_get_u8(attr);
    } else if (type == NL80211_ATTR_WIPHY_RETRY_SHORT) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->wiphy_retry_short = (__u8)ynl_attr_get_u8(attr);
    } else if (type == NL80211_ATTR_WIPHY_RTS_THRESHOLD) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->wiphy_rts_threshold = (__u32)ynl_attr_get_u32(attr);
    } else if (type == NL80211_ATTR_WOWLAN_TRIGGERS_SUPPORTED) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;

      parg.rsp_policy = &nl80211_wowlan_triggers_attrs_nest;
      parg.data = &dst->wowlan_triggers_supported.emplace();
      if (nl80211_wowlan_triggers_attrs_parse(&parg, attr))
        return YNL_PARSE_CB_ERROR;
    }
  }

  if (n_interface_combinations) {
    dst->interface_combinations.resize(n_interface_combinations);
    i = 0;
    parg.rsp_policy = &nl80211_if_combination_attributes_nest;
    ynl_attr_for_each_nested(attr, attr_interface_combinations) {
      parg.data = &dst->interface_combinations[i];
      if (nl80211_if_combination_attributes_parse(&parg, attr,
                                                  ynl_attr_type(attr)))
        return YNL_PARSE_CB_ERROR;
      i++;
    }
  }
  if (n_supported_commands) {
    dst->supported_commands.resize(n_supported_commands);
    i = 0;
    ynl_attr_for_each_nested(attr, attr_supported_commands) {
      dst->supported_commands[i] = ynl_attr_get_u32(attr);
      i++;
    }
  }

  return YNL_PARSE_CB_OK;
}

std::unique_ptr<nl80211_get_wiphy_rsp_list>
nl80211_get_wiphy_dump(ynl_cpp::ynl_socket &ys,
                       nl80211_get_wiphy_req_dump &req) {
  struct ynl_dump_no_alloc_state yds = {};
  struct nlmsghdr *nlh;
  int err;

  auto ret = std::make_unique<nl80211_get_wiphy_rsp_list>();
  yds.yarg.ys = ys;
  yds.yarg.rsp_policy = &nl80211_nl80211_attrs_nest;
  yds.yarg.data = ret.get();
  yds.alloc_cb = [](void *arg) -> void * {
    return &(
        static_cast<nl80211_get_wiphy_rsp_list *>(arg)->objs.emplace_back());
  };
  yds.cb = nl80211_get_wiphy_rsp_dump_parse;
  yds.rsp_cmd = 3;

  nlh = ynl_gemsg_start_dump(ys, ((struct ynl_sock *)ys)->family_id,
                             NL80211_CMD_GET_WIPHY, 1);
  ((struct ynl_sock *)ys)->req_policy = &nl80211_nl80211_attrs_nest;

  if (req.wiphy.has_value())
    ynl_attr_put_u32(nlh, NL80211_ATTR_WIPHY, req.wiphy.value());
  if (req.wdev.has_value())
    ynl_attr_put_u64(nlh, NL80211_ATTR_WDEV, req.wdev.value());
  if (req.ifindex.has_value())
    ynl_attr_put_u32(nlh, NL80211_ATTR_IFINDEX, req.ifindex.value());
  if (req.split_wiphy_dump)
    ynl_attr_put(nlh, NL80211_ATTR_SPLIT_WIPHY_DUMP, NULL, 0);

  err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
  if (err < 0)
    return nullptr;

  return ret;
}

/* ============== NL80211_CMD_GET_INTERFACE ============== */
/* NL80211_CMD_GET_INTERFACE - do */
int nl80211_get_interface_rsp_parse(const struct nlmsghdr *nlh,
                                    struct ynl_parse_arg *yarg) {
  nl80211_get_interface_rsp *dst;
  const struct nlattr *attr;
  struct ynl_parse_arg parg;

  dst = (nl80211_get_interface_rsp *)yarg->data;
  parg.ys = yarg->ys;

  ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
    unsigned int type = ynl_attr_type(attr);

    if (type == NL80211_ATTR_IFNAME) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->ifname.assign(ynl_attr_get_str(attr));
    } else if (type == NL80211_ATTR_IFTYPE) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->iftype = (__u32)ynl_attr_get_u32(attr);
    } else if (type == NL80211_ATTR_IFINDEX) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->ifindex = (__u32)ynl_attr_get_u32(attr);
    } else if (type == NL80211_ATTR_WIPHY) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->wiphy = (__u32)ynl_attr_get_u32(attr);
    } else if (type == NL80211_ATTR_WDEV) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->wdev = (__u64)ynl_attr_get_u64(attr);
    } else if (type == NL80211_ATTR_MAC) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      unsigned int len = ynl_attr_data_len(attr);
      __u8 *data = (__u8 *)ynl_attr_data(attr);
      dst->mac.assign(data, data + len);
    } else if (type == NL80211_ATTR_GENERATION) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->generation = (__u32)ynl_attr_get_u32(attr);
    } else if (type == NL80211_ATTR_TXQ_STATS) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;

      parg.rsp_policy = &nl80211_txq_stats_attrs_nest;
      parg.data = &dst->txq_stats.emplace();
      if (nl80211_txq_stats_attrs_parse(&parg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_ATTR_4ADDR) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->_4addr = (__u8)ynl_attr_get_u8(attr);
    }
  }

  return YNL_PARSE_CB_OK;
}

std::unique_ptr<nl80211_get_interface_rsp>
nl80211_get_interface(ynl_cpp::ynl_socket &ys, nl80211_get_interface_req &req) {
  struct ynl_req_state yrs = {
      .yarg =
          {
              .ys = ys,
          },
  };
  std::unique_ptr<nl80211_get_interface_rsp> rsp;
  struct nlmsghdr *nlh;
  int err;

  nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock *)ys)->family_id,
                            NL80211_CMD_GET_INTERFACE, 1);
  ((struct ynl_sock *)ys)->req_policy = &nl80211_nl80211_attrs_nest;
  yrs.yarg.rsp_policy = &nl80211_nl80211_attrs_nest;

  if (req.ifname.size() > 0)
    ynl_attr_put_str(nlh, NL80211_ATTR_IFNAME, req.ifname.data());

  rsp.reset(new nl80211_get_interface_rsp());
  yrs.yarg.data = rsp.get();
  yrs.cb = nl80211_get_interface_rsp_parse;
  yrs.rsp_cmd = 7;

  err = ynl_exec(ys, nlh, &yrs);
  if (err < 0)
    return nullptr;

  return rsp;
}

/* NL80211_CMD_GET_INTERFACE - dump */
int nl80211_get_interface_rsp_dump_parse(const struct nlmsghdr *nlh,
                                         struct ynl_parse_arg *yarg) {
  nl80211_get_interface_rsp_dump *dst;
  const struct nlattr *attr;
  struct ynl_parse_arg parg;

  dst = (nl80211_get_interface_rsp_dump *)yarg->data;
  parg.ys = yarg->ys;

  ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
    unsigned int type = ynl_attr_type(attr);

    if (type == NL80211_ATTR_IFNAME) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->ifname.assign(ynl_attr_get_str(attr));
    } else if (type == NL80211_ATTR_IFTYPE) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->iftype = (__u32)ynl_attr_get_u32(attr);
    } else if (type == NL80211_ATTR_IFINDEX) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->ifindex = (__u32)ynl_attr_get_u32(attr);
    } else if (type == NL80211_ATTR_WIPHY) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->wiphy = (__u32)ynl_attr_get_u32(attr);
    } else if (type == NL80211_ATTR_WDEV) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->wdev = (__u64)ynl_attr_get_u64(attr);
    } else if (type == NL80211_ATTR_MAC) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      unsigned int len = ynl_attr_data_len(attr);
      __u8 *data = (__u8 *)ynl_attr_data(attr);
      dst->mac.assign(data, data + len);
    } else if (type == NL80211_ATTR_GENERATION) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->generation = (__u32)ynl_attr_get_u32(attr);
    } else if (type == NL80211_ATTR_TXQ_STATS) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;

      parg.rsp_policy = &nl80211_txq_stats_attrs_nest;
      parg.data = &dst->txq_stats.emplace();
      if (nl80211_txq_stats_attrs_parse(&parg, attr))
        return YNL_PARSE_CB_ERROR;
    } else if (type == NL80211_ATTR_4ADDR) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->_4addr = (__u8)ynl_attr_get_u8(attr);
    }
  }

  return YNL_PARSE_CB_OK;
}

std::unique_ptr<nl80211_get_interface_rsp_list>
nl80211_get_interface_dump(ynl_cpp::ynl_socket &ys,
                           nl80211_get_interface_req_dump &req) {
  struct ynl_dump_no_alloc_state yds = {};
  struct nlmsghdr *nlh;
  int err;

  auto ret = std::make_unique<nl80211_get_interface_rsp_list>();
  yds.yarg.ys = ys;
  yds.yarg.rsp_policy = &nl80211_nl80211_attrs_nest;
  yds.yarg.data = ret.get();
  yds.alloc_cb = [](void *arg) -> void * {
    return &(static_cast<nl80211_get_interface_rsp_list *>(arg)
                 ->objs.emplace_back());
  };
  yds.cb = nl80211_get_interface_rsp_dump_parse;
  yds.rsp_cmd = 7;

  nlh = ynl_gemsg_start_dump(ys, ((struct ynl_sock *)ys)->family_id,
                             NL80211_CMD_GET_INTERFACE, 1);
  ((struct ynl_sock *)ys)->req_policy = &nl80211_nl80211_attrs_nest;

  if (req.ifname.size() > 0)
    ynl_attr_put_str(nlh, NL80211_ATTR_IFNAME, req.ifname.data());

  err = ynl_exec_dump_no_alloc(ys, nlh, &yds);
  if (err < 0)
    return nullptr;

  return ret;
}

/* ============== NL80211_CMD_GET_PROTOCOL_FEATURES ============== */
/* NL80211_CMD_GET_PROTOCOL_FEATURES - do */
int nl80211_get_protocol_features_rsp_parse(const struct nlmsghdr *nlh,
                                            struct ynl_parse_arg *yarg) {
  nl80211_get_protocol_features_rsp *dst;
  const struct nlattr *attr;

  dst = (nl80211_get_protocol_features_rsp *)yarg->data;

  ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
    unsigned int type = ynl_attr_type(attr);

    if (type == NL80211_ATTR_PROTOCOL_FEATURES) {
      if (ynl_attr_validate(yarg, attr))
        return YNL_PARSE_CB_ERROR;
      dst->protocol_features = (__u32)ynl_attr_get_u32(attr);
    }
  }

  return YNL_PARSE_CB_OK;
}

std::unique_ptr<nl80211_get_protocol_features_rsp>
nl80211_get_protocol_features(ynl_cpp::ynl_socket &ys,
                              nl80211_get_protocol_features_req &req) {
  std::unique_ptr<nl80211_get_protocol_features_rsp> rsp;
  struct ynl_req_state yrs = {
      .yarg =
          {
              .ys = ys,
          },
  };
  struct nlmsghdr *nlh;
  int err;

  nlh = ynl_gemsg_start_req(ys, ((struct ynl_sock *)ys)->family_id,
                            NL80211_CMD_GET_PROTOCOL_FEATURES, 1);
  ((struct ynl_sock *)ys)->req_policy = &nl80211_nl80211_attrs_nest;
  yrs.yarg.rsp_policy = &nl80211_nl80211_attrs_nest;

  if (req.protocol_features.has_value())
    ynl_attr_put_u32(nlh, NL80211_ATTR_PROTOCOL_FEATURES,
                     req.protocol_features.value());

  rsp.reset(new nl80211_get_protocol_features_rsp());
  yrs.yarg.data = rsp.get();
  yrs.cb = nl80211_get_protocol_features_rsp_parse;
  yrs.rsp_cmd = NL80211_CMD_GET_PROTOCOL_FEATURES;

  err = ynl_exec(ys, nlh, &yrs);
  if (err < 0)
    return nullptr;

  return rsp;
}

const struct ynl_family ynl_nl80211_family = {
    .name = "nl80211",
    .hdr_len = sizeof(struct genlmsghdr),
};
const struct ynl_family &get_ynl_nl80211_family() {
  return ynl_nl80211_family;
};
} // namespace ynl_cpp
