%%%-------------------------------------------------------------------
%%% @author colrack
%%% @copyright (C) 2017, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 09. dic 2017 17:04
%%%-------------------------------------------------------------------
-author("colrack").

-include_lib("public_key/include/public_key.hrl").

-define(TABLE_SESSION, wpn_session_record).
-define(TABLE_MONITOR_TO_SESSION, wpn_monitor_to_session).
-define(TABLE_TUN_FD, wpn_tun_fd).

-define(TABLE_PDR, wpn_pdr_record).
-define(TABLE_PDR_SOCK, wpn_pdr_sock_record).
-define(TABLE_PDR_IPV4, wpn_pdr_ipv4_record).
-define(TABLE_PDR_IPV6, wpn_pdr_ipv6_record).

-define(TABLE_FAR, wpn_far_record).
-define(TABLE_BAR, wpn_bar_record).
-define(TABLE_URR, wpn_urr_record).
-define(TABLE_QER, wpn_qer_record).

%%====================================================================
%% WPN messages - data structures
%%====================================================================
-record(tft, {
}).
-type tft() :: #tft{}.

-record(pdi_dp, {
  source_iface :: 'DTLS' | 'LAN',
  network_instance :: string(),
  ip_addr :: inet:ip4_address() | inet:ip6_address(),
  socket :: ssl:sslsocket() | inet:socket(),
  sdf_filter :: tft()
}).
-type pdi_up() :: #pdi_dp{}.

-record(outer_header_removal, {
  hdr :: none | 'UDP/DTLS/IPv4' | 'UDP/DTLS/IPv6'
}).
-type outer_header_removal() :: #outer_header_removal{}.

-record(pdr_dp, {
  pdr_id :: 0..65535,
  precedence :: 0..4294967295,
  pdi = #pdi_dp{} :: pdi_up(),
  outer_header_removal :: outer_header_removal(),
  far_id :: 0..4294967295,
  urr_ids :: [0..4294967295],
  qer_ids :: [0..4294967295]
}).
-type pdr_dp() :: #pdr_dp{}.

-type apply_action() :: dupl | nocp | buff | forw | drop.

-record(outer_header_creation, {
  hdr :: none | 'UDP/DTLS/IPv4' | 'UDP/DTLS/IPv6',
  sock :: inet:socket()
}).
-type outer_header_creation() :: #outer_header_creation{}.

-record(forwarding_params, {
  destination_iface :: 'DTLS' | 'LAN',
  network_instance :: string(),
  outer_header_creation :: outer_header_creation(),
  transport_level_marking :: binary() %% ToS/Traffic Class
}).
-type forwarding_params() :: #forwarding_params{}.

-record(duplication_params, {
  destination_iface :: 'LI',
  outer_header_creation :: outer_header_creation(),
  transport_level_marking :: binary() %% ToS/Traffic Class
}).
-type duplication_params() :: #duplication_params{}.

-record(far_dp, {
  far_id :: 0..4294967295,
  apply_action :: [apply_action()],
  forwarding_params :: forwarding_params(),
  duplication_params :: duplication_params(),
  bar_id :: 0..255
}).
-type far_dp() :: #far_dp{}.

-record(urr_dp, {
  urr_id :: 0..4294967295,
  measurement_method,
  reporting_triggers,
  measurement_period,
  volume_threshold,
  volume_quota,
  time_threshold,
  time_quota,
  quota_holding_time
}).
-type urr_dp() :: #urr_dp{}.

-record(qer_dp, {
  qer_id :: 0..4294967295,
  qer_correlation_id :: 0..4294967295,
  gate_status,
  maximum_bitrate,
  guaranteed_bitrate,
  packet_rate,
  dl_flow_level_marking
}).
-type qer_dp() :: #qer_dp{}.

-record(bar_dp, {
  bar_id :: 0..255
}).
-type bar_dp() :: #bar_dp{}.

%%====================================================================
%% Session Establishment Request - record
%%====================================================================
-record(ser_dp, {
  cert_fingerprint :: tuple(), % cert fingerprint

  create_pdrs = [] :: [urr_dp()],
  create_fars = [] :: [far_dp()],
  create_urrs = [] :: [urr_dp()],
  create_qers = [] :: [qer_dp()],
  create_bars = [] :: [bar_dp()],

  pdn_type :: ipv4 | ipv6
}).
-type ser_dp() :: #ser_dp{}.

%%====================================================================
%% Session Modification Request - record
%%====================================================================
-record(smr_dp, {
  cert_fingerprint :: tuple(), % cert fingerprint

  remove_pdrs = [] :: [0..65535],
  remove_fars = [] :: [0..4294967295],
  remove_urrs = [] :: [0..4294967295],
  remove_qers = [] :: [0..4294967295],
  remove_bars = [] :: [0..255],

  create_pdrs = [] :: [urr_dp()],
  create_fars = [] :: [far_dp()],
  create_urrs = [] :: [urr_dp()],
  create_qers = [] :: [qer_dp()],
  create_bars = [] :: [bar_dp()],

  update_pdrs = [] :: [urr_dp()],
  update_fars = [] :: [far_dp()],
  update_urrs = [] :: [urr_dp()],
  update_qers = [] :: [qer_dp()],
  update_bars = [] :: [bar_dp()],

  query_urr = [] :: [0..4294967295]
}).
-type smr_dp() :: #smr_dp{}.

%%====================================================================
%% Session Report Request - data structures
%%====================================================================
-record(down_link_data_report, {
  pdr_id :: 0..65535,
  down_link_data_svc_info
}).
-type down_link_data_report() :: #down_link_data_report{}.

-record(usage_report, {
}).
-type usage_report() :: #usage_report{}.

-record(error_indication_report, {
}).
-type error_indication_report() :: #error_indication_report{}.

%%====================================================================
%% Session Report Request - record
%%====================================================================
-record(srr_dp, {
  cert_fingerprint :: tuple(), % cert fingerprint

  report_type :: erir | usar | dldr,
  down_link_data_report :: down_link_data_report(),
  usage_report :: usage_report(),
  error_indication_report :: error_indication_report(),
  load_control_information,
  overload_control_information
}).
-type srr_dp() :: #srr_dp{}.

%%====================================================================
%% DATA PLANE in memory STATE (in ETS)
%% record marked with "TABLE" are saved in ETS tables
%%====================================================================

%%====================================================================
%% Table Key        | Table
%% -------------------------------------------------------------------
%% PubKey           | Session
%% MonitorReference | Session Monitor
%%
%% {PubKey, PDR_ID  | PDR
%% DTLS SOCK        | [PDR]
%% IPv4             | [PDR]
%% IPv6             | [PDR]
%%
%% {PubKey, FAR_ID} | FAR
%% {PubKey, BAR_ID} | BAR
%% {PubKey, URR_ID} | URR
%% {PubKey, QER_ID} | QER
%%====================================================================
-record(pdr_record_key, {
  cert_fingerprint :: tuple(), % cert fingerprint
  pdr_id :: 0..65535
}).
-type pdr_record_key() :: #pdr_record_key{}.

-record(far_record_key, {
  cert_fingerprint :: tuple(), % cert fingerprint
  far_id :: 0..4294967295
}).
-type far_record_key() :: #far_record_key{}.

-record(urr_record_key, {
  cert_fingerprint :: tuple(), % cert fingerprint
  urr_id :: 0..4294967295
}).
-type urr_record_key() :: #urr_record_key{}.

-record(qer_record_key, {
  cert_fingerprint :: tuple(), % cert fingerprint
  qer_id :: 0..4294967295
}).
-type qer_record_key() :: #qer_record_key{}.

-record(bar_record_key, {
  cert_fingerprint :: tuple(), % cert fingerprint
  bar_id :: 0..255
}).
-type bar_record_key() :: #bar_record_key{}.

-record(monitor_to_session, { % TABLE
  monitor_ref :: reference(),
  cert_fingerprint :: tuple() % cert fingerprint
}).
-type monitor_to_session() :: #monitor_to_session{}.

-record(pdr_record_ref, {
  precedence :: 0..4294967295,
  sdf_filter :: tft(),
  cert_fingerprint :: tuple(), % cert fingerprint
  pdr_id :: 0..65535
}).
-type pdr_record_ref() :: #pdr_record_ref{}.

-record(pdr_sock_record, { % TABLE
  sock :: inet:sock(),
  pdrs :: [pdr_record_ref()]
}).
-type pdr_sock_record() :: #pdr_sock_record{}.

-record(pdr_ipv4_record, { % TABLE
  ip :: inet:ip4_address(),
  pdrs :: [pdr_record_ref()]
}).
-type pdr_ipv4_record() :: #pdr_ipv4_record{}.

-record(pdr_ipv6_record, { % TABLE
  ip :: inet:ip6_address(),
  pdrs :: [pdr_record_ref()]
}).
-type pdr_ipv6_record() :: #pdr_ipv6_record{}.

-record(far_record, { % TABLE
  far_record_key :: far_record_key(),

  apply_actions :: [apply_action()],
  forwarding_params :: forwarding_params(),
  duplication_params :: duplication_params(),

  bar_id :: 0..255
}).
-type far_record() :: #far_record{}.

-record(urr_record, { % TABLE
  urr_record_key :: urr_record_key(),

  measurement_method,
  reporting_triggers,
  measurement_period,
  volume_threshold,
  volume_quota,
  time_threshold,
  time_quota,
  quota_holding_time,
  ur_seqn,
  start_time,
  end_time,
  volume_measurement,
  duration_measurement,
  application_detection_info,
  ip_addr,
  network_instance,
  time_of_first_packet,
  time_of_last_packet
}).
-type urr_record() :: #urr_record{}.

-record(qer_record, { % TABLE
  qer_record_key :: qer_record_key(),

  qer_correlation_id :: 0..4294967295,
  gate_status,
  maximum_bitrate,
  guaranteed_bitrate,
  packet_rate,
  dl_flow_level_marking
}).
-type qer_record() :: #qer_record{}.

-record(bar_record, { % TABLE
  bar_record_key :: bar_record_key(),

  down_link_data_notification_delay :: 0..255
}).
-type bar_record() :: #bar_record{}.

-record(pdr_record, { % TABLE
  pdr_record_key :: pdr_record_key(),

  type :: sock | ipv4 | ipv6,
  pdr_key :: inet:socket() | inet:ip4_address() | inet:ip6_address(),

  far_id :: 0..4294967295,

  urr_ids :: [0..4294967295],
  qer_ids :: [0..4294967295]
}).
-type pdr_record() :: #pdr_record{}.

-record(session_record, { % TABLE
  cert_fingerprint :: tuple(), % cert fingerprint

  monitor_ref :: reference(),
  user_pid :: pid(),

  pdrs :: [0..65535],

  pdn_type :: ipv4 | ipv6
}).
-type session_record() :: #session_record{}.
