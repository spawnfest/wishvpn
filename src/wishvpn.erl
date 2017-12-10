%%%-------------------------------------------------------------------
%%% @author colrack
%%% @copyright (C) 2017, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 09. dic 2017 10:22
%%%-------------------------------------------------------------------
-module(wishvpn).
-author("colrack").

-include("wishvpn.hrl").

%% API
-export([start/0, stop/0]).

-export([create_ip_net/2, delete_ip_net/1]).

-export([create_dtls_dp/2, delete_dtls_dp/1]).

-export([test_ser_1/1, test_ser_2/1]).

%%-----------------------------------------------------------------------------
%% @doc
%% Start the application
%%
%% @end
%%-----------------------------------------------------------------------------
-spec start() -> {'ok', Started} | {'error', Reason} when
  Started :: [atom()],
  Reason :: term().
start() ->
  application:ensure_all_started(?MODULE).

%%-----------------------------------------------------------------------------
%% @doc
%% Stop the application
%%
%% @end
%%-----------------------------------------------------------------------------
-spec stop() -> 'ok' | {'error', Reason} when
  Reason :: term().
stop() ->
  application:stop(?MODULE).

%%-----------------------------------------------------------------------------
%% @doc
%% Create IP network
%%
%% @end
%%-----------------------------------------------------------------------------
create_ip_net(Name, IFace) ->
  wpn_ip_net_srv_sup:start([Name, IFace]).

%%-----------------------------------------------------------------------------
%% @doc
%% Delete IP network
%%
%% @end
%%-----------------------------------------------------------------------------
delete_ip_net(Name) ->
  wpn_ip_net_srv_sup:stop(Name).

%%-----------------------------------------------------------------------------
%% @doc
%% Create DTLS server for data plane
%%
%% @end
%%-----------------------------------------------------------------------------
create_dtls_dp(Name, LocalIps) ->
  wpn_dtls_dp_srv_sup:start([Name, LocalIps]).

%%-----------------------------------------------------------------------------
%% @doc
%% Delete DTLS server for data plane
%%
%% @end
%%-----------------------------------------------------------------------------
delete_dtls_dp(Name) ->
  wpn_dtls_dp_srv_sup:stop(Name).


test_ser_1(SslSocket) ->
  CertFingerPrint = {sha, "55D0BA03BFA419F7D6C62FF5070DD17A53C69397"},
  test_ser_ul_dl_peer({10,8,0,2}, "net0", SslSocket, CertFingerPrint).

test_ser_2(SslSocket) ->
  CertFingerPrint = {sha, "0D7E44C0AEAAA794ACCCBCEE8E13867CD8D81540"},
  test_ser_ul_dl_peer({10,8,0,1}, "net1", SslSocket, CertFingerPrint).

test_ser_ul_dl_peer(IP, NI, SslSocket, CertFingerPrint) -> #ser_dp{
  cert_fingerprint = CertFingerPrint,
  pdn_type = ipv4,
  create_pdrs = [
    #pdr_dp{
      pdr_id = 0,
      precedence = 0,
      pdi = #pdi_dp{
        source_iface = 'DTLS',
        socket = SslSocket,
        network_instance = NI
      },
      outer_header_removal = #outer_header_removal{ hdr = 'UDP/DTLS/IPv4' },
      far_id = 0},
    #pdr_dp{
      pdr_id = 1,
      precedence = 0,
      pdi = #pdi_dp{
        source_iface = 'LAN',
        ip_addr = IP,
        network_instance = NI
      },
      outer_header_removal = #outer_header_removal{ hdr = 'none'},
      far_id = 1}
  ],
  create_fars = [
    #far_dp{
      far_id = 0,
      apply_action = [forw],
      forwarding_params = #forwarding_params{
        destination_iface = 'LAN',
        network_instance = NI,
        outer_header_creation = #outer_header_creation{
          hdr = 'none'}}},
    #far_dp{
      far_id = 1,
      apply_action = [forw],
      forwarding_params = #forwarding_params{
        destination_iface = 'DTLS',
        network_instance = NI,
        outer_header_creation = #outer_header_creation{
          hdr = 'UDP/DTLS/IPv4',
          sock = SslSocket}}}
  ]
}.
