%%%-------------------------------------------------------------------
%% @doc wishvpn public API
%% @end
%%%-------------------------------------------------------------------

-module(wishvpn_app).

-behaviour(application).

%% Application callbacks
-export([start/2, stop/1]).

%%====================================================================
%% API
%%====================================================================
start(_StartType, _StartArgs) ->
  Res = wishvpn_sup:start_link(),
  {ok, App} = application:get_application(),
  DTLSStacks = application:get_env(App, dtls_stacks, []),
  NETStacks = application:get_env(App, lan_stacks, []),
  [create_dtls_stacks(S) || S <- DTLSStacks],
  [create_net_stacks(S) || S <- NETStacks],
  Res.

stop(_State) ->
  ok.

%%====================================================================
%% Internal functions
%%====================================================================
create_dtls_stacks(S) ->
  Name = proplists:get_value(name, S),
  Transports = proplists:get_value(transports, S),
  wishvpn:create_dtls_dp(Name, Transports).

create_net_stacks(S) ->
  Name = proplists:get_value(name, S),
  IFace = proplists:get_value(iface, S),
  wishvpn:create_ip_net(Name, IFace).
