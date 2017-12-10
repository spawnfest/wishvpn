%%%-------------------------------------------------------------------
%% @doc wishvpn top level supervisor.
%% @end
%%%-------------------------------------------------------------------

-module(wishvpn_sup).

-behaviour(supervisor).

%% API
-export([start_link/0]).

%% Supervisor callbacks
-export([init/1]).

-define(SERVER, ?MODULE).

%%====================================================================
%% API functions
%%====================================================================

start_link() ->
  supervisor:start_link({local, ?SERVER}, ?MODULE, []).

%%====================================================================
%% Supervisor callbacks
%%====================================================================

%% Child :: {Id,StartFunc,Restart,Shutdown,Type,Modules}
init([]) ->
  SupFlags = #{strategy  => one_for_one,
    intensity => 5,
    period    => 30},
  {ok, {SupFlags, [wpn_srv_spec(), wpn_dtls_dp_srv_sup_spec(),
    wpn_ip_net_srv_sup_spec()]}}.

%%====================================================================
%% Internal functions
%%====================================================================
wpn_srv_spec() ->
  #{id       => wpn_srv,                   % mandatory
    start    => {wpn_srv, start_link, []}, % mandatory
    restart  => permanent,                 % optional
    type     => supervisor}.               % optional

wpn_dtls_dp_srv_sup_spec() ->
  #{id       => wpn_dtls_dp_srv_sup,                   % mandatory
    start    => {wpn_dtls_dp_srv_sup, start_link, []}, % mandatory
    restart  => permanent,                             % optional
    type     => supervisor}.                           % optional

wpn_ip_net_srv_sup_spec() ->
  #{id       => wpn_ip_net_srv_sup,                   % mandatory
    start    => {wpn_ip_net_srv_sup, start_link, []}, % mandatory
    restart  => permanent,                            % optional
    type     => supervisor}.                          % optional
