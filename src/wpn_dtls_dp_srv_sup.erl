%%%-------------------------------------------------------------------
%%% @author colrack
%%% @copyright (C) 2017, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 09. dic 2017 10:30
%%%-------------------------------------------------------------------
-module(wpn_dtls_dp_srv_sup).
-author("colrack").

-behaviour(supervisor).

%% API
-export([start/1, stop/1, stacks/0]).

-export([start_link/0]).

%% Supervisor callbacks
-export([init/1]).

-define(SERVER, ?MODULE).

%%%===================================================================
%%% API functions
%%%===================================================================
start(Args) ->
  supervisor:start_child(?MODULE, Args).

stop(Name) ->
  Pid = erlang:whereis(list_to_atom(Name)),
  supervisor:terminate_child(?MODULE, Pid).

-spec stacks() -> list(pid()).
stacks() ->
  F = fun({_,Pid,_,_}, Acc) -> [Pid | Acc] end,
  lists:foldl(F, [], supervisor:which_children(?MODULE)).

%%--------------------------------------------------------------------
%% @doc
%% Starts the supervisor
%%
%% @end
%%--------------------------------------------------------------------
-spec(start_link() ->
  {ok, Pid :: pid()} | ignore | {error, Reason :: term()}).
start_link() ->
  supervisor:start_link({local, ?SERVER}, ?MODULE, []).

%%%===================================================================
%%% Supervisor callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Whenever a supervisor is started using supervisor:start_link/[2,3],
%% this function is called by the new process to find out about
%% restart strategy, maximum restart frequency and child
%% specifications.
%%
%% @end
%%--------------------------------------------------------------------
-spec(init(Args :: term()) ->
  {ok, {SupFlags :: {RestartStrategy :: supervisor:strategy(),
    MaxR :: non_neg_integer(), MaxT :: non_neg_integer()},
    [ChildSpec :: supervisor:child_spec()]
  }} |
  ignore |
  {error, Reason :: term()}).
init([]) ->
  SupFlags = #{strategy  => simple_one_for_one,
    intensity => 10,
    period    => 3600},
  ChildSpec = wpn_dtls_dp_srv_spec(),
  Children = [ChildSpec],
  {ok, {SupFlags, Children}}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
wpn_dtls_dp_srv_spec() ->
  #{id       => wpn_dtls_dp_srv,                   % mandatory
    start    => {wpn_dtls_dp_srv, start_link, []}, % mandatory
    restart  => transient,                         % optional
    shutdown => 5000,                              % optional
    type     => worker}.                           % optional
