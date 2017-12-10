%%%-------------------------------------------------------------------
%%% @author colrack
%%% @copyright (C) 2017, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 09. dic 2017 10:29
%%%-------------------------------------------------------------------
-module(wpn_ip_net_srv).
-author("colrack").

-behaviour(gen_server).

-include("wishvpn.hrl").

%% API
-export([start_link/2]).

-export([send/2]).

%% gen_server callbacks
-export([init/1,
  handle_call/3,
  handle_cast/2,
  handle_info/2,
  terminate/2,
  code_change/3]).

-define(SERVER, ?MODULE).

-record(state, {net_tun, net_tun_fd}).

%%%===================================================================
%%% API
%%%===================================================================
send(Pid, Data) when is_pid(Pid), is_binary(Data) ->
  gen_server:call(Pid, {send, Data});
send(Pid, Data) when is_pid(Pid), is_list(Data) ->
  gen_server:call(Pid, {send, list_to_binary(Data)}).

%%--------------------------------------------------------------------
%% @doc
%% Starts the server
%%
%% @end
%%--------------------------------------------------------------------
-spec(start_link(Name :: string(), Iface :: string()) ->
  {ok, Pid :: pid()} | ignore | {error, Reason :: term()}).
start_link(Name, Iface) ->
  gen_server:start_link(?MODULE, [Name, Iface], []).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Initializes the server
%%
%% @spec init(Args) -> {ok, State} |
%%                     {ok, State, Timeout} |
%%                     ignore |
%%                     {stop, Reason}
%% @end
%%--------------------------------------------------------------------
-spec(init(Args :: term()) ->
  {ok, State :: #state{}} | {ok, State :: #state{}, timeout() | hibernate} |
  {stop, Reason :: term()} | ignore).
init([Name, Iface]) ->
  {ok, TunRef} = tuncer:create(Iface, [{active, true}, tun, no_pi]),
%%  ok = tuncer:up(TunRef, {10,0,0,0}),
%%  ok = tuncer:persist(TunRef, false),
  TunFd = tuncer:getfd(TunRef),
  erlang:register(list_to_atom(Name), self()),
  {ok, #state{net_tun = TunRef, net_tun_fd = TunFd}}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling call messages
%%
%% @end
%%--------------------------------------------------------------------
-spec(handle_call(Request :: term(), From :: {pid(), Tag :: term()},
    State :: #state{}) ->
  {reply, Reply :: term(), NewState :: #state{}} |
  {reply, Reply :: term(), NewState :: #state{}, timeout() | hibernate} |
  {noreply, NewState :: #state{}} |
  {noreply, NewState :: #state{}, timeout() | hibernate} |
  {stop, Reason :: term(), Reply :: term(), NewState :: #state{}} |
  {stop, Reason :: term(), NewState :: #state{}}).
handle_call({send, Data}, _From, #state{net_tun_fd = TunFd} = State) ->
  tuncer:write(TunFd, Data),
  {reply, ok, State};
handle_call(_Request, _From, State) ->
  {reply, ok, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling cast messages
%%
%% @end
%%--------------------------------------------------------------------
-spec(handle_cast(Request :: term(), State :: #state{}) ->
  {noreply, NewState :: #state{}} |
  {noreply, NewState :: #state{}, timeout() | hibernate} |
  {stop, Reason :: term(), NewState :: #state{}}).
handle_cast(_Request, State) ->
  {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling all non call/cast messages
%%
%% @spec handle_info(Info, State) -> {noreply, State} |
%%                                   {noreply, State, Timeout} |
%%                                   {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
-spec(handle_info(Info :: timeout() | term(), State :: #state{}) ->
  {noreply, NewState :: #state{}} |
  {noreply, NewState :: #state{}, timeout() | hibernate} |
  {stop, Reason :: term(), NewState :: #state{}}).
handle_info({tuntap, _Ref, <<4:4, _IHL:4, _:11/binary, Src:4/binary,
  Dst:4/binary, _/binary>> = Pkt}, State) ->
  IpDst = list_to_tuple(binary_to_list(Dst)),
  handle_pkt(IpDst, Pkt),
  {noreply, State};
handle_info({tuntap, _Ref, <<6:4, _:28, _:4/binary, _Src:16/binary,
  Dst:16/binary, _/binary>> = _Pkt}, State) ->
  <<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>> = Dst,
  _IP = {A, B, C, D, E, F, G, H},
  %% TODO
  {noreply, State};
handle_info({tuntap_error, _PID, _Error}, State) ->
  %% TODO
  {noreply, State};
handle_info({'DOWN', _MRef, process, _UePid, _Reason}, State) ->
  %% TODO
  {noreply, State};
handle_info(Info, State) ->
  erlang:error(badarg, [Info, State]),
  {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called by a gen_server when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any
%% necessary cleaning up. When it returns, the gen_server terminates
%% with Reason. The return value is ignored.
%%
%% @spec terminate(Reason, State) -> void()
%% @end
%%--------------------------------------------------------------------
-spec(terminate(Reason :: (normal | shutdown | {shutdown, term()} | term()),
    State :: #state{}) -> term()).
terminate(_Reason, _State) ->
  ok.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Convert process state when code is changed
%%
%% @spec code_change(OldVsn, State, Extra) -> {ok, NewState}
%% @end
%%--------------------------------------------------------------------
-spec(code_change(OldVsn :: term() | {down, term()}, State :: #state{},
    Extra :: term()) ->
  {ok, NewState :: #state{}} | {error, Reason :: term()}).
code_change(_OldVsn, State, _Extra) ->
  {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
handle_pkt(Ip, Pkt) ->
  case ets:lookup(?TABLE_PDR_IPV4, Ip) of
    [#pdr_ipv4_record{pdrs = PDRs}] ->
      #pdr_record_ref{cert_fingerprint = CF, pdr_id = PdrId} =
        wpn_srv:get_highest_pdr(PDRs),

      PdrRecordKey = #pdr_record_key{cert_fingerprint = CF, pdr_id = PdrId},
      #pdr_record{far_id = FarId} = wpn_srv:get_pdr_record(PdrRecordKey),

      FarRecordKey = #far_record_key{cert_fingerprint = CF, far_id = FarId},

      #far_record{apply_actions = ApplyActions,
        forwarding_params = #forwarding_params{
          destination_iface = 'DTLS',
          network_instance = _NI,
          outer_header_creation = #outer_header_creation{
            hdr = 'UDP/DTLS/IPv4',
            sock = DTLSSock
          }
        }} = wpn_srv:get_far_record(FarRecordKey),

      case lists:member(forw, ApplyActions) of
        true -> ssl:send(DTLSSock, Pkt);
        _ -> ok
      end,
      ok;
    _ -> drop, lager:debug("Dropping data for ~p~n ~p", [Ip, Pkt])
  end.
