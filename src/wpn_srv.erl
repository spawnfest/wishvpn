%%%-------------------------------------------------------------------
%%% @author colrack
%%% @copyright (C) 2017, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 09. dic 2017 11:06
%%%-------------------------------------------------------------------
-module(wpn_srv).
-author("colrack").

-behaviour(gen_server).

-include("wishvpn.hrl").
-include_lib("public_key/include/public_key.hrl").

%% API
-export([start_link/0]).

-export([ser/1]).

%% Utilities
-export([get_highest_pdr/1, get_pdr_record/1, get_far_record/1,
  get_tun_pid_from_net_instance/1]).

-export([insert_session/1]).

%% gen_server callbacks
-export([init/1,
  handle_call/3,
  handle_cast/2,
  handle_info/2,
  terminate/2,
  code_change/3]).

-define(SERVER, ?MODULE).

-record(state, {}).

%%%===================================================================
%%% API
%%%===================================================================

-spec ser(SER) -> ok | {'error', Reason} when
  SER :: ser_dp(),
  Reason :: term().

ser(#ser_dp{} = SER) ->
  gen_server:call(?MODULE, {ser, SER}).

%%--------------------------------------------------------------------
%% @doc
%% Starts the server
%%
%% @end
%%--------------------------------------------------------------------
-spec(start_link() ->
  {ok, Pid :: pid()} | ignore | {error, Reason :: term()}).
start_link() ->
  gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

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
init([]) ->
  ets:new(?TABLE_SESSION, [set, named_table, public, {keypos, 2}]),
  ets:new(?TABLE_MONITOR_TO_SESSION, [set, named_table, public, {keypos, 2}]),
  ets:new(?TABLE_TUN_FD, [set, named_table, public, {keypos, 2}]),

  ets:new(?TABLE_PDR, [set, named_table, public, {keypos, 2}]),
  ets:new(?TABLE_PDR_SOCK, [set, named_table, public, {keypos, 2}]),
  ets:new(?TABLE_PDR_IPV4, [set, named_table, public, {keypos, 2}]),
  ets:new(?TABLE_PDR_IPV6, [set, named_table, public, {keypos, 2}]),

  ets:new(?TABLE_FAR, [set, named_table, public, {keypos, 2}]),
  ets:new(?TABLE_BAR, [set, named_table, public, {keypos, 2}]),
  ets:new(?TABLE_URR, [set, named_table, public, {keypos, 2}]),
  ets:new(?TABLE_QER, [set, named_table, public, {keypos, 2}]),

  {ok, #state{}}.

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
handle_call({ser, SER}, _From, State) ->
  insert_session(SER),
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
handle_info(_Info, State) ->
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
%%% Utilities functions
%%%===================================================================
get_highest_pdr([PDR]) -> PDR;
get_highest_pdr([PDR|_] = PDRs) ->
  HighestPDRFun = fun(#pdr_record_ref{precedence = Prec} = PDR1,
      #pdr_record_ref{precedence = PrecAcc} = PDR2) ->
    if
      Prec > PrecAcc -> PDR1;
      true -> PDR2
    end
                  end,
  lists:foldl(HighestPDRFun, PDR, PDRs);
get_highest_pdr(_) -> discard.

get_pdr_record(#pdr_record_key{} = PdrRecordKey) ->
  case ets:lookup(?TABLE_PDR, PdrRecordKey) of
    [#pdr_record{} = PdrRecord] -> PdrRecord;
    _ -> notfound
  end.

get_far_record(#far_record_key{} = FarRecordKey) ->
  case ets:lookup(?TABLE_FAR, FarRecordKey) of
    [#far_record{} = FarRecord] -> FarRecord;
    _ -> notfound
  end.

get_tun_pid_from_net_instance(NI) when is_list(NI) ->
  {ok, App} = application:get_application(wishvpn),
  NetInstances = application:get_env(App, net_instances, []),
  LanStacks = application:get_env(App, lan_stacks, []),
  F = fun(E, Acc) ->
    CurNI = proplists:get_value(name, E, ""),
    if
      CurNI == NI -> E;
      true -> Acc
    end
      end,
  NetInstance = lists:foldl(F, 0, NetInstances),

  LanStackName = proplists:get_value(lan_stack, NetInstance, ""),

  G = fun(E, Acc) ->
    CurLanStack = proplists:get_value(name, E, ""),
    if
      CurLanStack == LanStackName -> E;
      true -> Acc
    end
      end,
  LanStack = lists:foldl(G, 0, LanStacks),
  ProcessName = proplists:get_value(name, LanStack),
  erlang:whereis(list_to_atom(ProcessName)).

%%%===================================================================
%%% Internal functions
%%%===================================================================
insert_session(#ser_dp{
  cert_fingerprint = CertFingerPrint,
  create_pdrs = CreatePDRs,
  create_fars = CreateFARs,
  create_urrs = CreateURRs,
  create_qers = CreateQERs,
  create_bars = CreateBARs,
  pdn_type = PDNType}) ->
  UserPidRef = erlang:monitor(process, self()),

  %%--------------------------------------------------------------------
  %% Process PDRs
  %%--------------------------------------------------------------------
  CreatePDRFun = fun(#pdr_dp{ pdr_id = PdrId,
    precedence = Prec,
    pdi = #pdi_dp{ source_iface = SrcIface, socket = Socket, ip_addr = IpAddr},
    outer_header_removal = #outer_header_removal{ hdr = OutHdrRem },
    far_id = FarId,
    urr_ids = UrrIds,
    qer_ids = QerIds}, PDRs) ->

    PdrRecordKey = #pdr_record_key{
      cert_fingerprint = CertFingerPrint,
      pdr_id = PdrId
    },

    {PdrType, PdrKey} =
      case OutHdrRem of
        'UDP/DTLS/IPv4' -> {sock, Socket};
        'UDP/DTLS/IPv6' -> {sock, Socket};
        _ ->
          case IpAddr of
            {_,_,_,_} = IPv4 -> {ipv4, IPv4};
            {_,_,_,_,_,_,_,_} = IPv6 -> {ipv6, IPv6}
          end
      end,

    ets:insert(?TABLE_PDR, #pdr_record{
      pdr_record_key = PdrRecordKey,
      type = PdrType,
      pdr_key = PdrKey,
      far_id = FarId,
      qer_ids = QerIds,
      urr_ids = UrrIds
    }),

    PDRRecordRef = #pdr_record_ref{
      precedence = Prec,
      cert_fingerprint = CertFingerPrint,
      pdr_id = PdrId
    },

    case PdrType of
      ipv4 ->
        case ets:lookup(?TABLE_PDR_IPV4, PdrKey) of
          [#pdr_ipv4_record{pdrs = OldPDRs}] ->
            ets:insert(?TABLE_PDR_IPV4,
              #pdr_ipv4_record{ip = PdrKey, pdrs = [PDRRecordRef|OldPDRs]});
          _ -> ets:insert(?TABLE_PDR_IPV4,
            #pdr_ipv4_record{ip = PdrKey, pdrs = [PDRRecordRef]})
        end;
      ipv6 ->
        case ets:lookup(?TABLE_PDR_IPV6, PdrKey) of
          [#pdr_ipv6_record{pdrs = OldPDRs}] ->
            ets:insert(?TABLE_PDR_IPV6,
              #pdr_ipv6_record{ip = PdrKey, pdrs = [PDRRecordRef|OldPDRs]});
          _ -> ets:insert(?TABLE_PDR_IPV6,
            #pdr_ipv6_record{ip = PdrKey, pdrs = [PDRRecordRef]})
        end;
      sock ->
        case ets:lookup(?TABLE_PDR_SOCK, PdrKey) of
          [#pdr_sock_record{pdrs = OldPDRs}] ->
            ets:insert(?TABLE_PDR_SOCK,
              #pdr_sock_record{sock = PdrKey, pdrs = [PDRRecordRef|OldPDRs]});
          _ -> ets:insert(?TABLE_PDR_SOCK,
            #pdr_sock_record{sock = PdrKey, pdrs = [PDRRecordRef]})
        end
    end,

    [PdrId|PDRs]
                 end,
  PDRs = lists:foldl(CreatePDRFun, [], CreatePDRs),

  ets:insert(?TABLE_SESSION, #session_record{
    cert_fingerprint = CertFingerPrint,

    monitor_ref = UserPidRef,
    user_pid = self(),

    pdrs = PDRs,

    pdn_type = PDNType
  }),

  ets:insert(?TABLE_MONITOR_TO_SESSION, #monitor_to_session{
    monitor_ref = UserPidRef,
    cert_fingerprint = CertFingerPrint
  }),

  %%--------------------------------------------------------------------
  %% Process FARs
  %%--------------------------------------------------------------------
  CreateFARFun = fun(#far_dp{ far_id = FarId,
    apply_action = Actions,
    forwarding_params = ForwardingParams,
    duplication_params = DuplicationParams,
    bar_id = BarId
  }) ->
    ets:insert(?TABLE_FAR, #far_record{
      far_record_key = #far_record_key{cert_fingerprint = CertFingerPrint,
        far_id = FarId},
      apply_actions = Actions,
      forwarding_params = ForwardingParams,
      duplication_params = DuplicationParams,
      bar_id = BarId
    })
                 end,
  [CreateFARFun(X) || X <- CreateFARs],

  %%--------------------------------------------------------------------
  %% Process URRs
  %%--------------------------------------------------------------------
  CreateURRFun = fun(X) -> X end,
  [CreateURRFun(X) || X <- CreateURRs],

  %%--------------------------------------------------------------------
  %% Process QERs
  %%--------------------------------------------------------------------
  CreateQERFun = fun(X) -> X end,
  [CreateQERFun(X) || X <- CreateQERs],

  %%--------------------------------------------------------------------
  %% Process BARs
  %%--------------------------------------------------------------------
  CreateBARFun = fun(X) -> X end,
  [CreateBARFun(X) || X <- CreateBARs],

  ok.
