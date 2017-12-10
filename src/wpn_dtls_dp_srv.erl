%%%-------------------------------------------------------------------
%%% @author colrack
%%% @copyright (C) 2017, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 09. dic 2017 10:29
%%%-------------------------------------------------------------------
-module(wpn_dtls_dp_srv).
-author("colrack").

-behaviour(gen_server).

-include("wishvpn.hrl").
-include_lib("public_key/include/public_key.hrl").

%% API
-export([start_link/2, mk_opts/1]).

-export([get_socks/1]).

%% gen_server callbacks
-export([init/1,
  handle_call/3,
  handle_cast/2,
  handle_info/2,
  terminate/2,
  code_change/3]).

-define(SERVER, ?MODULE).

-record(state, {dtls_socks = []}).

%%%===================================================================
%%% API
%%%===================================================================
get_socks(Pid) when is_pid(Pid) ->
  gen_server:call(Pid, get_socks).

%%--------------------------------------------------------------------
%% @doc
%% Starts the server
%%
%% @end
%%--------------------------------------------------------------------
-spec(start_link(Name :: string(), Transports :: list()) ->
  {ok, Pid :: pid()} | ignore | {error, Reason :: term()}).
start_link(Name, Transports) ->
  gen_server:start_link(?MODULE, [Name, Transports], []).

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
init([Name, Transports]) ->
  OpenSocksF = fun(Transport, Acc) ->
    Side = proplists:get_value(side, Transport, listen),
    IPString = proplists:get_value(ip, Transport, "127.0.0.1"),
    {ok, IP} = inet:parse_address(IPString),
    RemoteIPString = proplists:get_value(remote_ip, Transport, "127.0.0.1"),
    {ok, RemoteIP} = inet:parse_address(RemoteIPString),
    Port = proplists:get_value(port, Transport, 2914),
    SockRes = case Side of
                listen ->
                  {ok, S} = ssl:listen(Port, mk_opts(Side) ++ [{active, false}, {ip, IP}]),
                  Self = self(),
                  {_,_} = erlang:spawn_monitor(fun() -> accept(S, Self) end),
                  {ok, S};
                connect ->
                  {ok, S} = ssl:connect(RemoteIP, Port,
                    mk_opts(connect) ++ [{active, true}], 2000),
                  SER = wishvpn:test_ser_2(S),
                  wpn_srv:ser(SER),
                  {ok, S}
              end,
    case SockRes of
      {ok, Sock} -> [Sock | Acc];
      _ -> Acc
    end
               end,
  Sockets = lists:foldl(OpenSocksF, [], Transports),
  erlang:register(list_to_atom(Name), self()),
  {ok, #state{dtls_socks = Sockets}}.

accept(LSocket, Pid) ->
  {ok, Socket} = ssl:transport_accept(LSocket),
  ok = ssl:ssl_accept(Socket),
%%  {ok, Cert} = ssl:peercert(Socket),
%%  #'OTPCertificate'{
%%    tbsCertificate = #'OTPTBSCertificate'{
%%      subjectPublicKeyInfo = #'OTPSubjectPublicKeyInfo'{
%%        subjectPublicKey = SubjectPublicKey
%%      }
%%    }
%%  } = public_key:pkix_decode_cert(Cert, otp),
%%  lager:info("Cert: ~p", [public_key:pkix_decode_cert(Cert, otp)]),

  SER = wishvpn:test_ser_1(Socket),
  wpn_srv:ser(SER),

  ssl:controlling_process(Socket, Pid),
  ssl:setopts(LSocket, [{active, once}]),
  ssl:setopts(Socket, [{active, true}]),
  accept(LSocket, Pid).

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
handle_call(get_socks, _From, #state{dtls_socks = Socks} = State) ->
  {reply, {ok, Socks}, State};
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
handle_info({ssl, Sock, Data}, State) ->
  case ets:lookup(?TABLE_PDR_SOCK, Sock) of
    [#pdr_sock_record{pdrs = PDRs}] ->
      #pdr_record_ref{cert_fingerprint = CF, pdr_id = PdrId} =
        wpn_srv:get_highest_pdr(PDRs),

      PdrRecordKey = #pdr_record_key{cert_fingerprint = CF, pdr_id = PdrId},
      #pdr_record{far_id = FarId} = wpn_srv:get_pdr_record(PdrRecordKey),

      FarRecordKey = #far_record_key{cert_fingerprint = CF, far_id = FarId},
      #far_record{apply_actions = ApplyActions,
        forwarding_params = #forwarding_params{
          outer_header_creation = #outer_header_creation{
            hdr = none
          },
          network_instance = NI
        }} = wpn_srv:get_far_record(FarRecordKey),

      LanProcess = wpn_srv:get_tun_pid_from_net_instance(NI),

      case lists:member(forw, ApplyActions) of
        true -> wpn_ip_net_srv:send(LanProcess, Data);
        _ -> ok
      end;
    _ -> drop, lager:debug("Dropping data from ~p", [Sock])
  end,
  {noreply, State};
handle_info({ssl_closed, _Sock}, State) ->
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
mk_opts(listen) ->
  [{verify_fun,
    {fun ssl_verify_fingerprint:verify_fun/3,
      [{check_fingerprint,
        {sha, "0D7E44C0AEAAA794ACCCBCEE8E13867CD8D81540"}}]}},
    {verify, verify_none}]
  ++ mk_opts("server");
mk_opts(connect) ->
  [{verify_fun,
    {fun ssl_verify_fingerprint:verify_fun/3,
      [{check_fingerprint,
        {sha, "55D0BA03BFA419F7D6C62FF5070DD17A53C69397"}}]}},
    {verify, verify_none}]
  ++ mk_opts("client");
mk_opts(Role) ->
  Dir = filename:join([code:priv_dir(wishvpn), "certs", "etc"]),
  [{verify, verify_peer},
%%    {verify, verify_none},
%%    {depth, 2},
    {protocol, dtls},
    {cacertfile, filename:join([Dir, Role, "cacerts.pem"])},
    {certfile, filename:join([Dir, Role, "cert.pem"])},
    {keyfile, filename:join([Dir, Role, "key.pem"])}].
