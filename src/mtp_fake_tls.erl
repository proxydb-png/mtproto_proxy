%%% ============================================================================
%%% mtp_fake_tls.erl - Reality Hybrid (Fixed)
%%% 
%%% FIX: به جای ssl:connect (که خودش ClientHello می‌فرسته)،
%%% از gen_tcp:connect استفاده می‌کنیم و ClientHello کلاینت رو
%%% مستقیماً روی TCP socket خام می‌فرستیم.
%%% ============================================================================

-module(mtp_fake_tls).

-behaviour(mtp_codec).

%% API exports
-export([format_secret_base64/2,
         format_secret_hex/2]).
-export([from_client_hello/2,
         from_client_hello/3,
         from_client_hello/5,
         reality_handshake/3,
         derive_sni_secret/3,
         parse_sni/1,
         tls_decode_error_alert/0,
         new/0,
         try_decode_packet/2,
         decode_all/2,
         encode_packet/2]).
-export([make_client_hello/2,
         make_client_hello/4,
         make_client_hello_reality/3,
         parse_server_hello/1]).
-export([init/1]).

-export_type([codec/0, meta/0]).

-include_lib("kernel/include/logger.hrl").

-dialyzer(no_improper_lists).

%% ============================================================================
%% Records & Types
%% ============================================================================

-record(st, {
    socket :: term() | undefined,
    reality_host :: binary() | undefined,
    reality_port :: integer() | undefined,
    recv_buffer :: binary() | undefined,
    handshake_complete :: boolean()
}).

-record(client_hello,
        {pseudorandom :: binary(),
         session_id :: binary(),
         cipher_suites :: list(),
         compression_methods :: list(),
         extensions :: [{non_neg_integer(), any()}]
        }).

-opaque codec() :: #st{}.

-type meta() :: #{session_id := binary(),
                  timestamp := non_neg_integer(),
                  client_digest := binary(),
                  sni_domain => binary(),
                  reality_server => binary(),
                  reality_socket => term()}.

%% ============================================================================
%% Constants
%% ============================================================================

-define(u16, 16/unsigned-big).
-define(u24, 24/unsigned-big).
-define(MAX_IN_PACKET_SIZE, 65535).
-define(MAX_OUT_PACKET_SIZE, 16384).

-define(TLS_10_VERSION, 3, 1).
-define(TLS_12_VERSION, 3, 3).
-define(TLS_13_VERSION, 3, 4).
-define(TLS_REC_CHANGE_CIPHER, 20).
-define(TLS_REC_ALERT, 21).
-define(TLS_REC_HANDSHAKE, 22).
-define(TLS_REC_DATA, 23).

-define(TLS_ALERT_FATAL, 2).
-define(TLS_ALERT_DECODE_ERROR, 50).

-define(TLS_12_DATA, ?TLS_REC_DATA, ?TLS_12_VERSION).

-define(DIGEST_POS, 11).
-define(DIGEST_LEN, 32).

-define(TLS_TAG_CLI_HELLO, 1).
-define(EXT_SNI, 0).
-define(EXT_SNI_HOST_NAME, 0).
-define(EXT_KEY_SHARE, 51).

-define(TIMESTAMP_TOLERANCE_SECONDS, 300).

-define(CACHE_KEY_DOMAINS, {?MODULE, domain_cache}).
-define(CACHE_KEY_CLIENT_HELLO_CACHE, {?MODULE, ch_cache}).

-define(DEFAULT_REALITY_SERVERS, [
    #{host => <<"www.microsoft.com">>, port => 443},
    #{host => <<"www.google.com">>, port => 443},
    #{host => <<"www.cloudflare.com">>, port => 443}
]).

%% ============================================================================
%% JA4 Profiles (unchanged)
%% ============================================================================

-define(REALITY_PROFILES, #{
    <<"www.microsoft.com">> => #{
        cipher_order => [16#13, 16#01, 16#13, 16#02, 16#13, 16#03],
        extensions_order => [51, 0, 43, 16, 13, 10, 45, 23, 65281],
        alpn => [<<"h2">>, <<"http/1.1">>],
        key_share_groups => [16#001d],
        sig_algorithms => [16#04, 16#03, 16#05, 16#03, 16#06, 16#03],
        supported_groups => [16#001d, 16#0017, 16#0018]
    },
    <<"www.google.com">> => #{
        cipher_order => [16#13, 16#01, 16#13, 16#02, 16#13, 16#03, 16#c0, 16#2b],
        extensions_order => [51, 0, 43, 16, 13, 10, 45, 23, 65281],
        alpn => [<<"h2">>, <<"http/1.1">>],
        key_share_groups => [16#001d],
        sig_algorithms => [16#04, 16#03, 16#05, 16#03, 16#06, 16#03, 16#08, 16#04],
        supported_groups => [16#001d, 16#0017, 16#0018]
    },
    <<"www.cloudflare.com">> => #{
        cipher_order => [16#13, 16#01, 16#13, 16#02, 16#13, 16#03],
        extensions_order => [51, 0, 43, 16, 13, 10, 45, 23, 65281],
        alpn => [<<"h2">>, <<"http/1.1">>],
        key_share_groups => [16#001d],
        sig_algorithms => [16#04, 16#03, 16#05, 16#03, 16#06, 16#03],
        supported_groups => [16#001d, 16#0017, 16#0018]
    }
}).

%% ============================================================================
%% Initialization
%% ============================================================================

-spec init(AllowedDomains :: [binary()]) -> ok.
init(AllowedDomains) ->
    {ExactMap, WildcardList} = categorize_domains(AllowedDomains, #{}, []),
    DomainCache = #{exact => ExactMap, wildcard => WildcardList},
    put(?CACHE_KEY_DOMAINS, DomainCache),
    put(?CACHE_KEY_CLIENT_HELLO_CACHE, #{}),
    ?LOG_INFO("Reality Hybrid initialized", []),
    ok.

%% ============================================================================
%% Domain Management
%% ============================================================================

categorize_domains([], ExactMap, Wildcards) -> {ExactMap, Wildcards};
categorize_domains([<<"*.", Suffix/binary>> | T], ExactMap, Wildcards) ->
    categorize_domains(T, ExactMap, [Suffix | Wildcards]);
categorize_domains([Domain | T], ExactMap, Wildcards) ->
    categorize_domains(T, maps:put(Domain, true, ExactMap), Wildcards).

is_domain_allowed(Domain, AllowedDomains) when is_binary(Domain) ->
    case get(?CACHE_KEY_DOMAINS) of
        #{exact := ExactMap, wildcard := Wildcards} ->
            maps:is_key(Domain, ExactMap) orelse check_wildcard(Domain, Wildcards);
        undefined ->
            {ExactMap, Wildcards} = categorize_domains(AllowedDomains, #{}, []),
            maps:is_key(Domain, ExactMap) orelse check_wildcard(Domain, Wildcards)
    end.

check_wildcard(_Domain, []) -> false;
check_wildcard(Domain, [Suffix | T]) ->
    SuffixWithDot = <<".", Suffix/binary>>,
    SuffixLen = byte_size(SuffixWithDot),
    DomainLen = byte_size(Domain),
    case DomainLen > SuffixLen of
        true ->
            StartPos = DomainLen - SuffixLen,
            <<_Head:StartPos/binary, Tail:SuffixLen/binary>> = Domain,
            Tail =:= SuffixWithDot orelse check_wildcard(Domain, T);
        false -> check_wildcard(Domain, T)
    end.

%% ============================================================================
%% Secret Formatting
%% ============================================================================

format_secret_hex(Secret, Domain) when byte_size(Secret) == 16 ->
    mtp_handler:hex(<<16#ee, Secret/binary, Domain/binary>>);
format_secret_hex(HexSecret, Domain) when byte_size(HexSecret) == 32 ->
    format_secret_hex(mtp_handler:unhex(HexSecret), Domain).

format_secret_base64(Secret, Domain) when byte_size(Secret) == 16 ->
    base64url(<<16#ee, Secret/binary, Domain/binary>>);
format_secret_base64(HexSecret, Domain) when byte_size(HexSecret) == 32 ->
    format_secret_base64(mtp_handler:unhex(HexSecret), Domain).

base64url(Bin) ->
    << << (urlencode_digit(D)) >> || <<D>> <= base64:encode(Bin), D =/= $= >>.

urlencode_digit($/) -> $_;
urlencode_digit($+) -> $-;
urlencode_digit(D)  -> D.

%% ============================================================================
%% ClientHello Generation
%% ============================================================================

make_client_hello_reality(Secret, _SniDomain, RealityHost) ->
    CurrentTime = erlang:system_time(second),
    case get_cached_client_hello(RealityHost, CurrentTime) of
        {ok, CachedHello} ->
            update_client_hello_timestamp(CachedHello, Secret, CurrentTime);
        not_found ->
            Profile = maps:get(RealityHost, ?REALITY_PROFILES, default_profile()),
            SessionId = crypto:strong_rand_bytes(32),
            Hello = build_ja4_client_hello(Profile, Secret, CurrentTime, SessionId, RealityHost),
            cache_client_hello(RealityHost, Hello, CurrentTime),
            Hello
    end.

build_ja4_client_hello(Profile, Secret, Timestamp, SessionId, RealityHost) ->
    #{cipher_order := Ciphers, extensions_order := ExtOrder,
      alpn := Alpn, key_share_groups := KeyGroups,
      sig_algorithms := SigAlgos, supported_groups := SupGroups} = Profile,
    
    Extensions = build_extensions_ordered(ExtOrder, RealityHost, Alpn, KeyGroups, SigAlgos, SupGroups),
    ExtBin = iolist_to_binary(Extensions),
    ExtLen = byte_size(ExtBin),
    
    CipherBin = << <<C:?u16>> || C <- Ciphers >>,
    CSLen = byte_size(CipherBin),
    SessIdLen = byte_size(SessionId),
    
    HelloBody = iolist_to_binary([
        <<16#03, 16#03>>,
        binary:copy(<<0>>, 32),
        <<SessIdLen:8, SessionId/binary>>,
        <<CSLen:?u16, CipherBin/binary>>,
        <<1, 0>>,
        <<ExtLen:?u16, ExtBin/binary>>
    ]),
    
    HelloBodyLen = byte_size(HelloBody),
    TlsLen = HelloBodyLen + 4,
    
    Template = <<?TLS_REC_HANDSHAKE, ?TLS_10_VERSION, TlsLen:?u16,
                 ?TLS_TAG_CLI_HELLO, HelloBodyLen:?u24, HelloBody/binary>>,
    
    embed_auth_in_random(Template, Secret, Timestamp).

build_extensions_ordered(Order, Host, Alpn, KeyGroups, SigAlgos, SupGroups) ->
    lists:map(fun
        (51) -> build_key_share_ext(KeyGroups);
        (0)  -> build_sni_ext(Host);
        (43) -> <<0, 43, 0, 3, 2, 16#03, 16#04>>;
        (16) -> build_alpn_ext(Alpn);
        (13) -> build_sig_algos_ext(SigAlgos);
        (10) -> build_supported_groups_ext(SupGroups);
        (45) -> <<0, 45, 0, 2, 1, 1>>;
        (23) -> <<0, 23, 0, 0>>;
        (65281) -> <<16#ff, 1, 0, 1, 0>>;
        (_) -> <<>>
    end, Order).

build_key_share_ext([Primary | _]) ->
    KeyData = crypto:strong_rand_bytes(32),
    KSLen = byte_size(KeyData) + 4,
    <<0, 51, (KSLen + 2):?u16, KSLen:?u16, Primary:?u16, 0, 32, KeyData/binary>>.

build_sni_ext(Host) ->
    HostLen = byte_size(Host),
    [<<0, 0, (HostLen + 5):?u16, (HostLen + 3):?u16, 0, HostLen:?u16>>, Host].

build_alpn_ext(Protocols) ->
    Entries = [<<(byte_size(P)):8, P/binary>> || P <- Protocols],
    Data = iolist_to_binary(Entries),
    DataLen = byte_size(Data),
    <<0, 16, (DataLen + 2):?u16, DataLen:?u16, Data/binary>>.

build_sig_algos_ext(Algos) ->
    Data = iolist_to_binary([<<A:8>> || A <- Algos]),
    DataLen = byte_size(Data),
    <<0, 13, (DataLen + 2):?u16, DataLen:?u16, Data/binary>>.

build_supported_groups_ext(Groups) ->
    Data = << <<G:?u16>> || G <- Groups >>,
    DataLen = byte_size(Data),
    <<0, 10, (DataLen + 2):?u16, DataLen:?u16, Data/binary>>.

default_profile() ->
    #{cipher_order => [16#13, 16#01, 16#13, 16#02, 16#13, 16#03],
      extensions_order => [51, 0, 43, 16, 13, 10, 45, 23, 65281],
      alpn => [<<"h2">>, <<"http/1.1">>],
      key_share_groups => [16#001d],
      sig_algorithms => [16#04, 16#03, 16#05, 16#03, 16#06, 16#03],
      supported_groups => [16#001d, 16#0017, 16#0018]}.

embed_auth_in_random(Template, Secret, Timestamp) ->
    <<Left:?DIGEST_POS/binary, _:?DIGEST_LEN/binary, Right/binary>> = Template,
    FakeHello = <<Left/binary, (binary:copy(<<0>>, ?DIGEST_LEN))/binary, Right/binary>>,
    Digest = hmac(sha256, Secret, FakeHello),
    EncTimestamp = <<(binary:copy(<<0>>, ?DIGEST_LEN - 4))/binary, Timestamp:32/unsigned-little>>,
    FakeRandom = crypto:exor(Digest, EncTimestamp),
    <<Left/binary, FakeRandom:?DIGEST_LEN/binary, Right/binary>>.

update_client_hello_timestamp(CachedHello, Secret, CurrentTime) ->
    <<Left:?DIGEST_POS/binary, _:?DIGEST_LEN/binary, Right/binary>> = CachedHello,
    FakeHello = <<Left/binary, (binary:copy(<<0>>, ?DIGEST_LEN))/binary, Right/binary>>,
    Digest = hmac(sha256, Secret, FakeHello),
    EncTimestamp = <<(binary:copy(<<0>>, ?DIGEST_LEN - 4))/binary, CurrentTime:32/unsigned-little>>,
    FakeRandom = crypto:exor(Digest, EncTimestamp),
    <<Left/binary, FakeRandom:?DIGEST_LEN/binary, Right/binary>>.

cache_client_hello(RealityHost, ClientHello, Timestamp) ->
    Cache = get(?CACHE_KEY_CLIENT_HELLO_CACHE),
    put(?CACHE_KEY_CLIENT_HELLO_CACHE, maps:put(RealityHost, {ClientHello, Timestamp}, Cache)),
    ok.

get_cached_client_hello(RealityHost, CurrentTime) ->
    Cache = get(?CACHE_KEY_CLIENT_HELLO_CACHE),
    case maps:find(RealityHost, Cache) of
        {ok, {Hello, CachedTime}} when CurrentTime - CachedTime < 3600 -> {ok, Hello};
        _ -> not_found
    end.

make_client_hello(Secret, SniDomain) ->
    Servers = ?DEFAULT_REALITY_SERVERS,
    Server = lists:nth(rand:uniform(length(Servers)), Servers),
    make_client_hello_reality(Secret, SniDomain, maps:get(host, Server)).

make_client_hello(Timestamp, SessionId, HexSecret, SniDomain) when byte_size(HexSecret) == 32 ->
    make_client_hello(Timestamp, SessionId, mtp_handler:unhex(HexSecret), SniDomain);
make_client_hello(_Timestamp, _SessionId, Secret, SniDomain) ->
    make_client_hello(Secret, SniDomain).

%% ============================================================================
%% Reality Handshake - FIXED VERSION
%% از gen_tcp استفاده می‌کنیم، نه ssl:connect
%% ============================================================================

-spec reality_handshake(ClientHello :: binary(), RealityHost :: binary(), 
                         RealityPort :: inet:port_number()) ->
          {ok, ServerResponse :: binary(), Socket :: term()} | {error, term()}.
reality_handshake(ClientHello, RealityHost, RealityPort) ->
    ?LOG_INFO("Reality handshake to ~s:~p (raw TCP)", [RealityHost, RealityPort]),
    
    %% ۱. بازنویسی SNI به سرور واقعی
    RewrittenHello = rewrite_client_hello_sni(ClientHello, RealityHost),
    ?LOG_DEBUG("SNI rewritten, ClientHello size: ~p", [byte_size(RewrittenHello)]),
    
    %% ۲. اتصال TCP خام (نه SSL!)
    case gen_tcp:connect(binary_to_list(RealityHost), RealityPort,
                         [binary, {active, false}, {packet, raw}], 5000) of
        {ok, TcpSocket} ->
            ?LOG_DEBUG("TCP connected to ~s", [RealityHost]),
            
            %% ۳. ارسال ClientHello کلاینت روی TCP خام
            case gen_tcp:send(TcpSocket, RewrittenHello) of
                ok ->
                    ?LOG_DEBUG("ClientHello forwarded to ~s", [RealityHost]),
                    
                    %% ۴. دریافت پاسخ سرور (ServerHello + بقیه Handshake)
                    case receive_raw_tls_response(TcpSocket, <<>>, 10) of
                        {ok, ServerResponse} ->
                            ?LOG_INFO("Received real TLS response (~p bytes)", 
                                      [byte_size(ServerResponse)]),
                            {ok, ServerResponse, TcpSocket};
                        {error, Reason} ->
                            gen_tcp:close(TcpSocket),
                            {error, {server_no_response, Reason}}
                    end;
                {error, Reason} ->
                    gen_tcp:close(TcpSocket),
                    {error, {send_failed, Reason}}
            end;
        {error, Reason} ->
            ?LOG_ERROR("TCP connect failed to ~s:~p - ~p", [RealityHost, RealityPort, Reason]),
            {error, {connection_failed, Reason}}
    end.

%% دریافت پاسخ TLS خام از سرور واقعی
receive_raw_tls_response(_Socket, _Acc, 0) ->
    {error, timeout};
receive_raw_tls_response(Socket, Acc, Retries) ->
    case gen_tcp:recv(Socket, 0, 1000) of
        {ok, Data} ->
            NewAcc = <<Acc/binary, Data/binary>>,
            ?LOG_DEBUG("Received ~p bytes from reality server (total: ~p)", 
                       [byte_size(Data), byte_size(NewAcc)]),
            case is_handshake_complete(NewAcc) of
                true -> {ok, NewAcc};
                false -> receive_raw_tls_response(Socket, NewAcc, Retries)
            end;
        {error, timeout} ->
            receive_raw_tls_response(Socket, Acc, Retries - 1);
        {error, Reason} ->
            {error, Reason}
    end.

is_handshake_complete(Data) ->
    byte_size(Data) > 500 andalso
        binary:match(Data, <<?TLS_REC_CHANGE_CIPHER>>) =/= nomatch.

%% بازنویسی SNI (با حفظ طول کل)
rewrite_client_hello_sni(ClientHello, RealityHost) ->
    <<TlsHeader:5/binary, Rest/binary>> = ClientHello,
    {BeforeSni, OldSni, AfterSni} = extract_sni_from_client_hello(Rest),
    
    OldSniLen = byte_size(OldSni),
    NewSniBin = iolist_to_binary(build_sni_ext(RealityHost)),
    NewSniLen = byte_size(NewSniBin),
    
    %% Padding اگر طول SNI جدید کمتر از قبلیه
    {FinalNewSni, LengthDiff} = if
        NewSniLen < OldSniLen ->
            Pad = binary:copy(<<0>>, OldSniLen - NewSniLen),
            {<<NewSniBin/binary, Pad/binary>>, 0};
        NewSniLen > OldSniLen ->
            {NewSniBin, NewSniLen - OldSniLen};
        true ->
            {NewSniBin, 0}
    end,
    
    NewPayload = <<BeforeSni/binary, FinalNewSni/binary, AfterSni/binary>>,
    NewLen = byte_size(NewPayload),
    
    <<Type:8, Version:?u16, _OldLen:?u16>> = TlsHeader,
    NewTlsHeader = <<Type:8, Version:?u16, NewLen:?u16>>,
    
    <<NewTlsHeader/binary, NewPayload/binary>>.

extract_sni_from_client_hello(Data) -> extract_sni_from_client_hello(Data, <<>>).

extract_sni_from_client_hello(<<?EXT_SNI:?u16, ExtLen:?u16, SniExt:ExtLen/binary, Rest/binary>>, Acc) ->
    {Acc, <<?EXT_SNI:?u16, ExtLen:?u16, SniExt/binary>>, Rest};
extract_sni_from_client_hello(<<Type:?u16, Len:?u16, Data:Len/binary, Rest/binary>>, Acc) ->
    extract_sni_from_client_hello(Rest, <<Acc/binary, Type:?u16, Len:?u16, Data/binary>>);
extract_sni_from_client_hello(<<>>, Acc) ->
    {Acc, <<>>, <<>>}.

%% ============================================================================
%% from_client_hello
%% ============================================================================

from_client_hello(Data, Secret, AllowedDomains, RealityHost, RealityPort) ->
    #client_hello{pseudorandom = ClientDigest, session_id = SessionId, extensions = Extensions} = 
        parse_client_hello(Data),
    
    SniDomain = case lists:keyfind(?EXT_SNI, 1, Extensions) of
        {_, [{?EXT_SNI_HOST_NAME, Domain}]} -> Domain;
        _ -> undefined
    end,
    
    case SniDomain of
        undefined ->
            ?LOG_WARNING("No SNI, rejecting"),
            error({protocol_error, tls_no_sni});
        _ ->
            is_domain_allowed(SniDomain, AllowedDomains) orelse
                error({protocol_error, tls_domain_not_allowed, SniDomain})
    end,
    
    validate_client_auth(Data, Secret, ClientDigest),
    
    case reality_handshake(Data, RealityHost, RealityPort) of
        {ok, ServerResponse, Socket} ->
            Meta = #{session_id => SessionId,
                     timestamp => extract_timestamp(ClientDigest, Data, Secret),
                     client_digest => ClientDigest,
                     sni_domain => SniDomain,
                     reality_server => RealityHost,
                     reality_socket => Socket},
            {ok, ServerResponse, Meta, #st{
                socket = Socket,
                reality_host = RealityHost,
                reality_port = RealityPort,
                recv_buffer = <<>>,
                handshake_complete = true
            }};
        {error, Reason} ->
            ?LOG_ERROR("Reality handshake failed: ~p", [Reason]),
            error({protocol_error, reality_handshake_failed, Reason})
    end.

from_client_hello(Data, Secret, AllowedDomains) ->
    Servers = ?DEFAULT_REALITY_SERVERS,
    Server = lists:nth(rand:uniform(length(Servers)), Servers),
    #{host := Host, port := Port} = Server,
    from_client_hello(Data, Secret, AllowedDomains, Host, Port).

from_client_hello(Data, Secret) ->
    from_client_hello(Data, Secret, []).

validate_client_auth(Data, Secret, ClientDigest) ->
    ServerDigest = make_server_digest(Data, Secret),
    <<Zeroes:(?DIGEST_LEN - 4)/binary, Timestamp:32/unsigned-little>> = 
        crypto:exor(ClientDigest, ServerDigest),
    lists:all(fun(B) -> B == 0 end, binary_to_list(Zeroes)) orelse
        error({protocol_error, tls_invalid_digest}),
    abs(erlang:system_time(second) - Timestamp) =< ?TIMESTAMP_TOLERANCE_SECONDS
        orelse error({protocol_error, tls_timestamp_expired}),
    ok.

extract_timestamp(ClientDigest, Data, Secret) ->
    ServerDigest = make_server_digest(Data, Secret),
    <<_Zeroes:(?DIGEST_LEN - 4)/binary, Timestamp:32/unsigned-little>> = 
        crypto:exor(ClientDigest, ServerDigest),
    Timestamp.

%% ============================================================================
%% ClientHello Parsing
%% ============================================================================

parse_client_hello(<<?TLS_REC_HANDSHAKE, ?TLS_10_VERSION, TlsFrameLen:?u16,
                     ?TLS_TAG_CLI_HELLO, HelloLen:?u24, ?TLS_12_VERSION,
                     Random:?DIGEST_LEN/binary,
                     SessIdLen, SessId:SessIdLen/binary,
                     CipherSuitesLen:?u16, CipherSuites:CipherSuitesLen/binary,
                     CompMethodsLen, CompMethods:CompMethodsLen/binary,
                     ExtensionsLen:?u16, Extensions:ExtensionsLen/binary>>
                  ) when TlsFrameLen >= 200, HelloLen >= 100 ->
    #client_hello{pseudorandom = Random, session_id = SessId,
                  cipher_suites = parse_suites(CipherSuites),
                  compression_methods = parse_compression(CompMethods),
                  extensions = parse_extensions(Extensions)};
parse_client_hello(_Data) ->
    error({protocol_error, tls_bad_client_hello, bad_client_hello}).

parse_suites(Bin) -> [Suite || <<Suite:?u16>> <= Bin].
parse_compression(Bin) -> [Bin].

parse_extensions(Exts) ->
    [{Type, parse_extension(Type, Data)}
     || <<Type:?u16, Length:?u16, Data:Length/binary>> <= Exts].

parse_extension(?EXT_SNI, <<ListLen:?u16, List:ListLen/binary>>) ->
    [{Type, Value} || <<Type, Len:?u16, Value:Len/binary>> <= List];
parse_extension(?EXT_KEY_SHARE, <<Len:?u16, Exts:Len/binary>>) ->
    [{Group, Key} || <<Group:?u16, KeyLen:?u16, Key:KeyLen/binary>> <= Exts];
parse_extension(_Type, Data) -> Data.

make_server_digest(<<Left:?DIGEST_POS/binary, _:?DIGEST_LEN/binary, Right/binary>>, Secret) ->
    hmac(sha256, Secret, [Left, binary:copy(<<0>>, ?DIGEST_LEN), Right]).

parse_sni(Data) ->
    try
        #client_hello{extensions = Extensions} = parse_client_hello(Data),
        case lists:keyfind(?EXT_SNI, 1, Extensions) of
            {_, [{?EXT_SNI_HOST_NAME, Domain}]} -> {ok, Domain};
            _ -> {error, no_sni}
        end
    catch error:{protocol_error, _, _} -> {error, bad_hello}
    end.

tls_decode_error_alert() ->
    <<?TLS_REC_ALERT, ?TLS_12_VERSION, 0, 2, ?TLS_ALERT_FATAL, ?TLS_ALERT_DECODE_ERROR>>.

derive_sni_secret(BaseSecret, SniDomain, Salt) when byte_size(BaseSecret) == 16 ->
    SecretHex = mtp_handler:hex(BaseSecret),
    <<Derived:16/binary, _/binary>> = crypto:hash(sha256, [Salt, SecretHex, SniDomain]),
    Derived.

parse_server_hello(Data) when is_binary(Data) ->
    case is_handshake_complete(Data) of
        true -> {ok, Data};
        false -> {incomplete, Data}
    end.

%% ============================================================================
%% Data Stream Codec - FIXED for raw TCP
%% ============================================================================

new() ->
    #st{handshake_complete = false}.

try_decode_packet(Bin, #st{handshake_complete = false} = St) ->
    try_decode_packet_direct(Bin, St);
try_decode_packet(Bin, #st{socket = Socket, recv_buffer = Buf} = St)
  when Socket =/= undefined ->
    _ = send_to_socket(Bin, Socket),
    case recv_from_socket(Socket, Buf) of
        {ok, DecodedData, NewBuf} ->
            {ok, DecodedData, <<>>, St#st{recv_buffer = NewBuf}};
        {incomplete, NewBuf} ->
            {incomplete, St#st{recv_buffer = NewBuf}}
    end;
try_decode_packet(Bin, St) ->
    try_decode_packet_direct(Bin, St).

try_decode_packet_direct(<<?TLS_12_DATA, Size:?u16, Data:Size/binary, Tail/binary>>, St) ->
    {ok, Data, Tail, St};
try_decode_packet_direct(<<?TLS_REC_CHANGE_CIPHER, ?TLS_12_VERSION, Size:?u16,
                           _Data:Size/binary, Tail/binary>>, St) ->
    try_decode_packet_direct(Tail, St);
try_decode_packet_direct(Bin, St) when byte_size(Bin) =< (?MAX_IN_PACKET_SIZE + 5) ->
    {incomplete, St};
try_decode_packet_direct(Bin, _St) ->
    error({protocol_error, tls_max_size, byte_size(Bin)}).

send_to_socket(<<>>, _) -> ok;
send_to_socket(Data, Socket) -> gen_tcp:send(Socket, Data).

recv_from_socket(Socket, Buffer) ->
    case extract_application_data(Buffer) of
        {ok, Data, Rest} -> {ok, Data, Rest};
        incomplete ->
            case gen_tcp:recv(Socket, 0, 100) of
                {ok, NewData} ->
                    NewBuffer = <<Buffer/binary, NewData/binary>>,
                    case extract_application_data(NewBuffer) of
                        {ok, Data, Rest} -> {ok, Data, Rest};
                        incomplete -> {incomplete, NewBuffer}
                    end;
                {error, timeout} -> {incomplete, Buffer};
                {error, _} -> {incomplete, Buffer}
            end
    end.

extract_application_data(<<?TLS_12_DATA, Size:?u16, Rest/binary>>) ->
    case byte_size(Rest) >= Size of
        true -> <<Data:Size/binary, Tail/binary>> = Rest, {ok, Data, Tail};
        false -> incomplete
    end;
extract_application_data(<<_:8, _Mj:8, _Mn:8, Size:?u16, Rest/binary>>) ->
    case byte_size(Rest) >= Size of
        true -> <<_:Size/binary, Tail/binary>> = Rest, extract_application_data(Tail);
        false -> incomplete
    end;
extract_application_data(<<>>) -> incomplete;
extract_application_data(_) -> incomplete.

decode_all(Bin, St) -> decode_all(Bin, <<>>, St).

decode_all(Bin, Acc, St0) ->
    case try_decode_packet(Bin, St0) of
        {incomplete, St} -> {Acc, Bin, St};
        {ok, Data, Tail, St} -> decode_all(Tail, <<Acc/binary, Data/binary>>, St)
    end.

encode_packet(Bin, #st{socket = undefined} = St) ->
    {encode_as_frames(Bin), St};
encode_packet(Bin, #st{socket = Socket} = St) when Socket =/= undefined ->
    Frames = iolist_to_binary(encode_as_frames(Bin)),
    _ = send_to_socket(Frames, Socket),
    {<<>>, St}.

encode_as_frames(Bin) when byte_size(Bin) =< ?MAX_OUT_PACKET_SIZE ->
    as_tls_data_frame(Bin);
encode_as_frames(<<Chunk:?MAX_OUT_PACKET_SIZE/binary, Tail/binary>>) ->
    [as_tls_data_frame(Chunk) | encode_as_frames(Tail)].

as_tls_data_frame(Bin) -> as_tls_frame(?TLS_REC_DATA, Bin).

as_tls_frame(Type, Data) ->
    Size = iolist_size(Data),
    [<<Type, ?TLS_12_VERSION, Size:?u16>> | Data].

-if(?OTP_RELEASE >= 23).
hmac(Algo, Key, Str) -> crypto:mac(hmac, Algo, Key, Str).
-else.
hmac(Algo, Key, Str) -> crypto:hmac(Algo, Key, Str).
-endif.
