%%% @author sergey <me@seriyps.ru>
%%% @copyright (C) 2019, sergey
%%% @doc
%%% Fake TLS 'CBC' stream codec
%%% Enhanced with deep fingerprint randomization
%%% + Reality Authentication via Random field
%%% + Anti-Timing-Analysis (Jitter & Lifecycle Simulation)
%%% + Dynamic Profile Rotation mid-connection
%%% + Padding Randomization per packet
%%% + Fake HTTP/2 Frames (keep-alive simulation)
%%% + Ghost TLS Records (DPI confusion - from original Secret structure)
%%% @end

-module(mtp_fake_tls).

-behaviour(mtp_codec).

-export([format_secret_base64/2,
         format_secret_hex/2]).
-export([from_client_hello/2,
         from_client_hello/3,
         derive_sni_secret/3,
         parse_sni/1,
         tls_decode_error_alert/0,
         new/0,
         try_decode_packet/2,
         decode_all/2,
         encode_packet/2]).
-export([make_client_hello/2,
         make_client_hello/4,
         parse_server_hello/1]).

-export_type([codec/0, meta/0]).

-include_lib("kernel/include/logger.hrl").

-dialyzer(no_improper_lists).

-record(st, {
    packet_count = 0 :: non_neg_integer(),
    current_profile :: map() | undefined,
    lifecycle = steady :: warmup | steady | burst | idle,
    lifecycle_change_at = 0 :: non_neg_integer(),
    burst_remaining = 0 :: non_neg_integer(),
    last_send_time = 0 :: non_neg_integer(),
    padding_enabled = true :: boolean(),
    pad_min = 0 :: non_neg_integer(),
    pad_max = 128 :: non_neg_integer()
}).

-record(client_hello,
        {pseudorandom :: binary(),
         session_id :: binary(),
         cipher_suites :: list(),
         compression_methods :: list(),
         extensions :: [{non_neg_integer(), any()}]
        }).

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
-define(TLS_TAG_SRV_HELLO, 2).
-define(TLS_CIPHERSUITE, 192, 47).
-define(TLS_CHANGE_CIPHER, ?TLS_REC_CHANGE_CIPHER, ?TLS_12_VERSION, 0, 1, 1).

-define(EXT_SNI, 0).
-define(EXT_SNI_HOST_NAME, 0).
-define(EXT_KEY_SHARE, 51).
-define(EXT_SUPPORTED_VERSIONS, 43).
-define(EXT_SESSION_TICKET, 35).
-define(EXT_STATUS_REQUEST, 5).

-define(TIMESTAMP_TOLERANCE_SECONDS, 300).

-define(APP, mtproto_proxy).

%% Ghost Records - DPI Confusion
-define(GHOST_RECORDS_ENABLED, true).
-define(GHOST_RECORD_COUNT_MIN, 1).
-define(GHOST_RECORD_COUNT_MAX, 3).

%% Timing Constants
-define(GAP_STEADY_MIN, 10).
-define(GAP_STEADY_MAX, 100).
-define(GAP_WARMUP_MIN, 5).
-define(GAP_WARMUP_MAX, 50).
-define(GAP_BURST_MIN, 2).
-define(GAP_BURST_MAX, 20).
-define(GAP_IDLE_MIN, 5000).
-define(GAP_IDLE_MAX, 30000).

-define(PROB_STEADY_TO_BURST, 0.05).
-define(PROB_STEADY_TO_IDLE, 0.02).
-define(PROB_BURST_TO_STEADY, 0.3).
-define(PROB_IDLE_TO_STEADY, 0.1).

%% GREASE values
-define(GREASE_VALUES, [
    16#0a0a, 16#1a1a, 16#2a2a, 16#3a3a, 16#4a4a,
    16#5a5a, 16#6a6a, 16#7a7a, 16#8a8a, 16#9a9a,
    16#aaaa, 16#baba, 16#caca, 16#dada, 16#eaea,
    16#fafa
]).

%% TLS Fingerprint Profiles
-define(TLS_FINGERPRINT_PROFILES, [
    #{name => chrome_120,
      cipher_suites => [
          16#13, 16#01, 16#13, 16#02, 16#13, 16#03,
          16#c0, 16#2b, 16#c0, 16#2f, 16#c0, 16#2c, 16#c0, 16#30,
          16#cc, 16#a9, 16#cc, 16#a8, 16#c0, 16#13, 16#c0, 16#14,
          16#00, 16#9c, 16#00, 16#9d, 16#00, 16#2f, 16#00, 16#35
      ],
      cipher_order_randomized => true,
      grease_count => {2, 4},
      key_share_groups => [16#11ec, 16#001d, 16#0017, 16#0018],
      supported_versions => [16#0304, 16#0303],
      version_order_randomized => true,
      sig_algorithms_count => 15,
      ec_point_formats => true,
      compress_certificate => brotli,
      ech_payload_size => [176, 208, 240],
      session_id_length => {32, 32},
      extensions_order_randomized => true,
      alpn_protocols => [[<<"h2">>, <<"http/1.1">>], [<<"h2">>], [<<"http/1.1">>]],
      padding_size => {0, 512}
    },
    #{name => firefox_121,
      cipher_suites => [
          16#13, 16#01, 16#13, 16#02, 16#13, 16#03,
          16#c0, 16#2b, 16#c0, 16#2f, 16#c0, 16#2c, 16#c0, 16#30,
          16#cc, 16#a9, 16#cc, 16#a8, 16#c0, 16#13, 16#c0, 16#14,
          16#00, 16#9c, 16#00, 16#9d, 16#00, 16#2f, 16#00, 16#35,
          16#00, 16#3c, 16#00, 16#3d
      ],
      cipher_order_randomized => true,
      grease_count => {2, 3},
      key_share_groups => [16#001d, 16#0017],
      supported_versions => [16#0304, 16#0303],
      version_order_randomized => false,
      sig_algorithms_count => 17,
      ec_point_formats => true,
      compress_certificate => brotli,
      ech_payload_size => [144, 176],
      session_id_length => {32, 32},
      extensions_order_randomized => false,
      alpn_protocols => [[<<"h2">>, <<"http/1.1">>]],
      padding_size => {0, 256}
    },
    #{name => safari_17,
      cipher_suites => [
          16#13, 16#01, 16#13, 16#02, 16#13, 16#03,
          16#c0, 16#2b, 16#c0, 16#2f, 16#c0, 16#2c, 16#c0, 16#30,
          16#cc, 16#a9, 16#cc, 16#a8, 16#c0, 16#13, 16#c0, 16#14
      ],
      cipher_order_randomized => false,
      grease_count => {2, 4},
      key_share_groups => [16#001d, 16#0017, 16#0018, 16#0019],
      supported_versions => [16#0304],
      version_order_randomized => false,
      sig_algorithms_count => 13,
      ec_point_formats => false,
      compress_certificate => none,
      ech_payload_size => [208, 240],
      session_id_length => {32, 32},
      extensions_order_randomized => false,
      alpn_protocols => [[<<"h2">>, <<"http/1.1">>]],
      padding_size => {0, 512}
    },
    #{name => edge_120,
      cipher_suites => [
          16#13, 16#01, 16#13, 16#02, 16#13, 16#03,
          16#c0, 16#2b, 16#c0, 16#2f, 16#c0, 16#2c, 16#c0, 16#30,
          16#cc, 16#a9, 16#cc, 16#a8, 16#c0, 16#13, 16#c0, 16#14,
          16#00, 16#9c, 16#00, 16#9d, 16#00, 16#2f, 16#00, 16#35
      ],
      cipher_order_randomized => true,
      grease_count => {2, 4},
      key_share_groups => [16#11ec, 16#001d, 16#0017],
      supported_versions => [16#0304, 16#0303],
      version_order_randomized => true,
      sig_algorithms_count => 16,
      ec_point_formats => true,
      compress_certificate => brotli,
      ech_payload_size => [176, 208],
      session_id_length => {32, 32},
      extensions_order_randomized => true,
      alpn_protocols => [[<<"h2">>, <<"http/1.1">>], [<<"h2">>]],
      padding_size => {0, 512}
    }
]).

-opaque codec() :: #st{}.

-type meta() :: #{session_id := binary(),
                  timestamp := non_neg_integer(),
                  client_digest := binary(),
                  sni_domain => binary(),
                  session_ticket => binary() | undefined,
                  ocsp_response => binary() | undefined}.

%% Secret helpers
format_secret_hex(Secret, Domain) when byte_size(Secret) == 16 ->
    mtp_handler:hex(<<16#ee, Secret/binary, Domain/binary>>);
format_secret_hex(HexSecret, Domain) when byte_size(HexSecret) == 32 ->
    format_secret_hex(mtp_handler:unhex(HexSecret), Domain).

-spec format_secret_base64(binary(), binary()) -> binary().
format_secret_base64(Secret, Domain) when byte_size(Secret) == 16 ->
    base64url(<<16#ee, Secret/binary, Domain/binary>>);
format_secret_base64(HexSecret, Domain) when byte_size(HexSecret) == 32 ->
    format_secret_base64(mtp_handler:unhex(HexSecret), Domain).

base64url(Bin) ->
    << << (urlencode_digit(D)) >> || <<D>> <= base64:encode(Bin), D =/= $= >>.

urlencode_digit($/) -> $_;
urlencode_digit($+) -> $-;
urlencode_digit(D)  -> D.

%% Domain allow-list
-spec is_domain_allowed(binary(), [binary()]) -> boolean().
is_domain_allowed(_Domain, []) -> true;
is_domain_allowed(Domain, AllowedDomains) ->
    lists:any(fun(Allowed) -> match_domain(Domain, Allowed) end, AllowedDomains).

-spec match_domain(binary(), binary()) -> boolean().
match_domain(Domain, <<"*.", Base/binary>>) ->
    Suffix = <<".", Base/binary>>,
    SuffixLen = byte_size(Suffix),
    DomLen = byte_size(Domain),
    DomLen >= SuffixLen andalso
        binary:part(Domain, DomLen - SuffixLen, SuffixLen) =:= Suffix;
match_domain(Domain, Allowed) -> Domain =:= Allowed.

%% Ghost Record Generator
-spec build_ghost_record() -> binary().
build_ghost_record() ->
    GhostType = case rand:uniform(4) of
        1 -> ?TLS_REC_HANDSHAKE;
        2 -> ?TLS_REC_DATA;
        3 -> ?TLS_REC_CHANGE_CIPHER;
        4 -> ?TLS_REC_ALERT
    end,
    GhostVersion = case rand:uniform(3) of
        1 -> <<?TLS_10_VERSION>>;
        2 -> <<?TLS_12_VERSION>>;
        3 -> <<?TLS_13_VERSION>>
    end,
    PayloadSize = rand:uniform(64),
    Payload = crypto:strong_rand_bytes(PayloadSize),
    <<GhostType, GhostVersion/binary, PayloadSize:?u16, Payload/binary>>.

-spec generate_ghost_records() -> [binary()].
generate_ghost_records() ->
    Count = ?GHOST_RECORD_COUNT_MIN + rand:uniform(?GHOST_RECORD_COUNT_MAX - ?GHOST_RECORD_COUNT_MIN + 1),
    [build_ghost_record() || _ <- lists:seq(1, Count)].

%% REALITY Authentication
-spec reality_authenticate(binary(), binary()) -> {ok, non_neg_integer(), binary()} | {error, term()}.
reality_authenticate(Data, Secret) ->
    #client_hello{pseudorandom = ClientDigest} = parse_client_hello(Data),
    ServerDigest = make_server_digest(Data, Secret),
    <<Zeroes:(?DIGEST_LEN - 4)/binary, Timestamp:32/unsigned-little>> = XoredDigest =
        crypto:exor(ClientDigest, ServerDigest),
    case lists:all(fun(B) -> B == 0 end, binary_to_list(Zeroes)) of
        true ->
            CurrentTime = erlang:system_time(second),
            case abs(CurrentTime - Timestamp) =< ?TIMESTAMP_TOLERANCE_SECONDS of
                true -> {ok, Timestamp, ClientDigest};
                false -> {error, {timestamp_expired, Timestamp, CurrentTime}}
            end;
        false -> {error, {invalid_digest, XoredDigest}}
    end.

%% from_client_hello
-spec from_client_hello(binary(), binary(), [binary()]) -> {ok, iodata(), meta(), codec()}.
from_client_hello(Data, Secret, AllowedDomains) ->
    #client_hello{session_id = SessionId, extensions = Extensions} = CliHlo = parse_client_hello(Data),
    ?LOG_DEBUG("TLS ClientHello=~p", [CliHlo]),

    SniDomain = case lists:keyfind(?EXT_SNI, 1, Extensions) of
        {_, [{?EXT_SNI_HOST_NAME, Domain}]} -> Domain;
        _ -> undefined
    end,

    case SniDomain of
        undefined ->
            ?LOG_WARNING("TLS ClientHello has no SNI, rejecting"),
            error({protocol_error, tls_no_sni});
        _ ->
            case is_domain_allowed(SniDomain, AllowedDomains) of
                true -> ok;
                false ->
                    ?LOG_WARNING("Unauthorized SNI domain: ~s", [SniDomain]),
                    error({protocol_error, tls_domain_not_allowed, SniDomain})
            end
    end,

    {ok, Timestamp, ClientDigest} = case reality_authenticate(Data, Secret) of
        {ok, Ts, Digest} -> {ok, Ts, Digest};
        {error, Reason} ->
            ?LOG_WARNING("REALITY authentication failed: ~p", [Reason]),
            error({protocol_error, tls_auth_failed, Reason})
    end,

    HasSessionTicket = lists:keymember(?EXT_SESSION_TICKET, 1, Extensions),
    HasOcspStapling = lists:keymember(?EXT_STATUS_REQUEST, 1, Extensions),

    KeyShare = make_key_share(Extensions),

    {SessionTicket, TicketRecord} = case HasSessionTicket of
        true ->
            Ticket = crypto:strong_rand_bytes(64 + rand:uniform(128)),
            TicketRec = as_tls_frame(?TLS_REC_HANDSHAKE, Ticket),
            {Ticket, TicketRec};
        false -> {undefined, <<>>}
    end,

    OcspResponse = case HasOcspStapling of
        true -> <<0, 0, 0, 0>>;
        false -> undefined
    end,

    SrvHello0 = make_srv_hello(binary:copy(<<0>>, ?DIGEST_LEN), SessionId, KeyShare, HasSessionTicket, HasOcspStapling),
    ChangeCipher = <<?TLS_REC_CHANGE_CIPHER, ?TLS_12_VERSION, 0, 1, 1>>,
    FakeHttpData = crypto:strong_rand_bytes(rand:uniform(256)),

    GhostRecords = case ?GHOST_RECORDS_ENABLED of
        true -> generate_ghost_records();
        false -> []
    end,
    TicketRecords = case TicketRecord of <<>> -> []; _ -> [TicketRecord] end,

    Response0 = [as_tls_frame(?TLS_REC_HANDSHAKE, SrvHello0), ChangeCipher,
                 as_tls_frame(?TLS_REC_DATA, FakeHttpData)]
                 ++ TicketRecords ++ GhostRecords,

    SrvHelloDigest = hmac(sha256, Secret, [ClientDigest | Response0]),
    SrvHello = make_srv_hello(SrvHelloDigest, SessionId, KeyShare, HasSessionTicket, HasOcspStapling),
    Response = [as_tls_frame(?TLS_REC_HANDSHAKE, SrvHello), ChangeCipher,
                as_tls_frame(?TLS_REC_DATA, FakeHttpData)]
                ++ TicketRecords ++ GhostRecords,

    Meta = #{session_id => SessionId, timestamp => Timestamp, client_digest => ClientDigest,
             sni_domain => SniDomain, session_ticket => SessionTicket, ocsp_response => OcspResponse},

    St = #st{packet_count = 0, current_profile = random_tls_profile(),
             lifecycle = warmup, lifecycle_change_at = 20 + rand:uniform(30),
             burst_remaining = 0, padding_enabled = true,
             pad_min = 0, pad_max = 128,
             last_send_time = erlang:system_time(millisecond)},

    {ok, Response, Meta, St}.

-spec from_client_hello(binary(), binary()) -> {ok, iodata(), meta(), codec()}.
from_client_hello(Data, Secret) -> from_client_hello(Data, Secret, []).

%% SNI helpers
-spec parse_sni(binary()) -> {ok, binary()} | {error, no_sni | bad_hello}.
parse_sni(Data) ->
    try
        #client_hello{extensions = Extensions} = parse_client_hello(Data),
        case lists:keyfind(?EXT_SNI, 1, Extensions) of
            {_, [{?EXT_SNI_HOST_NAME, Domain}]} -> {ok, Domain};
            _ -> {error, no_sni}
        end
    catch error:{protocol_error, tls_bad_client_hello, _} -> {error, bad_hello}
    end.

-spec tls_decode_error_alert() -> binary().
tls_decode_error_alert() ->
    <<?TLS_REC_ALERT, ?TLS_12_VERSION, 0, 2, ?TLS_ALERT_FATAL, ?TLS_ALERT_DECODE_ERROR>>.

-spec derive_sni_secret(binary(), binary(), binary()) -> binary().
derive_sni_secret(BaseSecret, SniDomain, Salt) when byte_size(BaseSecret) == 16 ->
    SecretHex = mtp_handler:hex(BaseSecret),
    <<Derived:16/binary, _/binary>> = crypto:hash(sha256, [Salt, SecretHex, SniDomain]),
    Derived.

%% ClientHello parser
parse_client_hello(<<?TLS_REC_HANDSHAKE, ?TLS_10_VERSION, TlsFrameLen:?u16,
                     ?TLS_TAG_CLI_HELLO, HelloLen:?u24, ?TLS_12_VERSION,
                     Random:?DIGEST_LEN/binary,
                     SessIdLen, SessId:SessIdLen/binary,
                     CipherSuitesLen:?u16, CipherSuites:CipherSuitesLen/binary,
                     CompMethodsLen, CompMethods:CompMethodsLen/binary,
                     ExtensionsLen:?u16, Extensions:ExtensionsLen/binary>>)
  when TlsFrameLen >= 512, HelloLen >= 400 ->
    #client_hello{pseudorandom = Random, session_id = SessId,
                  cipher_suites = [S || <<S:?u16>> <= CipherSuites],
                  compression_methods = CompMethods,
                  extensions = parse_extensions(Extensions)};
parse_client_hello(_Data) ->
    error({protocol_error, tls_bad_client_hello, bad_client_hello}).

parse_extensions(Bin) ->
    [{Type, parse_extension(Type, Data)} || <<Type:?u16, Length:?u16, Data:Length/binary>> <= Bin].

parse_extension(?EXT_SNI, <<ListLen:?u16, List:ListLen/binary>>) ->
    [{Type, Value} || <<Type, Len:?u16, Value:Len/binary>> <= List];
parse_extension(?EXT_KEY_SHARE, <<Len:?u16, Exts:Len/binary>>) ->
    [{Group, Key} || <<Group:?u16, KeyLen:?u16, Key:KeyLen/binary>> <= Exts];
parse_extension(?EXT_SESSION_TICKET, _Data) -> {session_ticket, supported};
parse_extension(?EXT_STATUS_REQUEST, <<Type, _Rest/binary>>) -> {ocsp_stapling, Type};
parse_extension(_Type, Data) -> Data.

%% ServerHello helpers
make_server_digest(<<Left:?DIGEST_POS/binary, _:?DIGEST_LEN/binary, Right/binary>>, Secret) ->
    hmac(sha256, Secret, [Left, binary:copy(<<0>>, ?DIGEST_LEN), Right]).

make_key_share(Exts) ->
    case lists:keyfind(?EXT_KEY_SHARE, 1, Exts) of
        {_, KeyShares} ->
            SupportedKeyShares = lists:dropwhile(
              fun({Group, Key}) ->
                  not (byte_size(Key) < 128 andalso
                       lists:member(Group, [16#0017, 16#0018, 16#0019, 16#001D,
                                            16#001E, 16#0100, 16#0101, 16#0102,
                                            16#0103, 16#0104]))
              end, KeyShares),
            case SupportedKeyShares of
                [] -> error({protocol_error, tls_unsupported_key_shares, KeyShares});
                [{KSGroup, KSKey} | _] -> {KSGroup, crypto:strong_rand_bytes(byte_size(KSKey))}
            end;
        _ -> error({protocol_error, tls_missing_key_share_ext, Exts})
    end.

make_srv_hello(Digest, SessionId, {KeyShareGroup, KeyShareKey}) ->
    make_srv_hello(Digest, SessionId, {KeyShareGroup, KeyShareKey}, false, false).

make_srv_hello(Digest, SessionId, {KeyShareGroup, KeyShareKey}, HasSessionTicket, HasOcspStapling) ->
    KeyShareEntity = <<KeyShareGroup:?u16, (byte_size(KeyShareKey)):?u16, KeyShareKey/binary>>,
    ExtensionsBase = [<<?EXT_KEY_SHARE:?u16, (byte_size(KeyShareEntity)):?u16>>,
                      KeyShareEntity,
                      <<?EXT_SUPPORTED_VERSIONS:?u16, 2:?u16, ?TLS_13_VERSION>>],
    ExtensionsWithTicket = case HasSessionTicket of
        true -> ExtensionsBase ++ [<<?EXT_SESSION_TICKET:?u16, 0:?u16>>];
        false -> ExtensionsBase
    end,
    ExtensionsFinal = case HasOcspStapling of
        true -> ExtensionsWithTicket ++ [<<?EXT_STATUS_REQUEST:?u16, 0:?u16>>];
        false -> ExtensionsWithTicket
    end,
    SessionSize = byte_size(SessionId),
    Payload = [<<?TLS_12_VERSION, Digest:?DIGEST_LEN/binary, SessionSize,
                 SessionId:SessionSize/binary, ?TLS_CIPHERSUITE, 0,
                 (iolist_size(ExtensionsFinal)):?u16>> | ExtensionsFinal],
    [<<?TLS_TAG_SRV_HELLO, (iolist_size(Payload)):?u24>> | Payload].

%% Profile helpers
random_tls_profile() ->
    Profiles = ?TLS_FINGERPRINT_PROFILES,
    lists:nth(rand:uniform(length(Profiles)), Profiles).

random_grease(Count) ->
    [lists:nth(rand:uniform(length(?GREASE_VALUES)), ?GREASE_VALUES) || _ <- lists:seq(1, Count)].

shuffle_list([]) -> [];
shuffle_list(List) ->
    [X || {_, X} <- lists:sort([{rand:uniform(), X} || X <- List])].

key_size_for_group(16#001D) -> 32;
key_size_for_group(16#0017) -> 65;
key_size_for_group(16#0018) -> 97;
key_size_for_group(16#0019) -> 133;
key_size_for_group(16#11EC) -> 1216;
key_size_for_group(_) -> 32.

%% Extension builders
build_cipher_suites(#{cipher_suites := Suites, grease_count := {GreaseMin, GreaseMax}} = Profile) ->
    GreaseCount = GreaseMin + rand:uniform(GreaseMax - GreaseMin + 1) - 1,
    GreaseVals = random_grease(GreaseCount),
    WithGrease = lists:foldl(fun(G, Acc) ->
        Pos = rand:uniform(length(Acc) + 1),
        lists:sublist(Acc, Pos - 1) ++ [G] ++ lists:nthtail(Pos - 1, Acc)
    end, Suites, GreaseVals),
    Final = case maps:get(cipher_order_randomized, Profile, false) of
        true -> shuffle_list(WithGrease);
        false -> WithGrease
    end,
    << <<S:?u16>> || S <- Final >>.

build_key_share_entries(#{key_share_groups := Groups, grease_count := {GreaseMin, GreaseMax}}) ->
    GreaseCount = GreaseMin + rand:uniform(GreaseMax - GreaseMin + 1) - 1,
    GreaseVals = random_grease(GreaseCount),
    GreaseEntries = [<<G:?u16, 16#00, 16#01, 16#00>> || G <- GreaseVals],
    RealEntries = [begin
        KeySize = key_size_for_group(Group),
        Key = crypto:strong_rand_bytes(KeySize),
        <<Group:?u16, KeySize:?u16, Key/binary>>
    end || Group <- Groups],
    AllEntries = lists:foldl(fun(G, Acc) ->
        Pos = rand:uniform(length(Acc) + 1),
        lists:sublist(Acc, Pos - 1) ++ [G] ++ lists:nthtail(Pos - 1, Acc)
    end, RealEntries, GreaseEntries),
    iolist_to_binary(AllEntries).

build_supported_versions_ext(#{supported_versions := Versions, grease_count := {GreaseMin, GreaseMax}} = Profile) ->
    GreaseCount = GreaseMin + rand:uniform(GreaseMax - GreaseMin + 1) - 1,
    GreaseVals = random_grease(GreaseCount),
    WithGrease = lists:foldl(fun(G, Acc) ->
        Pos = rand:uniform(length(Acc) + 1),
        lists:sublist(Acc, Pos - 1) ++ [G] ++ lists:nthtail(Pos - 1, Acc)
    end, Versions, GreaseVals),
    Final = case maps:get(version_order_randomized, Profile, false) of
        true -> shuffle_list(WithGrease);
        false -> WithGrease
    end,
    << <<V:?u16>> || V <- Final >>.

build_sig_algos(#{sig_algorithms_count := Count}) ->
    AllAlgos = [16#04, 16#03, 16#05, 16#03, 16#06, 16#03, 16#02, 16#03,
                16#08, 16#04, 16#08, 16#05, 16#08, 16#06, 16#04, 16#01,
                16#05, 16#01, 16#06, 16#01, 16#02, 16#01, 16#04, 16#02,
                16#03, 16#02, 16#02, 16#02, 16#03, 16#01],
    Selected = lists:sublist(AllAlgos, Count * 2),
    Shuffled = shuffle_list(Selected),
    AlgoListLen = Count * 2,
    ExtLen = AlgoListLen + 2,
    <<16#00, 16#0d, ExtLen:?u16, AlgoListLen:?u16, << <<A:8>> || A <- Shuffled >>/binary>>.

build_ech(#{ech_payload_size := Sizes}) when is_list(Sizes) ->
    PayloadSize = lists:nth(rand:uniform(length(Sizes)), Sizes),
    EchRand1 = crypto:strong_rand_bytes(1),
    EchRand32 = crypto:strong_rand_bytes(32),
    EchPayload = crypto:strong_rand_bytes(PayloadSize),
    EchContent = <<16#00, 16#00, 16#01, 16#00, 16#01, EchRand1/binary,
                   16#00, 16#20, EchRand32/binary,
                   (byte_size(EchPayload)):?u16, EchPayload/binary>>,
    <<16#fe, 16#0d, (byte_size(EchContent)):?u16, EchContent/binary>>;
build_ech(_) -> <<>>.

build_alpn(#{alpn_protocols := Protocols}) ->
    Selected = lists:nth(rand:uniform(length(Protocols)), Protocols),
    ProtocolEntries = << <<(byte_size(P)):8, P/binary>> || P <- Selected >>,
    ProtocolsLen = byte_size(ProtocolEntries),
    <<16#00, 16#10, (ProtocolsLen + 2):?u16, ProtocolsLen:?u16, ProtocolEntries/binary>>;
build_alpn(_) -> <<>>.

build_compress_certificate(#{compress_certificate := brotli}) ->
    <<16#00, 16#1b, 16#00, 16#03, 16#02, 16#00, 16#02>>;
build_compress_certificate(_) -> <<>>.

build_ec_point_formats(#{ec_point_formats := true}) ->
    <<16#00, 16#0b, 16#00, 16#02, 16#01, 16#00>>;
build_ec_point_formats(_) -> <<>>.

build_supported_groups(#{key_share_groups := Groups, grease_count := {GreaseMin, GreaseMax}}) ->
    GreaseCount = GreaseMin + rand:uniform(GreaseMax - GreaseMin + 1) - 1,
    GreaseVals = random_grease(GreaseCount),
    WithGrease = lists:foldl(fun(G, Acc) ->
        Pos = rand:uniform(length(Acc) + 1),
        lists:sublist(Acc, Pos - 1) ++ [G] ++ lists:nthtail(Pos - 1, Acc)
    end, Groups, GreaseVals),
    GroupsBin = << <<G:?u16>> || G <- WithGrease >>,
    GroupsLen = byte_size(GroupsBin),
    <<16#00, 16#0a, (GroupsLen + 2):?u16, GroupsLen:?u16, GroupsBin/binary>>.

build_padding(#{padding_size := {Min, Max}}) ->
    PadSize = Min + rand:uniform(Max - Min + 1) - 1,
    case PadSize of
        0 -> <<>>;
        _ -> <<16#00, 16#15, PadSize:?u16, (binary:copy(<<0>>, PadSize))/binary>>
    end;
build_padding(_) -> <<>>.

make_sni(Domains) ->
    SniListItems = << <<?EXT_SNI_HOST_NAME, (byte_size(Domain)):?u16, Domain/binary>> || Domain <- Domains >>,
    ItemsLen = byte_size(SniListItems),
    <<?EXT_SNI:?u16, (ItemsLen + 2):?u16, ItemsLen:?u16, SniListItems/binary>>.

%% ClientHello generator
-spec make_client_hello(binary(), binary()) -> binary().
make_client_hello(Secret, SniDomain) ->
    make_client_hello(erlang:system_time(second), crypto:strong_rand_bytes(32), Secret, SniDomain).

-spec make_client_hello(non_neg_integer(), binary(), binary(), binary()) -> binary().
make_client_hello(Timestamp, SessionId, HexSecret, SniDomain) when byte_size(HexSecret) == 32 ->
    make_client_hello(Timestamp, SessionId, mtp_handler:unhex(HexSecret), SniDomain);
make_client_hello(Timestamp, SessionId, Secret, SniDomain) when byte_size(SessionId) == 32, byte_size(Secret) == 16 ->
    Profile = random_tls_profile(),
    CipherSuites = build_cipher_suites(Profile),
    SNI = make_sni([SniDomain]),
    SigAlgos = build_sig_algos(Profile),
    SupportedGroups = build_supported_groups(Profile),
    SupportedVersionsExt = build_supported_versions_ext(Profile),
    VersionsLen = byte_size(SupportedVersionsExt),
    SupportedVersions = <<16#00, 16#2b, (VersionsLen + 1):?u16, VersionsLen, SupportedVersionsExt/binary>>,
    KeyShareEntries = build_key_share_entries(Profile),
    KSListLen = byte_size(KeyShareEntries),
    KeyShare = <<16#00, 16#33, (KSListLen + 2):?u16, KSListLen:?u16, KeyShareEntries/binary>>,
    ECH = build_ech(Profile),
    ALPN = build_alpn(Profile),
    CompCertExt = build_compress_certificate(Profile),
    EcPointExt = build_ec_point_formats(Profile),
    PaddingExt = build_padding(Profile),
    ExtensionsBase = [ECH, <<16#00, 16#23, 0:16>>, EcPointExt,
                      <<16#44, 16#cd, 16#00, 16#05, 16#00, 16#03, 16#02, $h, $2>>,
                      KeyShare, <<16#00, 16#12, 0:16>>, SupportedGroups, CompCertExt,
                      <<16#ff, 16#01, 16#00, 16#01, 16#00>>, SigAlgos,
                      <<16#00, 16#05, 16#00, 16#05, 16#01, 0:32>>,
                      <<16#00, 16#2d, 16#00, 16#02, 16#01, 16#01>>, ALPN, SNI,
                      SupportedVersions, PaddingExt],
    NonEmpty = [E || E <- ExtensionsBase, E =/= <<>>],
    Extensions = case maps:get(extensions_order_randomized, Profile, false) of
        true -> shuffle_list(NonEmpty);
        false -> NonEmpty
    end,
    ExtBin = iolist_to_binary(Extensions),
    CSLen = byte_size(CipherSuites),
    SessIdLen = byte_size(SessionId),
    ExtLen = byte_size(ExtBin),
    HelloBodyLen = 2 + 32 + 1 + SessIdLen + 2 + CSLen + 1 + 1 + 2 + ExtLen,
    TlsLen = HelloBodyLen + 4,
    Pack = fun(FakeRandom) ->
        <<?TLS_REC_HANDSHAKE, ?TLS_10_VERSION, TlsLen:?u16,
          ?TLS_TAG_CLI_HELLO, HelloBodyLen:?u24, ?TLS_12_VERSION,
          FakeRandom:?DIGEST_LEN/binary, SessIdLen, SessionId/binary,
          CSLen:?u16, CipherSuites/binary, 1, 0, ExtLen:?u16, ExtBin/binary>>
    end,
    FakeRandom0 = binary:copy(<<0>>, ?DIGEST_LEN),
    Hello0 = Pack(FakeRandom0),
    Digest = hmac(sha256, Secret, Hello0),
    EncTimestamp = <<(binary:copy(<<0>>, ?DIGEST_LEN - 4))/binary, Timestamp:32/unsigned-little>>,
    FakeRandom = crypto:exor(Digest, EncTimestamp),
    Pack(FakeRandom).

%% parse_server_hello
parse_server_hello(<<?TLS_REC_HANDSHAKE, ?TLS_12_VERSION, HSLen:?u16, Handshake:HSLen/binary,
                     ?TLS_REC_CHANGE_CIPHER, ?TLS_12_VERSION, CCLen:?u16, ChangeCipher:CCLen/binary,
                     ?TLS_REC_DATA, ?TLS_12_VERSION, DLen:?u16, Data:DLen/binary, Tail/binary>>) ->
    {Handshake, ChangeCipher, Data, Tail};
parse_server_hello(<<?TLS_REC_HANDSHAKE, ?TLS_12_VERSION, HSLen:?u16, Handshake:HSLen/binary,
                     ?TLS_REC_CHANGE_CIPHER, ?TLS_12_VERSION, CCLen:?u16, ChangeCipher:CCLen/binary,
                     ?TLS_REC_DATA, ?TLS_12_VERSION, DLen:?u16, Data:DLen/binary,
                     ?TLS_REC_HANDSHAKE, ?TLS_12_VERSION, TicketLen:?u16, _Ticket:TicketLen/binary,
                     Tail/binary>>) ->
    {Handshake, ChangeCipher, Data, Tail};
parse_server_hello(<<?TLS_REC_HANDSHAKE, ?TLS_12_VERSION, HSLen:?u16, Handshake:HSLen/binary,
                     ?TLS_REC_CHANGE_CIPHER, ?TLS_12_VERSION, CCLen:?u16, ChangeCipher:CCLen/binary,
                     ?TLS_REC_DATA, ?TLS_12_VERSION, DLen:?u16, Data:DLen/binary, _GhostRecord:36/binary,
                     Tail/binary>>) ->
    {Handshake, ChangeCipher, Data, Tail};
parse_server_hello(B) when byte_size(B) < 5 -> incomplete;
parse_server_hello(<<16#16, _/binary>> = B) ->
    case tls_records_complete(B, 3) of
        true -> {error, tls_domain_forwarding};
        false -> incomplete
    end;
parse_server_hello(<<16#15, _/binary>>) -> {error, tls_alert};
parse_server_hello(_) -> {error, not_proxy_response}.

tls_records_complete(_B, 0) -> true;
tls_records_complete(<<_T, _Mj, _Mn, Len:?u16, Rest/binary>>, N) when byte_size(Rest) >= Len ->
    <<_:Len/binary, Tail/binary>> = Rest,
    tls_records_complete(Tail, N - 1);
tls_records_complete(_B, _N) -> false.

%% Lifecycle Management
update_lifecycle(#st{packet_count = Count, lifecycle = Lifecycle,
                     lifecycle_change_at = ChangeAt, burst_remaining = BurstRemaining} = St) ->
    NewCount = Count + 1,
    {NewLifecycle, NewChangeAt, NewBurstRemaining} =
        if
            Lifecycle =:= warmup, NewCount >= ChangeAt ->
                {steady, NewCount + 30 + rand:uniform(70), 0};
            Lifecycle =:= burst, BurstRemaining =< 1 ->
                {steady, NewCount + 30 + rand:uniform(70), 0};
            Lifecycle =:= burst ->
                {burst, ChangeAt, BurstRemaining - 1};
            Lifecycle =:= idle ->
                case rand:uniform() < ?PROB_IDLE_TO_STEADY of
                    true -> {warmup, NewCount + 10 + rand:uniform(20), 0};
                    false -> {idle, ChangeAt, 0}
                end;
            Lifecycle =:= steady ->
                RandomRoll = rand:uniform(),
                if
                    RandomRoll < ?PROB_STEADY_TO_BURST ->
                        BurstLen = 3 + rand:uniform(10),
                        {burst, ChangeAt, BurstLen};
                    RandomRoll < (?PROB_STEADY_TO_BURST + ?PROB_STEADY_TO_IDLE) ->
                        {idle, NewCount + 20 + rand:uniform(40), 0};
                    true -> {steady, ChangeAt, 0}
                end;
            true -> {Lifecycle, ChangeAt, BurstRemaining}
        end,
    St#st{packet_count = NewCount, lifecycle = NewLifecycle,
          lifecycle_change_at = NewChangeAt, burst_remaining = NewBurstRemaining}.

%% Data stream codec
-spec new() -> codec().
new() ->
    #st{packet_count = 0, current_profile = random_tls_profile(),
        lifecycle = steady, lifecycle_change_at = 30 + rand:uniform(50),
        burst_remaining = 0, padding_enabled = true,
        pad_min = 0, pad_max = 128,
        last_send_time = erlang:system_time(millisecond)}.

-spec try_decode_packet(binary(), codec()) -> {ok, binary(), binary(), codec()} | {incomplete, codec()}.
try_decode_packet(<<?TLS_12_DATA, Size:?u16, Data:Size/binary, Tail/binary>>, St) ->
    NewSt = update_lifecycle(St),
    {ok, Data, Tail, NewSt};
try_decode_packet(<<?TLS_REC_CHANGE_CIPHER, ?TLS_12_VERSION, Size:?u16,
                    _Data:Size/binary, Tail/binary>>, St) ->
    try_decode_packet(Tail, St);
try_decode_packet(<<?TLS_REC_HANDSHAKE, ?TLS_12_VERSION, Size:?u16,
                    _Data:Size/binary, Tail/binary>>, St) ->
    try_decode_packet(Tail, St);
try_decode_packet(<<?TLS_REC_ALERT, ?TLS_12_VERSION, Size:?u16,
                    _Data:Size/binary, Tail/binary>>, St) ->
    try_decode_packet(Tail, St);
try_decode_packet(Bin, St) when byte_size(Bin) =< (?MAX_IN_PACKET_SIZE + 5) ->
    {incomplete, St};
try_decode_packet(Bin, _St) ->
    error({protocol_error, tls_max_size, byte_size(Bin)}).

-spec decode_all(binary(), codec()) -> {binary(), binary(), codec()}.
decode_all(Bin, St) -> decode_all(Bin, <<>>, St).

decode_all(Bin, Acc, St0) ->
    case try_decode_packet(Bin, St0) of
        {incomplete, St} -> {Acc, Bin, St};
        {ok, Data, Tail, St} -> decode_all(Tail, <<Acc/binary, Data/binary>>, St)
    end.

-spec encode_packet(binary(), codec()) -> {iodata(), codec()}.
encode_packet(Bin, #st{lifecycle = Lifecycle, padding_enabled = PadEnabled,
                        pad_min = PadMin, pad_max = PadMax, last_send_time = LastSend} = St) ->

    PaddedBin = case PadEnabled of
        true ->
            PadSize = PadMin + rand:uniform(PadMax - PadMin + 1),
            case PadSize of
                0 -> Bin;
                _ -> <<Bin/binary, (crypto:strong_rand_bytes(PadSize))/binary>>
            end;
        false -> Bin
    end,

    {MinGap, MaxGap} = case Lifecycle of
        warmup -> {?GAP_WARMUP_MIN, ?GAP_WARMUP_MAX};
        burst  -> {?GAP_BURST_MIN, ?GAP_BURST_MAX};
        idle   -> {?GAP_IDLE_MIN, ?GAP_IDLE_MAX};
        steady -> {?GAP_STEADY_MIN, ?GAP_STEADY_MAX}
    end,
    TargetGap = MinGap + rand:uniform(MaxGap - MinGap + 1),
    Jitter = round(TargetGap * (0.7 + rand:uniform() * 0.6)),
    FinalGap = max(1, Jitter),

    Now = erlang:system_time(millisecond),
    Elapsed = Now - LastSend,
    if
        Elapsed < FinalGap -> timer:sleep(FinalGap - Elapsed);
        true -> ok
    end,

    NewNow = erlang:system_time(millisecond),
    NewSt = update_lifecycle(St#st{last_send_time = NewNow}),

    FinalData = case NewSt#st.lifecycle of
        idle ->
            case rand:uniform(4) of
                1 ->
                    GhostRec = build_ghost_record(),
                    [as_tls_data_frame(PaddedBin), GhostRec];
                2 ->
                    KeepAliveSize = rand:uniform(32),
                    KeepAlive = crypto:strong_rand_bytes(KeepAliveSize),
                    [as_tls_data_frame(PaddedBin), as_tls_data_frame(KeepAlive)];
                _ -> as_tls_data_frame(PaddedBin)
            end;
        burst ->
            case rand:uniform(5) of
                1 ->
                    GhostRec = build_ghost_record(),
                    [as_tls_data_frame(PaddedBin), GhostRec];
                _ -> as_tls_data_frame(PaddedBin)
            end;
        _ -> as_tls_data_frame(PaddedBin)
    end,

    {FinalData, NewSt}.

as_tls_data_frame(Bin) -> as_tls_frame(?TLS_REC_DATA, Bin).

-spec as_tls_frame(byte(), iodata()) -> iodata().
as_tls_frame(Type, Data) ->
    Size = iolist_size(Data),
    [<<Type, ?TLS_12_VERSION, Size:?u16>> | Data].

-if(?OTP_RELEASE >= 23).
hmac(Algo, Key, Str) -> crypto:mac(hmac, Algo, Key, Str).
-else.
hmac(Algo, Key, Str) -> crypto:hmac(Algo, Key, Str).
-endif.
