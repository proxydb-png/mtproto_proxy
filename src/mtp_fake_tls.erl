%%% @author sergey <me@seriyps.ru>
%%% @copyright (C) 2019, sergey
%%% @doc
%%% Fake TLS 'CBC' stream codec (DPI-hardened, wire-compatible)
%%% https://github.com/telegramdesktop/tdesktop/commit/69b6b487382c12efc43d52f472cab5954ab850e2
%%% Looks like TLS1.3 from outside. Not real TLS crypto.
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
         tls_alert/1,
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
          session_ticket :: binary() | undefined,
          ocsp_response :: binary() | undefined,
          session_ticket_lifetime :: non_neg_integer() | undefined,
          out_seq = 0 :: non_neg_integer()
         }).

-record(client_hello, {
          pseudorandom :: binary(),
          session_id :: binary(),
          cipher_suites :: [non_neg_integer()],
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
-define(TLS_ALERT_WARNING, 1).
-define(TLS_ALERT_CLOSE_NOTIFY, 0).
-define(TLS_ALERT_HANDSHAKE_FAILURE, 40).
-define(TLS_ALERT_DECODE_ERROR, 50).
-define(TLS_ALERT_UNRECOGNIZED_NAME, 112).

-define(TLS_12_DATA, ?TLS_REC_DATA, ?TLS_12_VERSION).

-define(DIGEST_POS, 11).
-define(DIGEST_LEN, 32).

-define(TLS_TAG_CLI_HELLO, 1).
-define(TLS_TAG_SRV_HELLO, 2).
-define(TLS_TAG_NEW_SESSION_TICKET, 4).

%% Wire-compatible constant used by original mtproto fake-tls
-define(TLS_CIPHERSUITE, 192, 47). %% 0xC02F

-define(EXT_SNI, 0).
-define(EXT_SNI_HOST_NAME, 0).
-define(EXT_STATUS_REQUEST, 5).
-define(EXT_SUPPORTED_GROUPS, 10).
-define(EXT_EC_POINT_FORMATS, 11).
-define(EXT_SIG_ALGS, 13).
-define(EXT_ALPN, 16).
-define(EXT_SESSION_TICKET, 35).
-define(EXT_SUPPORTED_VERSIONS, 43).
-define(EXT_PSK_MODES, 45).
-define(EXT_KEY_SHARE, 51).
-define(EXT_COMPRESS_CERT, 27).
-define(EXT_PADDING, 21).
-define(EXT_SCT, 18).
-define(EXT_RENEG, 16#ff01).
-define(EXT_ECH, 16#fe0d).

-define(GREASE_VALUES, [
    16#0a0a, 16#1a1a, 16#2a2a, 16#3a3a, 16#4a4a,
    16#5a5a, 16#6a6a, 16#7a7a, 16#8a8a, 16#9a9a,
    16#aaaa, 16#baba, 16#caca, 16#dada, 16#eaea,
    16#fafa
]).

-define(TLS_FINGERPRINT_PROFILES, [
    #{name => chrome_like,
      grease_count => {2, 4},
      cipher_order_randomized => true,
      version_order_randomized => true,
      extensions_order_randomized => true,
      key_share_groups => [16#11ec, 16#001d, 16#0017, 16#0018],
      supported_versions => [16#0304, 16#0303],
      sig_algorithms_count => 15,
      ec_point_formats => true,
      compress_certificate => brotli,
      ech_payload_size => [176, 208, 240],
      alpn_protocols => [[<<"h2">>, <<"http/1.1">>], [<<"h2">>]],
      padding_size => {64, 512},
      session_ticket_enabled => true,
      ocsp_stapling_enabled => true},
    #{name => firefox_like,
      grease_count => {2, 3},
      cipher_order_randomized => true,
      version_order_randomized => false,
      extensions_order_randomized => false,
      key_share_groups => [16#001d, 16#0017],
      supported_versions => [16#0304, 16#0303],
      sig_algorithms_count => 17,
      ec_point_formats => true,
      compress_certificate => brotli,
      ech_payload_size => [144, 176],
      alpn_protocols => [[<<"h2">>, <<"http/1.1">>]],
      padding_size => {0, 256},
      session_ticket_enabled => true,
      ocsp_stapling_enabled => false},
    #{name => safari_like,
      grease_count => {2, 4},
      cipher_order_randomized => false,
      version_order_randomized => false,
      extensions_order_randomized => false,
      key_share_groups => [16#001d, 16#0017, 16#0018, 16#0019],
      supported_versions => [16#0304],
      sig_algorithms_count => 13,
      ec_point_formats => false,
      compress_certificate => none,
      ech_payload_size => [208, 240],
      alpn_protocols => [[<<"h2">>, <<"http/1.1">>]],
      padding_size => {0, 512},
      session_ticket_enabled => false,
      ocsp_stapling_enabled => true},
    #{name => edge_like,
      grease_count => {2, 4},
      cipher_order_randomized => true,
      version_order_randomized => true,
      extensions_order_randomized => true,
      key_share_groups => [16#11ec, 16#001d, 16#0017],
      supported_versions => [16#0304, 16#0303],
      sig_algorithms_count => 16,
      ec_point_formats => true,
      compress_certificate => brotli,
      ech_payload_size => [176, 208],
      alpn_protocols => [[<<"h2">>, <<"http/1.1">>], [<<"h2">>]],
      padding_size => {32, 480},
      session_ticket_enabled => true,
      ocsp_stapling_enabled => true}
]).

-opaque codec() :: #st{}.
-type meta() :: #{session_id := binary(),
                  timestamp := non_neg_integer(),
                  client_digest := binary(),
                  sni_domain => binary(),
                  session_ticket => binary() | undefined,
                  ocsp_response => binary() | undefined}.

%% ===================================================================
%% Secret helpers
%% ===================================================================

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

%% ===================================================================
%% Domain allow-list
%% ===================================================================

-spec is_domain_allowed(binary(), [binary()]) -> boolean().
is_domain_allowed(_Domain, []) -> true;
is_domain_allowed(Domain, AllowedDomains) ->
    lists:any(fun(A) -> match_domain(Domain, A) end, AllowedDomains).

match_domain(Domain, <<"*.", Base/binary>>) ->
    Suffix = <<".", Base/binary>>,
    S = byte_size(Suffix),
    D = byte_size(Domain),
    D >= S andalso binary:part(Domain, {D, -S}) =:= Suffix;
match_domain(Domain, Allowed) ->
    Domain =:= Allowed.

%% ===================================================================
%% Fake OCSP / SessionTicket (metadata only; not injected into appdata stream)
%% ===================================================================

generate_ocsp_response(_ServerDigest) ->
    OcspStatus = 0,
    ResponderId = crypto:strong_rand_bytes(20),
    ProducedAt = erlang:system_time(seconds),
    ThisUpdate = ProducedAt,
    NextUpdate = ProducedAt + 604800,
    CertId = crypto:strong_rand_bytes(36),
    Single = <<CertId/binary, 0,
               (encode_generalized_time(ThisUpdate))/binary,
               (encode_generalized_time(NextUpdate))/binary>>,
    Responses = <<1:32, Single/binary>>,
    ResponseData = <<0, ResponderId/binary,
                     (encode_generalized_time(ProducedAt))/binary,
                     Responses/binary>>,
    Sig = crypto:strong_rand_bytes(256),
    Basic = <<ResponseData/binary, 1:24, Sig/binary>>,
    <<OcspStatus, (byte_size(Basic)):?u24, Basic/binary>>.

encode_generalized_time(Timestamp) ->
    {{Y, M, D}, {H, Mi, S}} =
        calendar:universal_time_to_local_time(
          calendar:gregorian_seconds_to_datetime(Timestamp + 62167219200)),
    list_to_binary(
      io_lib:format("~4..0w~2..0w~2..0w~2..0w~2..0w~2..0wZ",
                    [Y, M, D, H, Mi, S])).

generate_session_ticket(_Secret) ->
    TicketAgeAdd = crypto:strong_rand_bytes(4),
    TicketNonce = crypto:strong_rand_bytes(16 + rand:uniform(16)),
    Ticket = crypto:strong_rand_bytes(128 + rand:uniform(128)),
    Lifetime = 604800,
    <<Lifetime:32,
      TicketAgeAdd/binary,
      (byte_size(TicketNonce)):8, TicketNonce/binary,
      (byte_size(Ticket)):?u16, Ticket/binary,
      0:?u16>>.

%% ===================================================================
%% Server-side handshake
%% IMPORTANT: keep original record shape for client compatibility:
%%   ServerHello | CCS | single ApplicationData
%% Optional ticket only in meta / not as extra pre-stream noise by default.
%% ===================================================================

-spec from_client_hello(binary(), binary()) ->
          {ok, iodata(), meta(), codec()}.
from_client_hello(Data, Secret) ->
    from_client_hello(Data, Secret, []).

-spec from_client_hello(binary(), binary(), [binary()]) ->
          {ok, iodata(), meta(), codec()}.
from_client_hello(Data, Secret, AllowedDomains) ->
    #client_hello{
       pseudorandom = ClientDigest,
       session_id = SessionId,
       extensions = Extensions
      } = parse_client_hello(Data),

    ?LOG_DEBUG("TLS ClientHello parsed, exts=~p", [length(Extensions)]),

    SniDomain =
        case lists:keyfind(?EXT_SNI, 1, Extensions) of
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
                    ?LOG_WARNING("TLS unauthorized SNI '~s' allowed=~p",
                                 [SniDomain, AllowedDomains]),
                    error({protocol_error, tls_domain_not_allowed, SniDomain})
            end
    end,

    HasSessionTicket = lists:keymember(?EXT_SESSION_TICKET, 1, Extensions),
    HasOcspStapling = lists:keymember(?EXT_STATUS_REQUEST, 1, Extensions),

    ServerDigest = make_server_digest(Data, Secret),
    Xored = crypto:exor(ClientDigest, ServerDigest),
    <<Zeroes:(?DIGEST_LEN - 4)/binary, Timestamp:32/unsigned-little>> = Xored,
    case lists:all(fun(B) -> B =:= 0 end, binary_to_list(Zeroes)) of
        true -> ok;
        false -> error({protocol_error, tls_invalid_digest, Xored})
    end,

    KeyShare = make_key_share(Extensions),

    %% zero-digest first pass (same as original)
    SrvHello0 = make_srv_hello(binary:copy(<<0>>, ?DIGEST_LEN),
                               SessionId, KeyShare,
                               HasSessionTicket, HasOcspStapling),

    %% single fake appdata — size varied a bit for DPI, but ONLY ONE record
    FakeHttpData = crypto:strong_rand_bytes(64 + rand:uniform(192)),

    Response0 = [as_tls_frame(?TLS_REC_HANDSHAKE, SrvHello0),
                 as_tls_frame(?TLS_REC_CHANGE_CIPHER, [1]),
                 as_tls_frame(?TLS_REC_DATA, FakeHttpData)],

    SrvHelloDigest = hmac(sha256, Secret, [ClientDigest | Response0]),
    SrvHello = make_srv_hello(SrvHelloDigest, SessionId, KeyShare,
                              HasSessionTicket, HasOcspStapling),

    Response = [as_tls_frame(?TLS_REC_HANDSHAKE, SrvHello),
                as_tls_frame(?TLS_REC_CHANGE_CIPHER, [1]),
                as_tls_frame(?TLS_REC_DATA, FakeHttpData)],

    SessionTicket =
        case HasSessionTicket of
            true -> generate_session_ticket(Secret);
            false -> undefined
        end,
    OcspResponse =
        case HasOcspStapling of
            true -> generate_ocsp_response(ServerDigest);
            false -> undefined
        end,

    Meta = #{session_id => SessionId,
             timestamp => Timestamp,
             client_digest => ClientDigest,
             sni_domain => SniDomain,
             session_ticket => SessionTicket,
             ocsp_response => OcspResponse},

    St = #st{session_ticket = SessionTicket,
             ocsp_response = OcspResponse,
             session_ticket_lifetime =
                 case HasSessionTicket of
                     true -> 604800;
                     false -> undefined
                 end,
             out_seq = 0},
    {ok, Response, Meta, St}.

-spec parse_sni(binary()) -> {ok, binary()} | {error, no_sni | bad_hello}.
parse_sni(Data) ->
    try
        #client_hello{extensions = Exts} = parse_client_hello(Data),
        case lists:keyfind(?EXT_SNI, 1, Exts) of
            {_, [{?EXT_SNI_HOST_NAME, Domain}]} -> {ok, Domain};
            _ -> {error, no_sni}
        end
    catch
        error:{protocol_error, tls_bad_client_hello, _} ->
            {error, bad_hello}
    end.

-spec tls_decode_error_alert() -> binary().
tls_decode_error_alert() ->
    tls_alert(decode_error).

%% Helper for upper layer on protocol_error (optional use)
-spec tls_alert(atom()) -> binary().
tls_alert(unrecognized_name) ->
    <<?TLS_REC_ALERT, ?TLS_12_VERSION, 0, 2,
      ?TLS_ALERT_FATAL, ?TLS_ALERT_UNRECOGNIZED_NAME>>;
tls_alert(handshake_failure) ->
    <<?TLS_REC_ALERT, ?TLS_12_VERSION, 0, 2,
      ?TLS_ALERT_FATAL, ?TLS_ALERT_HANDSHAKE_FAILURE>>;
tls_alert(close_notify) ->
    <<?TLS_REC_ALERT, ?TLS_12_VERSION, 0, 2,
      ?TLS_ALERT_WARNING, ?TLS_ALERT_CLOSE_NOTIFY>>;
tls_alert(_) ->
    <<?TLS_REC_ALERT, ?TLS_12_VERSION, 0, 2,
      ?TLS_ALERT_FATAL, ?TLS_ALERT_DECODE_ERROR>>.

-spec derive_sni_secret(binary(), binary(), binary()) -> binary().
derive_sni_secret(BaseSecret, SniDomain, Salt) when byte_size(BaseSecret) == 16 ->
    SecretHex = mtp_handler:hex(BaseSecret),
    <<Derived:16/binary, _/binary>> =
        crypto:hash(sha256, [Salt, SecretHex, SniDomain]),
    Derived.

%% ===================================================================
%% ClientHello parser
%% ===================================================================

parse_client_hello(<<?TLS_REC_HANDSHAKE, ?TLS_10_VERSION, TlsFrameLen:?u16,
                     ?TLS_TAG_CLI_HELLO, HelloLen:?u24, ?TLS_12_VERSION,
                     Random:?DIGEST_LEN/binary,
                     SessIdLen, SessId:SessIdLen/binary,
                     CipherSuitesLen:?u16, CipherSuites:CipherSuitesLen/binary,
                     CompMethodsLen, CompMethods:CompMethodsLen/binary,
                     ExtensionsLen:?u16, Extensions:ExtensionsLen/binary>>)
  when TlsFrameLen >= 512, HelloLen >= 400 ->
    #client_hello{
       pseudorandom = Random,
       session_id = SessId,
       cipher_suites = [S || <<S:?u16>> <= CipherSuites],
       compression_methods = [CompMethods],
       extensions = parse_extensions(Extensions)
      };
parse_client_hello(_Data) ->
    error({protocol_error, tls_bad_client_hello, bad_client_hello}).

parse_extensions(Exts) ->
    [{Type, parse_extension(Type, Data)}
     || <<Type:?u16, Len:?u16, Data:Len/binary>> <= Exts].

parse_extension(?EXT_SNI, <<ListLen:?u16, List:ListLen/binary>>) ->
    [{Type, Value} || <<Type, L:?u16, Value:L/binary>> <= List];
parse_extension(?EXT_KEY_SHARE, <<Len:?u16, Body:Len/binary>>) ->
    [{Group, Key} || <<Group:?u16, KL:?u16, Key:KL/binary>> <= Body];
parse_extension(?EXT_SESSION_TICKET, _) ->
    {session_ticket, supported};
parse_extension(?EXT_STATUS_REQUEST, <<Type, _/binary>>) ->
    {ocsp_stapling, Type};
parse_extension(_, Data) ->
    Data.

make_server_digest(<<Left:?DIGEST_POS/binary, _:?DIGEST_LEN/binary, Right/binary>>, Secret) ->
    hmac(sha256, Secret, [Left, binary:copy(<<0>>, ?DIGEST_LEN), Right]).

make_key_share(Exts) ->
    case lists:keyfind(?EXT_KEY_SHARE, 1, Exts) of
        {_, KeyShares} ->
            Supported =
                lists:dropwhile(
                  fun({Group, Key}) ->
                          not (byte_size(Key) < 128 andalso
                               lists:member(Group, [16#0017, 16#0018, 16#0019,
                                                    16#001D, 16#001E,
                                                    16#0100, 16#0101, 16#0102,
                                                    16#0103, 16#0104]))
                  end, KeyShares),
            case Supported of
                [] ->
                    error({protocol_error, tls_unsupported_key_shares, KeyShares});
                [{G, K} | _] ->
                    {G, crypto:strong_rand_bytes(byte_size(K))}
            end;
        _ ->
            error({protocol_error, tls_missing_key_share_ext, Exts})
    end.

make_srv_hello(Digest, SessionId, {KSGroup, KSKey},
               HasSessionTicket, HasOcspStapling) ->
    KSEntity = <<KSGroup:?u16, (byte_size(KSKey)):?u16, KSKey/binary>>,
    Ext0 = [
        <<?EXT_KEY_SHARE:?u16, (byte_size(KSEntity)):?u16, KSEntity/binary>>,
        <<?EXT_SUPPORTED_VERSIONS:?u16, 2:?u16, ?TLS_13_VERSION>>
    ],
    Ext1 = case HasSessionTicket of
               true  -> Ext0 ++ [<<?EXT_SESSION_TICKET:?u16, 0:?u16>>];
               false -> Ext0
           end,
    Ext2 = case HasOcspStapling of
               true  -> Ext1 ++ [<<?EXT_STATUS_REQUEST:?u16, 0:?u16>>];
               false -> Ext1
           end,
    SessSize = byte_size(SessionId),
    Payload = [<<?TLS_12_VERSION,
                 Digest:?DIGEST_LEN/binary,
                 SessSize, SessionId:SessSize/binary,
                 ?TLS_CIPHERSUITE,
                 0,
                 (iolist_size(Ext2)):?u16>> | Ext2],
    [<<?TLS_TAG_SRV_HELLO, (iolist_size(Payload)):?u24>> | Payload].

%% ===================================================================
%% ClientHello builder (outbound) — safe place for heavy randomization
%% ===================================================================

random_tls_profile() ->
    Ps = ?TLS_FINGERPRINT_PROFILES,
    lists:nth(rand:uniform(length(Ps)), Ps).

random_grease(N) ->
    [lists:nth(rand:uniform(length(?GREASE_VALUES)), ?GREASE_VALUES)
     || _ <- lists:seq(1, N)].

shuffle_list([]) -> [];
shuffle_list(L) ->
    [X || {_, X} <- lists:sort([{rand:uniform(), E} || E <- L])].

inject_grease(List, []) -> List;
inject_grease(List, [G | Rest]) ->
    Pos = rand:uniform(length(List) + 1),
    New = lists:sublist(List, Pos - 1) ++ [G] ++ lists:nthtail(Pos - 1, List),
    inject_grease(New, Rest).

grease_n(#{grease_count := {Min, Max}}) ->
    Min - 1 + rand:uniform(max(1, Max - Min + 1)).

build_cipher_suites(Profile) ->
    %% Include original-friendly suites + modern ones
    Base = [
        16#1301, 16#1302, 16#1303,
        16#c02b, 16#c02f, 16#c02c, 16#c030,
        16#cca9, 16#cca8,
        16#c013, 16#c014,
        16#009c, 16#009d, 16#002f, 16#0035
    ],
    WithG = inject_grease(Base, random_grease(grease_n(Profile))),
    Final = case maps:get(cipher_order_randomized, Profile, false) of
                true -> shuffle_list(WithG);
                false -> WithG
            end,
    << <<S:?u16>> || S <- Final >>.

key_size_for_group(16#001D) -> 32;
key_size_for_group(16#0017) -> 65;
key_size_for_group(16#0018) -> 97;
key_size_for_group(16#0019) -> 133;
key_size_for_group(16#11EC) -> 1216;
key_size_for_group(_) -> 32.

build_key_share_entries(#{key_share_groups := Groups} = Profile) ->
    GreaseEntries = [<<G:?u16, 1:?u16, 0>> || G <- random_grease(grease_n(Profile))],
    Real = [begin
                KS = key_size_for_group(G),
                <<G:?u16, KS:?u16, (crypto:strong_rand_bytes(KS))/binary>>
            end || G <- Groups],
    iolist_to_binary(inject_grease(Real, GreaseEntries)).

build_supported_versions_ext(#{supported_versions := Vers} = Profile) ->
    WithG = inject_grease(Vers, random_grease(grease_n(Profile))),
    Final = case maps:get(version_order_randomized, Profile, false) of
                true -> shuffle_list(WithG);
                false -> WithG
            end,
    << <<V:?u16>> || V <- Final >>.

build_sig_algos(#{sig_algorithms_count := Count}) ->
    All = [16#0403, 16#0503, 16#0603, 16#0804, 16#0805, 16#0806,
           16#0401, 16#0501, 16#0601, 16#0203, 16#0201,
           16#0402, 16#0303, 16#0301, 16#0302],
    Selected = lists:sublist(shuffle_list(All), Count),
    Bin = << <<A:?u16>> || A <- Selected >>,
    <<?EXT_SIG_ALGS:?u16, (byte_size(Bin) + 2):?u16,
      (byte_size(Bin)):?u16, Bin/binary>>.

build_ech(#{ech_payload_size := Sizes}) when is_list(Sizes) ->
    N = lists:nth(rand:uniform(length(Sizes)), Sizes),
    Content = <<0, 0, 1, 0, 1,
                (crypto:strong_rand_bytes(1))/binary,
                0, 32, (crypto:strong_rand_bytes(32))/binary,
                N:?u16, (crypto:strong_rand_bytes(N))/binary>>,
    <<?EXT_ECH:?u16, (byte_size(Content)):?u16, Content/binary>>;
build_ech(_) -> <<>>.

build_alpn(#{alpn_protocols := Protos}) ->
    Selected = lists:nth(rand:uniform(length(Protos)), Protos),
    Entries = << <<(byte_size(P)):8, P/binary>> || P <- Selected >>,
    <<?EXT_ALPN:?u16, (byte_size(Entries) + 2):?u16,
      (byte_size(Entries)):?u16, Entries/binary>>;
build_alpn(_) -> <<>>.

build_compress_certificate(#{compress_certificate := brotli}) ->
    <<?EXT_COMPRESS_CERT:?u16, 3:?u16, 2, 0, 2>>;
build_compress_certificate(_) -> <<>>.

build_ec_point_formats(#{ec_point_formats := true}) ->
    <<?EXT_EC_POINT_FORMATS:?u16, 2:?u16, 1, 0>>;
build_ec_point_formats(_) -> <<>>.

build_supported_groups(#{key_share_groups := Groups} = Profile) ->
    WithG = inject_grease(Groups, random_grease(grease_n(Profile))),
    Bin = << <<G:?u16>> || G <- WithG >>,
    <<?EXT_SUPPORTED_GROUPS:?u16, (byte_size(Bin) + 2):?u16,
      (byte_size(Bin)):?u16, Bin/binary>>.

build_padding(#{padding_size := {Min, Max}}) ->
    %% uniform in [Min, Max]
    Pad = case Max =< Min of
              true -> Min;
              false -> Min + rand:uniform(Max - Min + 1) - 1
          end,
    case Pad =< 0 of
        true -> <<>>;
        false -> <<?EXT_PADDING:?u16, Pad:?u16, 0:Pad/unit:8>>
    end;
build_padding(_) -> <<>>.

build_session_ticket_ext(#{session_ticket_enabled := true}) ->
    <<?EXT_SESSION_TICKET:?u16, 0:?u16>>;
build_session_ticket_ext(_) -> <<>>.

build_ocsp_stapling_ext(#{ocsp_stapling_enabled := true}) ->
    <<?EXT_STATUS_REQUEST:?u16, 5:?u16, 1, 0, 0, 0, 0>>;
build_ocsp_stapling_ext(_) -> <<>>.

make_sni(Domains) ->
    Items = << <<?EXT_SNI_HOST_NAME, (byte_size(D)):?u16, D/binary>> || D <- Domains >>,
    <<?EXT_SNI:?u16, (byte_size(Items) + 2):?u16,
      (byte_size(Items)):?u16, Items/binary>>.

-spec make_client_hello(binary(), binary()) -> binary().
make_client_hello(Secret, SniDomain) ->
    make_client_hello(erlang:system_time(second),
                      crypto:strong_rand_bytes(32),
                      Secret, SniDomain).

-spec make_client_hello(non_neg_integer(), binary(), binary(), binary()) -> binary().
make_client_hello(Timestamp, SessionId, HexSecret, SniDomain)
  when byte_size(HexSecret) == 32 ->
    make_client_hello(Timestamp, SessionId, mtp_handler:unhex(HexSecret), SniDomain);
make_client_hello(Timestamp, SessionId, Secret, SniDomain)
  when byte_size(SessionId) == 32, byte_size(Secret) == 16 ->
    Profile = random_tls_profile(),
    CipherSuites = build_cipher_suites(Profile),
    SNI = make_sni([SniDomain]),
    SVBody = build_supported_versions_ext(Profile),
    SupportedVersions =
        <<?EXT_SUPPORTED_VERSIONS:?u16,
          (byte_size(SVBody) + 1):?u16,
          (byte_size(SVBody)):8, SVBody/binary>>,
    KSBody = build_key_share_entries(Profile),
    KeyShare =
        <<?EXT_KEY_SHARE:?u16,
          (byte_size(KSBody) + 2):?u16,
          (byte_size(KSBody)):?u16, KSBody/binary>>,
    Ext0 = [
        build_ech(Profile),
        build_session_ticket_ext(Profile),
        build_ec_point_formats(Profile),
        KeyShare,
        <<?EXT_SCT:?u16, 0:?u16>>,
        build_supported_groups(Profile),
        build_compress_certificate(Profile),
        <<?EXT_RENEG:?u16, 1:?u16, 0>>,
        build_sig_algos(Profile),
        build_ocsp_stapling_ext(Profile),
        <<?EXT_PSK_MODES:?u16, 2:?u16, 1, 1>>,
        build_alpn(Profile),
        SNI,
        SupportedVersions,
        build_padding(Profile)
    ],
    NonEmpty = [E || E <- Ext0, E =/= <<>>],
    Exts = case maps:get(extensions_order_randomized, Profile, false) of
               true -> shuffle_list(NonEmpty);
               false -> NonEmpty
           end,
    ExtBin = iolist_to_binary(Exts),
    CSLen = byte_size(CipherSuites),
    SessLen = byte_size(SessionId),
    ExtLen = byte_size(ExtBin),
    HelloBodyLen = 2 + 32 + 1 + SessLen + 2 + CSLen + 1 + 1 + 2 + ExtLen,
    TlsLen = HelloBodyLen + 4,
    Pack = fun(FakeRandom) ->
                   <<?TLS_REC_HANDSHAKE, ?TLS_10_VERSION, TlsLen:?u16,
                     ?TLS_TAG_CLI_HELLO, HelloBodyLen:?u24, ?TLS_12_VERSION,
                     FakeRandom:?DIGEST_LEN/binary,
                     SessLen, SessionId/binary,
                     CSLen:?u16, CipherSuites/binary,
                     1, 0,
                     ExtLen:?u16, ExtBin/binary>>
           end,
    Hello0 = Pack(binary:copy(<<0>>, ?DIGEST_LEN)),
    Digest = hmac(sha256, Secret, Hello0),
    EncTs = <<0:(?DIGEST_LEN - 4)/unit:8, Timestamp:32/unsigned-little>>,
    Pack(crypto:exor(Digest, EncTs)).

%% ===================================================================
%% parse_server_hello — original 3-record shape
%% ===================================================================

parse_server_hello(<<?TLS_REC_HANDSHAKE, ?TLS_12_VERSION, HSLen:?u16, Handshake:HSLen/binary,
                     ?TLS_REC_CHANGE_CIPHER, ?TLS_12_VERSION, CCLen:?u16, ChangeCipher:CCLen/binary,
                     ?TLS_REC_DATA, ?TLS_12_VERSION, DLen:?u16, Data:DLen/binary,
                     Tail/binary>>) ->
    {Handshake, ChangeCipher, Data, Tail};
parse_server_hello(B) when byte_size(B) < 5 ->
    incomplete;
parse_server_hello(<<16#16, _/binary>> = B) ->
    case tls_records_complete(B, 4) of
        true  -> {error, tls_domain_forwarding};
        false -> incomplete
    end;
parse_server_hello(<<16#15, _/binary>>) ->
    {error, tls_alert};
parse_server_hello(_) ->
    {error, not_proxy_response}.

tls_records_complete(_B, 0) -> true;
tls_records_complete(<<_T, _A, _B, Len:?u16, Rest/binary>>, N)
  when byte_size(Rest) >= Len ->
    <<_:Len/binary, Tail/binary>> = Rest,
    tls_records_complete(Tail, N - 1);
tls_records_complete(_, _) -> false.

%% ===================================================================
%% Stream codec — no payload mutation
%% ===================================================================

-spec new() -> codec().
new() -> #st{}.

-spec try_decode_packet(binary(), codec()) ->
          {ok, binary(), binary(), codec()} | {incomplete, codec()}.
try_decode_packet(<<?TLS_12_DATA, Size:?u16, Data:Size/binary, Tail/binary>>, St) ->
    {ok, Data, Tail, St};
try_decode_packet(<<?TLS_REC_CHANGE_CIPHER, ?TLS_12_VERSION, Size:?u16,
                    _Data:Size/binary, Tail/binary>>, St) ->
    try_decode_packet(Tail, St);
try_decode_packet(Bin, St) when byte_size(Bin) =< (?MAX_IN_PACKET_SIZE + 5) ->
    {incomplete, St};
try_decode_packet(Bin, _St) ->
    error({protocol_error, tls_max_size, byte_size(Bin)}).

-spec decode_all(binary(), codec()) -> {binary(), binary(), codec()}.
decode_all(Bin, St) ->
    decode_all(Bin, <<>>, St).

decode_all(Bin, Acc, St0) ->
    case try_decode_packet(Bin, St0) of
        {incomplete, St} -> {Acc, Bin, St};
        {ok, Data, Tail, St} ->
            decode_all(Tail, <<Acc/binary, Data/binary>>, St)
    end.

-spec encode_packet(binary(), codec()) -> {iodata(), codec()}.
encode_packet(Bin, #st{out_seq = Seq} = St) ->
    {encode_as_frames(Bin, Seq), St#st{out_seq = Seq + 1}}.

%% Vary frame sizes slightly (safe). Never alter bytes inside payload.
encode_as_frames(<<>>, _Seq) -> [];
encode_as_frames(Bin, Seq) when byte_size(Bin) =< ?MAX_OUT_PACKET_SIZE ->
    %% sometimes split small/medium to reduce fixed-size signature
    case byte_size(Bin) > 1200 andalso (Seq rem 3 =:= 0) of
        true ->
            Mid = 600 + rand:uniform(600),
            case Bin of
                <<A:Mid/binary, B/binary>> when byte_size(B) > 0 ->
                    [as_tls_data_frame(A), as_tls_data_frame(B)];
                _ ->
                    [as_tls_data_frame(Bin)]
            end;
        false ->
            [as_tls_data_frame(Bin)]
    end;
encode_as_frames(<<Chunk:?MAX_OUT_PACKET_SIZE/binary, Tail/binary>>, Seq) ->
    [as_tls_data_frame(Chunk) | encode_as_frames(Tail, Seq)].

as_tls_data_frame(Bin) ->
    as_tls_frame(?TLS_REC_DATA, Bin).

as_tls_frame(Type, Data) ->
    Size = iolist_size(Data),
    [<<Type, ?TLS_12_VERSION, Size:?u16>> | Data].

-if(?OTP_RELEASE >= 23).
hmac(Algo, Key, Str) -> crypto:mac(hmac, Algo, Key, Str).
-else.
hmac(Algo, Key, Str) -> crypto:hmac(Algo, Key, Str).
-endif.
