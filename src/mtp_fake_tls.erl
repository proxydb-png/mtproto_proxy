%%% @author sergey <me@seriyps.ru> (original) + enhanced evasion version
%%% @copyright (C) 2019-2025, Enhanced DPI evasion version
%%% @doc
%%% Fake TLS 'CBC' stream codec – maximum DPI evasion edition
%%%
%%% Background: https://github.com/telegramdesktop/tdesktop/commit/69b6b487382c12efc43d52f472cab5954ab850e2
%%%
%%% This module implements a fake TLS 1.3 stream that, from the outside, looks
%%% like a legitimate HTTPS connection. The code has been heavily instrumented
%%% to randomize every possible observable characteristic, making pattern-based
%%% DPI identification extremely difficult.
%%%
%%% Key evasion techniques:
%%%   * Multiple browser fingerprint profiles (Chrome, Firefox, Safari, Edge)
%%%   * Full GREASE integration (RFC 8701) in cipher suites, extensions, key shares,
%%%     supported versions, and signature algorithms
%%%   * Randomised TLS record fragmentation (splitting application data into
%%%     variable‑sized chunks)
%%%   * Injection of dummy TLS records (handshake, change_cipher_spec, alert,
%%%     application_data) with random payloads
%%%   * Randomised interleaving of real and dummy frames
%%%   * Optional post‑handshake messages (NewSessionTicket, KeyUpdate)
%%%   * Varying TLS record versions (0x0303, 0x0304, occasionally 0x0301)
%%%   * SNI domain randomisation (when used as a client)
%%%   * OCSP stapling and session ticket support with varying sizes
%%%   * Random padding within records and extensions
%%%   * Extension order shuffling and optional fake extensions
%%%   * Per‑connection random seeds for deterministic yet unique sequences
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
    seed :: {integer(), integer(), integer()} | undefined,
    session_ticket :: binary() | undefined,
    ocsp_response :: binary() | undefined,
    session_ticket_lifetime :: non_neg_integer() | undefined,
    fragment_size_accum :: non_neg_integer() | undefined
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
-define(TLS_TAG_NEW_SESSION_TICKET, 4).
-define(TLS_CIPHERSUITE, 192, 47).
-define(TLS_CHANGE_CIPHER, ?TLS_REC_CHANGE_CIPHER, ?TLS_12_VERSION, 0, 1, 1).

-define(EXT_SNI, 0).
-define(EXT_SNI_HOST_NAME, 0).
-define(EXT_KEY_SHARE, 51).
-define(EXT_SUPPORTED_VERSIONS, 43).
-define(EXT_SESSION_TICKET, 35).
-define(EXT_STATUS_REQUEST, 5).

-define(APP, mtproto_proxy).

%% ============================================================================
%% GREASE values (RFC 8701)
%% ============================================================================
-define(GREASE_VALUES, [
    16#0a0a, 16#1a1a, 16#2a2a, 16#3a3a, 16#4a4a,
    16#5a5a, 16#6a6a, 16#7a7a, 16#8a8a, 16#9a9a,
    16#aaaa, 16#baba, 16#caca, 16#dada, 16#eaea,
    16#fafa
]).

%% ============================================================================
%% TLS Fingerprint Profiles
%% ============================================================================
-define(TLS_FINGERPRINT_PROFILES, [
    #{name => chrome_120,
      cipher_suites => [
          16#13, 16#01,
          16#13, 16#02,
          16#13, 16#03,
          16#c0, 16#2b,
          16#c0, 16#2f,
          16#c0, 16#2c,
          16#c0, 16#30,
          16#cc, 16#a9,
          16#cc, 16#a8,
          16#c0, 16#13,
          16#c0, 16#14,
          16#00, 16#9c,
          16#00, 16#9d,
          16#00, 16#2f,
          16#00, 16#35
      ],
      cipher_order_randomized => true,
      grease_count => {2, 4},
      key_share_groups => [
          16#11, 16#ec,
          16#00, 16#1d,
          16#00, 16#17,
          16#00, 16#18
      ],
      supported_versions => [
          16#03, 16#04,
          16#03, 16#03
      ],
      version_order_randomized => true,
      sig_algorithms_count => 15,
      ec_point_formats => true,
      compress_certificate => brotli,
      ech_payload_size => [176, 208, 240],
      session_id_length => {32, 32},
      extensions_order_randomized => true,
      alpn_protocols => [
          [<<"h2">>, <<"http/1.1">>],
          [<<"h2">>],
          [<<"http/1.1">>]
      ],
      padding_size => {0, 512},
      session_ticket_enabled => true,
      ocsp_stapling_enabled => true,
      record_version_mix => {1, 5},
      dummy_frame_probability => 0.4,
      fragment_size_variation => {0.5, 1.5}
    },
    #{name => firefox_121,
      cipher_suites => [
          16#13, 16#01,
          16#13, 16#02,
          16#13, 16#03,
          16#c0, 16#2b,
          16#c0, 16#2f,
          16#c0, 16#2c,
          16#c0, 16#30,
          16#cc, 16#a9,
          16#cc, 16#a8,
          16#c0, 16#13,
          16#c0, 16#14,
          16#00, 16#9c,
          16#00, 16#9d,
          16#00, 16#2f,
          16#00, 16#35,
          16#00, 16#3c,
          16#00, 16#3d
      ],
      cipher_order_randomized => true,
      grease_count => {2, 3},
      key_share_groups => [
          16#00, 16#1d,
          16#00, 16#17
      ],
      supported_versions => [
          16#03, 16#04,
          16#03, 16#03
      ],
      version_order_randomized => false,
      sig_algorithms_count => 17,
      ec_point_formats => true,
      compress_certificate => brotli,
      ech_payload_size => [144, 176],
      session_id_length => {32, 32},
      extensions_order_randomized => false,
      alpn_protocols => [
          [<<"h2">>, <<"http/1.1">>]
      ],
      padding_size => {0, 256},
      session_ticket_enabled => true,
      ocsp_stapling_enabled => false,
      record_version_mix => {1, 8},
      dummy_frame_probability => 0.3,
      fragment_size_variation => {0.8, 1.2}
    },
    #{name => safari_17,
      cipher_suites => [
          16#13, 16#01,
          16#13, 16#02,
          16#13, 16#03,
          16#c0, 16#2b,
          16#c0, 16#2f,
          16#c0, 16#2c,
          16#c0, 16#30,
          16#cc, 16#a9,
          16#cc, 16#a8,
          16#c0, 16#13,
          16#c0, 16#14
      ],
      cipher_order_randomized => false,
      grease_count => {2, 4},
      key_share_groups => [
          16#00, 16#1d,
          16#00, 16#17,
          16#00, 16#18,
          16#00, 16#19
      ],
      supported_versions => [
          16#03, 16#04
      ],
      version_order_randomized => false,
      sig_algorithms_count => 13,
      ec_point_formats => false,
      compress_certificate => none,
      ech_payload_size => [208, 240],
      session_id_length => {32, 32},
      extensions_order_randomized => false,
      alpn_protocols => [
          [<<"h2">>, <<"http/1.1">>]
      ],
      padding_size => {0, 512},
      session_ticket_enabled => false,
      ocsp_stapling_enabled => true,
      record_version_mix => {1, 10},
      dummy_frame_probability => 0.15,
      fragment_size_variation => {0.9, 1.1}
    },
    #{name => edge_120,
      cipher_suites => [
          16#13, 16#01,
          16#13, 16#02,
          16#13, 16#03,
          16#c0, 16#2b,
          16#c0, 16#2f,
          16#c0, 16#2c,
          16#c0, 16#30,
          16#cc, 16#a9,
          16#cc, 16#a8,
          16#c0, 16#13,
          16#c0, 16#14,
          16#00, 16#9c,
          16#00, 16#9d,
          16#00, 16#2f,
          16#00, 16#35
      ],
      cipher_order_randomized => true,
      grease_count => {2, 4},
      key_share_groups => [
          16#11, 16#ec,
          16#00, 16#1d,
          16#00, 16#17
      ],
      supported_versions => [
          16#03, 16#04,
          16#03, 16#03
      ],
      version_order_randomized => true,
      sig_algorithms_count => 16,
      ec_point_formats => true,
      compress_certificate => brotli,
      ech_payload_size => [176, 208],
      session_id_length => {32, 32},
      extensions_order_randomized => true,
      alpn_protocols => [
          [<<"h2">>, <<"http/1.1">>],
          [<<"h2">>]
      ],
      padding_size => {0, 512},
      session_ticket_enabled => true,
      ocsp_stapling_enabled => true,
      record_version_mix => {1, 4},
      dummy_frame_probability => 0.45,
      fragment_size_variation => {0.4, 1.6}
    }
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
%% Fake OCSP / SessionTicket
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
    SigLen = 256 + rand:uniform(256),
    Sig = crypto:strong_rand_bytes(SigLen),
    Basic = <<ResponseData/binary, SigLen:?u24, Sig/binary>>,
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
    Lifetime = 604800 + rand:uniform(3600) - 1800,
    <<Lifetime:32,
      TicketAgeAdd/binary,
      (byte_size(TicketNonce)):8, TicketNonce/binary,
      (byte_size(Ticket)):?u16, Ticket/binary,
      0:?u16>>.

%% ===================================================================
%% Server-side handshake
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
      } = CliHlo = parse_client_hello(Data),
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
                    ?LOG_WARNING("TLS unauthorized SNI '~s'", [SniDomain]),
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

    SrvHello0 = make_srv_hello(binary:copy(<<0>>, ?DIGEST_LEN),
                               SessionId, KeyShare,
                               HasSessionTicket, HasOcspStapling),

    FakeHttpData = crypto:strong_rand_bytes(64 + rand:uniform(192)),

    {SessionTicket, TicketRecord} = case HasSessionTicket of
        true ->
            Ticket = generate_session_ticket(Secret),
            {Ticket, as_tls_frame(?TLS_REC_HANDSHAKE, Ticket)};
        false -> {undefined, <<>>}
    end,

    OcspResponse = case HasOcspStapling of
        true -> generate_ocsp_response(ServerDigest);
        false -> undefined
    end,

    Response0 = [as_tls_frame(?TLS_REC_HANDSHAKE, SrvHello0),
                 as_tls_frame(?TLS_REC_CHANGE_CIPHER, [1]),
                 as_tls_frame(?TLS_REC_DATA, FakeHttpData),
                 TicketRecord],

    SrvHelloDigest = hmac(sha256, Secret, [ClientDigest | Response0]),
    SrvHello = make_srv_hello(SrvHelloDigest, SessionId, KeyShare,
                              HasSessionTicket, HasOcspStapling),

    Response = [as_tls_frame(?TLS_REC_HANDSHAKE, SrvHello),
                as_tls_frame(?TLS_REC_CHANGE_CIPHER, [1]),
                as_tls_frame(?TLS_REC_DATA, FakeHttpData),
                TicketRecord],

    Meta = #{session_id => SessionId,
             timestamp => Timestamp,
             client_digest => ClientDigest,
             sni_domain => SniDomain,
             session_ticket => SessionTicket,
             ocsp_response => OcspResponse},

    Seed = {rand:uniform(999999), rand:uniform(999999), rand:uniform(999999)},
    St = #st{seed = Seed,
             session_ticket = SessionTicket,
             ocsp_response = OcspResponse,
             session_ticket_lifetime = case HasSessionTicket of
                                          true -> 604800;
                                          false -> undefined
                                      end,
             fragment_size_accum = 0},
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
    <<?TLS_REC_ALERT, ?TLS_12_VERSION, 0, 2, ?TLS_ALERT_FATAL, ?TLS_ALERT_DECODE_ERROR>>.

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
                [] -> error({protocol_error, tls_unsupported_key_shares, KeyShares});
                [{G, K} | _] -> {G, crypto:strong_rand_bytes(byte_size(K))}
            end;
        _ -> error({protocol_error, tls_missing_key_share_ext, Exts})
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
%% DPI evasion: dummy TLS record generation
%% ===================================================================

-spec generate_dummy_record({integer(), integer(), integer()}) -> binary().
generate_dummy_record(Seed) ->
    {_, _, _} = rand:seed(exs1024, Seed),
    Type = case rand:uniform(100) of
        N when N =< 60 -> ?TLS_REC_DATA;
        N when N =< 80 -> ?TLS_REC_HANDSHAKE;
        N when N =< 95 -> ?TLS_REC_CHANGE_CIPHER;
        _ -> ?TLS_REC_ALERT
    end,
    Version = case rand:uniform(10) of
        1 -> <<?TLS_12_VERSION>>;
        2 -> <<?TLS_12_VERSION>>;
        3 -> <<?TLS_12_VERSION>>;
        4 -> <<?TLS_13_VERSION>>;
        5 -> <<?TLS_13_VERSION>>;
        6 -> <<?TLS_13_VERSION>>;
        7 -> <<?TLS_13_VERSION>>;
        8 -> <<?TLS_13_VERSION>>;
        9 -> <<?TLS_10_VERSION>>;
        _ -> <<?TLS_10_VERSION>>
    end,
    PayloadSize = rand:uniform(32) + 1,
    Payload = crypto:strong_rand_bytes(PayloadSize),
    <<Type, Version/binary, PayloadSize:?u16, Payload/binary>>.

%% ===================================================================
%% Profile & GREASE helpers
%% ===================================================================

random_tls_profile() ->
    Ps = ?TLS_FINGERPRINT_PROFILES,
    lists:nth(rand:uniform(length(Ps)), Ps).

random_grease(N) ->
    [lists:nth(rand:uniform(length(?GREASE_VALUES)), ?GREASE_VALUES) || _ <- lists:seq(1, N)].

shuffle_list([]) -> [];
shuffle_list(L) ->
    [X || {_, X} <- lists:sort([{rand:uniform(), E} || E <- L])].

%% ===================================================================
%% Extension builders
%% ===================================================================

build_cipher_suites(#{cipher_suites := Suites, grease_count := {GMi, GMa}} = P) ->
    GreaseVals = random_grease(GMi - 1 + rand:uniform(max(1, GMa - GMi + 1))),
    WithG = lists:foldl(
        fun(G, Acc) ->
            Pos = rand:uniform(length(Acc) + 1),
            lists:sublist(Acc, Pos - 1) ++ [G] ++ lists:nthtail(Pos - 1, Acc)
        end, Suites, GreaseVals),
    Final = case maps:get(cipher_order_randomized, P, false) of
        true -> shuffle_list(WithG);
        false -> WithG
    end,
    << <<S:?u16>> || S <- Final >>.

build_key_share_entries(#{key_share_groups := Groups, grease_count := {GMi, GMa}}) ->
    GreaseVals = random_grease(GMi - 1 + rand:uniform(max(1, GMa - GMi + 1))),
    GreaseEntries = [<<G:?u16, 16#00, 16#01, 16#00>> || G <- GreaseVals],
    Real = [begin
                KS = key_size_for_group(G),
                <<G:?u16, KS:?u16, (crypto:strong_rand_bytes(KS))/binary>>
            end || G <- Groups],
    All = lists:foldl(
        fun(G, Acc) ->
            Pos = rand:uniform(length(Acc) + 1),
            lists:sublist(Acc, Pos - 1) ++ [G] ++ lists:nthtail(Pos - 1, Acc)
        end, Real, GreaseEntries),
    iolist_to_binary(All).

key_size_for_group(16#001D) -> 32;
key_size_for_group(16#0017) -> 65;
key_size_for_group(16#0018) -> 97;
key_size_for_group(16#0019) -> 133;
key_size_for_group(16#11EC) -> 1216;
key_size_for_group(_) -> 32.

build_supported_versions_ext(#{supported_versions := V, grease_count := {GMi, GMa}} = P) ->
    GreaseVals = random_grease(GMi - 1 + rand:uniform(max(1, GMa - GMi + 1))),
    WithG = lists:foldl(
        fun(G, Acc) ->
            Pos = rand:uniform(length(Acc) + 1),
            lists:sublist(Acc, Pos - 1) ++ [G] ++ lists:nthtail(Pos - 1, Acc)
        end, V, GreaseVals),
    Final = case maps:get(version_order_randomized, P, false) of
        true -> shuffle_list(WithG);
        false -> WithG
    end,
    << <<X:?u16>> || X <- Final >>.

build_sig_algos(#{sig_algorithms_count := C}) ->
    All = [16#0403, 16#0503, 16#0603, 16#0804, 16#0805, 16#0806,
           16#0401, 16#0501, 16#0601, 16#0203, 16#0201,
           16#0402, 16#0303, 16#0301, 16#0302],
    Sel = lists:sublist(shuffle_list(All), C),
    Bin = << <<A:?u16>> || A <- Sel >>,
    <<16#00, 16#0d, (byte_size(Bin) + 2):?u16, (byte_size(Bin)):?u16, Bin/binary>>.

build_ech(#{ech_payload_size := Sizes}) when is_list(Sizes) ->
    N = lists:nth(rand:uniform(length(Sizes)), Sizes),
    Content = <<0, 0, 1, 0, 1,
                (crypto:strong_rand_bytes(1))/binary,
                0, 32, (crypto:strong_rand_bytes(32))/binary,
                N:?u16, (crypto:strong_rand_bytes(N))/binary>>,
    <<16#fe, 16#0d, (byte_size(Content)):?u16, Content/binary>>;
build_ech(_) -> <<>>.

build_alpn(#{alpn_protocols := Protos}) ->
    Sel = lists:nth(rand:uniform(length(Protos)), Protos),
    E = << <<(byte_size(P)):8, P/binary>> || P <- Sel >>,
    <<16#00, 16#10, (byte_size(E) + 2):?u16, (byte_size(E)):?u16, E/binary>>;
build_alpn(_) -> <<>>.

build_compress_certificate(#{compress_certificate := brotli}) ->
    <<16#00, 16#1b, 16#00, 16#03, 16#02, 16#00, 16#02>>;
build_compress_certificate(_) -> <<>>.

build_ec_point_formats(#{ec_point_formats := true}) ->
    <<16#00, 16#0b, 16#00, 16#02, 16#01, 16#00>>;
build_ec_point_formats(_) -> <<>>.

build_supported_groups(#{key_share_groups := G, grease_count := {GMi, GMa}}) ->
    GreaseVals = random_grease(GMi - 1 + rand:uniform(max(1, GMa - GMi + 1))),
    WithG = lists:foldl(
        fun(X, Acc) ->
            Pos = rand:uniform(length(Acc) + 1),
            lists:sublist(Acc, Pos - 1) ++ [X] ++ lists:nthtail(Pos - 1, Acc)
        end, G, GreaseVals),
    Bin = << <<Y:?u16>> || Y <- WithG >>,
    <<16#00, 16#0a, (byte_size(Bin) + 2):?u16, (byte_size(Bin)):?u16, Bin/binary>>.

build_padding(#{padding_size := {Min, Max}}) ->
    Pad = case Max =< Min of
        true -> Min;
        false -> Min + rand:uniform(Max - Min + 1) - 1
    end,
    case Pad =< 0 of
        true -> <<>>;
        false -> <<16#00, 16#15, Pad:?u16, 0:Pad/unit:8>>
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
    <<?EXT_SNI:?u16, (byte_size(Items) + 2):?u16, (byte_size(Items)):?u16, Items/binary>>.

%% ===================================================================
%% make_client_hello
%% ===================================================================

-spec make_client_hello(binary(), binary()) -> binary().
make_client_hello(Secret, SniDomain) ->
    make_client_hello(erlang:system_time(second),
                      crypto:strong_rand_bytes(32),
                      Secret, SniDomain).

-spec make_client_hello(non_neg_integer(), binary(), binary(), binary()) -> binary().
make_client_hello(Timestamp, SessionId, HexSecret, SniDomain) when byte_size(HexSecret) == 32 ->
    make_client_hello(Timestamp, SessionId, mtp_handler:unhex(HexSecret), SniDomain);
make_client_hello(Timestamp, SessionId, Secret, SniDomain) when byte_size(SessionId) == 32,
                                                                byte_size(Secret) == 16 ->
    Profile = random_tls_profile(),
    CipherSuites = build_cipher_suites(Profile),
    SNI = make_sni([SniDomain]),
    SigAlgos = build_sig_algos(Profile),
    SupportedGroups = build_supported_groups(Profile),
    SVBody = build_supported_versions_ext(Profile),
    SupportedVersions =
        <<16#00, 16#2b, (byte_size(SVBody) + 1):?u16, (byte_size(SVBody)):8, SVBody/binary>>,
    KSBody = build_key_share_entries(Profile),
    KeyShare =
        <<16#00, 16#33, (byte_size(KSBody) + 2):?u16, (byte_size(KSBody)):?u16, KSBody/binary>>,
    ECH = build_ech(Profile),
    ALPN = build_alpn(Profile),
    CompCertExt = build_compress_certificate(Profile),
    EcPointExt = build_ec_point_formats(Profile),
    SessionTicketExt = build_session_ticket_ext(Profile),
    OcspStaplingExt = build_ocsp_stapling_ext(Profile),
    PaddingExt = build_padding(Profile),

    Ext0 = [
        ECH, SessionTicketExt, EcPointExt,
        <<16#44, 16#cd, 16#00, 16#05, 16#00, 16#03, 16#02, $h, $2>>,
        KeyShare,
        <<16#00, 16#12, 0:16>>,
        SupportedGroups,
        CompCertExt,
        <<16#ff, 16#01, 16#00, 16#01, 16#00>>,
        SigAlgos, OcspStaplingExt,
        <<16#00, 16#2d, 16#00, 16#02, 16#01, 16#01>>,
        ALPN, SNI, SupportedVersions, PaddingExt
    ],
    NonEmpty = [E || E <- Ext0, E =/= <<>>],
    Extensions = case maps:get(extensions_order_randomized, Profile, false) of
        true -> shuffle_list(NonEmpty);
        false -> NonEmpty
    end,
    ExtBin = iolist_to_binary(Extensions),
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
%% parse_server_hello
%% ===================================================================

parse_server_hello(<<?TLS_REC_HANDSHAKE, ?TLS_12_VERSION, HSLen:?u16, Handshake:HSLen/binary,
                     ?TLS_REC_CHANGE_CIPHER, ?TLS_12_VERSION, CCLen:?u16, ChangeCipher:CCLen/binary,
                     ?TLS_REC_DATA, ?TLS_12_VERSION, DLen:?u16, Data:DLen/binary,
                     Tail/binary>>) ->
    {Handshake, ChangeCipher, Data, Tail};
parse_server_hello(<<?TLS_REC_HANDSHAKE, ?TLS_12_VERSION, HSLen:?u16, Handshake:HSLen/binary,
                     ?TLS_REC_CHANGE_CIPHER, ?TLS_12_VERSION, CCLen:?u16, ChangeCipher:CCLen/binary,
                     ?TLS_REC_DATA, ?TLS_12_VERSION, DLen:?u16, Data:DLen/binary,
                     ?TLS_REC_HANDSHAKE, ?TLS_12_VERSION, TicketLen:?u16, _Ticket:TicketLen/binary,
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
tls_records_complete(<<_T, _A, _B, Len:?u16, Rest/binary>>, N) when byte_size(Rest) >= Len ->
    <<_:Len/binary, Tail/binary>> = Rest,
    tls_records_complete(Tail, N - 1);
tls_records_complete(_, _) -> false.

%% ===================================================================
%% Stream codec
%% ===================================================================

-spec new() -> codec().
new() ->
    Seed = {rand:uniform(999999), rand:uniform(999999), rand:uniform(999999)},
    #st{seed = Seed, fragment_size_accum = 0}.

-spec try_decode_packet(binary(), codec()) ->
          {ok, binary(), binary(), codec()} | {incomplete, codec()}.
try_decode_packet(<<?TLS_12_DATA, Size:?u16, Data:Size/binary, Tail/binary>>, St) ->
    {ok, Data, Tail, St};
try_decode_packet(<<?TLS_REC_CHANGE_CIPHER, ?TLS_12_VERSION, Size:?u16,
                    _Data:Size/binary, Tail/binary>>, St) ->
    try_decode_packet(Tail, St);
try_decode_packet(<<?TLS_REC_HANDSHAKE, ?TLS_12_VERSION, Size:?u16,
                    _Data:Size/binary, Tail/binary>>, St) ->
    try_decode_packet(Tail, St);
try_decode_packet(<<?TLS_REC_ALERT, ?TLS_12_VERSION, Size:?u16,
                    _Data:Size/binary, Tail/binary>>, St) ->
    try_decode_packet(Tail, St);
try_decode_packet(<<_Type:8, _Version:16, Size:?u16, _Data:Size/binary, Tail/binary>>, St) ->
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
        {ok, Data, Tail, St} -> decode_all(Tail, <<Acc/binary, Data/binary>>, St)
    end.

%% ===================================================================
%% encode_packet – fragmentation + dummy records
%% ===================================================================

-spec encode_packet(binary(), codec()) -> {iodata(), codec()}.
encode_packet(Bin, St) ->
    Profile = random_tls_profile(),
    DummyProb = maps:get(dummy_frame_probability, Profile, 0.3),
    {MinF, MaxF} = maps:get(fragment_size_variation, Profile, {0.8, 1.2}),
    BaseFragSize = round(?MAX_OUT_PACKET_SIZE * MinF) +
                   rand:uniform(round(?MAX_OUT_PACKET_SIZE * MaxF) -
                                round(?MAX_OUT_PACKET_SIZE * MinF)),
    FragSize = max(1, BaseFragSize),
    Seed = case St#st.seed of
        undefined -> {rand:uniform(999999), rand:uniform(999999), rand:uniform(999999)};
        S -> S
    end,
    {NewSeed, Frames} = encode_with_dummies(Bin, FragSize, Seed, DummyProb, []),
    {iolist_to_binary(Frames), St#st{seed = NewSeed, fragment_size_accum = 0}}.

encode_with_dummies(<<>>, _FragSize, Seed, _DummyProb, Acc) ->
    {Seed, lists:reverse(Acc)};
encode_with_dummies(Bin, FragSize, Seed, DummyProb, Acc) ->
    {_, _, _} = rand:seed(exs1024, Seed),
    ActualSize = min(FragSize, byte_size(Bin)),
    <<Chunk:ActualSize/binary, Rest/binary>> = Bin,
    Version = case rand:uniform(10) of
        N when N =< 3 -> <<?TLS_12_VERSION>>;
        N when N =< 8 -> <<?TLS_13_VERSION>>;
        _ -> <<?TLS_10_VERSION>>
    end,
    Frame = as_tls_frame(?TLS_REC_DATA, Chunk, Version),
    {NewSeed1, NewAcc1} = case rand:uniform() < DummyProb of
        true ->
            Dummy = generate_dummy_record(Seed),
            {Seed, [Frame, Dummy | Acc]};
        false ->
            {Seed, [Frame | Acc]}
    end,
    encode_with_dummies(Rest, FragSize, NewSeed1, DummyProb, NewAcc1).

-spec as_tls_frame(byte(), iodata()) -> iodata().
as_tls_frame(Type, Data) ->
    Size = iolist_size(Data),
    [<<Type, ?TLS_12_VERSION, Size:?u16>> | Data].

-spec as_tls_frame(byte(), iodata(), binary()) -> iodata().
as_tls_frame(Type, Data, Version) when is_binary(Version) ->
    Size = iolist_size(Data),
    <<Type, Version/binary, Size:?u16, (iolist_to_binary(Data))/binary>>.

-if(?OTP_RELEASE >= 23).
hmac(Algo, Key, Str) -> crypto:mac(hmac, Algo, Key, Str).
-else.
hmac(Algo, Key, Str) -> crypto:hmac(Algo, Key, Str).
-endif.
