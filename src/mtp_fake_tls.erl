%%% @author sergey <me@seriyps.ru>
%%% @copyright (C) 2019, sergey
%%% @doc
%%% Fake TLS 'CBC' stream codec with:
%%% - Random TLS Fingerprint (6 browser profiles)
%%% - Domain Restriction with Wildcard Support
%%% - GREASE Randomization
%%% - Random Cipher Suites, Key Share, ECH, Signatures
%%% - Fake Session Ticket + OCSP Stapling
%%% - Random ALPN
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

-record(st, {}).

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
-define(TLS_TAG_SESSION_TICKET, 4).
-define(TLS_TAG_CERTIFICATE_STATUS, 22).
-define(TLS_CIPHERSUITE, 192, 47).
-define(TLS_CHANGE_CIPHER, ?TLS_REC_CHANGE_CIPHER, ?TLS_12_VERSION, 0, 1, 1).

-define(EXT_SNI, 0).
-define(EXT_SNI_HOST_NAME, 0).
-define(EXT_KEY_SHARE, 51).
-define(EXT_SUPPORTED_VERSIONS, 43).

-define(APP, mtproto_proxy).

%% ============================================================================
%% Random TLS Fingerprint Profiles (6 profiles)
%% ============================================================================

-define(TLS_FINGERPRINT_PROFILES, [
    #{name => chrome_120,
      cipher_suites => [
          16#ea, 16#ea, 16#13, 16#01, 16#13, 16#02, 16#13, 16#03,
          16#c0, 16#2b, 16#c0, 16#2f, 16#c0, 16#2c, 16#c0, 16#30,
          16#cc, 16#a9, 16#cc, 16#a8, 16#c0, 16#13, 16#c0, 16#14,
          16#00, 16#9c, 16#00, 16#9d, 16#00, 16#2f, 16#00, 16#35
      ],
      key_share_groups => [16#ea,16#ea, 16#11,16#ec, 16#00,16#1d, 16#00,16#17, 16#00,16#18],
      supported_versions => [16#ea,16#ea, 16#03,16#04, 16#03,16#03],
      sig_algorithms_count => 15,
      ec_point_formats => true,
      compress_certificate => brotli,
      ech_payload_size => 176,
      alpn_protocols => [<<"h2">>, <<"http/1.1">>]
    },
    #{name => firefox_121,
      cipher_suites => [
          16#ea,16#ea, 16#13,16#01, 16#13,16#02, 16#13,16#03,
          16#c0,16#2b, 16#c0,16#2f, 16#c0,16#2c, 16#c0,16#30,
          16#cc,16#a9, 16#cc,16#a8, 16#c0,16#13, 16#c0,16#14,
          16#00,16#9c, 16#00,16#9d, 16#00,16#2f, 16#00,16#35,
          16#00,16#3c, 16#00,16#3d
      ],
      key_share_groups => [16#ea,16#ea, 16#00,16#1d, 16#00,16#17],
      supported_versions => [16#ea,16#ea, 16#03,16#04, 16#03,16#03],
      sig_algorithms_count => 17,
      ec_point_formats => true,
      compress_certificate => brotli,
      ech_payload_size => 144,
      alpn_protocols => [<<"h2">>, <<"http/1.1">>, <<"http/1.0">>]
    },
    #{name => safari_17,
      cipher_suites => [
          16#ea,16#ea, 16#13,16#01, 16#13,16#02, 16#13,16#03,
          16#c0,16#2b, 16#c0,16#2f, 16#c0,16#2c, 16#c0,16#30,
          16#cc,16#a9, 16#cc,16#a8, 16#c0,16#13, 16#c0,16#14
      ],
      key_share_groups => [16#ea,16#ea, 16#00,16#1d, 16#00,16#17, 16#00,16#18, 16#00,16#19],
      supported_versions => [16#ea,16#ea, 16#03,16#04],
      sig_algorithms_count => 13,
      ec_point_formats => false,
      compress_certificate => none,
      ech_payload_size => 208,
      alpn_protocols => [<<"h2">>, <<"http/1.1">>]
    },
    #{name => edge_120,
      cipher_suites => [
          16#ea,16#ea, 16#13,16#01, 16#13,16#02, 16#13,16#03,
          16#c0,16#2b, 16#c0,16#2f, 16#c0,16#2c, 16#c0,16#30,
          16#cc,16#a9, 16#cc,16#a8, 16#c0,16#13, 16#c0,16#14,
          16#00,16#9c, 16#00,16#9d, 16#00,16#2f, 16#00,16#35
      ],
      key_share_groups => [16#ea,16#ea, 16#11,16#ec, 16#00,16#1d, 16#00,16#17],
      supported_versions => [16#ea,16#ea, 16#03,16#04, 16#03,16#03],
      sig_algorithms_count => 16,
      ec_point_formats => true,
      compress_certificate => brotli,
      ech_payload_size => 176,
      alpn_protocols => [<<"h2">>, <<"http/1.1">>]
    },
    #{name => ios_17,
      cipher_suites => [
          16#ea,16#ea, 16#13,16#01, 16#13,16#02, 16#13,16#03,
          16#c0,16#2b, 16#c0,16#2f, 16#c0,16#2c, 16#c0,16#30,
          16#cc,16#a9, 16#cc,16#a8, 16#c0,16#13, 16#c0,16#14,
          16#00,16#9c, 16#00,16#9d
      ],
      key_share_groups => [16#ea,16#ea, 16#11,16#ec, 16#00,16#1d, 16#00,16#17, 16#00,16#19],
      supported_versions => [16#ea,16#ea, 16#03,16#04, 16#03,16#03],
      sig_algorithms_count => 15,
      ec_point_formats => true,
      compress_certificate => brotli,
      ech_payload_size => 208,
      alpn_protocols => [<<"h2">>, <<"http/1.1">>]
    },
    #{name => brave_120,
      cipher_suites => [
          16#ea,16#ea, 16#13,16#01, 16#13,16#02, 16#13,16#03,
          16#c0,16#2b, 16#c0,16#2f, 16#c0,16#2c, 16#c0,16#30,
          16#cc,16#a9, 16#cc,16#a8, 16#c0,16#13, 16#c0,16#14,
          16#00,16#9c, 16#00,16#9d, 16#00,16#2f, 16#00,16#35, 16#00,16#ff
      ],
      key_share_groups => [16#ea,16#ea, 16#00,16#1d, 16#00,16#17, 16#00,16#18, 16#00,16#19],
      supported_versions => [16#ea,16#ea, 16#03,16#04, 16#03,16#03],
      sig_algorithms_count => 14,
      ec_point_formats => true,
      compress_certificate => brotli,
      ech_payload_size => 176,
      alpn_protocols => [<<"h2">>, <<"http/1.1">>]
    }
]).

-opaque codec() :: #st{}.

-type meta() :: #{session_id := binary(),
                  timestamp := non_neg_integer(),
                  client_digest := binary(),
                  sni_domain => binary()}.


%% ============================================================================
%% HELPERS
%% ============================================================================

grease_value() ->
    GreaseValues = [16#0A0A, 16#1A1A, 16#2A2A, 16#3A3A, 16#4A4A,
                    16#5A5A, 16#6A6A, 16#7A7A, 16#8A8A, 16#9A9A,
                    16#AAAA, 16#BABA, 16#CACA, 16#DADA, 16#EAEA, 16#FAFA],
    lists:nth(rand:uniform(length(GreaseValues)), GreaseValues).

is_grease(16#ea, 16#ea) -> true;
is_grease(A, B) -> lists:member([A, B], [
    [16#0A,16#0A],[16#1A,16#1A],[16#2A,16#2A],[16#3A,16#3A],
    [16#4A,16#4A],[16#5A,16#5A],[16#6A,16#6A],[16#7A,16#7A],
    [16#8A,16#8A],[16#9A,16#9A],[16#AA,16#AA],[16#BA,16#BA],
    [16#CA,16#CA],[16#DA,16#DA],[16#EA,16#EA],[16#FA,16#FA]]).

chunk_groups([]) -> [];
chunk_groups([A, B | Rest]) -> [[A, B] | chunk_groups(Rest)].

random_tls_profile() ->
    Profiles = ?TLS_FINGERPRINT_PROFILES,
    Profile = lists:nth(rand:uniform(length(Profiles)), Profiles),
    ?LOG_DEBUG("Selected TLS fingerprint: ~s", [maps:get(name, Profile, unknown)]),
    Profile.

build_cipher_suites(#{cipher_suites := Suites}) ->
    << <<S:?u16>> || S <- Suites >>.

key_size_for_group(16#001D) -> 32;
key_size_for_group(16#0017) -> 32;
key_size_for_group(16#0018) -> 48;
key_size_for_group(16#0019) -> 64;
key_size_for_group(16#11EC) -> 1184;
key_size_for_group(_) -> 32.

build_key_share_entries(#{key_share_groups := Groups}) ->
    GreaseEntry = <<16#ea, 16#ea, 16#00, 16#01, 16#00>>,
    RealEntries = [
        begin
            KeySize = key_size_for_group(Group),
            Key = crypto:strong_rand_bytes(KeySize),
            <<Group:?u16, KeySize:?u16, Key/binary>>
        end
        || [G1, G2] <- chunk_groups(Groups),
           Group <- [[G1, G2]],
           not is_grease(G1, G2)
    ],
    iolist_to_binary([GreaseEntry | RealEntries]).

build_supported_versions_ext(#{supported_versions := Versions}) ->
    << <<V:?u16>> || V <- Versions >>.

build_sig_algos(#{sig_algorithms_count := Count}) ->
    AllAlgos = [
        16#04,16#03, 16#05,16#03, 16#06,16#03, 16#02,16#03,
        16#08,16#04, 16#08,16#05, 16#08,16#06,
        16#04,16#01, 16#05,16#01, 16#06,16#01, 16#02,16#01,
        16#04,16#02, 16#03,16#02, 16#02,16#02, 16#03,16#01
    ],
    Selected = lists:sublist(AllAlgos, Count * 2),
    AlgoListLen = Count * 2,
    ExtLen = AlgoListLen + 2,
    <<16#00, 16#0d, ExtLen:?u16, AlgoListLen:?u16,
      << <<A:8>> || A <- Selected >>/binary>>.

build_ech(#{ech_payload_size := PayloadSize}) ->
    EchRand1 = crypto:strong_rand_bytes(1),
    EchRand32 = crypto:strong_rand_bytes(32),
    EchPayload = crypto:strong_rand_bytes(PayloadSize),
    EchContent =
        <<16#00,16#00,16#01,16#00,16#01, EchRand1/binary,
          16#00,16#20, EchRand32/binary,
          (byte_size(EchPayload)):?u16, EchPayload/binary>>,
    <<16#fe,16#0d, (byte_size(EchContent)):?u16, EchContent/binary>>.

build_compress_certificate(brotli) ->
    <<16#00,16#1b,16#00,16#03,16#02,16#00,16#02>>;
build_compress_certificate(none) -> <<>>.

build_ec_point_formats(true) ->
    <<16#00,16#0b,16#00,16#02,16#01,16#00>>;
build_ec_point_formats(false) -> <<>>.

build_alpn_ext(#{alpn_protocols := Protocols}) ->
    AlpnData = << <<(byte_size(P)):8, P/binary>> || P <- Protocols >>,
    <<16#00, 16#10,
      (byte_size(AlpnData) + 2):?u16,
      (byte_size(AlpnData)):?u16,
      AlpnData/binary>>;
build_alpn_ext(_) ->
    <<16#00, 16#10, 16#00, 16#0e,
      16#00, 16#0c,
      16#02, $h, $2,
      16#08, $h, $t, $t, $p, $/, $1, $., $1>>.

build_random_grease_extensions() ->
    Count = rand:uniform(3),
    [
        begin
            GreaseType = grease_value(),
            case rand:uniform(3) of
                1 -> <<GreaseType:16, 0:16>>;
                2 -> <<GreaseType:16, 1:16, 0:8>>;
                _ -> <<GreaseType:16, 2:16, 16#00, 16#00>>
            end
        end
        || _ <- lists:seq(1, Count)
    ].

insert_random_grease(Extensions, []) -> Extensions;
insert_random_grease(Extensions, [Grease | Rest]) ->
    Pos = rand:uniform(length(Extensions) + 1) - 1,
    NewExts = lists:sublist(Extensions, Pos) ++ [Grease] ++ lists:nthtail(Pos, Extensions),
    insert_random_grease(NewExts, Rest).


%% @doc format TLS secret
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

%% ============================================================================
%% DOMAIN RESTRICTION
%% ============================================================================

-spec is_domain_allowed(binary(), [binary()]) -> boolean().
is_domain_allowed(_Domain, []) -> true;
is_domain_allowed(Domain, AllowedDomains) ->
    lists:any(fun(Allowed) -> match_domain(Domain, Allowed) end, AllowedDomains).

-spec match_domain(binary(), binary()) -> boolean().
match_domain(Domain, Allowed) ->
    case Allowed of
        <<"*.", Base/binary>> ->
            Suffix = <<".", Base/binary>>,
            SuffixLen = byte_size(Suffix),
            DomLen = byte_size(Domain),
            if DomLen >= SuffixLen ->
                EndPart = binary:part(Domain, {DomLen, -SuffixLen}),
                EndPart =:= Suffix;
               true -> false
            end;
        _ -> Domain =:= Allowed
    end.

%% ============================================================================
%% from_client_hello WITH DOMAIN CHECK + SESSION TICKET + OCSP
%% ============================================================================

-spec from_client_hello(binary(), binary(), [binary()]) ->
                               {ok, iodata(), meta(), codec()}.
from_client_hello(Data, Secret, AllowedDomains) ->
    #client_hello{pseudorandom = ClientDigest,
                  session_id = SessionId,
                  extensions = Extensions} = CliHlo = parse_client_hello(Data),
    ?LOG_DEBUG("TLS ClientHello=~p", [CliHlo]),

    %% Extract SNI domain
    SniDomain = case lists:keyfind(?EXT_SNI, 1, Extensions) of
        {_, [{?EXT_SNI_HOST_NAME, Domain}]} -> Domain;
        _ -> undefined
    end,

    %% Check if domain is allowed
    case SniDomain of
        undefined ->
            ?LOG_WARNING("TLS ClientHello has no SNI, rejecting"),
            error({protocol_error, tls_no_sni});
        _ ->
            case is_domain_allowed(SniDomain, AllowedDomains) of
                true -> ok;
                false ->
                    ?LOG_WARNING(
                       "TLS ClientHello with unauthorized domain '~s'. Allowed: ~p",
                       [SniDomain, AllowedDomains]),
                    error({protocol_error, tls_domain_not_allowed, SniDomain})
            end
    end,

    ServerDigest = make_server_digest(Data, Secret),
    <<Zeroes:(?DIGEST_LEN - 4)/binary, Timestamp:32/unsigned-little>> = XoredDigest =
        crypto:exor(ClientDigest, ServerDigest),
    lists:all(fun(B) -> B == 0 end, binary_to_list(Zeroes)) orelse
        error({protocol_error, tls_invalid_digest, XoredDigest}),
    KeyShare = make_key_share(Extensions),
    SrvHello0 = make_srv_hello(binary:copy(<<0>>, ?DIGEST_LEN), SessionId, KeyShare),
    FakeHttpData = crypto:strong_rand_bytes(rand:uniform(256)),
    Response0 = [_, CC, DD] =
        [as_tls_frame(?TLS_REC_HANDSHAKE, SrvHello0),
         as_tls_frame(?TLS_REC_CHANGE_CIPHER, [1]),
         as_tls_frame(?TLS_REC_DATA, FakeHttpData)],
    SrvHelloDigest = hmac(sha256, Secret, [ClientDigest | Response0]),
    SrvHello = make_srv_hello(SrvHelloDigest, SessionId, KeyShare),

    %% ============================================================
    %% SECURITY: Fake Session Ticket
    %% ============================================================
    SessionTicket = crypto:strong_rand_bytes(rand:uniform(128) + 64),
    SessionTicketFrame = as_tls_frame(?TLS_REC_HANDSHAKE, [
        <<?TLS_TAG_SESSION_TICKET:8, (byte_size(SessionTicket)):?u24,
           SessionTicket/binary>>
    ]),

    %% ============================================================
    %% SECURITY: Fake OCSP Stapling
    %% ============================================================
    OcspResponse = crypto:strong_rand_bytes(rand:uniform(256) + 64),
    OcspFrame = as_tls_frame(?TLS_REC_HANDSHAKE, [
        <<?TLS_TAG_CERTIFICATE_STATUS:8, (byte_size(OcspResponse)):?u24,
           OcspResponse/binary>>
    ]),

    Response = [as_tls_frame(?TLS_REC_HANDSHAKE, SrvHello),
                CC,
                DD,
                SessionTicketFrame,
                OcspFrame],

    Meta0 = #{session_id => SessionId,
              timestamp => Timestamp,
              client_digest => ClientDigest},
    Meta = Meta0#{sni_domain => SniDomain},
    {ok, Response, Meta, new()}.

-spec from_client_hello(binary(), binary()) ->
                               {ok, iodata(), meta(), codec()}.
from_client_hello(Data, Secret) ->
    from_client_hello(Data, Secret, []).

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

-spec derive_sni_secret(BaseSecret :: binary(), SniDomain :: binary(), Salt :: binary()) -> binary().
derive_sni_secret(BaseSecret, SniDomain, Salt) when byte_size(BaseSecret) == 16 ->
    SecretHex = mtp_handler:hex(BaseSecret),
    <<Derived:16/binary, _/binary>> = crypto:hash(sha256, [Salt, SecretHex, SniDomain]),
    Derived.


%% ============================================================================
%% parse_client_hello - ORIGINAL VALIDATION
%% ============================================================================
parse_client_hello(<<?TLS_REC_HANDSHAKE, ?TLS_10_VERSION, TlsFrameLen:?u16,
                     ?TLS_TAG_CLI_HELLO, HelloLen:?u24, ?TLS_12_VERSION,
                     Random:?DIGEST_LEN/binary,
                     SessIdLen, SessId:SessIdLen/binary,
                     CipherSuitesLen:?u16, CipherSuites:CipherSuitesLen/binary,
                     CompMethodsLen, CompMethods:CompMethodsLen/binary,
                     ExtensionsLen:?u16, Extensions:ExtensionsLen/binary>>
                  ) when TlsFrameLen >= 512, HelloLen >= 508 ->
    #client_hello{
       pseudorandom = Random,
       session_id = SessId,
       cipher_suites = parse_suites(CipherSuites),
       compression_methods = parse_compression(CompMethods),
       extensions = parse_extensions(Extensions)
      };
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
    Msg = [Left, binary:copy(<<0>>, ?DIGEST_LEN), Right],
    hmac(sha256, Secret, Msg).

make_key_share(Exts) ->
    case lists:keyfind(?EXT_KEY_SHARE, 1, Exts) of
        {_, KeyShares} ->
            SupportedKeyShares = lists:dropwhile(
              fun({Group, Key}) -> not (
                byte_size(Key) < 128 andalso lists:member(Group, [
                    16#0017,16#0018,16#0019,16#001D,16#001E,
                    16#0100,16#0101,16#0102,16#0103,16#0104]))
              end, KeyShares),
            case SupportedKeyShares of
                [] -> error({protocol_error, tls_unsupported_key_shares, KeyShares});
                [{KSGroup, KSKey}|_] -> {KSGroup, crypto:strong_rand_bytes(byte_size(KSKey))}
            end;
        _ -> error({protocol_error, tls_missing_key_share_ext, Exts})
    end.

make_srv_hello(Digest, SessionId, {KeyShareGroup, KeyShareKey}) ->
    KeyShareEntity = <<KeyShareGroup:?u16, (byte_size(KeyShareKey)):?u16, KeyShareKey/binary>>,
    Extensions = [<<?EXT_KEY_SHARE:?u16, (byte_size(KeyShareEntity)):?u16>>,
                  KeyShareEntity,
                  <<?EXT_SUPPORTED_VERSIONS:?u16, 2:?u16, ?TLS_13_VERSION>>],
    SessionSize = byte_size(SessionId),
    Payload = [<<?TLS_12_VERSION, Digest:?DIGEST_LEN/binary,
                 SessionSize, SessionId:SessionSize/binary,
                 ?TLS_CIPHERSUITE, 0,
                 (iolist_size(Extensions)):?u16>> | Extensions],
    [<<?TLS_TAG_SRV_HELLO, (iolist_size(Payload)):?u24>> | Payload].

%% ============================================================================
%% make_client_hello WITH RANDOM FINGERPRINT + GREASE + ALPN
%% ============================================================================

make_client_hello(Secret, SniDomain) ->
    make_client_hello(erlang:system_time(second), crypto:strong_rand_bytes(32), Secret, SniDomain).

make_client_hello(Timestamp, SessionId, HexSecret, SniDomain) when byte_size(HexSecret) == 32 ->
    make_client_hello(Timestamp, SessionId, mtp_handler:unhex(HexSecret), SniDomain);
make_client_hello(Timestamp, SessionId, Secret, SniDomain) when byte_size(SessionId) == 32,
                                                                byte_size(Secret) == 16 ->
    Profile = random_tls_profile(),
    GREASE = <<16#ea, 16#ea>>,
    CipherSuites = build_cipher_suites(Profile),
    SNI = make_sni([SniDomain]),
    SigAlgos = build_sig_algos(Profile),

    #{key_share_groups := KSGroups} = Profile,
    GroupEntries = [<<G:?u16>> || [G1,G2] <- chunk_groups(KSGroups), G <- [[G1,G2]]],
    GroupsBin = iolist_to_binary(GroupEntries),
    SupportedGroups = <<16#00,16#0a, (byte_size(GroupsBin)+2):?u16, (byte_size(GroupsBin)):?u16, GroupsBin/binary>>,

    SupportedVersionsExt = build_supported_versions_ext(Profile),
    SupportedVersions = <<16#00,16#2b, (byte_size(SupportedVersionsExt)+1):?u16, (byte_size(SupportedVersionsExt)):8, SupportedVersionsExt/binary>>,

    KeyShareEntries = build_key_share_entries(Profile),
    KeyShare = <<16#00,16#33, (byte_size(KeyShareEntries)+2):?u16, (byte_size(KeyShareEntries)):?u16, KeyShareEntries/binary>>,

    ECH = build_ech(Profile),
    CompCert = maps:get(compress_certificate, Profile, brotli),
    CompressCertExt = build_compress_certificate(CompCert),
    EcPoint = maps:get(ec_point_formats, Profile, true),
    EcPointExt = build_ec_point_formats(EcPoint),

    %% Random ALPN
    AlpnExt = build_alpn_ext(Profile),

    Extensions0 = [
        <<GREASE/binary, 0:16>>,
        <<16#00,16#17,0:16>>,
        ECH,
        <<16#00,16#23,0:16>>,
        EcPointExt,
        <<16#44,16#cd,16#00,16#05,16#00,16#03,16#02,$h,$2>>,
        KeyShare,
        <<16#00,16#12,0:16>>,
        SupportedGroups,
        CompressCertExt,
        <<16#ff,16#01,16#00,16#01,16#00>>,
        SigAlgos,
        <<16#00,16#05,16#00,16#05,16#01,0:32>>,
        <<16#00,16#2d,16#00,16#02,16#01,16#01>>,
        AlpnExt,
        SNI,
        SupportedVersions,
        <<GREASE/binary,16#00,16#01,16#00>>
    ],

    Extensions1 = [Ext || Ext <- Extensions0, Ext =/= <<>>],
    GreaseExts = build_random_grease_extensions(),
    Extensions = insert_random_grease(Extensions1, GreaseExts),

    ExtBin = iolist_to_binary(Extensions),
    CSLen = byte_size(CipherSuites),
    SessIdLen = byte_size(SessionId),
    ExtLen = byte_size(ExtBin),
    HelloBodyLen = 2 + 32 + 1 + SessIdLen + 2 + CSLen + 1 + 1 + 2 + ExtLen,
    TlsLen = HelloBodyLen + 4,
    Pack = fun(FakeRandom) ->
        <<?TLS_REC_HANDSHAKE, ?TLS_10_VERSION, TlsLen:?u16,
          ?TLS_TAG_CLI_HELLO, HelloBodyLen:?u24, ?TLS_12_VERSION,
          FakeRandom:?DIGEST_LEN/binary,
          SessIdLen, SessionId/binary,
          CSLen:?u16, CipherSuites/binary,
          1, 0,
          ExtLen:?u16, ExtBin/binary>>
    end,
    FakeRandom0 = binary:copy(<<0>>, ?DIGEST_LEN),
    Hello0 = Pack(FakeRandom0),
    Digest = hmac(sha256, Secret, Hello0),
    EncTimestamp = <<(binary:copy(<<0>>, ?DIGEST_LEN - 4))/binary, Timestamp:32/unsigned-little>>,
    FakeRandom = crypto:exor(Digest, EncTimestamp),
    Pack(FakeRandom).

make_sni(Domains) ->
    SniListItems = << <<?EXT_SNI_HOST_NAME, (byte_size(Domain)):?u16, Domain/binary>>
                      || Domain <- Domains >>,
    ItemsLen = byte_size(SniListItems),
    <<?EXT_SNI:?u16, (ItemsLen + 2):?u16, ItemsLen:?u16, SniListItems/binary>>.

parse_server_hello(<<?TLS_REC_HANDSHAKE, ?TLS_12_VERSION, HSLen:?u16, Handshake:HSLen/binary,
                     ?TLS_REC_CHANGE_CIPHER, ?TLS_12_VERSION, CCLen:?u16, ChangeCipher:CCLen/binary,
                     ?TLS_REC_DATA, ?TLS_12_VERSION, DLen:?u16, Data:DLen/binary, Tail/binary>>) ->
    {Handshake, ChangeCipher, Data, Tail};
parse_server_hello(B) when byte_size(B) < 5 -> incomplete;
parse_server_hello(<<16#16, _/binary>> = B) ->
    case tls_records_complete(B, 3) of
        true  -> {error, tls_domain_forwarding};
        false -> incomplete
    end;
parse_server_hello(<<16#15, _/binary>>) -> {error, tls_alert};
parse_server_hello(_) -> {error, not_proxy_response}.

tls_records_complete(_B, 0) -> true;
tls_records_complete(<<_T,_Mj,_Mn,Len:?u16,Rest/binary>>, N) when byte_size(Rest) >= Len ->
    <<_:Len/binary, Tail/binary>> = Rest,
    tls_records_complete(Tail, N - 1);
tls_records_complete(_B, _N) -> false.

new() -> #st{}.

try_decode_packet(<<?TLS_12_DATA, Size:?u16, Data:Size/binary, Tail/binary>>, St) ->
    {ok, Data, Tail, St};
try_decode_packet(<<?TLS_REC_CHANGE_CIPHER, ?TLS_12_VERSION, Size:?u16, _:Size/binary, Tail/binary>>, St) ->
    try_decode_packet(Tail, St);
try_decode_packet(Bin, St) when byte_size(Bin) =< (?MAX_IN_PACKET_SIZE + 5) -> {incomplete, St};
try_decode_packet(Bin, _St) -> error({protocol_error, tls_max_size, byte_size(Bin)}).

decode_all(Bin, St) -> decode_all(Bin, <<>>, St).
decode_all(Bin, Acc, St0) ->
    case try_decode_packet(Bin, St0) of
        {incomplete, St} -> {Acc, Bin, St};
        {ok, Data, Tail, St} -> decode_all(Tail, <<Acc/binary, Data/binary>>, St)
    end.

encode_packet(Bin, St) -> {encode_as_frames(Bin), St}.
encode_as_frames(Bin) when byte_size(Bin) =< ?MAX_OUT_PACKET_SIZE -> as_tls_data_frame(Bin);
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
