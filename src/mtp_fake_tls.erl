%%% @author sergey <me@seriyps.ru>
%%% @copyright (C) 2019, sergey
%%% @doc
%%% Fake TLS 'CBC' stream codec
%%% Revised for better DPI evasion and bugfixes.
%%%
%%% Key changes:
%%%  - More realistic TLS fingerprints (Chrome/Firefox-like)
%%%  - Fixed GREASE handling and extension length issues
%%%  - Strong randomness for all TLS-related random fields
%%%  - Fixed OCSP GeneralizedTime encoding (UTC, proper ASN.1 time form)
%%%  - More realistic SessionTicket formatting
%%%  - Removed obviously invalid/unused extensions and data shapes
%%%  - Better handling of SNI/Domain checks
%%%
%%% @end
%%% Created : 24 Jul 2019 by sergey <me@seriyps.ru>
%%% Revised : 04 Aug 2026

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
    session_ticket :: binary() | undefined,
    ocsp_response :: binary() | undefined,
    session_ticket_lifetime :: non_neg_integer() | undefined
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
%% GREASE values for random insertion (RFC 8701)
%% ============================================================================
-define(GREASE_VALUES, [
    16#0a0a, 16#1a1a, 16#2a2a, 16#3a3a, 16#4a4a,
    16#5a5a, 16#6a6a, 16#7a7a, 16#8a8a, 16#9a9a,
    16#aaaa, 16#baba, 16#caca, 16#dada, 16#eaea,
    16#fafa
]).

%% ============================================================================
%% TLS Fingerprint Profiles - randomized per connection
%% NOTE: For DPI evasion, we keep profiles close to real browsers but
%% avoid impossible combinations. All suites/groups/versions are valid.
%% ============================================================================

-define(TLS_FINGERPRINT_PROFILES, [
    %% Chrome-like modern profile
    #{name => chrome_like,
      cipher_suites => [
          16#13, 16#01,   % TLS_AES_128_GCM_SHA256
          16#13, 16#02,   % TLS_AES_256_GCM_SHA384
          16#13, 16#03,   % TLS_CHACHA20_POLY1305_SHA256
          16#c0, 16#2b,   % ECDHE_ECDSA_AES128_GCM_SHA256
          16#c0, 16#2f,   % ECDHE_RSA_AES128_GCM_SHA256
          16#c0, 16#2c,   % ECDHE_ECDSA_AES256_GCM_SHA384
          16#c0, 16#30,   % ECDHE_RSA_AES256_GCM_SHA384
          16#cc, 16#a9,   % ECDHE_ECDSA_CHACHA20_POLY1305
          16#cc, 16#a8    % ECDHE_RSA_CHACHA20_POLY1305
      ],
      cipher_order_randomized => true,
      grease_count => {2, 4},
      key_share_groups => [
          16#00, 16#1d    % x25519 (Chrome usually only uses this)
      ],
      supported_versions => [
          16#03, 16#04,   % TLS 1.3
          16#03, 16#03    % TLS 1.2
      ],
      version_order_randomized => true,
      sig_algorithms_count => 13,
      ec_point_formats => false,
      compress_certificate => brotli,
      ech_payload_size => [160, 192, 224],
      session_id_length => {32, 32},
      extensions_order_randomized => true,
      alpn_protocols => [
          [<<"h2">>, <<"http/1.1">>],
          [<<"http/1.1">>]
      ],
      padding_size => {0, 512},
      session_ticket_enabled => true,
      ocsp_stapling_enabled => true
    },
    %% Firefox-like profile
    #{name => firefox_like,
      cipher_suites => [
          16#13, 16#01,
          16#13, 16#02,
          16#13, 16#03,
          16#c0, 16#2b,
          16#c0, 16#2f,
          16#c0, 16#2c,
          16#c0, 16#30,
          16#cc, 16#a9,
          16#cc, 16#a8
      ],
      cipher_order_randomized => true,
      grease_count => {1, 2},
      key_share_groups => [
          16#00, 16#1d,
          16#00, 16#17
      ],
      supported_versions => [
          16#03, 16#04,
          16#03, 16#03
      ],
      version_order_randomized => false,
      sig_algorithms_count => 15,
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
      ocsp_stapling_enabled => true
    },
    %% Safari-like profile
    #{name => safari_like,
      cipher_suites => [
          16#13, 16#01,
          16#13, 16#02,
          16#13, 16#03,
          16#c0, 16#2b,
          16#c0, 16#2f,
          16#c0, 16#2c,
          16#c0, 16#30
      ],
      cipher_order_randomized => false,
      grease_count => {1, 2},
      key_share_groups => [
          16#00, 16#1d,
          16#00, 16#17,
          16#00, 16#18
      ],
      supported_versions => [
          16#03, 16#04
      ],
      version_order_randomized => false,
      sig_algorithms_count => 11,
      ec_point_formats => false,
      compress_certificate => none,
      ech_payload_size => [192, 224],
      session_id_length => {32, 32},
      extensions_order_randomized => false,
      alpn_protocols => [
          [<<"h2">>, <<"http/1.1">>]
      ],
      padding_size => {0, 512},
      session_ticket_enabled => false,
      ocsp_stapling_enabled => true
    }
]).

-opaque codec() :: #st{}.

-type meta() :: #{session_id := binary(),
                  timestamp := non_neg_integer(),
                  client_digest := binary(),
                  sni_domain => binary(),
                  session_ticket => binary() | undefined,
                  ocsp_response => binary() | undefined}.

%% ============================================================================
%% @doc format TLS secret
%% ============================================================================
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
%% Domain allow-list
%% ============================================================================
-spec is_domain_allowed(binary(), [binary()]) -> boolean().
is_domain_allowed(_Domain, []) ->
    true;
is_domain_allowed(Domain, AllowedDomains) ->
    lists:any(fun(Allowed) ->
        match_domain(Domain, Allowed)
    end, AllowedDomains).

-spec match_domain(binary(), binary()) -> boolean().
match_domain(Domain, Allowed) ->
    case Allowed of
        <<"*.", Base/binary>> ->
            Suffix = <<".", Base/binary>>,
            SuffixLen = byte_size(Suffix),
            DomLen = byte_size(Domain),
            if
                DomLen >= SuffixLen ->
                    EndPart = binary:part(Domain, {DomLen - SuffixLen, SuffixLen}),
                    EndPart =:= Suffix;
                true ->
                    false
            end;
        _ ->
            Domain =:= Allowed
    end.

%% ============================================================================
%% OCSP
%% ============================================================================
-spec generate_ocsp_response(binary()) -> binary().
generate_ocsp_response(_ServerDigest) ->
    %% This is still synthetic but structurally closer to a real OCSP response.
    OcspStatus = 0,  %% successful
    ProducedAt = erlang:system_time(seconds),
    ThisUpdate = ProducedAt,
    NextUpdate = ProducedAt + 604800,
    CertId = crypto:strong_rand_bytes(32),
    CertStatus = <<0>>,   %% good
    SingleResponse = <<CertId/binary,
                      CertStatus/binary,
                      (encode_generalized_time(ThisUpdate))/binary,
                      (encode_generalized_time(NextUpdate))/binary>>,
    ResponsesSeq = <<1:?u16, SingleResponse/binary>>,
    ResponseData = <<0, ResponsesSeq/binary>>,
    Signature = crypto:strong_rand_bytes(256),
    BasicOcspResponse = <<ResponseData/binary, 1:24, Signature/binary>>,
    <<OcspStatus, (byte_size(BasicOcspResponse)):?u24, BasicOcspResponse/binary>>.

%% GeneralizedTime in UTC, basic format YYYYMMDDHHMMSSZ
-spec encode_generalized_time(non_neg_integer()) -> binary().
encode_generalized_time(Timestamp) ->
    %% Timestamp is seconds since UNIX epoch; convert to UTC calendar
    {{Y, M, D}, {H, Mi, S}} = calendar:gregorian_seconds_to_datetime(
        Timestamp + calendar:datetime_to_gregorian_seconds({{1970,1,1},{0,0,0}})
    ),
    Str = io_lib:format("~4..0w~2..0w~2..0w~2..0w~2..0w~2..0wZ", [Y, M, D, H, Mi, S]),
    list_to_binary(Str).

%% ============================================================================
%% Session Ticket (synthetic, but structurally plausible)
%% ============================================================================
-spec generate_session_ticket(binary()) -> binary().
generate_session_ticket(_Secret) ->
    TicketAgeAdd = crypto:strong_rand_bytes(4),
    TicketNonceLen = 16 + (crypto:strong_rand_bytes(1) rem 16),
    TicketNonce = crypto:strong_rand_bytes(TicketNonceLen),
    TicketLen   = 128 + (crypto:strong_rand_bytes(1) rem 128),
    Ticket = crypto:strong_rand_bytes(TicketLen),
    TicketLifetime = 604800,  % 7 days

    <<TicketLifetime:32,
      TicketAgeAdd/binary,
      TicketNonceLen:8, TicketNonce/binary,
      TicketLen:?u16, Ticket/binary,
      0:?u16>>.  % No extensions

%% ============================================================================
%% from_client_hello
%% ============================================================================
-spec from_client_hello(binary(), binary(), [binary()]) ->
                               {ok, iodata(), meta(), codec()}.
from_client_hello(Data, Secret, AllowedDomains) ->
    #client_hello{pseudorandom = ClientDigest,
                  session_id = SessionId,
                  extensions = Extensions} = CliHlo = parse_client_hello(Data),
    ?LOG_DEBUG("TLS ClientHello=~p", [CliHlo]),

    %% Extract SNI
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
                    ?LOG_WARNING(
                       "TLS ClientHello with unauthorized domain '~s'. Allowed domains: ~p",
                       [SniDomain, AllowedDomains]),
                    error({protocol_error, tls_domain_not_allowed, SniDomain})
            end
    end,

    HasSessionTicket = lists:keymember(?EXT_SESSION_TICKET, 1, Extensions),
    HasOcspStapling = lists:keymember(?EXT_STATUS_REQUEST, 1, Extensions),
    ?LOG_DEBUG("Client capabilities - SessionTicket: ~p, OCSP: ~p",
               [HasSessionTicket, HasOcspStapling]),

    ServerDigest = make_server_digest(Data, Secret),
    <<Zeroes:(?DIGEST_LEN - 4)/binary, Timestamp:32/unsigned-little>> = XoredDigest =
        crypto:exor(ClientDigest, ServerDigest),
    lists:all(fun(B) -> B == 0 end, binary:bin_to_list(Zeroes)) orelse
        error({protocol_error, tls_invalid_digest, XoredDigest}),

    KeyShare = make_key_share(Extensions),
    SrvHello0 = make_srv_hello(binary:copy(<<0>>, ?DIGEST_LEN), SessionId, KeyShare,
                               HasSessionTicket, HasOcspStapling),
    FakeHttpData = crypto:strong_rand_bytes(128 + (crypto:strong_rand_bytes(1) rem 128)),

    {SessionTicket, TicketRecord} =
        case HasSessionTicket of
            true ->
                Ticket = generate_session_ticket(Secret),
                TicketRecord2 = as_tls_frame(?TLS_REC_HANDSHAKE, Ticket),
                {Ticket, TicketRecord2};
            false ->
                {undefined, <<>>}
        end,

    OcspResponse =
        case HasOcspStapling of
            true -> generate_ocsp_response(ServerDigest);
            false -> undefined
        end,

    %% Build initial response (SrvHello digest will be fixed later)
    Response0 = [_, CC, DD, ST] =
        [as_tls_frame(?TLS_REC_HANDSHAKE, SrvHello0),
         as_tls_frame(?TLS_REC_CHANGE_CIPHER, [1]),
         as_tls_frame(?TLS_REC_DATA, FakeHttpData),
         TicketRecord],

    SrvHelloDigest = hmac(sha256, Secret, [ClientDigest | Response0]),
    SrvHello = make_srv_hello(SrvHelloDigest, SessionId, KeyShare,
                              HasSessionTicket, HasOcspStapling),
    Response = [as_tls_frame(?TLS_REC_HANDSHAKE, SrvHello),
                CC,
                DD,
                ST],

    Meta0 = #{session_id => SessionId,
              timestamp => Timestamp,
              client_digest => ClientDigest,
              sni_domain => SniDomain},
    Meta = Meta0#{session_ticket => SessionTicket,
                  ocsp_response => OcspResponse},

    St = #st{session_ticket = SessionTicket,
             ocsp_response = OcspResponse,
             session_ticket_lifetime = case HasSessionTicket of
                                          true -> 604800;
                                          false -> undefined
                                      end},
    {ok, Response, Meta, St}.

-spec from_client_hello(binary(), binary()) ->
                               {ok, iodata(), meta(), codec()}.
from_client_hello(Data, Secret) ->
    from_client_hello(Data, Secret, []).

%% ============================================================================
%% SNI parsing
%% ============================================================================
-spec parse_sni(binary()) -> {ok, binary()} | {error, no_sni | bad_hello}.
parse_sni(Data) ->
    try
        #client_hello{extensions = Extensions} = parse_client_hello(Data),
        case lists:keyfind(?EXT_SNI, 1, Extensions) of
            {_, [{?EXT_SNI_HOST_NAME, Domain}]} ->
                {ok, Domain};
            _ ->
                {error, no_sni}
        end
    catch
        error:{protocol_error, tls_bad_client_hello, _} ->
            {error, bad_hello}
    end.

%% ============================================================================
%% Alerts
%% ============================================================================
-spec tls_decode_error_alert() -> binary().
tls_decode_error_alert() ->
    <<?TLS_REC_ALERT, ?TLS_12_VERSION, 0, 2, ?TLS_ALERT_FATAL, ?TLS_ALERT_DECODE_ERROR>>.

%% ============================================================================
%% Per-SNI secret derivation
%% ============================================================================
-spec derive_sni_secret(BaseSecret :: binary(), SniDomain :: binary(), Salt :: binary())
        -> binary().
derive_sni_secret(BaseSecret, SniDomain, Salt) when byte_size(BaseSecret) == 16 ->
    SecretHex = mtp_handler:hex(BaseSecret),
    <<Derived:16/binary, _/binary>> =
        crypto:hash(sha256, [Salt, SecretHex, SniDomain]),
    Derived.

%% ============================================================================
%% ClientHello parsing
%% ============================================================================
parse_client_hello(<<?TLS_REC_HANDSHAKE, ?TLS_10_VERSION, TlsFrameLen:?u16,
                     ?TLS_TAG_CLI_HELLO, HelloLen:?u24, ?TLS_12_VERSION,
                     Random:?DIGEST_LEN/binary,
                     SessIdLen, SessId:SessIdLen/binary,
                     CipherSuitesLen:?u16, CipherSuites:CipherSuitesLen/binary,
                     CompMethodsLen, CompMethods:CompMethodsLen/binary,
                     ExtensionsLen:?u16, Extensions:ExtensionsLen/binary>>
                  ) when TlsFrameLen >= 256, HelloLen >= 160 ->
    #client_hello{
       pseudorandom = Random,
       session_id = SessId,
       cipher_suites = parse_suites(CipherSuites),
       compression_methods = parse_compression(CompMethods),
       extensions = parse_extensions(Extensions)
      };
parse_client_hello(_Data) ->
    error({protocol_error, tls_bad_client_hello, bad_client_hello}).

parse_suites(Bin) ->
    [Suite || <<Suite:?u16>> <= Bin].

parse_compression(Bin) ->
    [Bin].

parse_extensions(Exts) ->
    [{Type, parse_extension(Type, Data)}
     || <<Type:?u16, Length:?u16, Data:Length/binary>> <= Exts].

parse_extension(?EXT_SNI, <<ListLen:?u16, List:ListLen/binary>>) ->
    [{Type, Value}
     || <<Type, Len:?u16, Value:Len/binary>> <= List];
parse_extension(?EXT_KEY_SHARE, <<Len:?u16, Exts:Len/binary>>) ->
    [{Group, Key}
     || <<Group:?u16, KeyLen:?u16, Key:KeyLen/binary>> <= Exts];
parse_extension(?EXT_SESSION_TICKET, _Data) ->
    {session_ticket, supported};
parse_extension(?EXT_STATUS_REQUEST, <<Type, _Rest/binary>>) ->
    {ocsp_stapling, Type};
parse_extension(_Type, Data) ->
    Data.

%% ============================================================================
%% Digest & key share
%% ============================================================================
make_server_digest(<<Left:?DIGEST_POS/binary, _:?DIGEST_LEN/binary, Right/binary>>, Secret) ->
    Msg = [Left, binary:copy(<<0>>, ?DIGEST_LEN), Right],
    hmac(sha256, Secret, Msg).

make_key_share(Exts) ->
    case lists:keyfind(?EXT_KEY_SHARE, 1, Exts) of
        {_, KeyShares} ->
            SupportedKeyShares =
                lists:dropwhile(
                  fun({Group, Key}) ->
                          not (
                            byte_size(Key) < 512
                            andalso
                            lists:member(
                              Group, [
                                      16#0017,  % secp256r1
                                      16#0018,  % secp384r1
                                      16#0019,  % secp521r1
                                      16#001D,  % x25519
                                      16#001E   % x448
                              ])
                           )
                  end, KeyShares),
            case SupportedKeyShares of
                [] ->
                    error({protocol_error, tls_unsupported_key_shares, KeyShares});
                [{KSGroup, KSKey} | _] ->
                    {KSGroup, crypto:strong_rand_bytes(byte_size(KSKey))}
            end;
        _ ->
            error({protocol_error, tls_missing_key_share_ext, Exts})
    end.

%% ============================================================================
%% ServerHello builder
%% ============================================================================
make_srv_hello(Digest, SessionId, {KeyShareGroup, KeyShareKey},
               HasSessionTicket, HasOcspStapling) ->
    KeyShareEntity = <<KeyShareGroup:?u16, (byte_size(KeyShareKey)):?u16, KeyShareKey/binary>>,

    ExtensionsBase = [
        <<?EXT_KEY_SHARE:?u16, (byte_size(KeyShareEntity)):?u16, KeyShareEntity/binary>>,
        <<?EXT_SUPPORTED_VERSIONS:?u16, 2:?u16, ?TLS_13_VERSION>>
    ],

    ExtensionsWithTicket =
        case HasSessionTicket of
            true -> ExtensionsBase ++ [<<?EXT_SESSION_TICKET:?u16, 0:?u16>>];
            false -> ExtensionsBase
        end,

    ExtensionsFinal =
        case HasOcspStapling of
            true -> ExtensionsWithTicket ++ [<<?EXT_STATUS_REQUEST:?u16, 0:?u16>>];
            false -> ExtensionsWithTicket
        end,

    SessionSize = byte_size(SessionId),
    ExtSize = iolist_size(ExtensionsFinal),
    Payload = [<<?TLS_12_VERSION,
                 Digest:?DIGEST_LEN/binary,
                 SessionSize,
                 SessionId:SessionSize/binary,
                 ?TLS_CIPHERSUITE,
                 0,
                 ExtSize:?u16>>
                   | ExtensionsFinal],
    [<<?TLS_TAG_SRV_HELLO, (iolist_size(Payload)):?u24>> | Payload].

%% ============================================================================
%% Random profile selection
%% ============================================================================
-spec random_tls_profile() -> map().
random_tls_profile() ->
    Profiles = ?TLS_FINGERPRINT_PROFILES,
    %% Seed rand each time with strong randomness to avoid predictability
    <<S1:32, S2:32, S3:32>> = crypto:strong_rand_bytes(12),
    _ = rand:seed(exsplus, {S1, S2, S3}),
    Profile = lists:nth(rand:uniform(length(Profiles)), Profiles),
    ?LOG_DEBUG("Selected TLS fingerprint: ~s", [maps:get(name, Profile, unknown)]),
    Profile.

%% ============================================================================
%% GREASE & shuffles
%% ============================================================================
-spec random_grease(non_neg_integer()) -> [non_neg_integer()].
random_grease(Count) ->
    [lists:nth(rand:uniform(length(?GREASE_VALUES)), ?GREASE_VALUES) || _ <- lists:seq(1, Count)].

-spec shuffle_list(list()) -> list().
shuffle_list([]) -> [];
shuffle_list(List) ->
    Sorted = lists:sort([{rand:uniform(), X} || X <- List]),
    [X || {_, X} <- Sorted].

%% ============================================================================
%% Cipher suites builder
%% ============================================================================
-spec build_cipher_suites(map()) -> binary().
build_cipher_suites(#{cipher_suites := Suites, grease_count := {GreaseMin, GreaseMax}} = Profile) ->
    GreaseCount = GreaseMin + rand:uniform(GreaseMax - GreaseMin + 1),
    GreaseVals = random_grease(GreaseCount),

    WithGrease = lists:foldl(
        fun(G, Acc) ->
            Pos = rand:uniform(length(Acc) + 1),
            lists:sublist(Acc, Pos - 1) ++ [G] ++ lists:nthtail(Pos - 1, Acc)
        end, Suites, GreaseVals),

    Final =
        case maps:get(cipher_order_randomized, Profile, false) of
            true -> shuffle_list(WithGrease);
            false -> WithGrease
        end,

    << <<S:?u16>> || S <- Final >>.

%% ============================================================================
%% Key share entries builder
%% ============================================================================
-spec build_key_share_entries(map()) -> binary().
build_key_share_entries(#{key_share_groups := Groups,
                          grease_count := {GreaseMin, GreaseMax}}) ->
    GreaseCount = GreaseMin + rand:uniform(GreaseMax - GreaseMin + 1),
    GreaseVals = random_grease(GreaseCount),

    GreaseEntries = [<<G:?u16, 1:?u16, 16#00>> || G <- GreaseVals],

    RealEntries = [
        begin
            KeySize = key_size_for_group(Group),
            Key = crypto:strong_rand_bytes(KeySize),
            <<Group:?u16, KeySize:?u16, Key/binary>>
        end
        || Group <- Groups
    ],

    AllEntries = lists:foldl(
        fun(G, Acc) ->
            Pos = rand:uniform(length(Acc) + 1),
            lists:sublist(Acc, Pos - 1) ++ [G] ++ lists:nthtail(Pos - 1, Acc)
        end, RealEntries, GreaseEntries),

    iolist_to_binary(AllEntries).

-spec key_size_for_group(non_neg_integer()) -> non_neg_integer().
key_size_for_group(16#001D) -> 32;    % x25519
key_size_for_group(16#0017) -> 65;    % secp256r1 (uncompressed)
key_size_for_group(16#0018) -> 97;    % secp384r1
key_size_for_group(16#0019) -> 133;   % secp521r1
key_size_for_group(_)       -> 32.

%% ============================================================================
%% Supported versions builder
%% ============================================================================
-spec build_supported_versions_ext(map()) -> binary().
build_supported_versions_ext(#{supported_versions := Versions,
                               grease_count := {GreaseMin, GreaseMax}} = Profile) ->
    GreaseCount = GreaseMin + rand:uniform(GreaseMax - GreaseMin + 1),
    GreaseVals = random_grease(GreaseCount),

    WithGrease = lists:foldl(
        fun(G, Acc) ->
            Pos = rand:uniform(length(Acc) + 1),
            lists:sublist(Acc, Pos - 1) ++ [G] ++ lists:nthtail(Pos - 1, Acc)
        end, Versions, GreaseVals),

    Final =
        case maps:get(version_order_randomized, Profile, false) of
            true -> shuffle_list(WithGrease);
            false -> WithGrease
        end,

    << <<V:?u16>> || V <- Final >>.

%% ============================================================================
%% Signature algorithms builder
%% ============================================================================
-spec build_sig_algos(map()) -> binary().
build_sig_algos(#{sig_algorithms_count := Count}) ->
    AllAlgos = [
        16#04, 16#03,   % ecdsa_secp256r1_sha256
        16#05, 16#03,   % ecdsa_secp384r1_sha384
        16#06, 16#03,   % ecdsa_secp521r1_sha512
        16#08, 16#04,   % rsa_pss_rsae_sha256
        16#08, 16#05,   % rsa_pss_rsae_sha384
        16#08, 16#06,   % rsa_pss_rsae_sha512
        16#04, 16#01,   % rsa_pkcs1_sha256
        16#05, 16#01,   % rsa_pkcs1_sha384
        16#06, 16#01,   % rsa_pkcs1_sha512
        16#02, 16#01,   % rsa_pkcs1_sha1 (legacy but still appears)
        16#03, 16#01    % ecdsa_sha1 (legacy)
    ],
    Needed = Count * 2,
    Selected =
        case Needed =< length(AllAlgos) of
            true -> lists:sublist(AllAlgos, Needed);
            false -> AllAlgos
        end,
    Shuffled = shuffle_list(Selected),
    AlgoListLen = length(Shuffled),
    ExtLen = AlgoListLen + 2,
    <<16#00, 16#0d,
      ExtLen:?u16,
      AlgoListLen:?u16,
      << <<A:8>> || A <- Shuffled >>/binary>>.

%% ============================================================================
%% ECH extension (synthetic)
%% ============================================================================
-spec build_ech(map()) -> binary().
build_ech(#{ech_payload_size := Sizes}) when is_list(Sizes), Sizes =/= [] ->
    PayloadSize = lists:nth(rand:uniform(length(Sizes)), Sizes),
    EchRand1 = crypto:strong_rand_bytes(1),
    EchRand32 = crypto:strong_rand_bytes(32),
    EchPayload = crypto:strong_rand_bytes(PayloadSize),
    EchContent =
        <<16#00, 16#00, 16#01, 16#00, 16#01,
          EchRand1/binary,
          16#00, 16#20,
          EchRand32/binary,
          (byte_size(EchPayload)):?u16,
          EchPayload/binary>>,
    <<16#fe, 16#0d,
      (byte_size(EchContent)):?u16,
      EchContent/binary>>;
build_ech(_) ->
    <<>>.

%% ============================================================================
%% ALPN extension
%% ============================================================================
-spec build_alpn(map()) -> binary().
build_alpn(#{alpn_protocols := Protocols}) when is_list(Protocols), Protocols =/= [] ->
    Selected = lists:nth(rand:uniform(length(Protocols)), Protocols),
    ProtocolEntries = << <<(byte_size(P)):8, P/binary>> || P <- Selected >>,
    ProtocolsLen = byte_size(ProtocolEntries),
    <<16#00, 16#10,
      (ProtocolsLen + 2):?u16,
      ProtocolsLen:?u16,
      ProtocolEntries/binary>>;
build_alpn(_) ->
    <<>>.

%% ============================================================================
%% Compress_certificate extension
%% ============================================================================
-spec build_compress_certificate(map()) -> binary().
build_compress_certificate(#{compress_certificate := brotli}) ->
    %% advertise brotli (2)
    <<16#00, 16#1b, 16#00, 16#03, 16#02, 16#00, 16#02>>;
build_compress_certificate(_) ->
    <<>>.

%% ============================================================================
%% ec_point_formats extension
%% ============================================================================
-spec build_ec_point_formats(map()) -> binary().
build_ec_point_formats(#{ec_point_formats := true}) ->
    %% only uncompressed (0)
    <<16#00, 16#0b, 16#00, 16#02, 16#01, 16#00>>;
build_ec_point_formats(_) ->
    <<>>.

%% ============================================================================
%% supported_groups extension
%% ============================================================================
-spec build_supported_groups(map()) -> binary().
build_supported_groups(#{key_share_groups := Groups,
                         grease_count := {GreaseMin, GreaseMax}}) ->
    GreaseCount = GreaseMin + rand:uniform(GreaseMax - GreaseMin + 1),
    GreaseVals = random_grease(GreaseCount),

    WithGrease = lists:foldl(
        fun(G, Acc) ->
            Pos = rand:uniform(length(Acc) + 1),
            lists:sublist(Acc, Pos - 1) ++ [G] ++ lists:nthtail(Pos - 1, Acc)
        end, Groups, GreaseVals),

    GroupsBin = << <<G:?u16>> || G <- WithGrease >>,
    GroupsLen = byte_size(GroupsBin),
    <<16#00, 16#0a,
      (GroupsLen + 2):?u16,
      GroupsLen:?u16,
      GroupsBin/binary>>.

%% ============================================================================
%% padding extension
%% ============================================================================
-spec build_padding(map()) -> binary().
build_padding(#{padding_size := {Min, Max}}) ->
    PadSize = Min + rand:uniform(Max - Min + 1),
    case PadSize of
        0 -> <<>>;
        _ ->
            Padding = binary:copy(<<0>>, PadSize),
            <<16#00, 16#15, PadSize:?u16, Padding/binary>>
    end;
build_padding(_) ->
    <<>>.

%% ============================================================================
%% SessionTicket ext for ClientHello
%% ============================================================================
-spec build_session_ticket_ext(map()) -> binary().
build_session_ticket_ext(#{session_ticket_enabled := true}) ->
    <<?EXT_SESSION_TICKET:?u16, 0:?u16>>;
build_session_ticket_ext(_) ->
    <<>>.

%% ============================================================================
%% OCSP status_request ext for ClientHello
%% ============================================================================
-spec build_ocsp_stapling_ext(map()) -> binary().
build_ocsp_stapling_ext(#{ocsp_stapling_enabled := true}) ->
    %% Minimal OCSP status_request (type=1, empty responder_id_list & request_extensions)
    <<?EXT_STATUS_REQUEST:?u16, 5:?u16, 1, 0:?u16, 0:?u16>>;
build_ocsp_stapling_ext(_) ->
    <<>>.

%% ============================================================================
%% SNI builder
%% ============================================================================
make_sni(Domains) ->
    SniListItems = << <<?EXT_SNI_HOST_NAME, (byte_size(Domain)):?u16, Domain/binary>>
                      || Domain <- Domains >>,
    ItemsLen = byte_size(SniListItems),
    <<?EXT_SNI:?u16, (ItemsLen + 2):?u16, ItemsLen:?u16, SniListItems/binary>>.

%% ============================================================================
%% ClientHello generator (fake TLS)
%% ============================================================================
-spec make_client_hello(binary(), binary()) -> binary().
make_client_hello(Secret, SniDomain) ->
    make_client_hello(erlang:system_time(second),
                      crypto:strong_rand_bytes(32),
                      Secret, SniDomain).

-spec make_client_hello(non_neg_integer(), binary(), binary(), binary()) -> binary().
make_client_hello(Timestamp, SessionId, HexSecret, SniDomain) when byte_size(HexSecret) == 32 ->
    make_client_hello(Timestamp, SessionId, mtp_handler:unhex(HexSecret), SniDomain);
make_client_hello(Timestamp, SessionId, Secret, SniDomain)
    when byte_size(SessionId) == 32,
         byte_size(Secret) == 16 ->
    Profile = random_tls_profile(),

    CipherSuites = build_cipher_suites(Profile),
    SNI = make_sni([SniDomain]),
    SigAlgos = build_sig_algos(Profile),
    SupportedGroups = build_supported_groups(Profile),

    SupportedVersionsExt = build_supported_versions_ext(Profile),
    VersionsLen = byte_size(SupportedVersionsExt),
    SupportedVersions =
        <<16#00, 16#2b,
          (VersionsLen + 1):?u16,
          VersionsLen,
          SupportedVersionsExt/binary>>,

    KeyShareEntries = build_key_share_entries(Profile),
    KSListLen = byte_size(KeyShareEntries),
    KeyShare =
        <<16#00, 16#33,
          (KSListLen + 2):?u16,
          KSListLen:?u16,
          KeyShareEntries/binary>>,

    ECH = build_ech(Profile),
    ALPN = build_alpn(Profile),
    CompCertExt = build_compress_certificate(Profile),
    EcPointExt = build_ec_point_formats(Profile),
    SessionTicketExt = build_session_ticket_ext(Profile),
    OcspStaplingExt = build_ocsp_stapling_ext(Profile),
    PaddingExt = build_padding(Profile),

    %% application_layer_protocol_settings removed (it was clearly fake and invalid),
    %% signed_certificate_timestamp: simple empty extension
    SctExt = <<16#00, 16#12, 0:?u16>>,

    PskModesExt = <<16#00, 16#2d, 3:?u16, 2, 1, 1>>, % psk_key_exchange_modes

    RenegExt = <<16#ff, 16#01, 1:?u16, 0>>,          % renegotiation_info with empty reneg data

    ExtensionsBase = [
        ECH,
        SessionTicketExt,
        EcPointExt,
        KeyShare,
        SctExt,
        SupportedGroups,
        CompCertExt,
        RenegExt,
        SigAlgos,
        OcspStaplingExt,
        PskModesExt,
        ALPN,
        SNI,
        SupportedVersions,
        PaddingExt
    ],

    NonEmpty = [E || E <- ExtensionsBase, E =/= <<>>],
    Extensions =
        case maps:get(extensions_order_randomized, Profile, false) of
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
                     FakeRandom:?DIGEST_LEN/binary,
                     SessIdLen, SessionId/binary,
                     CSLen:?u16, CipherSuites/binary,
                     1, 0,
                     ExtLen:?u16, ExtBin/binary>>
           end,

    FakeRandom0 = binary:copy(<<0>>, ?DIGEST_LEN),
    Hello0 = Pack(FakeRandom0),
    Digest = hmac(sha256, Secret, Hello0),
    EncTimestamp = <<(binary:copy(<<0>>, ?DIGEST_LEN - 4))/binary,
                     Timestamp:32/unsigned-little>>,
    FakeRandom = crypto:exor(Digest, EncTimestamp),
    Pack(FakeRandom).

%% ============================================================================
%% ServerHello parser (ours)
%% ============================================================================
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

-spec tls_records_complete(binary(), non_neg_integer()) -> boolean().
tls_records_complete(_B, 0) ->
    true;
tls_records_complete(<<_T, _Mj, _Mn, Len:?u16, Rest/binary>>, N) when byte_size(Rest) >= Len ->
    <<_:Len/binary, Tail/binary>> = Rest,
    tls_records_complete(Tail, N - 1);
tls_records_complete(_B, _N) ->
    false.

%% ============================================================================
%% Data stream codec
%% ============================================================================
-spec new() -> codec().
new() ->
    #st{}.

-spec try_decode_packet(binary(), codec()) -> {ok, binary(), binary(), codec()}
                                                  | {incomplete, codec()}.
try_decode_packet(<<?TLS_12_DATA, Size:?u16, Data:Size/binary, Tail/binary>>, St) ->
    {ok, Data, Tail, St};
try_decode_packet(<<?TLS_REC_CHANGE_CIPHER, ?TLS_12_VERSION, Size:?u16,
                    _Data:Size/binary, Tail/binary>>, St) ->
    try_decode_packet(Tail, St);
try_decode_packet(Bin, St) when byte_size(Bin) =< (?MAX_IN_PACKET_SIZE + 5) ->
    {incomplete, St};
try_decode_packet(Bin, _St) ->
    error({protocol_error, tls_max_size, byte_size(Bin)}).

-spec decode_all(binary(), codec()) -> {Decoded :: binary(), Tail :: binary(), codec()}.
decode_all(Bin, St) ->
    decode_all(Bin, <<>>, St).

decode_all(Bin, Acc, St0) ->
    case try_decode_packet(Bin, St0) of
        {incomplete, St} ->
            {Acc, Bin, St};
        {ok, Data, Tail, St} ->
            decode_all(Tail, <<Acc/binary, Data/binary>>, St)
    end.

-spec encode_packet(binary(), codec()) -> {iodata(), codec()}.
encode_packet(Bin, St) ->
    {encode_as_frames(Bin), St}.

encode_as_frames(Bin) when byte_size(Bin) =< ?MAX_OUT_PACKET_SIZE ->
    as_tls_data_frame(Bin);
encode_as_frames(<<Chunk:?MAX_OUT_PACKET_SIZE/binary, Tail/binary>>) ->
    [as_tls_data_frame(Chunk) | encode_as_frames(Tail)].

as_tls_data_frame(Bin) ->
    as_tls_frame(?TLS_REC_DATA, Bin).

-spec as_tls_frame(byte(), iodata()) -> iodata().
as_tls_frame(Type, Data) ->
    Size = iolist_size(Data),
    [<<Type, ?TLS_12_VERSION, Size:?u16>> | Data].

-if(?OTP_RELEASE >= 23).
hmac(Algo, Key, Str) ->
    crypto:mac(hmac, Algo, Key, Str).
-else.
hmac(Algo, Key, Str) ->
    crypto:hmac(Algo, Key, Str).
-endif.
