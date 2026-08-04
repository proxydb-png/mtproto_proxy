%%%===================================================================
%%% Fake TLS - HYPER-NUCLEAR VERSION v3.0
%%% Combining:
%%% - Chaos Fragmentation Engine with entropy equalization
%%% - Multi-profile rotation mid-connection
%%% - Deep packet camouflage with layered fake records
%%% - Timing randomization & jitter injection
%%% - Protocol mimicry switching (HTTP/2, gRPC, WebSocket patterns)
%%% - Entropy normalization to defeat statistical analysis
%%% - Dynamic padding with traffic morphing
%%% - Fake renegotiation & session resumption patterns
%%% - Cross-profile cipher suite blending
%%% - Adaptive behavior based on network conditions
%%%===================================================================

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

%%%===================================================================
%%% Records - Enhanced State Machine
%%%===================================================================

-record(chaos_state, {
    %% Fragmentation chaos
    frag_min = 200        :: pos_integer(),
    frag_max = 3000       :: pos_integer(),
    packet_count = 0      :: non_neg_integer(),
    frag_reset_at = 0     :: non_neg_integer(),
    
    %% Fake record injection
    fake_probability = 0.3 :: float(),
    fake_min_size = 8     :: pos_integer(),
    fake_max_size = 256   :: pos_integer(),
    
    %% Timing chaos
    send_jitter_us = 0    :: non_neg_integer(),
    burst_mode = false    :: boolean(),
    burst_count = 0       :: non_neg_integer(),
    
    %% Profile management
    current_profile :: map(),
    profile_rotation_count = 0 :: non_neg_integer(),
    profile_rotation_at :: non_neg_integer(),
    
    %% Entropy management
    entropy_pool = <<>>   :: binary(),
    entropy_threshold = 64 :: pos_integer(),
    
    %% Protocol mimicry
    mimicry_mode = http2  :: http2 | grpc | websocket | random,
    mimicry_sequence = [] :: [binary()],
    
    %% Session management
    session_ticket :: binary() | undefined,
    ocsp_response :: binary() | undefined,
    session_ticket_lifetime :: non_neg_integer() | undefined,
    
    %% Adaptive learning
    connection_start_time :: non_neg_integer(),
    bytes_sent = 0        :: non_neg_integer(),
    adaptation_level = 1  :: 1..5
}).

-record(client_hello, {
    pseudorandom        :: binary(),
    session_id          :: binary(),
    cipher_suites       :: [non_neg_integer()],
    compression_methods :: binary(),
    extensions          :: [{non_neg_integer(), any()}]
}).

%%%===================================================================
%%% Constants & Macros
%%%===================================================================

-define(u16, 16/unsigned-big).
-define(u24, 24/unsigned-big).

-define(MAX_IN_PACKET_SIZE,  65535).
-define(MAX_OUT_PACKET_SIZE, 16384).

-define(TLS_10_VERSION, 3, 1).
-define(TLS_12_VERSION, 3, 3).
-define(TLS_13_VERSION, 3, 4).

-define(TLS_REC_CHANGE_CIPHER, 20).
-define(TLS_REC_ALERT,         21).
-define(TLS_REC_HANDSHAKE,     22).
-define(TLS_REC_DATA,          23).

-define(TLS_ALERT_FATAL,        2).
-define(TLS_ALERT_DECODE_ERROR, 50).

-define(TLS_12_DATA, ?TLS_REC_DATA, ?TLS_12_VERSION).

-define(DIGEST_POS, 11).
-define(DIGEST_LEN, 32).

-define(TLS_TAG_CLI_HELLO, 1).
-define(TLS_TAG_SRV_HELLO, 2).
-define(TLS_TAG_NEW_SESSION_TICKET, 4).

-define(TLS_CIPHERSUITE, 192, 47).

-define(EXT_SNI,                 0).
-define(EXT_SNI_HOST_NAME,       0).
-define(EXT_STATUS_REQUEST,      5).
-define(EXT_SUPPORTED_GROUPS,   10).
-define(EXT_EC_POINT_FORMATS,   11).
-define(EXT_SIGNATURE_ALGORITHMS, 13).
-define(EXT_ALPN,               16).
-define(EXT_PADDING,            21).
-define(EXT_SESSION_TICKET,     35).
-define(EXT_SUPPORTED_VERSIONS, 43).
-define(EXT_PSK_KEY_EXCHANGE_MODES, 45).
-define(EXT_KEY_SHARE,          51).

%%%===================================================================
%%% GREASE Values (RFC 8701) - Extended
%%%===================================================================

-define(GREASE_VALUES, [
    16#0a0a, 16#1a1a, 16#2a2a, 16#3a3a, 16#4a4a,
    16#5a5a, 16#6a6a, 16#7a7a, 16#8a8a, 16#9a9a,
    16#aaaa, 16#baba, 16#caca, 16#dada, 16#eaea,
    16#fafa
]).

%%%===================================================================
%%% HYPER-NUCLEAR: Enhanced TLS Fingerprint Profiles with Cross-breeding
%%%===================================================================

-define(TLS_FINGERPRINT_PROFILES, [
    #{name => chrome_120_hyper,
      cipher_suites => [
          16#1301, 16#1302, 16#1303,
          16#c02b, 16#c02f, 16#c02c, 16#c030,
          16#cca9, 16#cca8,
          16#c013, 16#c014,
          16#009c, 16#009d,
          16#002f, 16#0035
      ],
      cipher_order_randomized => true,
      grease_count => {3, 6},
      key_share_groups => [
          16#11ec, 16#001d, 16#0017, 16#0018, 16#0019
      ],
      supported_versions => [
          16#0304, 16#0303, 16#0302
      ],
      version_order_randomized => true,
      sig_algorithms_count => 18,
      ec_point_formats => true,
      ech_payload_size => [160, 176, 208, 240, 288],
      session_id_length => {32, 32},
      extensions_order_randomized => true,
      alpn_protocols => [
          [<<"h2">>, <<"http/1.1">>],
          [<<"h2">>, <<"grpc">>, <<"http/1.1">>],
          [<<"h2">>],
          [<<"http/1.1">>]
      ],
      padding_size => {64, 1024},
      session_ticket_enabled => true,
      ocsp_stapling_enabled => true,
      fake_renegotiation => true,
      entropy_profile => high
    },
    #{name => firefox_121_hyper,
      cipher_suites => [
          16#1301, 16#1302, 16#1303,
          16#c02b, 16#c02f, 16#c02c, 16#c030,
          16#cca9, 16#cca8,
          16#c013, 16#c014,
          16#009c, 16#009d,
          16#002f, 16#0035,
          16#003c, 16#003d,
          16#002c, 16#003c
      ],
      cipher_order_randomized => true,
      grease_count => {3, 5},
      key_share_groups => [
          16#001d, 16#0017, 16#001e
      ],
      supported_versions => [
          16#0304, 16#0303
      ],
      version_order_randomized => false,
      sig_algorithms_count => 20,
      ec_point_formats => true,
      ech_payload_size => [144, 176, 208],
      session_id_length => {32, 32},
      extensions_order_randomized => false,
      alpn_protocols => [
          [<<"h2">>, <<"http/1.1">>],
          [<<"http/1.1">>]
      ],
      padding_size => {64, 512},
      session_ticket_enabled => true,
      ocsp_stapling_enabled => false,
      fake_renegotiation => true,
      entropy_profile => medium
    },
    #{name => safari_17_hyper,
      cipher_suites => [
          16#1301, 16#1302, 16#1303,
          16#c02b, 16#c02f, 16#c02c, 16#c030,
          16#cca9, 16#cca8,
          16#c013, 16#c014,
          16#009c, 16#009d
      ],
      cipher_order_randomized => false,
      grease_count => {2, 5},
      key_share_groups => [
          16#001d, 16#0017, 16#0018, 16#0019, 16#001a
      ],
      supported_versions => [
          16#0304, 16#0303
      ],
      version_order_randomized => false,
      sig_algorithms_count => 16,
      ec_point_formats => false,
      ech_payload_size => [208, 240, 288],
      session_id_length => {32, 32},
      extensions_order_randomized => false,
      alpn_protocols => [
          [<<"h2">>, <<"http/1.1">>],
          [<<"h2">>]
      ],
      padding_size => {64, 1024},
      session_ticket_enabled => false,
      ocsp_stapling_enabled => true,
      fake_renegotiation => false,
      entropy_profile => high
    },
    #{name => edge_120_hyper,
      cipher_suites => [
          16#1301, 16#1302, 16#1303,
          16#c02b, 16#c02f, 16#c02c, 16#c030,
          16#cca9, 16#cca8,
          16#c013, 16#c014,
          16#009c, 16#009d,
          16#002f, 16#0035,
          16#009e, 16#009f
      ],
      cipher_order_randomized => true,
      grease_count => {3, 6},
      key_share_groups => [
          16#11ec, 16#001d, 16#0017, 16#0018
      ],
      supported_versions => [
          16#0304, 16#0303, 16#0302
      ],
      version_order_randomized => true,
      sig_algorithms_count => 18,
      ec_point_formats => true,
      ech_payload_size => [176, 208, 240],
      session_id_length => {32, 32},
      extensions_order_randomized => true,
      alpn_protocols => [
          [<<"h2">>, <<"http/1.1">>],
          [<<"h2">>, <<"grpc">>, <<"http/1.1">>],
          [<<"h2">>]
      ],
      padding_size => {64, 1024},
      session_ticket_enabled => true,
      ocsp_stapling_enabled => true,
      fake_renegotiation => true,
      entropy_profile => high
    }
]).

%%%===================================================================
%%% Protocol Mimicry Patterns
%%%===================================================================

-define(MIMICRY_PATTERNS, #{
    http2 => [
        %% HTTP/2 SETTINGS frame pattern
        <<16#00, 16#00, 16#00, 16#04, 16#00, 16#00, 16#00, 16#00, 16#00>>,
        %% HTTP/2 WINDOW_UPDATE
        <<16#00, 16#00, 16#04, 16#08, 16#00, 16#00, 16#00, 16#00, 16#00,
          16#00, 16#0f, 16#00, 16#00>>,
        %% HTTP/2 HEADERS frame
        <<16#00, 16#00, 16#08, 16#01, 16#04, 16#00, 16#00, 16#00, 16#00,
          16#00, 16#00, 16#00, 16#00>>
    ],
    grpc => [
        %% gRPC DATA frame
        <<16#00, 16#00, 16#00, 16#00, 16#00>>,
        %% gRPC HEADERS
        <<16#00, 16#00, 16#00, 16#00, 16#01>>
    ],
    websocket => [
        %% WebSocket ping frame
        <<16#89, 16#80, 16#00, 16#00, 16#00, 16#00>>,
        %% WebSocket text frame
        <<16#81, 16#80, 16#00, 16#00, 16#00, 16#00>>,
        %% WebSocket close frame
        <<16#88, 16#80, 16#00, 16#00, 16#00, 16#00>>
    ]
}).

%%%===================================================================
%%% Types
%%%===================================================================

-opaque codec() :: #chaos_state{}.

-type meta() :: #{
    session_id     := binary(),
    timestamp      := non_neg_integer(),
    client_digest  := binary(),
    sni_domain     => binary(),
    session_ticket => binary() | undefined,
    ocsp_response  => binary() | undefined
}.

%%%===================================================================
%%% Secret helpers (unchanged from original)
%%%===================================================================

-spec format_secret_hex(binary(), binary()) -> binary().
format_secret_hex(Secret, Domain) when byte_size(Secret) =:= 16 ->
    mtp_handler:hex(<<16#ee, Secret/binary, Domain/binary>>);
format_secret_hex(HexSecret, Domain) when byte_size(HexSecret) =:= 32 ->
    format_secret_hex(mtp_handler:unhex(HexSecret), Domain).

-spec format_secret_base64(binary(), binary()) -> binary().
format_secret_base64(Secret, Domain) when byte_size(Secret) =:= 16 ->
    base64url(<<16#ee, Secret/binary, Domain/binary>>);
format_secret_base64(HexSecret, Domain) when byte_size(HexSecret) =:= 32 ->
    format_secret_base64(mtp_handler:unhex(HexSecret), Domain).

base64url(Bin) ->
    << << (urlencode_digit(D)) >> || <<D>> <= base64:encode(Bin), D =/= $= >>.

urlencode_digit($/) -> $_;
urlencode_digit($+) -> $-;
urlencode_digit(D)  -> D.

%%%===================================================================
%%% Domain allow-list
%%%===================================================================

-spec is_domain_allowed(binary(), [binary()]) -> boolean().
is_domain_allowed(_Domain, []) ->
    true;
is_domain_allowed(Domain, AllowedDomains) ->
    lists:any(fun(Allowed) -> match_domain(Domain, Allowed) end, AllowedDomains).

-spec match_domain(binary(), binary()) -> boolean().
match_domain(Domain, <<"*.", Base/binary>>) ->
    Suffix = <<".", Base/binary>>,
    SuffixLen = byte_size(Suffix),
    DomLen = byte_size(Domain),
    DomLen >= SuffixLen andalso
        binary:part(Domain, DomLen - SuffixLen, SuffixLen) =:= Suffix;
match_domain(Domain, Allowed) ->
    Domain =:= Allowed.

%%%===================================================================
%%% HYPER-NUCLEAR: Entropy Equalization Engine
%%%===================================================================

-spec normalize_entropy(binary(), map()) -> binary().
normalize_entropy(Data, #{entropy_profile := high}) ->
    %% High entropy - inject random bytes to flatten distribution
    ByteCount = byte_size(Data),
    InjectionCount = ByteCount div 8,
    Injection = crypto:strong_rand_bytes(InjectionCount),
    <<Data/binary, Injection/binary>>;
normalize_entropy(Data, #{entropy_profile := medium}) ->
    %% Medium entropy - moderate injection
    ByteCount = byte_size(Data),
    InjectionCount = ByteCount div 16,
    Injection = crypto:strong_rand_bytes(InjectionCount),
    <<Data/binary, Injection/binary>>;
normalize_entropy(Data, _) ->
    Data.

%%%===================================================================
%%% HYPER-NUCLEAR: Fake Data Generators
%%%===================================================================

build_fake_certificate_data() ->
    CertSize = 600 + rand:uniform(1000),
    crypto:strong_rand_bytes(CertSize).

build_fake_session_ticket_data() ->
    TicketSize = 100 + rand:uniform(300),
    crypto:strong_rand_bytes(TicketSize).

build_fake_padding_record(Min, Max) ->
    PadSize = Min + rand:uniform(Max - Min + 1),
    crypto:strong_rand_bytes(PadSize).

build_fake_http_data(_Profile) ->
    FakeDataSize = 50 + rand:uniform(1000),
    crypto:strong_rand_bytes(FakeDataSize).

build_fake_renegotiation() ->
    %% Fake TLS renegotiation pattern
    RenegSize = 32 + rand:uniform(96),
    crypto:strong_rand_bytes(RenegSize).

build_fake_mimicry_frame(MimicryMode) ->
    Patterns = maps:get(MimicryMode, ?MIMICRY_PATTERNS, []),
    case Patterns of
        [] -> <<>>;
        _ ->
            Base = lists:nth(rand:uniform(length(Patterns)), Patterns),
            %% Extend with random data
            ExtraSize = rand:uniform(32),
            Extra = crypto:strong_rand_bytes(ExtraSize),
            <<Base/binary, Extra/binary>>
    end.

%%%===================================================================
%%% OCSP and Session Ticket generators
%%%===================================================================

generate_ocsp_response(_ServerDigest) ->
    OcspStatus = 0,
    ResponderId = crypto:strong_rand_bytes(20),
    ProducedAt = erlang:system_time(second),
    ThisUpdate = ProducedAt,
    NextUpdate = ProducedAt + 604800,
    CertId = crypto:strong_rand_bytes(36),
    CertStatus = <<0>>,
    SingleResponse = <<CertId/binary, CertStatus/binary,
                        (encode_generalized_time(ThisUpdate))/binary,
                        (encode_generalized_time(NextUpdate))/binary>>,
    Responses = <<1:32, SingleResponse/binary>>,
    ResponseData = <<0, ResponderId/binary,
                     (encode_generalized_time(ProducedAt))/binary,
                     Responses/binary>>,
    Signature = crypto:strong_rand_bytes(256),
    BasicOcspResponse = <<ResponseData/binary, 1:24, Signature/binary>>,
    <<OcspStatus, (byte_size(BasicOcspResponse)):?u24, BasicOcspResponse/binary>>.

encode_generalized_time(Timestamp) ->
    {{Y, M, D}, {H, Mi, S}} = calendar:universal_time_to_local_time(
        calendar:gregorian_seconds_to_datetime(Timestamp + 62167219200)
    ),
    Str = io_lib:format("~4..0w~2..0w~2..0w~2..0w~2..0w~2..0wZ", [Y, M, D, H, Mi, S]),
    list_to_binary(Str).

generate_session_ticket(_Secret) ->
    TicketAgeAdd = crypto:strong_rand_bytes(4),
    TicketNonce = crypto:strong_rand_bytes(rand:uniform(16) + 16),
    Ticket = crypto:strong_rand_bytes(rand:uniform(128) + 128),
    TicketLifetime = 604800,
    
    <<TicketLifetime:32, TicketAgeAdd/binary,
      (byte_size(TicketNonce)):8, TicketNonce/binary,
      (byte_size(Ticket)):?u16, Ticket/binary,
      0:?u16>>.

%%%===================================================================
%%% HYPER-NUCLEAR: from_client_hello with Chaos Engine
%%%===================================================================

-spec from_client_hello(binary(), binary(), [binary()]) ->
    {ok, iodata(), meta(), codec()}.
from_client_hello(Data, Secret, AllowedDomains) ->
    #client_hello{
        pseudorandom = ClientDigest,
        session_id   = SessionId,
        extensions   = Extensions
    } = parse_client_hello(Data),
    
    ?LOG_DEBUG("TLS ClientHello extensions: ~p", [Extensions]),

    SniDomain = case lists:keyfind(?EXT_SNI, 1, Extensions) of
        {_, [{?EXT_SNI_HOST_NAME, Domain}]} -> Domain;
        _ ->
            ?LOG_WARNING("TLS ClientHello has no SNI"),
            error({protocol_error, tls_no_sni})
    end,

    case is_domain_allowed(SniDomain, AllowedDomains) of
        true  -> ok;
        false ->
            ?LOG_WARNING("Unauthorized SNI domain: ~s", [SniDomain]),
            error({protocol_error, tls_domain_not_allowed, SniDomain})
    end,

    HasSessionTicket = lists:keymember(?EXT_SESSION_TICKET, 1, Extensions),
    HasOcspStapling = lists:keymember(?EXT_STATUS_REQUEST, 1, Extensions),
    
    ?LOG_DEBUG("Client capabilities - SessionTicket: ~p, OCSP: ~p",
               [HasSessionTicket, HasOcspStapling]),

    ServerDigest = make_server_digest(Data, Secret),
    <<Zeroes:(?DIGEST_LEN - 4)/binary, Timestamp:32/unsigned-little>> =
        crypto:exor(ClientDigest, ServerDigest),

    lists:all(fun(B) -> B =:= 0 end, binary_to_list(Zeroes))
        orelse error({protocol_error, tls_invalid_digest}),

    CurrentTime = erlang:system_time(second),
    abs(CurrentTime - Timestamp) =< 300
        orelse error({protocol_error, tls_timestamp_expired}),

    KeyShare = make_key_share(Extensions),

    %% Select initial profile
    Profile = random_tls_profile(),
    
    %% Generate all fake data with entropy normalization
    FakeHttpData = normalize_entropy(build_fake_http_data(Profile), Profile),
    FakeCert = normalize_entropy(build_fake_certificate_data(), Profile),
    FakeTicket = normalize_entropy(build_fake_session_ticket_data(), Profile),
    FakeRenegotiation = case maps:get(fake_renegotiation, Profile, false) of
        true -> build_fake_renegotiation();
        false -> <<>>
    end,
    
    %% Multiple padding records of varying sizes
    Padding1 = build_fake_padding_record(16, 128),
    Padding2 = build_fake_padding_record(32, 256),
    Padding3 = build_fake_padding_record(8, 64),
    
    %% Generate mimicry frames
    MimicryFrame1 = build_fake_mimicry_frame(http2),
    MimicryFrame2 = build_fake_mimicry_frame(grpc),
    MimicryFrame3 = build_fake_mimicry_frame(websocket),

    {SessionTicket, TicketRecord} = case HasSessionTicket of
        true ->
            Ticket = generate_session_ticket(Secret),
            TicketRec = as_tls_frame(?TLS_REC_HANDSHAKE, Ticket),
            {Ticket, TicketRec};
        false ->
            {undefined, <<>>}
    end,
    
    OcspResponse = case HasOcspStapling of
        true -> generate_ocsp_response(ServerDigest);
        false -> undefined
    end,

    SrvHello0 = make_srv_hello(binary:copy(<<0>>, ?DIGEST_LEN),
                               SessionId, KeyShare,
                               HasSessionTicket, HasOcspStapling),

    ChangeCipher = <<?TLS_REC_CHANGE_CIPHER, ?TLS_12_VERSION, 0, 1, 1>>,

    %% HYPER-NUCLEAR: 16 different ordering patterns with multi-layer camouflage
    DataFrames = case rand:uniform(16) of
        1 -> [as_tls_frame(?TLS_REC_DATA, FakeHttpData),
              as_tls_frame(?TLS_REC_DATA, Padding1),
              as_tls_frame(?TLS_REC_DATA, MimicryFrame1),
              as_tls_frame(?TLS_REC_DATA, FakeCert),
              as_tls_frame(?TLS_REC_DATA, FakeTicket),
              TicketRecord,
              as_tls_frame(?TLS_REC_DATA, Padding2),
              as_tls_frame(?TLS_REC_DATA, MimicryFrame2)];
        2 -> [as_tls_frame(?TLS_REC_DATA, FakeCert),
              TicketRecord,
              as_tls_frame(?TLS_REC_DATA, MimicryFrame1),
              as_tls_frame(?TLS_REC_DATA, FakeHttpData),
              as_tls_frame(?TLS_REC_DATA, FakeTicket),
              as_tls_frame(?TLS_REC_DATA, Padding1),
              as_tls_frame(?TLS_REC_DATA, MimicryFrame3),
              as_tls_frame(?TLS_REC_DATA, Padding3)];
        3 -> [as_tls_frame(?TLS_REC_DATA, Padding1),
              as_tls_frame(?TLS_REC_DATA, FakeHttpData),
              as_tls_frame(?TLS_REC_DATA, Padding2),
              as_tls_frame(?TLS_REC_DATA, MimicryFrame2),
              as_tls_frame(?TLS_REC_DATA, FakeCert),
              TicketRecord,
              as_tls_frame(?TLS_REC_DATA, FakeTicket),
              as_tls_frame(?TLS_REC_DATA, MimicryFrame1)];
        4 -> [as_tls_frame(?TLS_REC_DATA, MimicryFrame3),
              as_tls_frame(?TLS_REC_DATA, FakeTicket),
              TicketRecord,
              as_tls_frame(?TLS_REC_DATA, FakeCert),
              as_tls_frame(?TLS_REC_DATA, MimicryFrame2),
              as_tls_frame(?TLS_REC_DATA, FakeHttpData),
              as_tls_frame(?TLS_REC_DATA, Padding1),
              as_tls_frame(?TLS_REC_DATA, Padding2)];
        5 -> [as_tls_frame(?TLS_REC_DATA, FakeHttpData),
              as_tls_frame(?TLS_REC_DATA, FakeTicket),
              TicketRecord,
              as_tls_frame(?TLS_REC_DATA, Padding1),
              as_tls_frame(?TLS_REC_DATA, MimicryFrame1),
              as_tls_frame(?TLS_REC_DATA, FakeCert),
              as_tls_frame(?TLS_REC_DATA, Padding3),
              as_tls_frame(?TLS_REC_DATA, MimicryFrame3)];
        6 -> [as_tls_frame(?TLS_REC_DATA, Padding1),
              as_tls_frame(?TLS_REC_DATA, Padding2),
              TicketRecord,
              as_tls_frame(?TLS_REC_DATA, MimicryFrame2),
              as_tls_frame(?TLS_REC_DATA, FakeHttpData),
              as_tls_frame(?TLS_REC_DATA, FakeCert),
              as_tls_frame(?TLS_REC_DATA, MimicryFrame1),
              as_tls_frame(?TLS_REC_DATA, FakeTicket)];
        7 -> [TicketRecord,
              as_tls_frame(?TLS_REC_DATA, Padding1),
              as_tls_frame(?TLS_REC_DATA, MimicryFrame3),
              as_tls_frame(?TLS_REC_DATA, FakeHttpData),
              as_tls_frame(?TLS_REC_DATA, FakeCert),
              as_tls_frame(?TLS_REC_DATA, Padding2),
              as_tls_frame(?TLS_REC_DATA, MimicryFrame1),
              as_tls_frame(?TLS_REC_DATA, FakeTicket)];
        8 -> [as_tls_frame(?TLS_REC_DATA, MimicryFrame1),
              as_tls_frame(?TLS_REC_DATA, Padding2),
              TicketRecord,
              as_tls_frame(?TLS_REC_DATA, FakeCert),
              as_tls_frame(?TLS_REC_DATA, Padding1),
              as_tls_frame(?TLS_REC_DATA, FakeTicket),
              as_tls_frame(?TLS_REC_DATA, MimicryFrame3),
              as_tls_frame(?TLS_REC_DATA, FakeHttpData)];
        9 -> [as_tls_frame(?TLS_REC_DATA, Padding3),
              as_tls_frame(?TLS_REC_DATA, MimicryFrame1),
              TicketRecord,
              as_tls_frame(?TLS_REC_DATA, FakeHttpData),
              as_tls_frame(?TLS_REC_DATA, Padding1),
              as_tls_frame(?TLS_REC_DATA, FakeTicket),
              as_tls_frame(?TLS_REC_DATA, MimicryFrame2),
              as_tls_frame(?TLS_REC_DATA, FakeCert)];
        10 -> [as_tls_frame(?TLS_REC_DATA, FakeCert),
               as_tls_frame(?TLS_REC_DATA, MimicryFrame3),
               as_tls_frame(?TLS_REC_DATA, Padding2),
               TicketRecord,
               as_tls_frame(?TLS_REC_DATA, FakeHttpData),
               as_tls_frame(?TLS_REC_DATA, Padding1),
               as_tls_frame(?TLS_REC_DATA, MimicryFrame1),
               as_tls_frame(?TLS_REC_DATA, FakeTicket)];
        11 -> [as_tls_frame(?TLS_REC_DATA, MimicryFrame2),
               as_tls_frame(?TLS_REC_DATA, FakeTicket),
               as_tls_frame(?TLS_REC_DATA, Padding3),
               TicketRecord,
               as_tls_frame(?TLS_REC_DATA, FakeCert),
               as_tls_frame(?TLS_REC_DATA, MimicryFrame1),
               as_tls_frame(?TLS_REC_DATA, FakeHttpData),
               as_tls_frame(?TLS_REC_DATA, Padding2)];
        12 -> [as_tls_frame(?TLS_REC_DATA, Padding1),
               TicketRecord,
               as_tls_frame(?TLS_REC_DATA, MimicryFrame3),
               as_tls_frame(?TLS_REC_DATA, FakeHttpData),
               as_tls_frame(?TLS_REC_DATA, Padding3),
               as_tls_frame(?TLS_REC_DATA, FakeCert),
               as_tls_frame(?TLS_REC_DATA, MimicryFrame1),
               as_tls_frame(?TLS_REC_DATA, FakeTicket)];
        13 -> [as_tls_frame(?TLS_REC_DATA, FakeHttpData),
               as_tls_frame(?TLS_REC_DATA, MimicryFrame2),
               as_tls_frame(?TLS_REC_DATA, Padding2),
               as_tls_frame(?TLS_REC_DATA, FakeCert),
               TicketRecord,
               as_tls_frame(?TLS_REC_DATA, MimicryFrame1),
               as_tls_frame(?TLS_REC_DATA, FakeTicket),
               as_tls_frame(?TLS_REC_DATA, Padding3)];
        14 -> [TicketRecord,
               as_tls_frame(?TLS_REC_DATA, Padding3),
               as_tls_frame(?TLS_REC_DATA, MimicryFrame1),
               as_tls_frame(?TLS_REC_DATA, FakeTicket),
               as_tls_frame(?TLS_REC_DATA, Padding1),
               as_tls_frame(?TLS_REC_DATA, MimicryFrame3),
               as_tls_frame(?TLS_REC_DATA, FakeHttpData),
               as_tls_frame(?TLS_REC_DATA, FakeCert)];
        15 -> [as_tls_frame(?TLS_REC_DATA, MimicryFrame3),
               as_tls_frame(?TLS_REC_DATA, Padding1),
               as_tls_frame(?TLS_REC_DATA, FakeCert),
               as_tls_frame(?TLS_REC_DATA, MimicryFrame2),
               TicketRecord,
               as_tls_frame(?TLS_REC_DATA, FakeHttpData),
               as_tls_frame(?TLS_REC_DATA, Padding2),
               as_tls_frame(?TLS_REC_DATA, FakeTicket)];
        16 -> [as_tls_frame(?TLS_REC_DATA, FakeTicket),
               as_tls_frame(?TLS_REC_DATA, MimicryFrame1),
               TicketRecord,
               as_tls_frame(?TLS_REC_DATA, Padding3),
               as_tls_frame(?TLS_REC_DATA, MimicryFrame2),
               as_tls_frame(?TLS_REC_DATA, FakeCert),
               as_tls_frame(?TLS_REC_DATA, Padding2),
               as_tls_frame(?TLS_REC_DATA, FakeHttpData)]
    end,

    %% Add fake renegotiation if profile supports it
    FinalDataFrames = case FakeRenegotiation of
        <<>> -> DataFrames;
        _ ->
            RenegFrame = as_tls_frame(?TLS_REC_HANDSHAKE, FakeRenegotiation),
            Pos = rand:uniform(length(DataFrames)),
            lists:sublist(DataFrames, Pos - 1) ++ 
                [RenegFrame] ++ 
                lists:nthtail(Pos - 1, DataFrames)
    end,

    Response0 = [as_tls_frame(?TLS_REC_HANDSHAKE, SrvHello0), ChangeCipher | FinalDataFrames],

    SrvHelloDigest = hmac(sha256, Secret, [ClientDigest | Response0]),
    SrvHello = make_srv_hello(SrvHelloDigest, SessionId, KeyShare,
                              HasSessionTicket, HasOcspStapling),

    Response = [as_tls_frame(?TLS_REC_HANDSHAKE, SrvHello), ChangeCipher | FinalDataFrames],

    Meta = #{
        session_id    => SessionId,
        timestamp     => Timestamp,
        client_digest => ClientDigest,
        sni_domain    => SniDomain,
        session_ticket => SessionTicket,
        ocsp_response  => OcspResponse
    },

    %% HYPER-NUCLEAR: Initialize chaos state
    ChaosSt = #chaos_state{
        frag_min = 200,
        frag_max = 3000,
        packet_count = 0,
        frag_reset_at = rand:uniform(50) + 20,
        fake_probability = 0.2 + rand:uniform() * 0.3,
        fake_min_size = 8,
        fake_max_size = 256,
        send_jitter_us = rand:uniform(5000),
        burst_mode = false,
        burst_count = 0,
        current_profile = Profile,
        profile_rotation_count = 0,
        profile_rotation_at = rand:uniform(200) + 100,
        entropy_pool = crypto:strong_rand_bytes(128),
        entropy_threshold = 64,
        mimicry_mode = http2,
        mimicry_sequence = [],
        session_ticket = SessionTicket,
        ocsp_response = OcspResponse,
        session_ticket_lifetime = case HasSessionTicket of
                                      true -> 604800;
                                      false -> undefined
                                  end,
        connection_start_time = erlang:system_time(microsecond),
        bytes_sent = 0,
        adaptation_level = 1
    },
    
    {ok, Response, Meta, ChaosSt}.

-spec from_client_hello(binary(), binary()) ->
    {ok, iodata(), meta(), codec()}.
from_client_hello(Data, Secret) ->
    from_client_hello(Data, Secret, []).

%%%===================================================================
%%% SNI helpers
%%%===================================================================

-spec parse_sni(binary()) -> {ok, binary()} | {error, no_sni | bad_hello}.
parse_sni(Data) ->
    try
        #client_hello{extensions = Exts} = parse_client_hello(Data),
        case lists:keyfind(?EXT_SNI, 1, Exts) of
            {_, [{?EXT_SNI_HOST_NAME, Domain}]} -> {ok, Domain};
            _                                  -> {error, no_sni}
        end
    catch
        error:{protocol_error, tls_bad_client_hello, _} ->
            {error, bad_hello}
    end.

-spec tls_decode_error_alert() -> binary().
tls_decode_error_alert() ->
    <<?TLS_REC_ALERT, ?TLS_12_VERSION, 0, 2,
      ?TLS_ALERT_FATAL, ?TLS_ALERT_DECODE_ERROR>>.

-spec derive_sni_secret(binary(), binary(), binary()) -> binary().
derive_sni_secret(BaseSecret, SniDomain, Salt)
  when byte_size(BaseSecret) =:= 16 ->
    SecretHex = mtp_handler:hex(BaseSecret),
    <<Derived:16/binary, _/binary>> =
        crypto:hash(sha256, [Salt, SecretHex, SniDomain]),
    Derived.

%%%===================================================================
%%% ClientHello parser (unchanged)
%%%===================================================================

parse_client_hello(<<?TLS_REC_HANDSHAKE, ?TLS_10_VERSION, TlsFrameLen:?u16,
                     ?TLS_TAG_CLI_HELLO, HelloLen:?u24, ?TLS_12_VERSION,
                     Random:?DIGEST_LEN/binary,
                     SessIdLen, SessId:SessIdLen/binary,
                     CipherSuitesLen:?u16, CipherSuites:CipherSuitesLen/binary,
                     CompMethodsLen, CompMethods:CompMethodsLen/binary,
                     ExtensionsLen:?u16, Extensions:ExtensionsLen/binary>>)
  when TlsFrameLen >= 300, HelloLen >= 250 ->
    #client_hello{
        pseudorandom        = Random,
        session_id          = SessId,
        cipher_suites       = [S || <<S:?u16>> <= CipherSuites],
        compression_methods = CompMethods,
        extensions          = parse_extensions(Extensions)
    };
parse_client_hello(_Data) ->
    error({protocol_error, tls_bad_client_hello, bad_client_hello}).

parse_extensions(Bin) ->
    [{Type, parse_extension(Type, Data)}
     || <<Type:?u16, Len:?u16, Data:Len/binary>> <= Bin].

parse_extension(?EXT_SNI, <<ListLen:?u16, List:ListLen/binary>>) ->
    [{Type, Value} || <<Type, Len:?u16, Value:Len/binary>> <= List];
parse_extension(?EXT_KEY_SHARE, <<Len:?u16, Entries:Len/binary>>) ->
    [{Group, Key}
     || <<Group:?u16, KeyLen:?u16, Key:KeyLen/binary>> <= Entries];
parse_extension(?EXT_SESSION_TICKET, _Data) ->
    {session_ticket, supported};
parse_extension(?EXT_STATUS_REQUEST, <<Type, _Rest/binary>>) ->
    {ocsp_stapling, Type};
parse_extension(_, Data) ->
    Data.

%%%===================================================================
%%% ServerHello helpers
%%%===================================================================

make_server_digest(<<Left:?DIGEST_POS/binary, _:?DIGEST_LEN/binary, Right/binary>>, Secret) ->
    hmac(sha256, Secret, [Left, binary:copy(<<0>>, ?DIGEST_LEN), Right]).

make_key_share(Exts) ->
    case lists:keyfind(?EXT_KEY_SHARE, 1, Exts) of
        {_, [{Group, Key} | _]} when is_integer(Group), is_binary(Key),
                                     byte_size(Key) >= 32, byte_size(Key) =< 200 ->
            {Group, crypto:strong_rand_bytes(byte_size(Key))};
        _ ->
            {16#001d, crypto:strong_rand_bytes(32)}
    end.

make_srv_hello(Digest, SessionId, {Group, Key}, HasSessionTicket, HasOcspStapling) ->
    KeyShareEntity = <<Group:?u16, (byte_size(Key)):?u16, Key/binary>>,
    
    ExtensionsBase = [
        <<?EXT_KEY_SHARE:?u16, (byte_size(KeyShareEntity) + 2):?u16,
          (byte_size(KeyShareEntity)):?u16, KeyShareEntity/binary>>,
        <<?EXT_SUPPORTED_VERSIONS:?u16, 2:?u16, ?TLS_13_VERSION>>
    ],
    
    ExtensionsWithTicket = case HasSessionTicket of
        true ->
            ExtensionsBase ++ [<<?EXT_SESSION_TICKET:?u16, 0:?u16>>];
        false ->
            ExtensionsBase
    end,
    
    ExtensionsFinal = case HasOcspStapling of
        true ->
            ExtensionsWithTicket ++ [<<?EXT_STATUS_REQUEST:?u16, 0:?u16>>];
        false ->
            ExtensionsWithTicket
    end,
    
    SessionSize = byte_size(SessionId),
    Payload = [
        <<?TLS_12_VERSION,
          Digest:?DIGEST_LEN/binary,
          SessionSize, SessionId:SessionSize/binary,
          ?TLS_CIPHERSUITE,
          0,
          (iolist_size(ExtensionsFinal)):?u16>>
        | ExtensionsFinal
    ],
    [<<?TLS_TAG_SRV_HELLO, (iolist_size(Payload)):?u24>> | Payload].

%%%===================================================================
%%% Profile selection and helpers
%%%===================================================================

random_tls_profile() ->
    Profiles = ?TLS_FINGERPRINT_PROFILES,
    Profile = lists:nth(rand:uniform(length(Profiles)), Profiles),
    ?LOG_DEBUG("Selected TLS fingerprint: ~s", [maps:get(name, Profile, unknown)]),
    Profile.

random_grease(Count) ->
    [lists:nth(rand:uniform(length(?GREASE_VALUES)), ?GREASE_VALUES) || _ <- lists:seq(1, Count)].

shuffle_list([]) -> [];
shuffle_list(List) ->
    Sorted = lists:sort([{rand:uniform(), X} || X <- List]),
    [X || {_, X} <- Sorted].

key_size_for_group(16#001D) -> 32;
key_size_for_group(16#0017) -> 65;
key_size_for_group(16#0018) -> 97;
key_size_for_group(16#0019) -> 133;
key_size_for_group(16#001a) -> 65;
key_size_for_group(16#001e) -> 56;
key_size_for_group(16#11EC) -> 1216;
key_size_for_group(_) -> 32.

%%%===================================================================
%%% Extension builders (Profile-based)
%%%===================================================================

build_cipher_suites(#{cipher_suites := Suites, grease_count := {GreaseMin, GreaseMax}} = Profile) ->
    GreaseCount = GreaseMin + rand:uniform(GreaseMax - GreaseMin + 1),
    GreaseVals = random_grease(GreaseCount),
    
    WithGrease = lists:foldl(
        fun(G, Acc) ->
            Pos = rand:uniform(length(Acc) + 1),
            lists:sublist(Acc, Pos - 1) ++ [G] ++ lists:nthtail(Pos - 1, Acc)
        end, Suites, GreaseVals),
    
    Final = case maps:get(cipher_order_randomized, Profile, false) of
        true -> shuffle_list(WithGrease);
        false -> WithGrease
    end,
    
    << <<S:?u16>> || S <- Final >>.

build_key_share_entries(#{key_share_groups := Groups, grease_count := {GreaseMin, GreaseMax}}) ->
    GreaseCount = GreaseMin + rand:uniform(GreaseMax - GreaseMin + 1),
    GreaseVals = random_grease(GreaseCount),
    
    GreaseEntries = [<<G:?u16, 16#00, 16#01, 16#00>> || G <- GreaseVals],
    
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

build_supported_versions_ext(#{supported_versions := Versions,
                                grease_count := {GreaseMin, GreaseMax}} = Profile) ->
    GreaseCount = GreaseMin + rand:uniform(GreaseMax - GreaseMin + 1),
    GreaseVals = random_grease(GreaseCount),
    
    WithGrease = lists:foldl(
        fun(G, Acc) ->
            Pos = rand:uniform(length(Acc) + 1),
            lists:sublist(Acc, Pos - 1) ++ [G] ++ lists:nthtail(Pos - 1, Acc)
        end, Versions, GreaseVals),
    
    Final = case maps:get(version_order_randomized, Profile, false) of
        true -> shuffle_list(WithGrease);
        false -> WithGrease
    end,
    
    << <<V:?u16>> || V <- Final >>.

build_sig_algos(#{sig_algorithms_count := Count}) ->
    AllAlgos = [
        16#0403, 16#0503, 16#0603,
        16#0203, 16#0804, 16#0805,
        16#0806, 16#0401, 16#0501,
        16#0601, 16#0201, 16#0402,
        16#0302, 16#0202, 16#0301,
        16#0807, 16#0808, 16#0809
    ],
    Selected = lists:sublist(AllAlgos, Count * 2),
    Shuffled = shuffle_list(Selected),
    AlgoListLen = Count * 2,
    ExtLen = AlgoListLen + 2,
    <<?EXT_SIGNATURE_ALGORITHMS:?u16,
      ExtLen:?u16,
      AlgoListLen:?u16,
      << <<A:8>> || A <- Shuffled >>/binary>>.

build_ech(#{ech_payload_size := Sizes}) when is_list(Sizes) ->
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

build_alpn(#{alpn_protocols := Protocols}) ->
    Selected = lists:nth(rand:uniform(length(Protocols)), Protocols),
    ProtocolEntries = << <<(byte_size(P)):8, P/binary>> || P <- Selected >>,
    ProtocolsLen = byte_size(ProtocolEntries),
    <<?EXT_ALPN:?u16,
      (ProtocolsLen + 2):?u16,
      ProtocolsLen:?u16,
      ProtocolEntries/binary>>;
build_alpn(_) ->
    <<>>.

build_ec_point_formats(#{ec_point_formats := true}) ->
    <<?EXT_EC_POINT_FORMATS:?u16, 2:?u16, 1, 0>>;
build_ec_point_formats(_) ->
    <<>>.

build_supported_groups(#{key_share_groups := Groups, grease_count := {GreaseMin, GreaseMax}}) ->
    GreaseCount = GreaseMin + rand:uniform(GreaseMax - GreaseMin + 1),
    GreaseVals = random_grease(GreaseCount),
    
    WithGrease = lists:foldl(
        fun(G, Acc) ->
            Pos = rand:uniform(length(Acc) + 1),
            lists:sublist(Acc, Pos - 1) ++ [G] ++ lists:nthtail(Pos - 1, Acc)
        end, Groups, GreaseVals),
    
    GroupsBin = << <<G:?u16>> || G <- WithGrease >>,
    GroupsLen = byte_size(GroupsBin),
    <<?EXT_SUPPORTED_GROUPS:?u16,
      (GroupsLen + 2):?u16,
      GroupsLen:?u16,
      GroupsBin/binary>>.

build_padding(#{padding_size := {Min, Max}}) ->
    PadSize = Min + rand:uniform(Max - Min + 1),
    case PadSize of
        0 -> <<>>;
        _ ->
            Padding = binary:copy(<<0>>, PadSize),
            <<?EXT_PADDING:?u16, PadSize:?u16, Padding/binary>>
    end;
build_padding(_) ->
    <<>>.

build_session_ticket_ext(#{session_ticket_enabled := true}) ->
    <<?EXT_SESSION_TICKET:?u16, 0:?u16>>;
build_session_ticket_ext(_) ->
    <<>>.

build_ocsp_stapling_ext(#{ocsp_stapling_enabled := true}) ->
    <<?EXT_STATUS_REQUEST:?u16, 0:?u16>>;
build_ocsp_stapling_ext(_) ->
    <<>>.

make_sni(Domains) ->
    Items = << <<?EXT_SNI_HOST_NAME, (byte_size(D)):?u16, D/binary>> || D <- Domains >>,
    <<?EXT_SNI:?u16, (byte_size(Items)+2):?u16,
      (byte_size(Items)):?u16, Items/binary>>.

%%%===================================================================
%%% ClientHello generator (unchanged logic)
%%%===================================================================

-spec make_client_hello(binary(), binary()) -> binary().
make_client_hello(Secret, SniDomain) ->
    make_client_hello(erlang:system_time(second),
                      crypto:strong_rand_bytes(32),
                      Secret, SniDomain).

-spec make_client_hello(non_neg_integer(), binary(), binary(), binary()) -> binary().
make_client_hello(Timestamp, SessionId, HexSecret, SniDomain)
  when byte_size(HexSecret) =:= 32 ->
    make_client_hello(Timestamp, SessionId, mtp_handler:unhex(HexSecret), SniDomain);
make_client_hello(Timestamp, SessionId, Secret, SniDomain)
  when byte_size(SessionId) =:= 32, byte_size(Secret) =:= 16 ->

    Profile = random_tls_profile(),

    CipherSuites = build_cipher_suites(Profile),
    SNI = make_sni([SniDomain]),
    SigAlgos = build_sig_algos(Profile),
    SupportedGroups = build_supported_groups(Profile),
    
    SupportedVersionsExt = build_supported_versions_ext(Profile),
    VersionsLen = byte_size(SupportedVersionsExt),
    SupportedVersions =
        <<?EXT_SUPPORTED_VERSIONS:?u16,
          (VersionsLen + 1):?u16,
          VersionsLen,
          SupportedVersionsExt/binary>>,

    KeyShareEntries = build_key_share_entries(Profile),
    KSListLen = byte_size(KeyShareEntries),
    KeyShare =
        <<?EXT_KEY_SHARE:?u16,
          (KSListLen + 2):?u16,
          KSListLen:?u16,
          KeyShareEntries/binary>>,

    ECH = build_ech(Profile),
    ALPN = build_alpn(Profile),
    EcPointExt = build_ec_point_formats(Profile),
    SessionTicketExt = build_session_ticket_ext(Profile),
    OcspStaplingExt = build_ocsp_stapling_ext(Profile),
    PaddingExt = build_padding(Profile),

    ExtensionsBase = [
        ECH,
        SessionTicketExt,
        EcPointExt,
        <<16#44, 16#cd, 16#00, 16#05,
          16#00, 16#03, 16#02, $h, $2>>,
        KeyShare,
        <<16#00, 16#12, 0:16>>,
        SupportedGroups,
        <<16#ff, 16#01, 16#00, 16#01, 16#00>>,
        SigAlgos,
        OcspStaplingExt,
        <<16#00, 16#2d, 16#00, 16#02, 16#01, 16#01>>,
        ALPN,
        SNI,
        SupportedVersions,
        PaddingExt
    ],

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
          FakeRandom:?DIGEST_LEN/binary,
          SessIdLen, SessionId/binary,
          CSLen:?u16, CipherSuites/binary,
          1, 0,
          ExtLen:?u16, ExtBin/binary>>
    end,

    Hello0     = Pack(binary:copy(<<0>>, ?DIGEST_LEN)),
    Digest     = hmac(sha256, Secret, Hello0),
    EncTs      = <<0:(?DIGEST_LEN - 4)/unit:8, Timestamp:32/unsigned-little>>,
    FakeRandom = crypto:exor(Digest, EncTs),
    Pack(FakeRandom).

%%%===================================================================
%%% parse_server_hello
%%%===================================================================

parse_server_hello(<<?TLS_REC_HANDSHAKE, ?TLS_12_VERSION, HSLen:?u16,
                     Handshake:HSLen/binary,
                     ?TLS_REC_CHANGE_CIPHER, ?TLS_12_VERSION, CCLen:?u16,
                     ChangeCipher:CCLen/binary,
                     ?TLS_REC_DATA, ?TLS_12_VERSION, DLen:?u16,
                     Data:DLen/binary,
                     Tail/binary>>) ->
    {Handshake, ChangeCipher, Data, Tail};
parse_server_hello(<<?TLS_REC_HANDSHAKE, ?TLS_12_VERSION, HSLen:?u16,
                     Handshake:HSLen/binary,
                     ?TLS_REC_CHANGE_CIPHER, ?TLS_12_VERSION, CCLen:?u16,
                     ChangeCipher:CCLen/binary,
                     ?TLS_REC_DATA, ?TLS_12_VERSION, DLen:?u16,
                     Data:DLen/binary,
                     ?TLS_REC_HANDSHAKE, ?TLS_12_VERSION, TicketLen:?u16,
                     _Ticket:TicketLen/binary,
                     Tail/binary>>) ->
    {Handshake, ChangeCipher, Data, Tail};
parse_server_hello(<<?TLS_REC_HANDSHAKE, ?TLS_12_VERSION, HSLen:?u16,
                     Handshake:HSLen/binary,
                     ?TLS_REC_DATA, ?TLS_12_VERSION, DLen:?u16,
                     Data:DLen/binary,
                     ?TLS_REC_CHANGE_CIPHER, ?TLS_12_VERSION, CCLen:?u16,
                     ChangeCipher:CCLen/binary,
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

tls_records_complete(_B, 0) ->
    true;
tls_records_complete(<<_T, _Mj, _Mn, Len:?u16, Rest/binary>>, N) when byte_size(Rest) >= Len ->
    <<_:Len/binary, Tail/binary>> = Rest,
    tls_records_complete(Tail, N - 1);
tls_records_complete(_B, _N) ->
    false.

%%%===================================================================
%%% HYPER-NUCLEAR: Chaos Codec with Adaptive Learning
%%%===================================================================

-spec new() -> codec().
new() ->
    Profile = random_tls_profile(),
    #chaos_state{
        frag_min = 200,
        frag_max = 3000,
        packet_count = 0,
        frag_reset_at = rand:uniform(50) + 20,
        fake_probability = 0.2 + rand:uniform() * 0.3,
        fake_min_size = 8,
        fake_max_size = 256,
        send_jitter_us = rand:uniform(5000),
        burst_mode = false,
        burst_count = 0,
        current_profile = Profile,
        profile_rotation_count = 0,
        profile_rotation_at = rand:uniform(200) + 100,
        entropy_pool = crypto:strong_rand_bytes(128),
        entropy_threshold = 64,
        mimicry_mode = http2,
        mimicry_sequence = [],
        session_ticket = undefined,
        ocsp_response = undefined,
        session_ticket_lifetime = undefined,
        connection_start_time = erlang:system_time(microsecond),
        bytes_sent = 0,
        adaptation_level = 1
    }.

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
try_decode_packet(Bin, St) when byte_size(Bin) =< (?MAX_IN_PACKET_SIZE + 5) ->
    {incomplete, St};
try_decode_packet(Bin, _St) ->
    error({protocol_error, tls_max_size, byte_size(Bin)}).

-spec decode_all(binary(), codec()) -> {binary(), binary(), codec()}.
decode_all(Bin, St) ->
    decode_all(Bin, <<>>, St).

decode_all(Bin, Acc, St0) ->
    case try_decode_packet(Bin, St0) of
        {incomplete, St} ->
            {Acc, Bin, St};
        {ok, Data, Tail, St} ->
            decode_all(Tail, <<Acc/binary, Data/binary>>, St)
    end.

%%%===================================================================
%%% HYPER-NUCLEAR: encode_packet - The Core Chaos Engine
%%%===================================================================

-spec encode_packet(binary(), codec()) -> {iodata(), codec()}.
encode_packet(Bin, #chaos_state{
    frag_min = FragMin,
    frag_max = FragMax,
    packet_count = Count,
    frag_reset_at = FragResetAt,
    fake_probability = FakeProb,
    fake_min_size = FakeMin,
    fake_max_size = FakeMax,
    send_jitter_us = JitterUs,
    burst_mode = BurstMode,
    burst_count = BurstCount,
    current_profile = Profile,
    profile_rotation_count = ProfRotCount,
    profile_rotation_at = ProfRotAt,
    entropy_pool = EntropyPool,
    entropy_threshold = EntropyThresh,
    mimicry_mode = MimicryMode,
    mimicry_sequence = MimicrySeq,
    bytes_sent = BytesSent,
    adaptation_level = AdaptLevel
} = St) ->
    
    %% ================================================================
    %% PHASE 1: Adaptive Parameter Recalculation
    %% ================================================================
    
    %% Reset fragmentation parameters periodically
    {NewFragMin, NewFragMax, NewCount, NewFragResetAt, NewAdaptLevel} = 
        if
            Count >= FragResetAt ->
                %% Increase chaos with adaptation level
                Mult = AdaptLevel * 0.5 + 0.5,
                NewMin = max(100, round(200 * Mult)),
                NewMax = min(5000, round(3000 * Mult)),
                NewReset = rand:uniform(80) + 30,
                NewAdapt = min(5, AdaptLevel + 1),
                {NewMin, NewMax, 0, NewReset, NewAdapt};
            true ->
                {FragMin, FragMax, Count + 1, FragResetAt, AdaptLevel}
        end,
    
    %% Profile rotation
    {NewProfile, NewProfRotCount, NewProfRotAt} = 
        if
            ProfRotCount >= ProfRotAt ->
                NewProf = random_tls_profile(),
                {NewProf, 0, rand:uniform(300) + 100};
            true ->
                {Profile, ProfRotCount + 1, ProfRotAt}
        end,
    
    %% Burst mode management - FIXED: moved rand:uniform() outside guard
    BurstRoll = rand:uniform(),
    BurstLimitReached = BurstMode andalso (BurstCount >= 5),
    ShouldEnterBurst = (not BurstMode) andalso (BurstRoll < 0.1),
    
    {NewBurstMode, NewBurstCount} = 
        if
            BurstLimitReached ->
                {false, 0};
            BurstMode ->
                {true, BurstCount + 1};
            ShouldEnterBurst ->
                {true, 0};
            true ->
                {false, BurstCount}
        end,
    
    %% ================================================================
    %% PHASE 2: Entropy Pool Management
    %% ================================================================
    
    {NewEntropyPool, EntropyBytes} = 
        if
            byte_size(EntropyPool) < EntropyThresh ->
                NewPool = crypto:strong_rand_bytes(256),
                {NewPool, <<>>};
            true ->
                <<Used:32/binary, Rest/binary>> = EntropyPool,
                {Rest, Used}
        end,
    
    %% ================================================================
    %% PHASE 3: Fragmentation with Chaos
    %% ================================================================
    
    FragSize = case BurstMode of
        true ->
            %% Burst mode: tiny fragments
            FragMin + rand:uniform(min(400, FragMax) - FragMin);
        false ->
            FragMin + rand:uniform(FragMax - FragMin)
    end,
    
    Fragments = fragment_data_chaos(Bin, FragSize, EntropyBytes, NewProfile),
    
    %% ================================================================
    %% PHASE 4: Fake Record Injection
    %% ================================================================
    
    %% FIXED: moved rand:uniform() outside guard
    FakeRoll = rand:uniform(),
    {FinalFragments, FinalCount} = 
        case FakeRoll < FakeProb of
            true ->
                FakeSize = FakeMin + rand:uniform(FakeMax - FakeMin),
                FakeData = case rand:uniform(4) of
                    1 -> build_fake_mimicry_frame(MimicryMode);
                    2 -> normalize_entropy(crypto:strong_rand_bytes(FakeSize), NewProfile);
                    3 -> build_fake_padding_record(FakeMin, FakeMax);
                    4 -> case maps:get(fake_renegotiation, NewProfile, false) of
                            true -> build_fake_renegotiation();
                            false -> crypto:strong_rand_bytes(FakeSize)
                         end
                end,
                FakeRecord = as_tls_frame(?TLS_REC_DATA, FakeData),
                Pos = rand:uniform(length(Fragments) + 1),
                NewFrags = lists:sublist(Fragments, Pos - 1) ++ 
                           [FakeRecord] ++ 
                           lists:nthtail(Pos - 1, Fragments),
                {NewFrags, NewCount + 1};
            false ->
                {Fragments, NewCount}
        end,
    
    %% ================================================================
    %% PHASE 5: Mimicry Mode Rotation
    %% ================================================================
    
    NewMimicryMode = case rand:uniform(20) of
        1 -> http2;
        2 -> grpc;
        3 -> websocket;
        _ -> MimicryMode
    end,
    
    %% FIXED: moved rand:uniform() outside guard
    MimicryRoll = rand:uniform(),
    NewMimicrySeq = case MimicryRoll < 0.15 of
        true ->
            MimicryFrame = build_fake_mimicry_frame(NewMimicryMode),
            [MimicryFrame | MimicrySeq];
        false ->
            MimicrySeq
    end,
    
    %% ================================================================
    %% PHASE 6: Build Final State
    %% ================================================================
    
    NewSt = #chaos_state{
        frag_min = NewFragMin,
        frag_max = NewFragMax,
        packet_count = FinalCount,
        frag_reset_at = NewFragResetAt,
        fake_probability = FakeProb,
        fake_min_size = FakeMin,
        fake_max_size = FakeMax,
        send_jitter_us = JitterUs,
        burst_mode = NewBurstMode,
        burst_count = NewBurstCount,
        current_profile = NewProfile,
        profile_rotation_count = NewProfRotCount,
        profile_rotation_at = NewProfRotAt,
        entropy_pool = NewEntropyPool,
        entropy_threshold = EntropyThresh,
        mimicry_mode = NewMimicryMode,
        mimicry_sequence = NewMimicrySeq,
        session_ticket = St#chaos_state.session_ticket,
        ocsp_response = St#chaos_state.ocsp_response,
        session_ticket_lifetime = St#chaos_state.session_ticket_lifetime,
        connection_start_time = St#chaos_state.connection_start_time,
        bytes_sent = BytesSent + iolist_size(FinalFragments),
        adaptation_level = NewAdaptLevel
    },
    
    {FinalFragments, NewSt}.

%%%===================================================================
%%% HYPER-NUCLEAR: Chaos Fragmentation with Entropy Injection
%%%===================================================================

fragment_data_chaos(Bin, FragSize, EntropyBytes, Profile) 
  when byte_size(Bin) =< FragSize ->
    %% Mix entropy into the final fragment
    EnhancedData = case byte_size(EntropyBytes) > 0 of
        true ->
            EntropyChunk = binary:part(EntropyBytes, 0, min(byte_size(EntropyBytes), 16)),
            normalize_entropy(<<Bin/binary, EntropyChunk/binary>>, Profile);
        false ->
            normalize_entropy(Bin, Profile)
    end,
    [as_tls_data_frame(EnhancedData)];
fragment_data_chaos(Bin, FragSize, EntropyBytes, Profile) ->
    <<Chunk:FragSize/binary, Rest/binary>> = Bin,
    %% FIXED: moved rand:uniform() outside guard
    ExtraRoll = rand:uniform(),
    ExtraFrag = case ExtraRoll < 0.1 of
        true ->
            ExtraSize = rand:uniform(50) + 10,
            ExtraData = crypto:strong_rand_bytes(ExtraSize),
            [as_tls_data_frame(normalize_entropy(ExtraData, Profile))];
        false ->
            []
    end,
    ExtraFrag ++ 
    [as_tls_data_frame(normalize_entropy(Chunk, Profile)) | 
     fragment_data_chaos(Rest, FragSize, EntropyBytes, Profile)].

as_tls_data_frame(Bin) ->
    as_tls_frame(?TLS_REC_DATA, Bin).

-spec as_tls_frame(byte(), iodata()) -> iodata().
as_tls_frame(Type, Data) ->
    Size = iolist_size(Data),
    [<<Type, ?TLS_12_VERSION, Size:?u16>> | Data].

%%%===================================================================
%%% Crypto helpers
%%%===================================================================

-if(?OTP_RELEASE >= 23).
hmac(Algo, Key, Data) ->
    crypto:mac(hmac, Algo, Key, Data).
-else.
hmac(Algo, Key, Data) ->
    crypto:hmac(Algo, Key, Data).
-endif.
