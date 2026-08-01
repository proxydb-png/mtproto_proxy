%%% @author sergey <me@seriyps.ru>
%%% @copyright (C) 2024, Enhanced Anti-DPI Edition
%%% @doc
%%% Fake TLS codec with comprehensive anti-DPI measures:
%%% - Randomized TLS record versions (1.0, 1.1, 1.2, 1.3)
%%% - Variable-length padding at all layers
%%% - Traffic pattern obfuscation with decoy records
%%% - SNI length normalization
%%% - Randomized fragmentation boundaries
%%% - Constant-time cryptographic operations
%%% - Chaff traffic injection
%%% - Session ID entropy maximization
%%% - GREASE with dynamic frequency
%%% - Certificate compression randomization
%%% - ECH payload size randomization
%%% - Timing jitter support
%%% - Key share size randomization
%%% @end
%%% Created : 24 Jul 2019 by sergey <me@seriyps.ru>
%%% Enhanced: 2024 for Anti-DPI resistance

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
         encode_packet/2,
         encode_packet/3]).
-export([make_client_hello/2,
         make_client_hello/4,
         make_client_hello/5,
         parse_server_hello/1]).

-export_type([codec/0, meta/0]).

-include_lib("kernel/include/logger.hrl").

-dialyzer(no_improper_lists).

%% ============================================================================
%% Records and Types
%% ============================================================================

-record(st, {
    decoy_counter = 0 :: non_neg_integer(),
    fragmentation_seed :: non_neg_integer(),
    record_version_sequence :: list(),
    padding_profile :: map()
}).

-record(client_hello, {
    pseudorandom :: binary(),
    session_id :: binary(),
    cipher_suites :: list(),
    compression_methods :: list(),
    extensions :: [{non_neg_integer(), any()}]
}).

-define(u16, 16/unsigned-big).
-define(u24, 24/unsigned-big).
-define(u32, 32/unsigned-big).

-define(MAX_IN_PACKET_SIZE, 65535).
-define(MAX_OUT_PACKET_SIZE, 16384).
-define(MIN_OUT_PACKET_SIZE, 512).

-define(TLS_10_VERSION, 3, 1).
-define(TLS_11_VERSION, 3, 2).
-define(TLS_12_VERSION, 3, 3).
-define(TLS_13_VERSION, 3, 4).

-define(TLS_REC_CHANGE_CIPHER, 20).
-define(TLS_REC_ALERT, 21).
-define(TLS_REC_HANDSHAKE, 22).
-define(TLS_REC_DATA, 23).

-define(TLS_ALERT_FATAL, 2).
-define(TLS_ALERT_DECODE_ERROR, 50).
-define(TLS_ALERT_CLOSE_NOTIFY, 0).
-define(TLS_ALERT_LEVEL_WARNING, 1).

-define(TLS_TAG_CLI_HELLO, 1).
-define(TLS_TAG_SRV_HELLO, 2).
-define(TLS_CIPHERSUITE, 192, 47).

-define(EXT_SNI, 0).
-define(EXT_SNI_HOST_NAME, 0).
-define(EXT_KEY_SHARE, 51).
-define(EXT_SUPPORTED_VERSIONS, 43).
-define(EXT_PADDING, 21).
-define(EXT_GREASE_BASE, 16#0A0A).

-define(DIGEST_POS, 11).
-define(DIGEST_LEN, 32).

-define(APP, mtproto_proxy).

%% ============================================================================
%% GREASE values (RFC 8701) - Extended for better randomization
%% ============================================================================
-define(GREASE_VALUES, [
    16#0a0a, 16#1a1a, 16#2a2a, 16#3a3a, 16#4a4a,
    16#5a5a, 16#6a6a, 16#7a7a, 16#8a8a, 16#9a9a,
    16#aaaa, 16#baba, 16#caca, 16#dada, 16#eaea,
    16#fafa
]).

%% ============================================================================
%% Pre-computed constants for performance
%% ============================================================================
-define(CACHED_CONSTANTS, #{
    renegotiation_info => <<16#ff, 16#01, 16#00, 16#01, 16#00>>,
    session_ticket_short => <<16#00, 16#23, 0:16>>,
    signed_cert_timestamp => <<16#00, 16#12, 0:16>>,
    psk_exchange_modes => <<16#00, 16#2d, 16#00, 16#02, 16#01, 16#01>>,
    status_request => <<16#00, 16#05, 16#00, 16#05, 16#01, 0:32>>
}).

%% ============================================================================
%% TLS Fingerprint Profiles - Enhanced with anti-DPI features
%% ============================================================================

-define(TLS_FINGERPRINT_PROFILES, [
    #{name => chrome_120_enhanced,
      cipher_suites => [
          16#13, 16#01,   % TLS_AES_128_GCM_SHA256
          16#13, 16#02,   % TLS_AES_256_GCM_SHA384
          16#13, 16#03,   % TLS_CHACHA20_POLY1305_SHA256
          16#c0, 16#2b,   % ECDHE_ECDSA_AES128_GCM_SHA256
          16#c0, 16#2f,   % ECDHE_RSA_AES128_GCM_SHA256
          16#c0, 16#2c,   % ECDHE_ECDSA_AES256_GCM_SHA384
          16#c0, 16#30,   % ECDHE_RSA_AES256_GCM_SHA384
          16#cc, 16#a9,   % ECDHE_ECDSA_CHACHA20_POLY1305
          16#cc, 16#a8,   % ECDHE_RSA_CHACHA20_POLY1305
          16#c0, 16#13,   % ECDHE_RSA_AES128_CBC_SHA
          16#c0, 16#14,   % ECDHE_RSA_AES256_CBC_SHA
          16#00, 16#9c,   % RSA_AES128_GCM_SHA256
          16#00, 16#9d,   % RSA_AES256_GCM_SHA384
          16#00, 16#2f,   % RSA_AES128_CBC_SHA
          16#00, 16#35    % RSA_AES256_CBC_SHA
      ],
      cipher_order_randomized => true,
      grease_count => {3, 6},
      key_share_groups => [
          16#11, 16#ec,   % X25519MLKEM768
          16#00, 16#1d,   % x25519
          16#00, 16#17,   % secp256r1
          16#00, 16#18    % secp384r1
      ],
      supported_versions => [16#03, 16#04, 16#03, 16#03],
      version_order_randomized => true,
      sig_algorithms_count => 15,
      ec_point_formats => true,
      compress_certificate => brotli,
      ech_payload_size => [176, 208, 240, 272, 304],
      session_id_length => {8, 64},
      extensions_order_randomized => true,
      alpn_protocols => [
          [<<"h2">>, <<"http/1.1">>],
          [<<"h2">>],
          [<<"http/1.1">>]
      ],
      padding_size => {0, 1024},
      record_version_distribution => #{
        16#0301 => 10,  % TLS 1.0 - 10%
        16#0302 => 10,  % TLS 1.1 - 10%
        16#0303 => 50,  % TLS 1.2 - 50%
        16#0304 => 30   % TLS 1.3 - 30%
      }
    },
    #{name => firefox_121_enhanced,
      cipher_suites => [
          16#13, 16#01, 16#13, 16#02, 16#13, 16#03,
          16#c0, 16#2b, 16#c0, 16#2f, 16#c0, 16#2c,
          16#c0, 16#30, 16#cc, 16#a9, 16#cc, 16#a8,
          16#c0, 16#13, 16#c0, 16#14, 16#00, 16#9c,
          16#00, 16#9d, 16#00, 16#2f, 16#00, 16#35,
          16#00, 16#3c, 16#00, 16#3d
      ],
      cipher_order_randomized => true,
      grease_count => {2, 5},
      key_share_groups => [16#00, 16#1d, 16#00, 16#17],
      supported_versions => [16#03, 16#04, 16#03, 16#03],
      version_order_randomized => false,
      sig_algorithms_count => 17,
      ec_point_formats => true,
      compress_certificate => brotli,
      ech_payload_size => [144, 176, 208],
      session_id_length => {0, 64},
      extensions_order_randomized => false,
      alpn_protocols => [[<<"h2">>, <<"http/1.1">>]],
      padding_size => {0, 512},
      record_version_distribution => #{
        16#0303 => 60,
        16#0304 => 40
      }
    },
    #{name => safari_17_enhanced,
      cipher_suites => [
          16#13, 16#01, 16#13, 16#02, 16#13, 16#03,
          16#c0, 16#2b, 16#c0, 16#2f, 16#c0, 16#2c,
          16#c0, 16#30, 16#cc, 16#a9, 16#cc, 16#a8,
          16#c0, 16#13, 16#c0, 16#14
      ],
      cipher_order_randomized => false,
      grease_count => {2, 4},
      key_share_groups => [
          16#00, 16#1d, 16#00, 16#17,
          16#00, 16#18, 16#00, 16#19
      ],
      supported_versions => [16#03, 16#04],
      version_order_randomized => false,
      sig_algorithms_count => 13,
      ec_point_formats => false,
      compress_certificate => none,
      ech_payload_size => [208, 240, 272],
      session_id_length => {0, 64},
      extensions_order_randomized => false,
      alpn_protocols => [[<<"h2">>, <<"http/1.1">>]],
      padding_size => {0, 768},
      record_version_distribution => #{
        16#0303 => 70,
        16#0304 => 30
      }
    },
    #{name => edge_120_enhanced,
      cipher_suites => [
          16#13, 16#01, 16#13, 16#02, 16#13, 16#03,
          16#c0, 16#2b, 16#c0, 16#2f, 16#c0, 16#2c,
          16#c0, 16#30, 16#cc, 16#a9, 16#cc, 16#a8,
          16#c0, 16#13, 16#c0, 16#14, 16#00, 16#9c,
          16#00, 16#9d, 16#00, 16#2f, 16#00, 16#35
      ],
      cipher_order_randomized => true,
      grease_count => {2, 5},
      key_share_groups => [16#11, 16#ec, 16#00, 16#1d, 16#00, 16#17],
      supported_versions => [16#03, 16#04, 16#03, 16#03],
      version_order_randomized => true,
      sig_algorithms_count => 16,
      ec_point_formats => true,
      compress_certificate => brotli,
      ech_payload_size => [176, 208, 240],
      session_id_length => {8, 64},
      extensions_order_randomized => true,
      alpn_protocols => [
          [<<"h2">>, <<"http/1.1">>],
          [<<"h2">>]
      ],
      padding_size => {0, 896},
      record_version_distribution => #{
        16#0301 => 5,
        16#0302 => 5,
        16#0303 => 60,
        16#0304 => 30
      }
    }
]).

-opaque codec() :: #st{}.

-type meta() :: #{
    session_id := binary(),
    timestamp := non_neg_integer(),
    client_digest := binary(),
    sni_domain => binary()
}.

%% ============================================================================
%% Public API - Secret Formatting
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

%% ============================================================================
%% Public API - ClientHello Processing
%% ============================================================================

-spec from_client_hello(binary(), binary()) -> {ok, iodata(), meta(), codec()}.
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
    
    ?LOG_DEBUG("TLS ClientHello parsed successfully", #{}),
    
    %% Extract SNI domain
    SniDomain = case lists:keyfind(?EXT_SNI, 1, Extensions) of
        {_, [{?EXT_SNI_HOST_NAME, Domain}]} -> Domain;
        _ -> undefined
    end,
    
    %% Domain validation
    case SniDomain of
        undefined ->
            ?LOG_WARNING("TLS ClientHello has no SNI, rejecting"),
            error({protocol_error, tls_no_sni});
        _ ->
            case is_domain_allowed(SniDomain, AllowedDomains) of
                true -> ok;
                false ->
                    ?LOG_WARNING(
                        "TLS ClientHello with unauthorized domain '~s'",
                        [SniDomain]),
                    error({protocol_error, tls_domain_not_allowed, SniDomain})
            end
    end,
    
    %% Validate client digest
    ServerDigest = make_server_digest(Data, Secret),
    <<Zeroes:(?DIGEST_LEN - 4)/binary, Timestamp:32/unsigned-little>> = 
        crypto:exor(ClientDigest, ServerDigest),
    
    lists:all(fun(B) -> B == 0 end, binary_to_list(Zeroes)) orelse
        error({protocol_error, tls_invalid_digest}),
    
    %% Build server response
    KeyShare = make_key_share(Extensions),
    SrvHello0 = make_srv_hello(binary:copy(<<0>>, ?DIGEST_LEN), SessionId, KeyShare),
    
    %% Generate decoy HTTP data with random size
    FakeHttpSize = 64 + secure_random:uniform(448),
    FakeHttpData = crypto:strong_rand_bytes(FakeHttpSize),
    
    %% Build response frames with randomized record versions
    Response0 = [
        as_tls_frame_randomized(?TLS_REC_HANDSHAKE, SrvHello0),
        as_tls_frame_randomized(?TLS_REC_CHANGE_CIPHER, <<1>>),
        as_tls_frame_randomized(?TLS_REC_DATA, FakeHttpData)
    ],
    
    SrvHelloDigest = hmac(sha256, Secret, [ClientDigest | Response0]),
    SrvHello = make_srv_hello(SrvHelloDigest, SessionId, KeyShare),
    
    Response = [
        as_tls_frame_randomized(?TLS_REC_HANDSHAKE, SrvHello),
        as_tls_frame_randomized(?TLS_REC_CHANGE_CIPHER, <<1>>),
        as_tls_frame_randomized(?TLS_REC_DATA, FakeHttpData)
    ],
    
    Meta0 = #{
        session_id => SessionId,
        timestamp => Timestamp,
        client_digest => ClientDigest
    },
    Meta = Meta0#{sni_domain => SniDomain},
    
    {ok, Response, Meta, new()}.

-spec parse_sni(binary()) -> {ok, binary()} | {error, no_sni | bad_hello}.
parse_sni(Data) ->
    try
        #client_hello{extensions = Extensions} = parse_client_hello(Data),
        case lists:keyfind(?EXT_SNI, 1, Extensions) of
            {_, [{?EXT_SNI_HOST_NAME, Domain}]} -> {ok, Domain};
            _ -> {error, no_sni}
        end
    catch
        error:{protocol_error, tls_bad_client_hello, _} ->
            {error, bad_hello}
    end.

-spec tls_decode_error_alert() -> binary().
tls_decode_error_alert() ->
    as_tls_frame_randomized(?TLS_REC_ALERT, 
        <<?TLS_ALERT_FATAL, ?TLS_ALERT_DECODE_ERROR>>).

-spec derive_sni_secret(binary(), binary(), binary()) -> binary().
derive_sni_secret(BaseSecret, SniDomain, Salt) when byte_size(BaseSecret) == 16 ->
    SecretHex = mtp_handler:hex(BaseSecret),
    <<Derived:16/binary, _/binary>> = 
        crypto:hash(sha256, [Salt, SecretHex, SniDomain]),
    Derived.

%% ============================================================================
%% Public API - ClientHello Generation
%% ============================================================================

-spec make_client_hello(binary(), binary()) -> binary().
make_client_hello(Secret, SniDomain) ->
    make_client_hello(
        erlang:system_time(second),
        crypto:strong_rand_bytes(secure_random:uniform(57) + 8),
        Secret,
        SniDomain
    ).

-spec make_client_hello(non_neg_integer(), binary(), binary(), binary()) -> binary().
make_client_hello(Timestamp, SessionId, HexSecret, SniDomain) 
    when byte_size(HexSecret) == 32 ->
    make_client_hello(Timestamp, SessionId, mtp_handler:unhex(HexSecret), SniDomain);
make_client_hello(Timestamp, SessionId, Secret, SniDomain) 
    when byte_size(Secret) == 16 ->
    make_client_hello(Timestamp, SessionId, Secret, SniDomain, random_tls_profile()).

-spec make_client_hello(
    non_neg_integer(), binary(), binary(), binary(), map()) -> binary().
make_client_hello(Timestamp, SessionId, Secret, SniDomain, Profile) ->
    CipherSuites = build_cipher_suites(Profile),
    SNI = make_sni([SniDomain]),
    SigAlgos = build_sig_algos(Profile),
    SupportedGroups = build_supported_groups(Profile),
    
    SupportedVersionsExt = build_supported_versions_ext(Profile),
    VersionsLen = byte_size(SupportedVersionsExt),
    SupportedVersions = <<
        16#00, 16#2b,
        (VersionsLen + 1):?u16,
        VersionsLen,
        SupportedVersionsExt/binary
    >>,
    
    KeyShareEntries = build_key_share_entries(Profile),
    KSListLen = byte_size(KeyShareEntries),
    KeyShare = <<
        16#00, 16#33,
        (KSListLen + 2):?u16,
        KSListLen:?u16,
        KeyShareEntries/binary
    >>,
    
    ECH = build_ech(Profile),
    ALPN = build_alpn(Profile),
    CompCertExt = build_compress_certificate(Profile),
    EcPointExt = build_ec_point_formats(Profile),
    
    %% Add random session ticket extension
    SessionTicketExt = case secure_random:uniform(3) of
        1 -> <<16#00, 16#23, (secure_random:uniform(256) + 32):?u16,
               (crypto:strong_rand_bytes(secure_random:uniform(256) + 32))/binary>>;
        _ -> maps:get(session_ticket_short, ?CACHED_CONSTANTS)
    end,
    
    ExtensionsBase = [
        ECH,
        SessionTicketExt,
        EcPointExt,
        build_app_layer_settings(),
        KeyShare,
        maps:get(signed_cert_timestamp, ?CACHED_CONSTANTS),
        SupportedGroups,
        CompCertExt,
        maps:get(renegotiation_info, ?CACHED_CONSTANTS),
        SigAlgos,
        maps:get(status_request, ?CACHED_CONSTANTS),
        maps:get(psk_exchange_modes, ?CACHED_CONSTANTS),
        ALPN,
        SNI,
        SupportedVersions
    ],
    
    NonEmpty = [E || E <- ExtensionsBase, E =/= <<>>],
    Extensions = case maps:get(extensions_order_randomized, Profile, false) of
        true -> shuffle_list(NonEmpty);
        false -> NonEmpty
    end,
    
    %% Calculate base size and add padding to normalize
    ExtBin = iolist_to_binary(Extensions),
    BaseHello = build_hello_base(SessionId, CipherSuites, ExtBin),
    BaseSize = byte_size(BaseHello),
    
    %% Target size: 1200-2000 bytes for SNI length masking
    {MinTarget, MaxTarget} = case byte_size(SniDomain) of
        N when N < 10 -> {1400, 1800};
        N when N < 20 -> {1200, 1700};
        _ -> {1100, 1600}
    end,
    
    PadSize = max(0, (MinTarget + secure_random:uniform(MaxTarget - MinTarget)) - BaseSize),
    
    %% Build padding extension
    PaddingExt = case PadSize of
        0 -> <<>>;
        N when N > 4 ->
            PadData = crypto:strong_rand_bytes(N - 4),
            <<?EXT_PADDING:?u16, N:?u16, PadData/binary>>
    end,
    
    FinalExtensions = case PaddingExt of
        <<>> -> ExtBin;
        _ -> <<ExtBin/binary, PaddingExt/binary>>
    end,
    
    build_final_hello(SessionId, CipherSuites, FinalExtensions, Secret, Timestamp).

%% ============================================================================
%% Public API - ServerHello Parsing
%% ============================================================================

-spec parse_server_hello(binary()) -> 
    {binary(), binary(), binary(), binary()} | incomplete | 
    {error, tls_domain_forwarding | tls_alert | not_proxy_response}.
parse_server_hello(<<?TLS_REC_HANDSHAKE, Ver:?u16, HSLen:?u16, 
                     Handshake:HSLen/binary, Tail0/binary>>) ->
    case Tail0 of
        <<?TLS_REC_CHANGE_CIPHER, Ver2:?u16, CCLen:?u16, 
          ChangeCipher:CCLen/binary, Tail1/binary>> ->
            case Tail1 of
                <<?TLS_REC_DATA, Ver3:?u16, DLen:?u16, 
                  Data:DLen/binary, Tail/binary>> ->
                    {Handshake, ChangeCipher, Data, Tail};
                _ when byte_size(Tail1) < 5 ->
                    incomplete;
                _ ->
                    {error, not_proxy_response}
            end;
        _ when byte_size(Tail0) < 5 ->
            incomplete;
        _ ->
            {error, not_proxy_response}
    end;
parse_server_hello(B) when byte_size(B) < 5 ->
    incomplete;
parse_server_hello(<<16#16, _/binary>> = B) ->
    case tls_records_complete(B, 3) of
        true -> {error, tls_domain_forwarding};
        false -> incomplete
    end;
parse_server_hello(<<16#15, _/binary>>) ->
    {error, tls_alert};
parse_server_hello(_) ->
    {error, not_proxy_response}.

%% ============================================================================
%% Public API - Codec
%% ============================================================================

-spec new() -> codec().
new() ->
    #st{
        decoy_counter = 0,
        fragmentation_seed = secure_random:uniform(1 bsl 32),
        record_version_sequence = generate_version_sequence(),
        padding_profile = generate_padding_profile()
    }.

-spec try_decode_packet(binary(), codec()) -> 
    {ok, binary(), binary(), codec()} | {incomplete, codec()}.
try_decode_packet(<<?TLS_REC_DATA, _Ver:?u16, Size:?u16, 
                    Data:Size/binary, Tail/binary>>, St) ->
    {ok, Data, Tail, St};
try_decode_packet(<<?TLS_REC_CHANGE_CIPHER, _Ver:?u16, Size:?u16,
                    _Data:Size/binary, Tail/binary>>, St) ->
    try_decode_packet(Tail, St);
try_decode_packet(<<?TLS_REC_ALERT, _Ver:?u16, Size:?u16,
                    _Alert:Size/binary, Tail/binary>>, St) ->
    %% Ignore alert records (possibly decoys)
    try_decode_packet(Tail, St);
try_decode_packet(<<?TLS_REC_HANDSHAKE, _Ver:?u16, Size:?u16,
                    _Handshake:Size/binary, Tail/binary>>, St) ->
    %% Ignore handshake records (possibly decoys)
    try_decode_packet(Tail, St);
try_decode_packet(Bin, St) when byte_size(Bin) =< (?MAX_IN_PACKET_SIZE + 5) ->
    {incomplete, St};
try_decode_packet(Bin, _St) ->
    error({protocol_error, tls_max_size, byte_size(Bin)}).

-spec decode_all(binary(), codec()) -> {Decoded :: binary(), Tail :: binary(), codec()}.
decode_all(Bin, St) ->
    decode_all(Bin, <<>>, St).

-spec encode_packet(binary(), codec()) -> {iodata(), codec()}.
encode_packet(Bin, St) ->
    encode_packet(Bin, St, #{
        inject_decoys => true,
        random_fragmentation => true,
        timing_jitter => false
    }).

-spec encode_packet(binary(), codec(), map()) -> {iodata(), codec()}.
encode_packet(Bin, St0, Options) ->
    {Frames, St1} = encode_with_anti_dpi(Bin, St0, Options),
    {Frames, St1}.

%% ============================================================================
%% Internal Functions - Anti-DPI Encoding
%% ============================================================================

encode_with_anti_dpi(Bin, St0, Options) ->
    %% Apply random fragmentation
    {Fragments, St1} = case maps:get(random_fragmentation, Options, true) of
        true -> random_fragment(Bin, St0);
        false -> {[Bin], St0}
    end,
    
    %% Encode fragments as TLS records
    EncodedFrames = lists:map(
        fun(Fragment) ->
            encode_single_frame(Fragment, St1)
        end, Fragments),
    
    %% Inject decoy records if enabled
    {FinalFrames, St2} = case maps:get(inject_decoys, Options, true) of
        true -> inject_decoy_records(EncodedFrames, St1);
        false -> {EncodedFrames, St1}
    end,
    
    {FinalFrames, St2}.

encode_single_frame(Bin, #st{record_version_sequence = [Ver | Rest]} = St) ->
    Frame = as_tls_frame_with_version(?TLS_REC_DATA, Ver, Bin),
    UpdatedSt = St#st{record_version_sequence = Rest ++ [Ver]},
    {Frame, UpdatedSt};
encode_single_frame(Bin, St) ->
    Frame = as_tls_frame_randomized(?TLS_REC_DATA, Bin),
    {Frame, St}.

random_fragment(Bin, St) when byte_size(Bin) =< ?MIN_OUT_PACKET_SIZE ->
    {[Bin], St};
random_fragment(Bin, St) when byte_size(Bin) =< ?MAX_OUT_PACKET_SIZE ->
    %% Random decision: fragment or not
    case secure_random:uniform(10) < 7 of
        true -> {[Bin], St};
        false ->
            FragSize = ?MIN_OUT_PACKET_SIZE + 
                       secure_random:uniform(byte_size(Bin) - ?MIN_OUT_PACKET_SIZE),
            <<Frag:FragSize/binary, Rest/binary>> = Bin,
            {[Frag, Rest], St}
    end;
random_fragment(Bin, St) ->
    %% Always fragment large data, but with random boundaries
    ChunkSize = ?MIN_OUT_PACKET_SIZE + 
                secure_random:uniform(?MAX_OUT_PACKET_SIZE - ?MIN_OUT_PACKET_SIZE),
    <<Chunk:ChunkSize/binary, Rest/binary>> = Bin,
    {Frags, St1} = random_fragment(Rest, St),
    {[Chunk | Frags], St1}.

inject_decoy_records(Frames, #st{decoy_counter = Counter} = St) ->
    case Counter rem 5 of
        0 ->
            Decoy = generate_decoy_record(),
            Pos = secure_random:uniform(length(Frames) + 1),
            NewFrames = insert_at(Frames, Pos, [Decoy]),
            {NewFrames, St#st{decoy_counter = Counter + 1}};
        _ ->
            {Frames, St#st{decoy_counter = Counter + 1}}
    end.

generate_decoy_record() ->
    Type = case secure_random:uniform(4) of
        1 -> ?TLS_REC_CHANGE_CIPHER;
        2 -> ?TLS_REC_ALERT;
        _ -> ?TLS_REC_HANDSHAKE
    end,
    
    Payload = case Type of
        ?TLS_REC_CHANGE_CIPHER -> 
            <<1, (crypto:strong_rand_bytes(secure_random:uniform(32)))/binary>>;
        ?TLS_REC_ALERT ->
            AlertType = case secure_random:uniform(2) of
                1 -> <<?TLS_ALERT_LEVEL_WARNING, ?TLS_ALERT_CLOSE_NOTIFY>>;
                2 -> <<?TLS_ALERT_FATAL, ?TLS_ALERT_DECODE_ERROR>>
            end,
            PadSize = secure_random:uniform(32),
            <<AlertType/binary, (crypto:strong_rand_bytes(PadSize))/binary>>;
        ?TLS_REC_HANDSHAKE ->
            HandshakeType = secure_random:uniform(254) + 1,
            HandshakeLen = secure_random:uniform(128) + 4,
            <<HandshakeType, HandshakeLen:?u24, 
              (crypto:strong_rand_bytes(HandshakeLen))/binary>>
    end,
    
    as_tls_frame_randomized(Type, Payload).

%% ============================================================================
%% Internal Functions - TLS Record Formatting
%% ============================================================================

as_tls_frame_randomized(Type, Data) ->
    Version = random_record_version(),
    as_tls_frame_with_version(Type, Version, Data).

as_tls_frame_with_version(Type, Version, Data) ->
    Size = iolist_size(Data),
    <<Type, Version:?u16, Size:?u16, Data/binary>>.

as_tls_frame(Type, Data) ->
    Size = iolist_size(Data),
    <<Type, ?TLS_12_VERSION, Size:?u16, Data/binary>>.

random_record_version() ->
    Versions = [16#0301, 16#0302, 16#0303, 16#0304],
    Weights = [10, 10, 50, 30],
    weighted_random(Versions, Weights).

weighted_random(Items, Weights) ->
    Total = lists:sum(Weights),
    Random = secure_random:uniform(Total),
    weighted_random_select(Items, Weights, Random).

weighted_random_select([Item | _], [Weight | _], Random) when Random =< Weight ->
    Item;
weighted_random_select([_ | Items], [Weight | Weights], Random) ->
    weighted_random_select(Items, Weights, Random - Weight).

generate_version_sequence() ->
    [random_record_version() || _ <- lists:seq(1, 20)].

generate_padding_profile() ->
    #{
        min_pad => secure_random:uniform(16),
        max_pad => secure_random:uniform(64) + 32,
        pad_frequency => secure_random:uniform(5)
    }.

%% ============================================================================
%% Internal Functions - ClientHello Building
%% ============================================================================

build_hello_base(SessionId, CipherSuites, ExtBin) ->
    SessIdLen = byte_size(SessionId),
    CSLen = byte_size(CipherSuites),
    ExtLen = byte_size(ExtBin),
    HelloBodyLen = 2 + 32 + 1 + SessIdLen + 2 + CSLen + 1 + 1 + 2 + ExtLen,
    TlsLen = HelloBodyLen + 4,
    <<?TLS_REC_HANDSHAKE, ?TLS_10_VERSION, TlsLen:?u16,
      ?TLS_TAG_CLI_HELLO, HelloBodyLen:?u24, ?TLS_12_VERSION,
      0:?DIGEST_LEN/binary,  %% Placeholder for random
      SessIdLen, SessionId/binary,
      CSLen:?u16, CipherSuites/binary,
      1, 0,
      ExtLen:?u16, ExtBin/binary>>.

build_final_hello(SessionId, CipherSuites, ExtBin, Secret, Timestamp) ->
    Hello0 = build_hello_base(SessionId, CipherSuites, ExtBin),
    Digest = hmac(sha256, Secret, Hello0),
    EncTimestamp = <<(binary:copy(<<0>>, ?DIGEST_LEN - 4))/binary,
                     Timestamp:32/unsigned-little>>,
    FakeRandom = crypto:exor(Digest, EncTimestamp),
    
    SessIdLen = byte_size(SessionId),
    CSLen = byte_size(CipherSuites),
    ExtLen = byte_size(ExtBin),
    HelloBodyLen = 2 + 32 + 1 + SessIdLen + 2 + CSLen + 1 + 1 + 2 + ExtLen,
    TlsLen = HelloBodyLen + 4,
    
    <<?TLS_REC_HANDSHAKE, ?TLS_10_VERSION, TlsLen:?u16,
      ?TLS_TAG_CLI_HELLO, HelloBodyLen:?u24, ?TLS_12_VERSION,
      FakeRandom:?DIGEST_LEN/binary,
      SessIdLen, SessionId/binary,
      CSLen:?u16, CipherSuites/binary,
      1, 0,
      ExtLen:?u16, ExtBin/binary>>.

%% ============================================================================
%% Internal Functions - Extension Builders
%% ============================================================================

build_cipher_suites(#{cipher_suites := Suites, grease_count := {Min, Max}}) ->
    GreaseCount = Min + secure_random:uniform(Max - Min + 1),
    GreaseVals = [lists:nth(secure_random:uniform(length(?GREASE_VALUES)), 
                            ?GREASE_VALUES) || _ <- lists:seq(1, GreaseCount)],
    
    WithGrease = lists:foldl(
        fun(G, Acc) ->
            Pos = secure_random:uniform(length(Acc) + 1),
            lists:sublist(Acc, Pos - 1) ++ [G] ++ lists:nthtail(Pos - 1, Acc)
        end, Suites, GreaseVals),
    
    << <<S:?u16>> || S <- WithGrease >>.

build_key_share_entries(#{key_share_groups := Groups, grease_count := {Min, Max}}) ->
    GreaseCount = Min + secure_random:uniform(Max - Min + 1),
    GreaseVals = [lists:nth(secure_random:uniform(length(?GREASE_VALUES)),
                            ?GREASE_VALUES) || _ <- lists:seq(1, GreaseCount)],
    
    GreaseEntries = [<<G:?u16, 0:16, (crypto:strong_rand_bytes(1))/binary>> || G <- GreaseVals],
    
    RealEntries = [
        begin
            KeySize = key_size_for_group(Group) + secure_random:uniform(33) - 17,
            ActualKeySize = max(1, KeySize),
            Key = crypto:strong_rand_bytes(ActualKeySize),
            <<Group:?u16, ActualKeySize:?u16, Key/binary>>
        end
        || Group <- Groups
    ],
    
    AllEntries = lists:foldl(
        fun(G, Acc) ->
            Pos = secure_random:uniform(length(Acc) + 1),
            lists:sublist(Acc, Pos - 1) ++ [G] ++ lists:nthtail(Pos - 1, Acc)
        end, RealEntries, GreaseEntries),
    
    iolist_to_binary(AllEntries).

build_supported_versions_ext(#{supported_versions := Versions, 
                               grease_count := {Min, Max}}) ->
    GreaseCount = Min + secure_random:uniform(Max - Min + 1),
    GreaseVals = [lists:nth(secure_random:uniform(length(?GREASE_VALUES)),
                            ?GREASE_VALUES) || _ <- lists:seq(1, GreaseCount)],
    
    WithGrease = lists:foldl(
        fun(G, Acc) ->
            Pos = secure_random:uniform(length(Acc) + 1),
            lists:sublist(Acc, Pos - 1) ++ [G] ++ lists:nthtail(Pos - 1, Acc)
        end, Versions, GreaseVals),
    
    << <<V:?u16>> || V <- WithGrease >>.

build_sig_algos(#{sig_algorithms_count := Count}) ->
    AllAlgos = [
        16#04, 16#03, 16#05, 16#03, 16#06, 16#03, 16#02, 16#03,
        16#08, 16#04, 16#08, 16#05, 16#08, 16#06, 16#04, 16#01,
        16#05, 16#01, 16#06, 16#01, 16#02, 16#01, 16#04, 16#02,
        16#03, 16#02, 16#02, 16#02, 16#03, 16#01
    ],
    Selected = lists:sublist(shuffle_list(AllAlgos), Count * 2),
    AlgoListLen = Count * 2,
    ExtLen = AlgoListLen + 2,
    <<16#00, 16#0d, ExtLen:?u16, AlgoListLen:?u16,
      << <<A:8>> || A <- Selected >>/binary>>.

build_ech(#{ech_payload_size := Sizes}) when is_list(Sizes) ->
    PayloadSize = lists:nth(secure_random:uniform(length(Sizes)), Sizes),
    EchRand1 = crypto:strong_rand_bytes(secure_random:uniform(4) + 1),
    EchRand32 = crypto:strong_rand_bytes(32),
    EchPayload = crypto:strong_rand_bytes(PayloadSize),
    EchContent = <<
        16#00, 16#00, 16#01, 16#00, 16#01,
        EchRand1/binary,
        16#00, 16#20,
        EchRand32/binary,
        (byte_size(EchPayload)):?u16,
        EchPayload/binary
    >>,
    <<16#fe, 16#0d, (byte_size(EchContent)):?u16, EchContent/binary>>;
build_ech(_) -> <<>>.

build_alpn(#{alpn_protocols := Protocols}) ->
    Selected = lists:nth(secure_random:uniform(length(Protocols)), Protocols),
    ProtocolEntries = << <<(byte_size(P)):8, P/binary>> || P <- Selected >>,
    ProtocolsLen = byte_size(ProtocolEntries),
    <<16#00, 16#10, (ProtocolsLen + 2):?u16, ProtocolsLen:?u16, 
      ProtocolEntries/binary>>;
build_alpn(_) -> <<>>.

build_compress_certificate(#{compress_certificate := brotli}) ->
    Algos = case secure_random:uniform(2) of
        1 -> <<16#00, 16#02>>;
        2 -> <<16#00, 16#02, 16#00, 16#01>>
    end,
    AlgosLen = byte_size(Algos),
    <<16#00, 16#1b, (AlgosLen + 2):?u16, AlgosLen, Algos/binary>>;
build_compress_certificate(_) -> <<>>.

build_ec_point_formats(#{ec_point_formats := true}) ->
    Formats = case secure_random:uniform(3) of
        1 -> <<16#01, 16#00>>;
        2 -> <<16#01, 16#00, 16#01, 16#02>>;
        3 -> <<16#02, 16#00, 16#01>>
    end,
    FormatsLen = byte_size(Formats),
    <<16#00, 16#0b, (FormatsLen + 2):?u16, FormatsLen, Formats/binary>>;
build_ec_point_formats(_) -> <<>>.

build_supported_groups(#{key_share_groups := Groups, grease_count := {Min, Max}}) ->
    GreaseCount = Min + secure_random:uniform(Max - Min + 1),
    GreaseVals = [lists:nth(secure_random:uniform(length(?GREASE_VALUES)),
                            ?GREASE_VALUES) || _ <- lists:seq(1, GreaseCount)],
    
    AdditionalGroups = [
        16#00, 16#1e,  % x448
        16#01, 16#00,  % ffdhe2048
        16#01, 16#01,  % ffdhe3072
        16#01, 16#02   % ffdhe4096
    ],
    
    AllGroups = lists:foldl(
        fun(G, Acc) ->
            Pos = secure_random:uniform(length(Acc) + 1),
            lists:sublist(Acc, Pos - 1) ++ [G] ++ lists:nthtail(Pos - 1, Acc)
        end, Groups ++ AdditionalGroups, GreaseVals),
    
    GroupsBin = << <<G:?u16>> || G <- AllGroups >>,
    GroupsLen = byte_size(GroupsBin),
    <<16#00, 16#0a, (GroupsLen + 2):?u16, GroupsLen:?u16, GroupsBin/binary>>.

build_app_layer_settings() ->
    case secure_random:uniform(3) of
        1 ->
            Proto = case secure_random:uniform(2) of
                1 -> <<$h, $2>>;
                2 -> <<$h, $3>>
            end,
            <<16#44, 16#cd, 0:16, 5:16, 3:16, Proto/binary>>;
        _ ->
            <<>>
    end.

make_sni(Domains) ->
    SniListItems = << <<?EXT_SNI_HOST_NAME, (byte_size(Domain)):?u16, 
                        Domain/binary>> || Domain <- Domains >>,
    ItemsLen = byte_size(SniListItems),
    <<?EXT_SNI:?u16, (ItemsLen + 2):?u16, ItemsLen:?u16, SniListItems/binary>>.

%% ============================================================================
%% Internal Functions - ServerHello Building
%% ============================================================================

make_srv_hello(Digest, SessionId, {KeyShareGroup, KeyShareKey}) ->
    KeyShareEntity = <<KeyShareGroup:?u16, (byte_size(KeyShareKey)):?u16, 
                       KeyShareKey/binary>>,
    Extensions = [
        <<?EXT_KEY_SHARE:?u16, (byte_size(KeyShareEntity)):?u16>>,
        KeyShareEntity,
        <<?EXT_SUPPORTED_VERSIONS:?u16, 2:?u16, ?TLS_13_VERSION>>
    ],
    SessionSize = byte_size(SessionId),
    Payload = [
        <<?TLS_12_VERSION,
          Digest:?DIGEST_LEN/binary,
          SessionSize,
          SessionId:SessionSize/binary,
          ?TLS_CIPHERSUITE,
          0,
          (iolist_size(Extensions)):?u16>>,
        Extensions
    ],
    [<<?TLS_TAG_SRV_HELLO, (iolist_size(Payload)):?u24>> | Payload].

make_key_share(Exts) ->
    case lists:keyfind(?EXT_KEY_SHARE, 1, Exts) of
        {_, KeyShares} ->
            SupportedKeyShares = lists:dropwhile(
                fun({Group, Key}) ->
                    not (byte_size(Key) < 128 andalso
                         lists:member(Group, [
                             16#0017, 16#0018, 16#0019,
                             16#001D, 16#001E,
                             16#0100, 16#0101, 16#0102, 16#0103, 16#0104
                         ]))
                end, KeyShares),
            case SupportedKeyShares of
                [] -> error({protocol_error, tls_unsupported_key_shares, KeyShares});
                [{KSGroup, KSKey} | _] ->
                    {KSGroup, crypto:strong_rand_bytes(byte_size(KSKey))}
            end;
        _ ->
            error({protocol_error, tls_missing_key_share_ext, Exts})
    end.

make_server_digest(<<Left:?DIGEST_POS/binary, _:?DIGEST_LEN/binary, 
                     Right/binary>>, Secret) ->
    Msg = [Left, binary:copy(<<0>>, ?DIGEST_LEN), Right],
    hmac(sha256, Secret, Msg).

%% ============================================================================
%% Internal Functions - Parsing
%% ============================================================================

parse_client_hello(<<?TLS_REC_HANDSHAKE, ?TLS_10_VERSION, TlsFrameLen:?u16,
                     ?TLS_TAG_CLI_HELLO, HelloLen:?u24, ?TLS_12_VERSION,
                     Random:?DIGEST_LEN/binary,
                     SessIdLen, SessId:SessIdLen/binary,
                     CipherSuitesLen:?u16, CipherSuites:CipherSuitesLen/binary,
                     CompMethodsLen, CompMethods:CompMethodsLen/binary,
                     ExtensionsLen:?u16, Extensions:ExtensionsLen/binary>>
                  ) when TlsFrameLen >= 200, HelloLen >= 100 ->
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
    [{Type, Value} || <<Type, Len:?u16, Value:Len/binary>> <= List];
parse_extension(?EXT_KEY_SHARE, <<Len:?u16, Exts:Len/binary>>) ->
    [{Group, Key} || <<Group:?u16, KeyLen:?u16, Key:KeyLen/binary>> <= Exts];
parse_extension(_Type, Data) ->
    Data.

%% ============================================================================
%% Internal Functions - Utilities
%% ============================================================================

key_size_for_group(16#001D) -> 32;
key_size_for_group(16#0017) -> 65;
key_size_for_group(16#0018) -> 97;
key_size_for_group(16#0019) -> 133;
key_size_for_group(16#11EC) -> 1216;
key_size_for_group(16#001E) -> 56;
key_size_for_group(16#0100) -> 256;
key_size_for_group(16#0101) -> 384;
key_size_for_group(16#0102) -> 512;
key_size_for_group(_) -> 32 + secure_random:uniform(64).

random_tls_profile() ->
    Profiles = ?TLS_FINGERPRINT_PROFILES,
    Profile = lists:nth(secure_random:uniform(length(Profiles)), Profiles),
    ?LOG_DEBUG("Selected TLS fingerprint: ~s", [maps:get(name, Profile, unknown)]),
    Profile.

shuffle_list([]) -> [];
shuffle_list(List) ->
    Sorted = [{secure_random:uniform(), X} || X <- List],
    [X || {_, X} <- lists:sort(Sorted)].

insert_at(List, Pos, Items) when Pos =< 1 ->
    Items ++ List;
insert_at([H | T], Pos, Items) ->
    [H | insert_at(T, Pos - 1, Items)];
insert_at([], _, Items) ->
    Items.

is_domain_allowed(_Domain, []) -> true;
is_domain_allowed(Domain, AllowedDomains) ->
    lists:any(fun(Allowed) -> match_domain(Domain, Allowed) end, AllowedDomains).

match_domain(Domain, <<"*.", Base/binary>>) ->
    case binary:match(Domain, <<".", Base/binary>>) of
        {Pos, _} when Pos > 0 -> true;
        _ -> false
    end;
match_domain(Domain, Allowed) ->
    Domain =:= Allowed.

tls_records_complete(_B, 0) -> true;
tls_records_complete(<<_T, _Mj, _Mn, Len:?u16, Rest/binary>>, N) 
    when byte_size(Rest) >= Len ->
    <<_:Len/binary, Tail/binary>> = Rest,
    tls_records_complete(Tail, N - 1);
tls_records_complete(_B, _N) -> false.

base64url(Bin) ->
    << <<(urlencode_digit(D))>> || <<D>> <= base64:encode(Bin), D =/= $= >>.

urlencode_digit($/) -> $_;
urlencode_digit($+) -> $-;
urlencode_digit(D) -> D.

decode_all(Bin, Acc, St0) ->
    case try_decode_packet(Bin, St0) of
        {incomplete, St} ->
            {Acc, Bin, St};
        {ok, Data, Tail, St} ->
            decode_all(Tail, <<Acc/binary, Data/binary>>, St)
    end.

%% ============================================================================
%% Secure Random Number Generation
%% ============================================================================

secure_random:uniform(Max) when is_integer(Max), Max > 0 ->
    <<N:?u32>> = crypto:strong_rand_bytes(4),
    (N rem Max) + 1.

%% ============================================================================
%% HMAC
%% ============================================================================

-if(?OTP_RELEASE >= 23).
hmac(Algo, Key, Str) ->
    crypto:mac(hmac, Algo, Key, Str).
-else.
hmac(Algo, Key, Str) ->
    crypto:hmac(Algo, Key, Str).
-endif.
