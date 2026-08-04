%%%===================================================================
%%% Fake TLS - REALITY Advanced v3.0 (Final Production Release)
%%%===================================================================
%%% Combines the best of both worlds:
%%% - REALITY-style authentication via Random field (from v1)
%%% - Deep fingerprint randomization with browser profiles (from v2)
%%% - GREASE techniques for maximum evasion
%%% - Domain allow-listing and SNI derivation
%%% - Advanced timing attack mitigation (NEW in v3)
%%% - Adaptive behavior patterns (NEW in v3)
%%% - HTTP/2 fingerprinting (NEW in v3)
%%% - Memory optimization and caching (NEW in v3)
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
%%% Records
%%%===================================================================

-record(st, {
    session_ticket :: binary() | undefined,
    ocsp_response :: binary() | undefined,
    session_ticket_lifetime :: non_neg_integer() | undefined,
    packet_count = 0 :: non_neg_integer(),
    profile_name :: atom() | undefined,
    timing_profile :: map() | undefined,  %% NEW: Timing behavior profile
    connection_start :: non_neg_integer() | undefined  %% NEW: Start timestamp
}).

-record(client_hello, {
    pseudorandom        :: binary(),
    session_id          :: binary(),
    cipher_suites       :: [non_neg_integer()],
    compression_methods :: binary(),
    extensions          :: [{non_neg_integer(), any()}]
}).

%%%===================================================================
%%% Constants
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
-define(EXT_ENCRYPTED_CLIENT_HELLO, 16#fe0d).

%%%===================================================================
%%% GREASE Values (RFC 8701)
%%%===================================================================

-define(GREASE_VALUES, [
    16#0a0a, 16#1a1a, 16#2a2a, 16#3a3a, 16#4a4a,
    16#5a5a, 16#6a6a, 16#7a7a, 16#8a8a, 16#9a9a,
    16#aaaa, 16#baba, 16#caca, 16#dada, 16#eaea,
    16#fafa
]).

%%%===================================================================
%%% Timing Profiles (NEW)
%%%===================================================================

-define(TIMING_PROFILES, [
    #{name => normal_network,
      processing_jitter_ms => {5, 25},
      packet_spacing_ms => {1, 10},
      burst_probability => 0.15,
      burst_size => {2, 5},
      initial_delay_ms => {0, 50}
    },
    #{name => congested_network,
      processing_jitter_ms => {10, 50},
      packet_spacing_ms => {5, 30},
      burst_probability => 0.05,
      burst_size => {1, 3},
      initial_delay_ms => {20, 100}
    },
    #{name => high_quality_network,
      processing_jitter_ms => {1, 10},
      packet_spacing_ms => {0, 5},
      burst_probability => 0.3,
      burst_size => {3, 8},
      initial_delay_ms => {0, 20}
    }
]).

%%%===================================================================
%%% Browser Fingerprint Profiles
%%%===================================================================

-define(TLS_FINGERPRINT_PROFILES, [
    #{name => chrome_120,
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
      grease_count => {2, 4},
      key_share_groups => [
          16#11, 16#ec,   % X25519MLKEM768
          16#00, 16#1d,   % x25519
          16#00, 16#17,   % secp256r1
          16#00, 16#18    % secp384r1
      ],
      supported_versions => [
          16#03, 16#04,   % TLS 1.3
          16#03, 16#03    % TLS 1.2
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
      http2_settings => #{  %% NEW: HTTP/2 fingerprint
          initial_window_size => 65535,
          max_frame_size => 16384,
          max_concurrent_streams => 256,
          header_table_size => 65536
      }
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
      http2_settings => #{
          initial_window_size => 131072,
          max_frame_size => 16384,
          max_concurrent_streams => 128,
          header_table_size => 65536
      }
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
      http2_settings => #{
          initial_window_size => 65535,
          max_frame_size => 16384,
          max_concurrent_streams => 100,
          header_table_size => 4096
      }
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
      http2_settings => #{
          initial_window_size => 65535,
          max_frame_size => 16384,
          max_concurrent_streams => 256,
          header_table_size => 65536
      }
    }
]).

%%%===================================================================
%%% Types
%%%===================================================================

-opaque codec() :: #st{}.

-type meta() :: #{
    session_id     := binary(),
    timestamp      := non_neg_integer(),
    client_digest  := binary(),
    sni_domain     => binary(),
    session_ticket => binary() | undefined,
    ocsp_response  => binary() | undefined,
    profile_name   => atom(),
    timing_profile => map()  %% NEW
}.

%%%===================================================================
%%% ETS Cache Tables (NEW)
%%%===================================================================

-define(PROFILE_CACHE, mtp_tls_profile_cache).
-define(TIMING_CACHE, mtp_tls_timing_cache).

%%%===================================================================
%%% Secret helpers
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
%%% Utility Functions
%%%===================================================================

-spec shuffle_list(list()) -> list().
shuffle_list([]) -> [];
shuffle_list(List) ->
    Sorted = lists:sort([{rand:uniform(), X} || X <- List]),
    [X || {_, X} <- Sorted].

-spec random_grease(non_neg_integer()) -> [non_neg_integer()].
random_grease(Count) ->
    [lists:nth(rand:uniform(length(?GREASE_VALUES)), ?GREASE_VALUES) || _ <- lists:seq(1, Count)].

%%%===================================================================
%%% Profile Caching System (NEW)
%%%===================================================================

-spec init_caches() -> ok.
init_caches() ->
    case ets:info(?PROFILE_CACHE) of
        undefined ->
            ets:new(?PROFILE_CACHE, [named_table, set, public,
                                     {read_concurrency, true},
                                     {write_concurrency, true}]);
        _ -> ok
    end,
    case ets:info(?TIMING_CACHE) of
        undefined ->
            ets:new(?TIMING_CACHE, [named_table, set, public,
                                    {read_concurrency, true},
                                    {write_concurrency, true}]);
        _ -> ok
    end.

-spec random_tls_profile() -> map().
random_tls_profile() ->
    init_caches(),
    case rand:uniform(10) of
        N when N =< 7 ->  %% 70% cache hit
            case ets:lookup(?PROFILE_CACHE, last_profile) of
                [{last_profile, Profile}] -> 
                    ?LOG_DEBUG("Using cached profile: ~s", [maps:get(name, Profile, unknown)]),
                    Profile;
                [] -> select_and_cache_profile()
            end;
        _ ->  %% 30% fresh profile for diversity
            select_and_cache_profile()
    end.

-spec select_and_cache_profile() -> map().
select_and_cache_profile() ->
    Profiles = ?TLS_FINGERPRINT_PROFILES,
    Profile = lists:nth(rand:uniform(length(Profiles)), Profiles),
    ets:insert(?PROFILE_CACHE, {last_profile, Profile}),
    ?LOG_DEBUG("Selected new TLS fingerprint: ~s", [maps:get(name, Profile, unknown)]),
    Profile.

%%%===================================================================
%%% Timing Attack Mitigation (NEW)
%%%===================================================================

-spec random_timing_profile() -> map().
random_timing_profile() ->
    TimingProfiles = ?TIMING_PROFILES,
    lists:nth(rand:uniform(length(TimingProfiles)), TimingProfiles).

-spec apply_processing_jitter(map()) -> ok.
apply_processing_jitter(#{processing_jitter_ms := {Min, Max}}) ->
    Jitter = Min + rand:uniform(Max - Min + 1),
    timer:sleep(Jitter);
apply_processing_jitter(_) ->
    timer:sleep(rand:uniform(20)).

-spec apply_packet_spacing(map(), non_neg_integer()) -> ok.
apply_packet_spacing(#{packet_spacing_ms := {Min, Max}}, PacketCount) ->
    case PacketCount > 1 of
        true ->
            Space = Min + rand:uniform(Max - Min + 1),
            timer:sleep(Space);
        false -> ok
    end;
apply_packet_spacing(_, _) -> ok.

-spec should_burst_packets(map()) -> boolean().
should_burst_packets(#{burst_probability := Prob}) ->
    rand:uniform() < Prob;
should_burst_packets(_) -> false.

-spec get_burst_size(map()) -> non_neg_integer().
get_burst_size(#{burst_size := {Min, Max}}) ->
    Min + rand:uniform(Max - Min + 1);
get_burst_size(_) -> 1.

-spec apply_initial_connection_delay(map()) -> ok.
apply_initial_connection_delay(#{initial_delay_ms := {Min, Max}}) ->
    Delay = Min + rand:uniform(Max - Min + 1),
    timer:sleep(Delay);
apply_initial_connection_delay(_) -> ok.

%%%===================================================================
%%% Adaptive Timing Behavior (NEW)
%%%===================================================================

-spec generate_timing_behavior(binary(), map()) -> map().
generate_timing_behavior(ClientDigest, TimingProfile) ->
    %% Use client digest to seed consistent timing behavior
    <<Seed:32, _/binary>> = crypto:hash(sha256, ClientDigest),
    _ = rand:seed(exsplus, {Seed, Seed + 1, Seed + 2}),
    
    %% Create session-specific timing variations
    #{
        initial_jitter => rand:uniform(100),
        packet_multiplier => 0.5 + rand:uniform() * 1.5,
        delay_pattern => random_delay_pattern(),
        burst_trigger => rand:uniform(10)
    }.

-spec random_delay_pattern() -> [non_neg_integer()].
random_delay_pattern() ->
    PatternType = rand:uniform(4),
    case PatternType of
        1 -> [1, 2, 5, 3, 1, 4, 2, 3, 1, 5];  %% Normal variation
        2 -> [1, 1, 1, 8, 1, 1, 2, 1, 1, 4];  %% Occasional spikes
        3 -> [2, 3, 2, 1, 2, 3, 1, 2, 3, 2];  %% Regular pattern
        4 -> [1, 3, 2, 4, 1, 5, 2, 3, 1, 2]   %% Mixed pattern
    end.

%%%===================================================================
%%% Key size helpers
%%%===================================================================

-spec key_size_for_group(non_neg_integer()) -> non_neg_integer().
key_size_for_group(16#001D) -> 32;    % x25519
key_size_for_group(16#0017) -> 65;    % secp256r1 (uncompressed)
key_size_for_group(16#0018) -> 97;    % secp384r1
key_size_for_group(16#0019) -> 133;   % secp521r1
key_size_for_group(16#11EC) -> 1216;  % X25519MLKEM768
key_size_for_group(_) -> 32.

%%%===================================================================
%%% OCSP and Session Ticket helpers
%%%===================================================================

generate_ocsp_response() ->
    <<0, 0, 0, 0>>.

generate_session_ticket() ->
    crypto:strong_rand_bytes(64 + rand:uniform(128)).

%%%===================================================================
%%% ClientHello parsing and validation (REALITY-style)
%%%===================================================================

-spec from_client_hello(binary(), binary(), [binary()]) ->
    {ok, iodata(), meta(), codec()}.
from_client_hello(Data, Secret, AllowedDomains) ->
    #client_hello{
        pseudorandom = ClientDigest,
        session_id   = SessionId,
        extensions   = Extensions
    } = parse_client_hello(Data),

    %% Extract SNI domain
    SniDomain = case lists:keyfind(?EXT_SNI, 1, Extensions) of
        {_, [{?EXT_SNI_HOST_NAME, Domain}]} -> Domain;
        _ ->
            ?LOG_WARNING("TLS ClientHello has no SNI"),
            error({protocol_error, tls_no_sni})
    end,

    %% Check domain allow-list
    case is_domain_allowed(SniDomain, AllowedDomains) of
        true  -> ok;
        false ->
            ?LOG_WARNING("Unauthorized SNI domain: ~s", [SniDomain]),
            error({protocol_error, tls_domain_not_allowed, SniDomain})
    end,

    %% Detect client profile from extensions for consistent behavior
    HasSessionTicket = lists:keymember(?EXT_SESSION_TICKET, 1, Extensions),
    HasOcspStapling = lists:keymember(?EXT_STATUS_REQUEST, 1, Extensions),

    %% REALITY-style authentication: verify secret in Random field
    ServerDigest = make_server_digest(Data, Secret),
    <<Zeroes:(?DIGEST_LEN - 4)/binary, Timestamp:32/unsigned-little>> =
        crypto:exor(ClientDigest, ServerDigest),

    lists:all(fun(B) -> B =:= 0 end, binary_to_list(Zeroes))
        orelse error({protocol_error, tls_invalid_digest}),

    CurrentTime = erlang:system_time(second),
    abs(CurrentTime - Timestamp) =< 300
        orelse error({protocol_error, tls_timestamp_expired}),

    %% Extract key share from client
    KeyShare = make_key_share(Extensions),

    %% Generate session ticket if client supports it
    {SessionTicket, TicketRecord} = case HasSessionTicket of
        true ->
            Ticket = generate_session_ticket(),
            TicketRec = as_tls_frame(?TLS_REC_HANDSHAKE, Ticket),
            {Ticket, TicketRec};
        false ->
            {undefined, <<>>}
    end,

    %% Generate OCSP response if client supports it
    OcspResponse = case HasOcspStapling of
        true -> generate_ocsp_response();
        false -> undefined
    end,

    %% Select a random profile for response behavior
    Profile = random_tls_profile(),
    ProfileName = maps:get(name, Profile),

    %% Select timing profile (NEW)
    TimingProfile = random_timing_profile(),
    apply_initial_connection_delay(TimingProfile),
    
    %% Generate timing behavior based on client (NEW)
    TimingBehavior = generate_timing_behavior(ClientDigest, TimingProfile),

    %% Build ServerHello with random digest placeholder
    SrvHello0 = make_srv_hello(binary:copy(<<0>>, ?DIGEST_LEN),
                               SessionId, KeyShare,
                               HasSessionTicket, HasOcspStapling),

    ChangeCipher = <<?TLS_REC_CHANGE_CIPHER, ?TLS_12_VERSION, 0, 1, 1>>,

    %% Randomize post-handshake data size for realism
    RealisticData = case rand:uniform(5) of
        1 -> <<"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n">>;
        2 -> <<"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nHello World!">>;
        3 -> crypto:strong_rand_bytes(rand:uniform(512));
        4 -> <<"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n">>;
        5 -> <<>>
    end,

    %% Build response to compute digest
    Response0 = [as_tls_frame(?TLS_REC_HANDSHAKE, SrvHello0),
                 ChangeCipher,
                 as_tls_frame(?TLS_REC_DATA, RealisticData) |
                 case TicketRecord of
                     <<>> -> [];
                     _ -> [TicketRecord]
                 end],

    %% Apply processing jitter before computation (NEW)
    apply_processing_jitter(TimingProfile),

    %% Compute REALITY-style digest for ServerHello
    SrvHelloDigest = hmac(sha256, Secret, [ClientDigest | Response0]),
    SrvHello = make_srv_hello(SrvHelloDigest, SessionId, KeyShare,
                              HasSessionTicket, HasOcspStapling),

    %% Final response with HTTP/2 settings if applicable (NEW)
    Http2Settings = build_http2_settings(Profile),

    Response = [as_tls_frame(?TLS_REC_HANDSHAKE, SrvHello),
                ChangeCipher,
                as_tls_frame(?TLS_REC_DATA, RealisticData) |
                case TicketRecord of
                    <<>> -> [];
                    _ -> [TicketRecord]
                end |
                case Http2Settings of
                    <<>> -> [];
                    _ -> [as_tls_frame(?TLS_REC_DATA, Http2Settings)]
                end],

    Meta = #{
        session_id    => SessionId,
        timestamp     => Timestamp,
        client_digest => ClientDigest,
        sni_domain    => SniDomain,
        session_ticket => SessionTicket,
        ocsp_response  => OcspResponse,
        profile_name   => ProfileName,
        timing_profile => TimingProfile  %% NEW
    },

    St = #st{
        session_ticket = SessionTicket,
        ocsp_response = OcspResponse,
        session_ticket_lifetime = case HasSessionTicket of
                                      true -> 604800;
                                      false -> undefined
                                  end,
        packet_count = 0,
        profile_name = ProfileName,
        timing_profile = maps:merge(TimingProfile, TimingBehavior),  %% NEW
        connection_start = erlang:system_time(millisecond)  %% NEW
    },

    {ok, Response, Meta, St}.

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
%%% HTTP/2 Settings Builder (NEW)
%%%===================================================================

-spec build_http2_settings(map()) -> binary().
build_http2_settings(#{http2_settings := Settings}) ->
    #{initial_window_size := InitWindow,
      max_frame_size := MaxFrame,
      max_concurrent_streams := MaxStreams,
      header_table_size := HeaderSize} = Settings,
    
    %% Build HTTP/2 SETTINGS frame
    SettingsPayload = <<
        16#04:16, InitWindow:32,     %% SETTINGS_INITIAL_WINDOW_SIZE
        16#05:16, MaxFrame:32,       %% SETTINGS_MAX_FRAME_SIZE
        16#03:16, MaxStreams:32,     %% SETTINGS_MAX_CONCURRENT_STREAMS
        16#01:16, HeaderSize:32      %% SETTINGS_HEADER_TABLE_SIZE
    >>,
    
    %% HTTP/2 preface + SETTINGS frame
    H2Preface = <<"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n">>,
    FrameHeader = <<
        (byte_size(SettingsPayload)):24,
        16#04:8,                      %% SETTINGS frame type
        16#00:8,                      %% No flags
        16#00:32                      %% Stream ID 0
    >>,
    
    <<H2Preface/binary, FrameHeader/binary, SettingsPayload/binary>>;
build_http2_settings(_) ->
    <<>>.

%%%===================================================================
%%% ClientHello parser
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
%%% ClientHello generator (with deep fingerprint randomization)
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

    %% Select random browser profile for fingerprint diversity
    Profile = random_tls_profile(),

    %% Build components using profile
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
    CompCertExt = build_compress_certificate(Profile),
    EcPointExt = build_ec_point_formats(Profile),
    PaddingExt = build_padding(Profile),

    ExtensionsBase = [
        ECH,
        <<16#00, 16#23, 0:16>>,                      % session_ticket
        EcPointExt,
        <<16#44, 16#cd, 16#00, 16#05,
          16#00, 16#03, 16#02, $h, $2>>,             % application_layer_protocol_settings
        KeyShare,
        <<16#00, 16#12, 0:16>>,                      % signed_certificate_timestamp
        SupportedGroups,
        CompCertExt,
        <<16#ff, 16#01, 16#00, 16#01, 16#00>>,       % renegotiation_info
        SigAlgos,
        <<16#00, 16#05, 16#00, 16#05,
          16#01, 0:32>>,                             % status_request (OCSP)
        <<16#00, 16#2d, 16#00, 16#02, 16#01, 16#01>>, % psk_key_exchange_modes
        ALPN,
        SNI,
        SupportedVersions,
        PaddingExt
    ],

    %% Filter empty extensions and optionally randomize order
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

    %% REALITY-style: embed timestamp in random field
    Hello0     = Pack(binary:copy(<<0>>, ?DIGEST_LEN)),
    Digest     = hmac(sha256, Secret, Hello0),
    EncTs      = <<0:(?DIGEST_LEN - 4)/unit:8, Timestamp:32/unsigned-little>>,
    FakeRandom = crypto:exor(Digest, EncTs),
    Pack(FakeRandom).

%%%===================================================================
%%% Extension builders (from v2)
%%%===================================================================

-spec build_cipher_suites(map()) -> binary().
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

-spec build_key_share_entries(map()) -> binary().
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

    Final = case maps:get(version_order_randomized, Profile, false) of
        true -> shuffle_list(WithGrease);
        false -> WithGrease
    end,

    << <<V:?u16>> || V <- Final >>.

-spec build_sig_algos(map()) -> binary().
build_sig_algos(#{sig_algorithms_count := Count}) ->
    AllAlgos = [
        16#04, 16#03,  16#05, 16#03,  16#06, 16#03,  16#02, 16#03,
        16#08, 16#04,  16#08, 16#05,  16#08, 16#06,  16#04, 16#01,
        16#05, 16#01,  16#06, 16#01,  16#02, 16#01,  16#04, 16#02,
        16#03, 16#02,  16#02, 16#02,  16#03, 16#01
    ],
    Selected = lists:sublist(AllAlgos, Count * 2),
    Shuffled = shuffle_list(Selected),
    AlgoListLen = Count * 2,
    ExtLen = AlgoListLen + 2,
    <<?EXT_SIGNATURE_ALGORITHMS:?u16,
      ExtLen:?u16,
      AlgoListLen:?u16,
      << <<A:8>> || A <- Shuffled >>/binary>>.

-spec build_ech(map()) -> binary().
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
    <<?EXT_ENCRYPTED_CLIENT_HELLO:?u16,
      (byte_size(EchContent)):?u16,
      EchContent/binary>>;
build_ech(_) ->
    <<>>.

-spec build_alpn(map()) -> binary().
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

-spec build_compress_certificate(map()) -> binary().
build_compress_certificate(#{compress_certificate := brotli}) ->
    <<16#00, 16#1b, 16#00, 16#03, 16#02, 16#00, 16#02>>;
build_compress_certificate(_) ->
    <<>>.

-spec build_ec_point_formats(map()) -> binary().
build_ec_point_formats(#{ec_point_formats := true}) ->
    <<?EXT_EC_POINT_FORMATS:?u16, 16#00, 16#02, 16#01, 16#00>>;
build_ec_point_formats(_) ->
    <<>>.

-spec build_supported_groups(map()) -> binary().
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

-spec build_padding(map()) -> binary().
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

-spec make_sni([binary()]) -> binary().
make_sni(Domains) ->
    SniListItems = << <<?EXT_SNI_HOST_NAME, (byte_size(Domain)):?u16, Domain/binary>>
                      || Domain <- Domains >>,
    ItemsLen = byte_size(SniListItems),
    <<?EXT_SNI:?u16, (ItemsLen + 2):?u16, ItemsLen:?u16, SniListItems/binary>>.

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
parse_server_hello(B) when byte_size(B) < 5 ->
    incomplete;
parse_server_hello(<<16#16, _/binary>> = B) ->
    case tls_records_complete(B, 3) of
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
%%% Data stream codec (Enhanced with timing mitigation)
%%%===================================================================

-spec new() -> codec().
new() ->
    #st{
        packet_count = 0,
        timing_profile = random_timing_profile(),
        connection_start = erlang:system_time(millisecond)
    }.

-spec try_decode_packet(binary(), codec()) -> {ok, binary(), binary(), codec()}
                                                  | {incomplete, codec()}.
try_decode_packet(<<?TLS_12_DATA, Size:?u16, Data:Size/binary, Tail/binary>>, St) ->
    NewSt = St#st{packet_count = St#st.packet_count + 1},
    %% Apply packet spacing for timing mitigation (NEW)
    apply_packet_spacing(St#st.timing_profile, NewSt#st.packet_count),
    {ok, Data, Tail, NewSt};
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
        {incomplete, St} ->
            {Acc, Bin, St};
        {ok, Data, Tail, St} ->
            decode_all(Tail, <<Acc/binary, Data/binary>>, St)
    end.

-spec encode_packet(binary(), codec()) -> {iodata(), codec()}.
encode_packet(Bin, St) ->
    NewCount = St#st.packet_count + 1,
    NewSt = St#st{packet_count = NewCount},
    
    %% Adaptive timing based on connection state (NEW)
    case should_burst_packets(St#st.timing_profile) of
        true ->
            %% Send multiple frames in burst
            BurstSize = get_burst_size(St#st.timing_profile),
            BurstPackets = lists:duplicate(BurstSize, as_tls_data_frame(Bin)),
            {BurstPackets, NewSt};
        false ->
            %% Single packet with processing jitter
            apply_processing_jitter(St#st.timing_profile),
            {as_tls_data_frame(Bin), NewSt}
    end.

as_tls_data_frame(Bin) ->
    as_tls_frame(?TLS_REC_DATA, Bin).

-spec as_tls_frame(byte(), iodata()) -> iodata().
as_tls_frame(Type, Data) ->
    Size = iolist_size(Data),
    [<<Type, ?TLS_12_VERSION, Size:?u16>> | Data].

%%%===================================================================
%%% Adaptive Connection Monitoring (NEW)
%%%===================================================================

-spec get_connection_stats(codec()) -> map().
get_connection_stats(#st{connection_start = Start, packet_count = Count} = St) ->
    case Start of
        undefined -> #{};
        _ ->
            Elapsed = erlang:system_time(millisecond) - Start,
            #{
                duration_ms => Elapsed,
                packet_count => Count,
                packets_per_second => case Elapsed of
                    0 -> 0;
                    _ -> round(Count / (Elapsed / 1000))
                end,
                profile_name => St#st.profile_name
            }
    end.

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

%%%===================================================================
%%% Module Initialization
%%%===================================================================

%% Initialize caches on module load
init_caches().

%%%===================================================================
%%% End of Module
%%%===================================================================
