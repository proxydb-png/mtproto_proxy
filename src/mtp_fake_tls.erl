%%% @author sergey <me@seriyps.ru>
%%% @copyright (C) 2019, sergey
%%% @doc
%%% Fake TLS 'CBC' stream codec
%%% Enhanced with deep fingerprint randomization, wildcard domain support,
%%% Replay Attack protection, performance optimizations (iolists, caching),
%%% PSK support, timing simulation, and packet size variety.
%%% @end
%%% Created : 24 Jul 2019 by sergey <me@seriyps.ru>

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
         make_client_hello_with_psk/3,
         make_client_hello_with_psk/5,
         parse_server_hello/1]).
-export([init/1,
         get_performance_report/0,
         select_profile_by_ua/1,
         random_tls_profile/0]).

-export_type([codec/0, meta/0]).

-include_lib("kernel/include/logger.hrl").

-dialyzer(no_improper_lists).

-record(st, {
    current_profile :: map() | undefined,
    packet_size_distribution :: {non_neg_integer(), non_neg_integer()} | undefined,
    metrics :: map() | undefined
}).

-record(client_hello,
        {pseudorandom :: binary(),
         session_id :: binary(),
         cipher_suites :: list(),
         compression_methods :: list(),
         extensions :: [{non_neg_integer(), any()}],
         psk_identity :: binary() | undefined,
         psk_binder :: binary() | undefined
        }).

-define(u16, 16/unsigned-big).
-define(u24, 24/unsigned-big).

-define(MAX_IN_PACKET_SIZE, 65535).      % sizeof(uint16) - 1
-define(MAX_OUT_PACKET_SIZE, 16384).     % 2^14 https://tools.ietf.org/html/rfc8446#section-5.1

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
-define(EXT_PSK, 41).

-define(TIMESTAMP_TOLERANCE_SECONDS, 300).

-define(APP, mtproto_proxy).

%% ============================================================================
%% Pre-computed & Cached Data (Domain Sets & TLS Profiles)
%% ============================================================================
-define(CACHE_KEY_DOMAINS, {?MODULE, domain_cache}).
-define(CACHE_KEY_PROFILES_TAB, {?MODULE, profiles_tab}).
-define(CACHE_KEY_METRICS, {?MODULE, metrics}).

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
%% ============================================================================

-define(TLS_FINGERPRINT_PROFILES, [
    #{name => chrome_120,
      cipher_suites => [
          16#13, 16#01, 16#13, 16#02, 16#13, 16#03,
          16#c0, 16#2b, 16#c0, 16#2f, 16#c0, 16#2c, 16#c0, 16#30,
          16#cc, 16#a9, 16#cc, 16#a8,
          16#c0, 16#13, 16#c0, 16#14,
          16#00, 16#9c, 16#00, 16#9d, 16#00, 16#2f, 16#00, 16#35
      ],
      cipher_order_randomized => true,
      grease_count => {2, 4},
      key_share_groups => [
          16#11, 16#ec, 16#00, 16#1d, 16#00, 16#17, 16#00, 16#18
      ],
      supported_versions => [
          16#03, 16#04, 16#03, 16#03
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
      timing_base_delay => 45,
      packet_size_distribution => {1024, 4096}
    },
    #{name => firefox_121,
      cipher_suites => [
          16#13, 16#01, 16#13, 16#02, 16#13, 16#03,
          16#c0, 16#2b, 16#c0, 16#2f, 16#c0, 16#2c, 16#c0, 16#30,
          16#cc, 16#a9, 16#cc, 16#a8,
          16#c0, 16#13, 16#c0, 16#14,
          16#00, 16#9c, 16#00, 16#9d, 16#00, 16#2f, 16#00, 16#35,
          16#00, 16#3c, 16#00, 16#3d
      ],
      cipher_order_randomized => true,
      grease_count => {2, 3},
      key_share_groups => [
          16#00, 16#1d, 16#00, 16#17
      ],
      supported_versions => [
          16#03, 16#04, 16#03, 16#03
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
      timing_base_delay => 55,
      packet_size_distribution => {512, 2048}
    },
    #{name => safari_17,
      cipher_suites => [
          16#13, 16#01, 16#13, 16#02, 16#13, 16#03,
          16#c0, 16#2b, 16#c0, 16#2f, 16#c0, 16#2c, 16#c0, 16#30,
          16#cc, 16#a9, 16#cc, 16#a8,
          16#c0, 16#13, 16#c0, 16#14
      ],
      cipher_order_randomized => false,
      grease_count => {2, 4},
      key_share_groups => [
          16#00, 16#1d, 16#00, 16#17, 16#00, 16#18, 16#00, 16#19
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
      timing_base_delay => 40,
      packet_size_distribution => {256, 1024}
    },
    #{name => edge_120,
      cipher_suites => [
          16#13, 16#01, 16#13, 16#02, 16#13, 16#03,
          16#c0, 16#2b, 16#c0, 16#2f, 16#c0, 16#2c, 16#c0, 16#30,
          16#cc, 16#a9, 16#cc, 16#a8,
          16#c0, 16#13, 16#c0, 16#14,
          16#00, 16#9c, 16#00, 16#9d, 16#00, 16#2f, 16#00, 16#35
      ],
      cipher_order_randomized => true,
      grease_count => {2, 4},
      key_share_groups => [
          16#11, 16#ec, 16#00, 16#1d, 16#00, 16#17
      ],
      supported_versions => [
          16#03, 16#04, 16#03, 16#03
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
      timing_base_delay => 48,
      packet_size_distribution => {1024, 4096}
    },
    #{name => ios_safari_17,
      cipher_suites => [
          16#13, 16#01, 16#13, 16#02, 16#13, 16#03,
          16#c0, 16#2b, 16#c0, 16#2f, 16#c0, 16#2c, 16#c0, 16#30,
          16#cc, 16#a9, 16#cc, 16#a8,
          16#c0, 16#13, 16#c0, 16#14
      ],
      cipher_order_randomized => false,
      grease_count => {2, 3},
      key_share_groups => [
          16#00, 16#1d, 16#00, 16#17, 16#00, 16#18
      ],
      supported_versions => [
          16#03, 16#04, 16#03, 16#03
      ],
      version_order_randomized => false,
      sig_algorithms_count => 14,
      ec_point_formats => true,
      compress_certificate => none,
      ech_payload_size => [144, 176],
      session_id_length => {32, 32},
      extensions_order_randomized => false,
      alpn_protocols => [
          [<<"h2">>, <<"http/1.1">>],
          [<<"h2">>]
      ],
      padding_size => {0, 256},
      timing_base_delay => 38,
      packet_size_distribution => {256, 1024}
    },
    #{name => android_chrome_120,
      cipher_suites => [
          16#13, 16#01, 16#13, 16#02, 16#13, 16#03,
          16#c0, 16#2b, 16#c0, 16#2f, 16#c0, 16#2c, 16#c0, 16#30,
          16#cc, 16#a9, 16#cc, 16#a8,
          16#c0, 16#13, 16#c0, 16#14,
          16#00, 16#9c, 16#00, 16#9d
      ],
      cipher_order_randomized => true,
      grease_count => {2, 4},
      key_share_groups => [
          16#11, 16#ec, 16#00, 16#1d, 16#00, 16#17
      ],
      supported_versions => [
          16#03, 16#04
      ],
      version_order_randomized => false,
      sig_algorithms_count => 13,
      ec_point_formats => true,
      compress_certificate => brotli,
      ech_payload_size => [176, 208],
      session_id_length => {32, 32},
      extensions_order_randomized => true,
      alpn_protocols => [
          [<<"h2">>, <<"http/1.1">>]
      ],
      padding_size => {0, 384},
      timing_base_delay => 50,
      packet_size_distribution => {512, 2048}
    },
    #{name => firefox_android_121,
      cipher_suites => [
          16#13, 16#01, 16#13, 16#02, 16#13, 16#03,
          16#c0, 16#2b, 16#c0, 16#2f, 16#c0, 16#2c, 16#c0, 16#30,
          16#cc, 16#a9, 16#cc, 16#a8,
          16#c0, 16#13, 16#c0, 16#14,
          16#00, 16#9c, 16#00, 16#9d
      ],
      cipher_order_randomized => false,
      grease_count => {2, 3},
      key_share_groups => [
          16#00, 16#1d, 16#00, 16#17
      ],
      supported_versions => [
          16#03, 16#04, 16#03, 16#03
      ],
      version_order_randomized => false,
      sig_algorithms_count => 16,
      ec_point_formats => true,
      compress_certificate => brotli,
      ech_payload_size => [144, 176],
      session_id_length => {32, 32},
      extensions_order_randomized => false,
      alpn_protocols => [
          [<<"h2">>, <<"http/1.1">>]
      ],
      padding_size => {0, 256},
      timing_base_delay => 58,
      packet_size_distribution => {512, 2048}
    }
]).

-opaque codec() :: #st{}.

-type meta() :: #{session_id := binary(),
                  timestamp := non_neg_integer(),
                  client_digest := binary(),
                  sni_domain => binary(),
                  profile_name => binary()}.

%% ============================================================================
%% @doc Initialize allowed domains for the proxy.
%% Parses the list, separates exact and wildcard domains, and caches them.
%% Also pre-computes all TLS profile data for ultra-fast client hello generation.
%% @end
%% ============================================================================
-spec init(AllowedDomains :: [binary()]) -> ok.
init(AllowedDomains) ->
    %% 1. Domain Caching
    {ExactMap, WildcardList} = categorize_domains(AllowedDomains, #{}, []),
    DomainCache = #{exact => ExactMap, wildcard => WildcardList, allowed_list => AllowedDomains},
    put(?CACHE_KEY_DOMAINS, DomainCache),

    %% 2. Profile Pre-computation & ETS Caching
    Profiles = ?TLS_FINGERPRINT_PROFILES,
    PrecomputedProfiles = [precompute_profile(P) || P <- Profiles],
    
    %% Create ETS table for profiles
    Tab = ets:new(mtp_tls_profiles, [named_table, public, {read_concurrency, true}]),
    [ets:insert(Tab, {N, P}) || {N, P} <- lists:enumerate(PrecomputedProfiles)],
    put(?CACHE_KEY_PROFILES_TAB, Tab),
    
    %% Initialize metrics
    put(?CACHE_KEY_METRICS, #{}),
    
    ?LOG_INFO("Fake-TLS profiles and domain cache initialized successfully. ~p profiles loaded.",
              [length(Profiles)]),
    ok.

%% ============================================================================
%% @doc Separate domains into exact matches and wildcard suffixes.
%% @end
%% ============================================================================
-spec categorize_domains([binary()], map(), [binary()]) -> {map(), [binary()]}.
categorize_domains([], ExactMap, Wildcards) ->
    {ExactMap, Wildcards};
categorize_domains([<<"*.", Suffix/binary>> | T], ExactMap, Wildcards) ->
    categorize_domains(T, ExactMap, [Suffix | Wildcards]);
categorize_domains([Domain | T], ExactMap, Wildcards) ->
    categorize_domains(T, maps:put(Domain, true, ExactMap), Wildcards).

%% ============================================================================
%% @doc Check if a domain is allowed based on the allowed domains list.
%% Uses cached domain data for O(1) exact lookup and fast wildcard matching.
%% @end
%% ============================================================================
-spec is_domain_allowed(Domain :: binary(), AllowedDomains :: [binary()]) -> boolean().
is_domain_allowed(Domain, AllowedDomains) when is_binary(Domain) ->
    case get(?CACHE_KEY_DOMAINS) of
        #{exact := ExactMap, wildcard := Wildcards} ->
            case maps:is_key(Domain, ExactMap) of
                true -> true;
                false -> check_wildcard(Domain, Wildcards)
            end;
        undefined ->
            {ExactMap, Wildcards} = categorize_domains(AllowedDomains, #{}, []),
            case maps:is_key(Domain, ExactMap) of
                true -> true;
                false -> check_wildcard(Domain, Wildcards)
            end
    end.

%% ============================================================================
%% @doc Check if a domain ends with any of the allowed wildcard suffixes.
%% This function correctly handles suffix matching to prevent domain hijacking.
%% @end
%% ============================================================================
-spec check_wildcard(Domain :: binary(), [binary()]) -> boolean().
check_wildcard(_Domain, []) -> false;
check_wildcard(Domain, [Suffix | T]) ->
    SuffixWithDot = <<".", Suffix/binary>>,
    SuffixLen = byte_size(SuffixWithDot),
    DomainLen = byte_size(Domain),
    case DomainLen > SuffixLen of
        true ->
            StartPos = DomainLen - SuffixLen,
            <<_Head:StartPos/binary, Tail:SuffixLen/binary>> = Domain,
            case Tail =:= SuffixWithDot of
                true -> true;
                false -> check_wildcard(Domain, T)
            end;
        false ->
            check_wildcard(Domain, T)
    end.

%% ============================================================================
%% @doc Pre-compute and cache static parts of a TLS profile.
%% The returned map contains pre-built binaries and extension templates,
%% minimizing runtime work during `make_client_hello`.
%% @end
%% ============================================================================
-spec precompute_profile(map()) -> map().
precompute_profile(Profile) ->
    StaticExtensions = [
        ec_point_formats_ext(Profile),
        compress_certificate_ext(Profile),
        psk_key_exchange_modes_ext(),
        renegotiation_info_ext(),
        signed_certificate_timestamp_ext(),
        session_ticket_ext(),
        status_request_ext()
    ],
    Profile#{static_extensions => [E || E <- StaticExtensions, E =/= <<>>]}.

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
%% @doc Parse fake-TLS "ClientHello" and generate "ServerHello + ChangeCipher + ApplicationData"
%% Version WITH domain checking and timestamp validation.
%% @end
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
                true ->
                    ok;
                false ->
                    ?LOG_WARNING(
                       "TLS ClientHello with unauthorized domain '~s'. "
                       "Allowed domains: ~p",
                       [SniDomain, AllowedDomains]),
                    error({protocol_error, tls_domain_not_allowed, SniDomain})
            end
    end,

    ServerDigest = make_server_digest(Data, Secret),
    <<Zeroes:(?DIGEST_LEN - 4)/binary, Timestamp:32/unsigned-little>> = XoredDigest =
        crypto:exor(ClientDigest, ServerDigest),
    lists:all(fun(B) -> B == 0 end, binary_to_list(Zeroes)) orelse
        error({protocol_error, tls_invalid_digest, XoredDigest}),

    %% ========================================================================
    %% بررسی انقضای Timestamp برای جلوگیری از حملات بازپخش (Replay Attack)
    %% ========================================================================
    CurrentTime = erlang:system_time(second),
    abs(CurrentTime - Timestamp) =< ?TIMESTAMP_TOLERANCE_SECONDS
        orelse begin
            ?LOG_WARNING(
               "TLS ClientHello timestamp expired. "
               "Current: ~p, Received: ~p, Diff: ~p seconds",
               [CurrentTime, Timestamp, abs(CurrentTime - Timestamp)]),
            error({protocol_error, tls_timestamp_expired, Timestamp, CurrentTime})
        end,

    %% ========================================================================
    %% Select profile and simulate timing
    %% ========================================================================
    Profile = select_profile_by_sni(SniDomain),
    simulate_timing(Profile, processing),
    log_profile_selection(Profile, SniDomain),

    KeyShare = make_key_share(Extensions),
    SrvHello0 = make_srv_hello(binary:copy(<<0>>, ?DIGEST_LEN), SessionId, KeyShare),
    FakeHttpData = crypto:strong_rand_bytes(rand:uniform(256)),
    Response0 = [_, CC, DD] =
        [as_tls_frame(?TLS_REC_HANDSHAKE, SrvHello0),
         as_tls_frame(?TLS_REC_CHANGE_CIPHER, [1]),
         as_tls_frame(?TLS_REC_DATA, FakeHttpData)],
    SrvHelloDigest = hmac(sha256, Secret, [ClientDigest | Response0]),
    SrvHello = make_srv_hello(SrvHelloDigest, SessionId, KeyShare),
    Response = [as_tls_frame(?TLS_REC_HANDSHAKE, SrvHello),
                CC,
                DD],
    Meta0 = #{session_id => SessionId,
              timestamp => Timestamp,
              client_digest => ClientDigest,
              profile_name => maps:get(name, Profile, unknown)},
    Meta = Meta0#{sni_domain => SniDomain},
    
    %% Record metrics
    record_performance_metric(handshake_time, erlang:monotonic_time(millisecond)),
    
    {ok, Response, Meta, #st{current_profile = Profile}}.

%% ============================================================================
%% @doc Backward-compatible version without domain checking.
%% @end
%% ============================================================================
-spec from_client_hello(binary(), binary()) ->
                               {ok, iodata(), meta(), codec()}.
from_client_hello(Data, Secret) ->
    from_client_hello(Data, Secret, []).

%% Extract the SNI domain from a raw ClientHello binary without validating the secret.
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

%% TLS fatal decode_error alert (RFC 8446 §6).
-spec tls_decode_error_alert() -> binary().
tls_decode_error_alert() ->
    <<?TLS_REC_ALERT, ?TLS_12_VERSION, 0, 2, ?TLS_ALERT_FATAL, ?TLS_ALERT_DECODE_ERROR>>.

%% Derive a per-SNI 16-byte secret from the base secret, SNI domain and a salt.
-spec derive_sni_secret(BaseSecret :: binary(), SniDomain :: binary(), Salt :: binary())
        -> binary().
derive_sni_secret(BaseSecret, SniDomain, Salt) when byte_size(BaseSecret) == 16 ->
    SecretHex = mtp_handler:hex(BaseSecret),
    <<Derived:16/binary, _/binary>> =
        crypto:hash(sha256, [Salt, SecretHex, SniDomain]),
    Derived.

%% ============================================================================
%% @doc Parse ClientHello with PSK support
%% @end
%% ============================================================================
parse_client_hello(<<?TLS_REC_HANDSHAKE, ?TLS_10_VERSION, TlsFrameLen:?u16,
                     ?TLS_TAG_CLI_HELLO, HelloLen:?u24, ?TLS_12_VERSION,
                     Random:?DIGEST_LEN/binary,
                     SessIdLen, SessId:SessIdLen/binary,
                     CipherSuitesLen:?u16, CipherSuites:CipherSuitesLen/binary,
                     CompMethodsLen, CompMethods:CompMethodsLen/binary,
                     ExtensionsLen:?u16, Extensions:ExtensionsLen/binary>>
                  ) when TlsFrameLen >= 512, HelloLen >= 400 ->
    Exts = parse_extensions(Extensions),
    {PskIdentity, PskBinder} = extract_psk(Exts),
    #client_hello{
       pseudorandom = Random,
       session_id = SessId,
       cipher_suites = parse_suites(CipherSuites),
       compression_methods = parse_compression(CompMethods),
       extensions = Exts,
       psk_identity = PskIdentity,
       psk_binder = PskBinder
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
parse_extension(?EXT_PSK, Data) ->
    parse_psk_extension(Data);
parse_extension(_Type, Data) ->
    Data.

%% ============================================================================
%% @doc Extract PSK from extensions
%% @end
%% ============================================================================
-spec extract_psk(Extensions :: list()) -> {binary() | undefined, binary() | undefined}.
extract_psk(Extensions) ->
    case lists:keyfind(?EXT_PSK, 1, Extensions) of
        {_, Data} ->
            case parse_psk_extension(Data) of
                {Identity, Binder} -> {Identity, Binder};
                _ -> {undefined, undefined}
            end;
        _ ->
            {undefined, undefined}
    end.

-spec parse_psk_extension(binary()) -> {binary(), binary()} | undefined.
parse_psk_extension(<<IdentitiesLen:?u16, IdentitiesData:IdentitiesLen/binary,
                      BindersLen:?u16, BindersData:BindersLen/binary>>) ->
    case parse_psk_identity(IdentitiesData) of
        {Identity, _} ->
            case parse_psk_binder(BindersData) of
                {Binder, _} -> {Identity, Binder};
                _ -> undefined
            end;
        _ -> undefined
    end;
parse_psk_extension(_) -> undefined.

parse_psk_identity(<<IdentityLen:?u16, Identity:IdentityLen/binary, 
                     Obsolete:4/binary, Rest/binary>>) ->
    {Identity, Rest};
parse_psk_identity(_) -> undefined.

parse_psk_binder(<<BinderLen:?u16, Binder:BinderLen/binary, Rest/binary>>) ->
    {Binder, Rest};
parse_psk_binder(_) -> undefined.

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
                            byte_size(Key) < 128
                            andalso
                            lists:member(
                              Group, [
                                      16#0017,  % secp256r1
                                      16#0018,  % secp384r1
                                      16#0019,  % secp521r1
                                      16#001D,  % x25519
                                      16#001E,  % x448
                                      16#0100,  % ffdhe2048
                                      16#0101,  % ffdhe3072
                                      16#0102,  % ffdhe4096
                                      16#0103,  % ffdhe6144
                                      16#0104   % ffdhe8192
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

make_srv_hello(Digest, SessionId, {KeyShareGroup, KeyShareKey}) ->
    KeyShareEntity = <<KeyShareGroup:?u16, (byte_size(KeyShareKey)):?u16, KeyShareKey/binary>>,
    Extensions =
        [<<?EXT_KEY_SHARE:?u16, (byte_size(KeyShareEntity)):?u16>>,
         KeyShareEntity,
         <<?EXT_SUPPORTED_VERSIONS:?u16, 2:?u16, ?TLS_13_VERSION>>],
    SessionSize = byte_size(SessionId),
    Payload = [<<?TLS_12_VERSION,
                 Digest:?DIGEST_LEN/binary,
                 SessionSize,
                 SessionId:SessionSize/binary,
                 ?TLS_CIPHERSUITE,
                 0,
                 (iolist_size(Extensions)):?u16>>
                   | Extensions],
    [<<?TLS_TAG_SRV_HELLO, (iolist_size(Payload)):?u24>> | Payload].

%% ============================================================================
%% @doc Randomly select a precomputed TLS fingerprint profile from ETS.
%% @end
%% ============================================================================
-spec random_tls_profile() -> map().
random_tls_profile() ->
    case get(?CACHE_KEY_PROFILES_TAB) of
        undefined ->
            %% Fallback to hardcoded profiles
            Profiles = ?TLS_FINGERPRINT_PROFILES,
            lists:nth(rand:uniform(length(Profiles)), Profiles);
        Tab ->
            Count = ets:info(Tab, size),
            case Count > 0 of
                true ->
                    N = rand:uniform(Count),
                    [{_, Profile}] = ets:lookup(Tab, N),
                    Profile;
                false ->
                    Profiles = ?TLS_FINGERPRINT_PROFILES,
                    lists:nth(rand:uniform(length(Profiles)), Profiles)
            end
    end.

%% ============================================================================
%% @doc Select profile based on SNI domain
%% @end
%% ============================================================================
-spec select_profile_by_sni(binary()) -> map().
select_profile_by_sni(SniDomain) ->
    case binary:match(SniDomain, <<"android">>) of
        {_, _} -> 
            case rand:uniform(2) of
                1 -> get_profile(android_chrome_120);
                2 -> get_profile(firefox_android_121)
            end;
        _ ->
            case binary:match(SniDomain, <<"ios">>) of
                {_, _} -> get_profile(ios_safari_17);
                _ -> random_tls_profile()
            end
    end.

%% ============================================================================
%% @doc Select profile based on User-Agent
%% @end
%% ============================================================================
-spec select_profile_by_ua(UserAgent :: binary()) -> map().
select_profile_by_ua(UserAgent) ->
    case binary:match(UserAgent, <<"Chrome">>) of
        {_, _} -> 
            case binary:match(UserAgent, <<"Android">>) of
                {_, _} -> get_profile(android_chrome_120);
                _ -> get_profile(chrome_120)
            end;
        _ ->
            case binary:match(UserAgent, <<"Firefox">>) of
                {_, _} ->
                    case binary:match(UserAgent, <<"Android">>) of
                        {_, _} -> get_profile(firefox_android_121);
                        _ -> get_profile(firefox_121)
                    end;
                _ ->
                    case binary:match(UserAgent, <<"Safari">>) of
                        {_, _} -> get_profile(ios_safari_17);
                        _ -> random_tls_profile()
                    end
            end
    end.

-spec get_profile(Name :: atom()) -> map().
get_profile(Name) ->
    lists:keyfind(Name, name, ?TLS_FINGERPRINT_PROFILES).

%% ============================================================================
%% @doc Simulate realistic timing based on profile
%% @end
%% ============================================================================
-spec simulate_timing(Profile :: map(), Action :: atom()) -> ok.
simulate_timing(Profile, Action) ->
    BaseDelay = maps:get(timing_base_delay, Profile, 50),
    Jitter = rand:uniform(BaseDelay div 5),
    Delay = BaseDelay + Jitter - (Jitter div 2),
    timer:sleep(Delay).

%% ============================================================================
%% @doc Log profile selection
%% @end
%% ============================================================================
-spec log_profile_selection(Profile :: map(), SniDomain :: binary()) -> ok.
log_profile_selection(Profile, SniDomain) ->
    ?LOG_INFO("TLS Profile selected for domain '~s': ~s (grease_count: ~p, extensions_randomized: ~p)",
              [SniDomain, maps:get(name, Profile, unknown),
               maps:get(grease_count, Profile, {0,0}),
               maps:get(extensions_order_randomized, Profile, false)]).

%% ============================================================================
%% @doc Record performance metrics
%% @end
%% ============================================================================
-spec record_performance_metric(Name :: atom(), Value :: integer()) -> ok.
record_performance_metric(Name, Value) ->
    Metrics = case get(?CACHE_KEY_METRICS) of
        undefined -> #{};
        M -> M
    end,
    NewMetrics = maps:update_with(Name, 
        fun(Vals) -> [Value | Vals] end, 
        [Value], 
        Metrics),
    put(?CACHE_KEY_METRICS, NewMetrics).

%% ============================================================================
%% @doc Get performance report
%% @end
%% ============================================================================
-spec get_performance_report() -> map().
get_performance_report() ->
    case get(?CACHE_KEY_METRICS) of
        undefined -> #{};
        Metrics ->
            maps:map(fun(_K, Vals) -> 
                Avg = lists:sum(Vals) div length(Vals),
                Min = lists:min(Vals),
                Max = lists:max(Vals),
                #{avg => Avg, min => Min, max => Max, count => length(Vals)}
            end, Metrics)
    end.

%% ============================================================================
%% @doc Generate random GREASE values
%% @end
%% ============================================================================
-spec random_grease(non_neg_integer()) -> [non_neg_integer()].
random_grease(Count) ->
    [lists:nth(rand:uniform(length(?GREASE_VALUES)), ?GREASE_VALUES) || _ <- lists:seq(1, Count)].

%% ============================================================================
%% @doc Fisher-Yates shuffle for lists
%% @end
%% ============================================================================
-spec shuffle_list(list()) -> list().
shuffle_list([]) -> [];
shuffle_list(List) ->
    Sorted = lists:sort([{rand:uniform(), X} || X <- List]),
    [X || {_, X} <- Sorted].

%% ============================================================================
%% @doc Build cipher suites binary with GREASE and optional order randomization
%% @end
%% ============================================================================
-spec build_cipher_suites(map()) -> iodata().
build_cipher_suites(#{cipher_suites := Suites, grease_count := {GreaseMin, GreaseMax}} = Profile) ->
    GreaseCount = GreaseMin + rand:uniform(GreaseMax - GreaseMin + 1) - 1,
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

    CSLen = length(Final) * 2,
    [<<CSLen:?u16>>, << <<S:?u16>> || S <- Final >>].

%% ============================================================================
%% @doc Build key share entries with GREASE
%% @end
%% ============================================================================
-spec build_key_share_entries(map()) -> iodata().
build_key_share_entries(#{key_share_groups := Groups, grease_count := {GreaseMin, GreaseMax}}) ->
    GreaseCount = GreaseMin + rand:uniform(GreaseMax - GreaseMin + 1) - 1,
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

%% ============================================================================
%% @doc Get key size for a given TLS group
%% @end
%% ============================================================================
-spec key_size_for_group(non_neg_integer()) -> non_neg_integer().
key_size_for_group(16#001D) -> 32;    % x25519
key_size_for_group(16#0017) -> 65;    % secp256r1 (uncompressed)
key_size_for_group(16#0018) -> 97;    % secp384r1
key_size_for_group(16#0019) -> 133;   % secp521r1
key_size_for_group(16#11EC) -> 1216;  % X25519MLKEM768
key_size_for_group(_) -> 32.

%% ============================================================================
%% @doc Build supported versions extension with GREASE
%% @end
%% ============================================================================
-spec build_supported_versions_ext(map()) -> iolist().
build_supported_versions_ext(#{supported_versions := Versions, 
                               grease_count := {GreaseMin, GreaseMax}} = Profile) ->
    GreaseCount = GreaseMin + rand:uniform(GreaseMax - GreaseMin + 1) - 1,
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

%% ============================================================================
%% @doc Build signature algorithms extension from profile
%% @end
%% ============================================================================
-spec build_sig_algos(map()) -> iodata().
build_sig_algos(#{sig_algorithms_count := Count}) ->
    AllAlgos = [
        16#04, 16#03, 16#05, 16#03, 16#06, 16#03, 16#02, 16#03,
        16#08, 16#04, 16#08, 16#05, 16#08, 16#06,
        16#04, 16#01, 16#05, 16#01, 16#06, 16#01, 16#02, 16#01,
        16#04, 16#02, 16#03, 16#02, 16#02, 16#02, 16#03, 16#01
    ],
    Selected = lists:sublist(AllAlgos, Count * 2),
    Shuffled = shuffle_list(Selected),
    AlgoListLen = Count * 2,
    ExtLen = AlgoListLen + 2,
    [<<16#00, 16#0d, ExtLen:?u16, AlgoListLen:?u16>>,
     << <<A:8>> || A <- Shuffled >>].

%% ============================================================================
%% @doc Build ECH extension from profile
%% @end
%% ============================================================================
-spec build_ech(map()) -> iodata().
build_ech(#{ech_payload_size := Sizes}) when is_list(Sizes) ->
    PayloadSize = lists:nth(rand:uniform(length(Sizes)), Sizes),
    EchRand1 = crypto:strong_rand_bytes(1),
    EchRand32 = crypto:strong_rand_bytes(32),
    EchPayload = crypto:strong_rand_bytes(PayloadSize),
    EchContent =
        [<<16#00, 16#00, 16#01, 16#00, 16#01>>,
         EchRand1,
         <<16#00, 16#20>>,
         EchRand32,
         <<(byte_size(EchPayload)):?u16>>,
         EchPayload],
    [<<16#fe, 16#0d, (iolist_size(EchContent)):?u16>> | EchContent];
build_ech(_) ->
    <<>>.

%% ============================================================================
%% @doc Build ALPN extension from profile
%% @end
%% ============================================================================
-spec build_alpn(map()) -> iodata().
build_alpn(#{alpn_protocols := Protocols}) ->
    Selected = lists:nth(rand:uniform(length(Protocols)), Protocols),
    ProtocolEntries = [<<(byte_size(P)):8, P/binary>> || P <- Selected],
    ProtocolsLen = iolist_size(ProtocolEntries),
    [<<16#00, 16#10, (ProtocolsLen + 2):?u16, ProtocolsLen:?u16>> | ProtocolEntries];
build_alpn(_) ->
    <<>>.

%% ============================================================================
%% @doc Build static extensions (precomputed in profile)
%% @end
%% ============================================================================
ec_point_formats_ext(#{ec_point_formats := true}) ->
    <<16#00, 16#0b, 16#00, 16#02, 16#01, 16#00>>;
ec_point_formats_ext(_) -> <<>>.

compress_certificate_ext(#{compress_certificate := brotli}) ->
    <<16#00, 16#1b, 16#00, 16#03, 16#02, 16#00, 16#02>>;
compress_certificate_ext(_) -> <<>>.

psk_key_exchange_modes_ext() ->
    <<16#00, 16#2d, 16#00, 16#02, 16#01, 16#01>>.

renegotiation_info_ext() ->
    <<16#ff, 16#01, 16#00, 16#01, 16#00>>.

signed_certificate_timestamp_ext() ->
    <<16#00, 16#12, 0:16>>.

session_ticket_ext() ->
    <<16#00, 16#23, 0:16>>.

status_request_ext() ->
    <<16#00, 16#05, 16#00, 16#05, 16#01, 0:32>>.

%% ============================================================================
%% @doc Build supported_groups extension
%% @end
%% ============================================================================
-spec build_supported_groups(map()) -> iodata().
build_supported_groups(#{key_share_groups := Groups, grease_count := {GreaseMin, GreaseMax}}) ->
    GreaseCount = GreaseMin + rand:uniform(GreaseMax - GreaseMin + 1) - 1,
    GreaseVals = random_grease(GreaseCount),
    
    WithGrease = lists:foldl(
        fun(G, Acc) ->
            Pos = rand:uniform(length(Acc) + 1),
            lists:sublist(Acc, Pos - 1) ++ [G] ++ lists:nthtail(Pos - 1, Acc)
        end, Groups, GreaseVals),
    
    GroupsBin = << <<G:?u16>> || G <- WithGrease >>,
    GroupsLen = byte_size(GroupsBin),
    [<<16#00, 16#0a, (GroupsLen + 2):?u16, GroupsLen:?u16>>, GroupsBin].

%% ============================================================================
%% @doc Build random padding extension
%% @end
%% ============================================================================
-spec build_padding(map()) -> iodata().
build_padding(#{padding_size := {Min, Max}}) ->
    PadSize = Min + rand:uniform(Max - Min + 1) - 1,
    case PadSize of
        0 -> <<>>;
        _ ->
            Padding = binary:copy(<<0>>, PadSize),
            <<16#00, 16#15, PadSize:?u16, Padding/binary>>
    end;
build_padding(_) ->
    <<>>.

%% ============================================================================
%% @doc Build SNI extension
%% @end
%% ============================================================================
make_sni(Domains) ->
    SniListItems = [<<?EXT_SNI_HOST_NAME, (byte_size(Domain)):?u16, Domain/binary>>
                      || Domain <- Domains],
    ItemsLen = iolist_size(SniListItems),
    [<<?EXT_SNI:?u16, (ItemsLen + 2):?u16, ItemsLen:?u16>> | SniListItems].

%% ============================================================================
%% @doc Build PSK extension
%% @end
%% ============================================================================
-spec build_psk_extension(binary(), binary(), binary(), non_neg_integer()) -> iodata().
build_psk_extension(Identity, Secret, SessionId, Timestamp) ->
    IdentityLen = byte_size(Identity),
    ObsoleteAge = 0,
    
    Binder = compute_psk_binder(Secret, SessionId, Timestamp, Identity),
    BinderLen = byte_size(Binder),
    
    IdentitiesData = <<IdentityLen:?u16, Identity/binary, ObsoleteAge:32/unsigned>>,
    IdentitiesLen = byte_size(IdentitiesData),
    BindersData = <<BinderLen:?u16, Binder/binary>>,
    BindersLen = byte_size(BindersData),
    
    ExtData = <<IdentitiesLen:?u16, IdentitiesData/binary,
                BindersLen:?u16, BindersData/binary>>,
    ExtLen = byte_size(ExtData),
    
    <<?EXT_PSK:?u16, ExtLen:?u16, ExtData/binary>>.

compute_psk_binder(Secret, SessionId, Timestamp, Identity) ->
    Context = <<SessionId/binary, Timestamp:32/unsigned-little, Identity/binary>>,
    crypto:mac(hmac, sha256, Secret, Context).

%% ============================================================================
%% @doc Generate Fake-TLS "ClientHello" with random fingerprint.
%% Uses precomputed profiles for maximum performance.
%% @end
%% ============================================================================
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
    
    SupportedVersionsExt = build_supported_versions_ext(Profile),
    VersionsLen = byte_size(SupportedVersionsExt),
    SupportedVersions =
        [<<16#00, 16#2b, (VersionsLen + 1):?u16, VersionsLen>>, SupportedVersionsExt],

    KeyShareEntries = build_key_share_entries(Profile),
    KSListLen = byte_size(KeyShareEntries),
    KeyShare =
        <<16#00, 16#33, (KSListLen + 2):?u16, KSListLen:?u16, KeyShareEntries/binary>>,

    ECH = build_ech(Profile),
    ALPN = build_alpn(Profile),
    PaddingExt = build_padding(Profile),
    
    AppSettingsExt = <<16#44, 16#cd, 16#00, 16#05, 16#00, 16#03, 16#02, $h, $2>>,

    #{static_extensions := StaticExts} = Profile,
    ExtensionsBase = [ECH | StaticExts] ++ [
        AppSettingsExt,
        KeyShare,
        SupportedGroups,
        SigAlgos,
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
    CSLen = iolist_size(CipherSuites),
    SessIdLen = byte_size(SessionId),
    ExtLen = byte_size(ExtBin),
    HelloBodyLen = 2 + 32 + 1 + SessIdLen + CSLen + 1 + 1 + 2 + ExtLen,
    TlsLen = HelloBodyLen + 4,
    Pack = fun(FakeRandom) ->
                   <<?TLS_REC_HANDSHAKE, ?TLS_10_VERSION, TlsLen:?u16,
                     ?TLS_TAG_CLI_HELLO, HelloBodyLen:?u24, ?TLS_12_VERSION,
                     FakeRandom:?DIGEST_LEN/binary,
                     SessIdLen, SessionId/binary,
                     (iolist_to_binary(CipherSuites))/binary,
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
%% @doc Generate Fake-TLS "ClientHello" with PSK support.
%% @end
%% ============================================================================
-spec make_client_hello_with_psk(Secret :: binary(), SniDomain :: binary(), 
                                   PskIdentity :: binary()) -> binary().
make_client_hello_with_psk(Secret, SniDomain, PskIdentity) ->
    Timestamp = erlang:system_time(second),
    SessionId = crypto:strong_rand_bytes(32),
    make_client_hello_with_psk(Timestamp, SessionId, Secret, SniDomain, PskIdentity).

-spec make_client_hello_with_psk(non_neg_integer(), binary(), binary(), 
                                   binary(), binary()) -> binary().
make_client_hello_with_psk(Timestamp, SessionId, Secret, SniDomain, PskIdentity) ->
    Profile = random_tls_profile(),
    
    %% PSK Extension
    PskExt = build_psk_extension(PskIdentity, Secret, SessionId, Timestamp),
    
    %% Other extensions
    CipherSuites = build_cipher_suites(Profile),
    SNI = make_sni([SniDomain]),
    SigAlgos = build_sig_algos(Profile),
    SupportedGroups = build_supported_groups(Profile),
    
    SupportedVersionsExt = build_supported_versions_ext(Profile),
    VersionsLen = byte_size(SupportedVersionsExt),
    SupportedVersions = [<<16#00, 16#2b, (VersionsLen + 1):?u16, VersionsLen>>, SupportedVersionsExt],
    
    KeyShareEntries = build_key_share_entries(Profile),
    KSListLen = byte_size(KeyShareEntries),
    KeyShare = <<16#00, 16#33, (KSListLen + 2):?u16, KSListLen:?u16, KeyShareEntries/binary>>,
    
    ECH = build_ech(Profile),
    ALPN = build_alpn(Profile),
    PaddingExt = build_padding(Profile),
    
    AppSettingsExt = <<16#44, 16#cd, 16#00, 16#05, 16#00, 16#03, 16#02, $h, $2>>,
    
    #{static_extensions := StaticExts} = Profile,
    ExtensionsBase = [ECH | StaticExts] ++ [
        AppSettingsExt,
        KeyShare,
        SupportedGroups,
        SigAlgos,
        ALPN,
        SNI,
        SupportedVersions,
        PskExt,
        PaddingExt
    ],
    
    NonEmpty = [E || E <- ExtensionsBase, E =/= <<>>],
    Extensions = case maps:get(extensions_order_randomized, Profile, false) of
        true -> shuffle_list(NonEmpty);
        false -> NonEmpty
    end,
    
    ExtBin = iolist_to_binary(Extensions),
    CSLen = iolist_size(CipherSuites),
    SessIdLen = byte_size(SessionId),
    ExtLen = byte_size(ExtBin),
    HelloBodyLen = 2 + 32 + 1 + SessIdLen + CSLen + 1 + 1 + 2 + ExtLen,
    TlsLen = HelloBodyLen + 4,
    
    Pack = fun(FakeRandom) ->
        <<?TLS_REC_HANDSHAKE, ?TLS_10_VERSION, TlsLen:?u16,
          ?TLS_TAG_CLI_HELLO, HelloBodyLen:?u24, ?TLS_12_VERSION,
          FakeRandom:?DIGEST_LEN/binary,
          SessIdLen, SessionId/binary,
          (iolist_to_binary(CipherSuites))/binary,
          1, 0,
          ExtLen:?u16, ExtBin/binary>>
    end,
    
    %% Simulate timing
    simulate_timing(Profile, handshake),
    
    %% Compute digest
    FakeRandom0 = binary:copy(<<0>>, ?DIGEST_LEN),
    Hello0 = Pack(FakeRandom0),
    Digest = hmac(sha256, Secret, Hello0),
    EncTimestamp = <<(binary:copy(<<0>>, ?DIGEST_LEN - 4))/binary, Timestamp:32/unsigned-little>>,
    FakeRandom = crypto:exor(Digest, EncTimestamp),
    Pack(FakeRandom).

%% ============================================================================
%% @doc Parses "ServerHello" (the one produced by from_client_hello/2).
%% @end
%% ============================================================================
parse_server_hello(<<?TLS_REC_HANDSHAKE, ?TLS_12_VERSION, HSLen:?u16, Handshake:HSLen/binary,
                     ?TLS_REC_CHANGE_CIPHER, ?TLS_12_VERSION, CCLen:?u16, ChangeCipher:CCLen/binary,
                     ?TLS_REC_DATA, ?TLS_12_VERSION, DLen:?u16, Data:DLen/binary,
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

%% ============================================================================
%% @doc Encode packet with variable size based on profile
%% @end
%% ============================================================================
-spec encode_packet(binary(), codec()) -> {iodata(), codec()}.
encode_packet(Bin, #st{current_profile = Profile} = St) ->
    case Profile of
        undefined ->
            {encode_as_frames(Bin), St};
        _ ->
            {Min, Max} = maps:get(packet_size_distribution, Profile, {512, 2048}),
            MaxSize = Min + rand:uniform(Max - Min + 1) - 1,
            {encode_as_frames_with_limit(Bin, MaxSize), St}
    end.

encode_as_frames(Bin) when byte_size(Bin) =< ?MAX_OUT_PACKET_SIZE ->
    as_tls_data_frame(Bin);
encode_as_frames(<<Chunk:?MAX_OUT_PACKET_SIZE/binary, Tail/binary>>) ->
    [as_tls_data_frame(Chunk) | encode_as_frames(Tail)].

encode_as_frames_with_limit(Bin, Limit) when byte_size(Bin) =< Limit ->
    as_tls_data_frame(Bin);
encode_as_frames_with_limit(<<Chunk:Limit/binary, Tail/binary>>, Limit) ->
    [as_tls_data_frame(Chunk) | encode_as_frames_with_limit(Tail, Limit)].

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
