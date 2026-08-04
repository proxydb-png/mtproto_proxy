%%% @author sergey <me@seriyps.ru>
%%% @copyright (C) 2019, sergey
%%% @doc
%%% Fake TLS 'CBC' stream codec
%%% https://github.com/telegramdesktop/tdesktop/commit/69b6b487382c12efc43d52f472cab5954ab850e2
%%% It's not real TLS, but it looks like TLS1.3 from outside
%%% Enhanced with deep fingerprint randomization and DPI evasion
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
         parse_server_hello/1]).

-export_type([codec/0, meta/0]).

-include_lib("kernel/include/logger.hrl").

-dialyzer(no_improper_lists).

-record(st, {
    jitter_buffer = [] :: list(),
    last_record_time = 0 :: non_neg_integer(),
    record_count = 0 :: non_neg_integer()
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
-define(MIN_OUT_PACKET_SIZE, 4096).

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
%% Each profile mimics a different real browser/TLS implementation
%% ============================================================================

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
      session_id_length => {31, 32},
      extensions_order_randomized => true,
      alpn_protocols => [
          [<<"h2">>, <<"http/1.1">>],
          [<<"h2">>],
          [<<"http/1.1">>]
      ],
      padding_size => {0, 512},
      record_version_randomization => true,
      dummy_record_probability => 0.2
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
      session_id_length => {28, 32},
      extensions_order_randomized => false,
      alpn_protocols => [
          [<<"h2">>, <<"http/1.1">>]
      ],
      padding_size => {0, 256},
      record_version_randomization => false,
      dummy_record_probability => 0.15
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
      session_id_length => {0, 32},
      extensions_order_randomized => false,
      alpn_protocols => [
          [<<"h2">>, <<"http/1.1">>]
      ],
      padding_size => {0, 512},
      record_version_randomization => true,
      dummy_record_probability => 0.25
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
      session_id_length => {24, 32},
      extensions_order_randomized => true,
      alpn_protocols => [
          [<<"h2">>, <<"http/1.1">>],
          [<<"h2">>]
      ],
      padding_size => {0, 512},
      record_version_randomization => true,
      dummy_record_probability => 0.2
    }
]).

-opaque codec() :: #st{}.

-type meta() :: #{session_id := binary(),
                  timestamp := non_neg_integer(),
                  client_digest := binary(),
                  sni_domain => binary(),
                  profile => atom()}.


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
%% @doc Check if a domain is allowed based on the allowed domains list.
%% Supports exact match and wildcard patterns like "*.example.com".
%% @end
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
                    EndPart = binary:part(Domain, {DomLen, -SuffixLen}),
                    EndPart =:= Suffix;
                true ->
                    false
            end;
        _ ->
            Domain =:= Allowed
    end.

%% ============================================================================
%% @doc Parse fake-TLS "ClientHello" and generate "ServerHello + ChangeCipher + ApplicationData"
%% Version WITH domain checking and DPI evasion.
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
    KeyShare = make_key_share(Extensions),
    
    %% Randomize session ID length for DPI evasion
    SessIdLen = rand:uniform(32),
    SrvSessionId = case SessIdLen of
        0 -> <<>>;
        _ -> crypto:strong_rand_bytes(SessIdLen)
    end,
    
    SrvHello0 = make_srv_hello(binary:copy(<<0>>, ?DIGEST_LEN), SrvSessionId, KeyShare),
    
    %% Random fake HTTP data with variable size and entropy
    FakeHttpSize = case rand:uniform(3) of
        1 -> rand:uniform(128);                    % small
        2 -> 128 + rand:uniform(384);              % medium
        3 -> 512 + rand:uniform(1024)              % large
    end,
    FakeHttpData = generate_realistic_http_data(FakeHttpSize),
    
    %% Handshake frames MUST use TLS 1.2 for compatibility
    Response0 = [_, CC, DD] =
        [as_tls_frame(?TLS_REC_HANDSHAKE, SrvHello0),
         as_tls_frame(?TLS_REC_CHANGE_CIPHER, [1]),
         as_tls_frame(?TLS_REC_DATA, FakeHttpData)],
    SrvHelloDigest = hmac(sha256, Secret, [ClientDigest | Response0]),
    SrvHello = make_srv_hello(SrvHelloDigest, SrvSessionId, KeyShare),
    
    %% Add dummy records randomly for DPI confusion
    DummyRecords = case rand:uniform(4) of
        1 -> [generate_dummy_record() || _ <- lists:seq(1, rand:uniform(2))];
        _ -> []
    end,
    
    Response = DummyRecords ++ [as_tls_frame(?TLS_REC_HANDSHAKE, SrvHello),
                CC,
                DD],
    Meta0 = #{session_id => SessionId,
              timestamp => Timestamp,
              client_digest => ClientDigest},
    Meta = Meta0#{sni_domain => SniDomain},
    {ok, Response, Meta, new()}.

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
%% DPI Evasion Helper Functions
%% ============================================================================

%% Generate realistic-looking HTTP data with lower entropy
-spec generate_realistic_http_data(non_neg_integer()) -> binary().
generate_realistic_http_data(Size) ->
    Templates = [
        <<"GET / HTTP/1.1\r\nHost: ">>,
        <<"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n">>,
        <<"POST /api/v1/data HTTP/1.1\r\nContent-Length: ">>,
        <<"HTTP/1.1 302 Found\r\nLocation: https://">>
    ],
    Template = lists:nth(rand:uniform(length(Templates)), Templates),
    TemplateSize = byte_size(Template),
    if
        Size =< TemplateSize ->
            binary:part(Template, {0, Size});
        true ->
            PadSize = Size - TemplateSize,
            %% Mix of printable ASCII and random bytes
            Padding = << << (case rand:uniform(3) of
                                1 -> $a + rand:uniform(26) - 1;
                                2 -> $A + rand:uniform(26) - 1;
                                3 -> rand:uniform(255)
                            end) >>
                         || _ <- lists:seq(1, PadSize) >>,
            <<Template/binary, Padding/binary>>
    end.

%% Generate dummy TLS records with realistic-looking content
-spec generate_dummy_record() -> iodata().
generate_dummy_record() ->
    Types = [?TLS_REC_DATA],
    Type = lists:nth(rand:uniform(length(Types)), Types),
    Size = rand:uniform(200),
    Payload = generate_realistic_http_data(Size),
    as_tls_frame_with_random_version(Type, Payload).

%% ============================================================================
%% Random TLS record version for DPI evasion
%% ============================================================================
-spec random_record_version() -> binary().
random_record_version() ->
    case rand:uniform(4) of
        1 -> <<?TLS_10_VERSION>>;
        2 -> <<?TLS_12_VERSION>>;
        3 -> <<?TLS_13_VERSION>>;
        4 -> <<?TLS_12_VERSION>>  % Bias toward TLS 1.2
    end.

-spec as_tls_frame_with_random_version(byte(), iodata()) -> iodata().
as_tls_frame_with_random_version(Type, Data) ->
    Version = random_record_version(),
    Size = iolist_size(Data),
    [<<Type, Version/binary, Size:?u16>> | Data].

%% ============================================================================
%% Parse functions
%% ============================================================================

parse_client_hello(<<?TLS_REC_HANDSHAKE, ?TLS_10_VERSION, TlsFrameLen:?u16,
                     ?TLS_TAG_CLI_HELLO, HelloLen:?u24, ?TLS_12_VERSION,
                     Random:?DIGEST_LEN/binary,
                     SessIdLen, SessId:SessIdLen/binary,
                     CipherSuitesLen:?u16, CipherSuites:CipherSuitesLen/binary,
                     CompMethodsLen, CompMethods:CompMethodsLen/binary,
                     ExtensionsLen:?u16, Extensions:ExtensionsLen/binary>>
                  ) when TlsFrameLen >= 512, HelloLen >= 400 ->
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
parse_extension(_Type, Data) ->
    Data.


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
%% @doc Randomly select a TLS fingerprint profile
%% @end
%% ============================================================================
-spec random_tls_profile() -> map().
random_tls_profile() ->
    Profiles = ?TLS_FINGERPRINT_PROFILES,
    Profile = lists:nth(rand:uniform(length(Profiles)), Profiles),
    ?LOG_DEBUG("Selected TLS fingerprint: ~s", [maps:get(name, Profile, unknown)]),
    Profile.

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

%% ============================================================================
%% @doc Build key share entries with GREASE
%% @end
%% ============================================================================
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

%% ============================================================================
%% @doc Build signature algorithms from profile
%% @end
%% ============================================================================
-spec build_sig_algos(map()) -> binary().
build_sig_algos(#{sig_algorithms_count := Count}) ->
    AllAlgos = [
        16#04, 16#03,
        16#05, 16#03,
        16#06, 16#03,
        16#02, 16#03,
        16#08, 16#04,
        16#08, 16#05,
        16#08, 16#06,
        16#04, 16#01,
        16#05, 16#01,
        16#06, 16#01,
        16#02, 16#01,
        16#04, 16#02,
        16#03, 16#02,
        16#02, 16#02,
        16#03, 16#01
    ],
    Selected = lists:sublist(AllAlgos, Count * 2),
    Shuffled = shuffle_list(Selected),
    AlgoListLen = Count * 2,
    ExtLen = AlgoListLen + 2,
    <<16#00, 16#0d,
      ExtLen:?u16,
      AlgoListLen:?u16,
      << <<A:8>> || A <- Shuffled >>/binary>>.

%% ============================================================================
%% @doc Build ECH extension from profile
%% @end
%% ============================================================================
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
    <<16#fe, 16#0d,
      (byte_size(EchContent)):?u16,
      EchContent/binary>>;
build_ech(_) ->
    <<>>.

%% ============================================================================
%% @doc Build ALPN extension from profile
%% @end
%% ============================================================================
-spec build_alpn(map()) -> binary().
build_alpn(#{alpn_protocols := Protocols}) ->
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
%% @doc Build compress_certificate extension
%% @end
%% ============================================================================
-spec build_compress_certificate(map()) -> binary().
build_compress_certificate(#{compress_certificate := brotli}) ->
    <<16#00, 16#1b, 16#00, 16#03, 16#02, 16#00, 16#02>>;
build_compress_certificate(_) ->
    <<>>.

%% ============================================================================
%% @doc Build ec_point_formats extension
%% @end
%% ============================================================================
-spec build_ec_point_formats(map()) -> binary().
build_ec_point_formats(#{ec_point_formats := true}) ->
    <<16#00, 16#0b, 16#00, 16#02, 16#01, 16#00>>;
build_ec_point_formats(_) ->
    <<>>.

%% ============================================================================
%% @doc Build supported_groups extension
%% @end
%% ============================================================================
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
    <<16#00, 16#0a,
      (GroupsLen + 2):?u16,
      GroupsLen:?u16,
      GroupsBin/binary>>.

%% ============================================================================
%% @doc Build random padding extension
%% @end
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
%% @doc Build SNI extension
%% @end
%% ============================================================================
make_sni(Domains) ->
    SniListItems = << <<?EXT_SNI_HOST_NAME, (byte_size(Domain)):?u16, Domain/binary>>
                      || Domain <- Domains >>,
    ItemsLen = byte_size(SniListItems),
    <<?EXT_SNI:?u16, (ItemsLen + 2):?u16, ItemsLen:?u16, SniListItems/binary>>.

%% ============================================================================
%% @doc Generate Fake-TLS "ClientHello" with random fingerprint.
%% ============================================================================
-spec make_client_hello(binary(), binary()) -> binary().
make_client_hello(Secret, SniDomain) ->
    make_client_hello(erlang:system_time(second),
                      generate_variable_session_id(),
                      Secret, SniDomain).

-spec generate_variable_session_id() -> binary().
generate_variable_session_id() ->
    %% Random length between 0 and 32 bytes
    case rand:uniform(4) of
        1 -> <<>>;  % Empty session ID
        2 -> crypto:strong_rand_bytes(rand:uniform(16));
        _ -> crypto:strong_rand_bytes(16 + rand:uniform(16))
    end.

-spec make_client_hello(non_neg_integer(), binary(), binary(), binary()) -> binary().
make_client_hello(Timestamp, SessionId, HexSecret, SniDomain) when byte_size(HexSecret) == 32 ->
    make_client_hello(Timestamp, SessionId, mtp_handler:unhex(HexSecret), SniDomain);
make_client_hello(Timestamp, SessionId, Secret, SniDomain) when byte_size(Secret) == 16 ->
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
    
    %% Use random record version for DPI evasion
    RecVersion = random_record_version(),
    
    Pack = fun(FakeRandom) ->
                   <<?TLS_REC_HANDSHAKE, RecVersion/binary, TlsLen:?u16,
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
%% Data stream codec with DPI evasion
%% ============================================================================

-spec new() -> codec().
new() ->
    #st{
        last_record_time = erlang:monotonic_time(millisecond),
        record_count = 0
    }.

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
%% @doc Encode packet with DPI evasion techniques
%% - Variable fragment sizes
%% - Random padding
%% - Dummy records
%% - Timing jitter (managed externally)
%% @end
%% ============================================================================
-spec encode_packet(binary(), codec()) -> {iodata(), codec()}.
encode_packet(Bin, St0) ->
    {Frames, St1} = encode_with_dpi_evasion(Bin, St0),
    {Frames, St1}.

-spec encode_with_dpi_evasion(binary(), #st{}) -> {iodata(), #st{}}.
encode_with_dpi_evasion(Bin, #st{record_count = Count} = St) ->
    %% Variable fragment sizes for DPI evasion
    MinSize = ?MIN_OUT_PACKET_SIZE,
    MaxSize = ?MAX_OUT_PACKET_SIZE,
    
    %% Randomize fragment size within range
    FragSize = MinSize + rand:uniform(MaxSize - MinSize),
    
    {MainFrames, St1} = encode_as_frames_with_variable_size(Bin, FragSize, St),
    
    %% Occasionally add dummy records
    DummyProb = rand:uniform(),
    {DummyFrames, St2} = if
        DummyProb < 0.15 ->  % 15% chance
            NumDummy = rand:uniform(2),
            Dummies = [generate_dummy_record() || _ <- lists:seq(1, NumDummy)],
            {Dummies, St1};
        true ->
            {[], St1}
    end,
    
    AllFrames = DummyFrames ++ MainFrames,
    NewCount = Count + 1,
    {AllFrames, St2#st{record_count = NewCount}}.

%% @doc Encode binary into TLS frames with variable size and padding
-spec encode_as_frames_with_variable_size(binary(), non_neg_integer(), #st{}) -> {[iodata()], #st{}}.
encode_as_frames_with_variable_size(Bin, MaxSize, St) when byte_size(Bin) =< MaxSize ->
    %% Add random padding to data frames
    PadLen = case rand:uniform(5) of
        1 -> rand:uniform(256);     % Large padding
        _ -> rand:uniform(32)       % Small padding
    end,
    Padding = crypto:strong_rand_bytes(PadLen),
    {[as_tls_frame_data_with_evasion(<<Bin/binary, Padding/binary>>)], St};
encode_as_frames_with_variable_size(Bin, MaxSize, St) ->
    %% Split binary into chunks
    <<Chunk:MaxSize/binary, Tail/binary>> = Bin,
    {Frames, St1} = encode_as_frames_with_variable_size(Tail, MaxSize, St),
    
    %% Vary padding for each chunk
    PadLen = rand:uniform(64),
    Padding = crypto:strong_rand_bytes(PadLen),
    {[as_tls_frame_data_with_evasion(<<Chunk/binary, Padding/binary>>) | Frames], St1}.

%% @doc Create TLS data frame with DPI evasion (random version + padding)
-spec as_tls_frame_data_with_evasion(binary()) -> iodata().
as_tls_frame_data_with_evasion(Bin) ->
    %% Randomize record version for data frames
    Version = random_record_version(),
    Size = byte_size(Bin),
    [<<?TLS_REC_DATA, Version/binary, Size:?u16>> | Bin].

%% @doc Create standard TLS frame (fixed TLS 1.2 for handshake)
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
