%%% @author sergey <me@seriyps.ru>
%%% @copyright (C) 2019, sergey
%%% @doc
%%% Fake TLS 'CBC' stream codec
%%% ...
%%% Minimal server response for maximum Telegram X compatibility.
%%% ClientHello retains full fingerprint (Session Ticket, OCSP, CompressCertificate extensions)
%%% but server response sends only ServerHello + ChangeCipher + ApplicationData.
%%% No extra handshake records that could break hash calculation.
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
    session_ticket :: binary() | undefined,
    ocsp_response :: binary() | undefined,
    session_ticket_lifetime :: non_neg_integer() | undefined,
    compress_cert_algorithm :: brotli | undefined
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

-define(APP, mtproto_proxy).

%% GREASE values
-define(GREASE_VALUES, [
    16#0a0a, 16#1a1a, 16#2a2a, 16#3a3a, 16#4a4a,
    16#5a5a, 16#6a6a, 16#7a7a, 16#8a8a, 16#9a9a,
    16#aaaa, 16#baba, 16#caca, 16#dada, 16#eaea,
    16#fafa
]).

%% Fingerprint profiles – same as before (full extensions)
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
      key_share_groups => [16#11, 16#ec, 16#00, 16#1d, 16#00, 16#17, 16#00, 16#18],
      supported_versions => [16#03, 16#04, 16#03, 16#03],
      version_order_randomized => true,
      sig_algorithms_count => 15,
      ec_point_formats => true,
      compress_certificate => brotli,
      ech_payload_size => [176, 208, 240],
      session_id_length => {32, 32},
      extensions_order_randomized => true,
      alpn_protocols => [[<<"h2">>, <<"http/1.1">>], [<<"h2">>], [<<"http/1.1">>]],
      padding_size => {0, 128},
      session_ticket_enabled => true,
      ocsp_stapling_enabled => true,
      alps_enabled => true,
      renegotiation_info_enabled => true
    },
    %% ... (other profiles unchanged)
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
      key_share_groups => [16#00, 16#1d, 16#00, 16#17],
      supported_versions => [16#03, 16#04, 16#03, 16#03],
      version_order_randomized => false,
      sig_algorithms_count => 17,
      ec_point_formats => true,
      compress_certificate => brotli,
      ech_payload_size => [144, 176],
      session_id_length => {32, 32},
      extensions_order_randomized => false,
      alpn_protocols => [[<<"h2">>, <<"http/1.1">>]],
      padding_size => {0, 128},
      session_ticket_enabled => true,
      ocsp_stapling_enabled => true,
      alps_enabled => false,
      renegotiation_info_enabled => true
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
      key_share_groups => [16#00, 16#1d, 16#00, 16#17, 16#00, 16#18, 16#00, 16#19],
      supported_versions => [16#03, 16#04],
      version_order_randomized => false,
      sig_algorithms_count => 13,
      ec_point_formats => false,
      compress_certificate => none,
      ech_payload_size => [208, 240],
      session_id_length => {32, 32},
      extensions_order_randomized => false,
      alpn_protocols => [[<<"h2">>, <<"http/1.1">>]],
      padding_size => {0, 128},
      session_ticket_enabled => true,
      ocsp_stapling_enabled => true,
      alps_enabled => false,
      renegotiation_info_enabled => false
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
      key_share_groups => [16#11, 16#ec, 16#00, 16#1d, 16#00, 16#17],
      supported_versions => [16#03, 16#04, 16#03, 16#03],
      version_order_randomized => true,
      sig_algorithms_count => 16,
      ec_point_formats => true,
      compress_certificate => brotli,
      ech_payload_size => [176, 208],
      session_id_length => {32, 32},
      extensions_order_randomized => true,
      alpn_protocols => [[<<"h2">>, <<"http/1.1">>], [<<"h2">>]],
      padding_size => {0, 128},
      session_ticket_enabled => true,
      ocsp_stapling_enabled => true,
      alps_enabled => true,
      renegotiation_info_enabled => true
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
%% format TLS secret
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
%% Domain checking
%% ============================================================================
-spec is_domain_allowed(binary(), [binary()]) -> boolean().
is_domain_allowed(_Domain, []) -> true;
is_domain_allowed(Domain, AllowedDomains) ->
    lists:any(fun(Allowed) -> match_domain(Domain, Allowed) end, AllowedDomains).

-spec match_domain(binary(), binary()) -> boolean().
match_domain(Domain, <<"*.", Base/binary>>) ->
    Suffix = <<".", Base/binary>>,
    SuffixLen = byte_size(Suffix),
    DomLen = byte_size(Domain),
    DomLen >= SuffixLen andalso binary:part(Domain, {DomLen, -SuffixLen}) =:= Suffix;
match_domain(Domain, Allowed) ->
    Domain =:= Allowed.

%% ============================================================================
%% from_client_hello – minimal server response, full client fingerprint
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

    %% Domain check
    case SniDomain of
        undefined ->
            ?LOG_WARNING("No SNI, rejecting"),
            error({protocol_error, tls_no_sni});
        _ ->
            case is_domain_allowed(SniDomain, AllowedDomains) of
                true -> ok;
                false ->
                    ?LOG_WARNING("Domain not allowed: ~s", [SniDomain]),
                    error({protocol_error, tls_domain_not_allowed, SniDomain})
            end
    end,

    %% Detect CompressCertificate capability for ServerHello advertisement only
    CompCertAlgo = case lists:keymember(16#001b, 1, Extensions) of
        true ->
            case lists:keyfind(16#001b, 1, Extensions) of
                {_, <<_Cnt, Algos/binary>>} ->
                    case binary:match(Algos, <<2>>) of
                        {_, _} -> brotli;
                        nomatch -> undefined
                    end;
                _ -> undefined
            end;
        false -> undefined
    end,

    %% Compute server digest and validate timestamp
    ServerDigest = make_server_digest(Data, Secret),
    <<Zeroes:(?DIGEST_LEN - 4)/binary, Timestamp:32/unsigned-little>> = XoredDigest =
        crypto:exor(ClientDigest, ServerDigest),
    lists:all(fun(B) -> B == 0 end, binary_to_list(Zeroes)) orelse
        error({protocol_error, tls_invalid_digest, XoredDigest}),

    KeyShare = make_key_share(Extensions),
    FakeHttpData = crypto:strong_rand_bytes(rand:uniform(128) + 64),

    %% --- Build minimal server response: SrvHello + CCS + Data ---
    %% No Session Ticket, no OCSP, no CompressedCertificate records.
    %% Only required extensions in ServerHello:
    %%   - Key Share
    %%   - Supported Versions (TLS 1.3)
    %%   - Optionally CompressCertificate (advertise, no record)
    %%   - No Session Ticket extension (optional, but we omit it for minimal size)
    %%   - No OCSP Stapling extension (optional, omit)
    
    SrvHello0 = make_srv_hello_minimal(binary:copy(<<0>>, ?DIGEST_LEN), SessionId, KeyShare, CompCertAlgo),
    SrvHelloFrame0 = as_tls_frame(?TLS_REC_HANDSHAKE, SrvHello0),
    ChangeCipherFrame = as_tls_frame(?TLS_REC_CHANGE_CIPHER, [1]),
    DataFrame = as_tls_frame(?TLS_REC_DATA, FakeHttpData),

    Response0 = [SrvHelloFrame0, ChangeCipherFrame, DataFrame],
    SrvHelloDigest = hmac(sha256, Secret, [ClientDigest | Response0]),

    SrvHello = make_srv_hello_minimal(SrvHelloDigest, SessionId, KeyShare, CompCertAlgo),
    SrvHelloFrame = as_tls_frame(?TLS_REC_HANDSHAKE, SrvHello),
    Response = [SrvHelloFrame, ChangeCipherFrame, DataFrame],

    Meta = #{session_id => SessionId,
             timestamp => Timestamp,
             client_digest => ClientDigest,
             sni_domain => SniDomain,
             session_ticket => undefined,
             ocsp_response => undefined},

    St = #st{session_ticket = undefined,
             ocsp_response = undefined,
             session_ticket_lifetime = undefined,
             compress_cert_algorithm = CompCertAlgo},
    {ok, Response, Meta, St}.

%% Backward compat
from_client_hello(Data, Secret) ->
    from_client_hello(Data, Secret, []).

%% Minimal ServerHello: key_share + supported_versions + optional compress_certificate
make_srv_hello_minimal(Digest, SessionId, {KeyShareGroup, KeyShareKey}, CompCertAlgo) ->
    KeyShareEntity = <<KeyShareGroup:?u16, (byte_size(KeyShareKey)):?u16, KeyShareKey/binary>>,
    Exts0 = [
        <<?EXT_KEY_SHARE:?u16, (byte_size(KeyShareEntity)):?u16, KeyShareEntity/binary>>,
        <<?EXT_SUPPORTED_VERSIONS:?u16, 2:?u16, ?TLS_13_VERSION>>
    ],
    Exts = case CompCertAlgo of
        brotli -> Exts0 ++ [<<16#00, 16#1b, 16#00, 16#03, 16#02, 16#02, 16#00>>];
        _ -> Exts0
    end,
    SessionSize = byte_size(SessionId),
    Payload = [<<?TLS_12_VERSION,
                 Digest:?DIGEST_LEN/binary,
                 SessionSize,
                 SessionId:SessionSize/binary,
                 ?TLS_CIPHERSUITE,
                 0,
                 (iolist_size(Exts)):?u16>>
               | Exts],
    [<<?TLS_TAG_SRV_HELLO, (iolist_size(Payload)):?u24>> | Payload].

%% ============================================================================
%% parse_sni, tls_decode_error_alert, derive_sni_secret, parse_client_hello ...
%% (keep the same as before, they are fine)
%% ============================================================================
-spec parse_sni(binary()) -> {ok, binary()} | {error, no_sni | bad_hello}.
parse_sni(Data) ->
    try
        #client_hello{extensions = Extensions} = parse_client_hello(Data),
        case lists:keyfind(?EXT_SNI, 1, Extensions) of
            {_, [{?EXT_SNI_HOST_NAME, Domain}]} -> {ok, Domain};
            _ -> {error, no_sni}
        end
    catch
        error:{protocol_error, tls_bad_client_hello, _} -> {error, bad_hello}
    end.

-spec tls_decode_error_alert() -> binary().
tls_decode_error_alert() ->
    <<?TLS_REC_ALERT, ?TLS_12_VERSION, 0, 2, ?TLS_ALERT_FATAL, ?TLS_ALERT_DECODE_ERROR>>.

-spec derive_sni_secret(binary(), binary(), binary()) -> binary().
derive_sni_secret(BaseSecret, SniDomain, Salt) when byte_size(BaseSecret) == 16 ->
    SecretHex = mtp_handler:hex(BaseSecret),
    <<Derived:16/binary, _/binary>> = crypto:hash(sha256, [Salt, SecretHex, SniDomain]),
    Derived.

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
parse_client_hello(_) ->
    error({protocol_error, tls_bad_client_hello, bad_client_hello}).

parse_suites(Bin) -> [Suite || <<Suite:?u16>> <= Bin].
parse_compression(Bin) -> [Bin].

parse_extensions(Exts) ->
    [{Type, parse_extension(Type, Data)} || <<Type:?u16, Length:?u16, Data:Length/binary>> <= Exts].

parse_extension(?EXT_SNI, <<ListLen:?u16, List:ListLen/binary>>) ->
    [{Type, Value} || <<Type, Len:?u16, Value:Len/binary>> <= List];
parse_extension(?EXT_KEY_SHARE, <<Len:?u16, Exts2:Len/binary>>) ->
    [{Group, Key} || <<Group:?u16, KeyLen:?u16, Key:KeyLen/binary>> <= Exts2];
parse_extension(_Type, Data) -> Data.

make_server_digest(<<Left:?DIGEST_POS/binary, _:?DIGEST_LEN/binary, Right/binary>>, Secret) ->
    Msg = [Left, binary:copy(<<0>>, ?DIGEST_LEN), Right],
    hmac(sha256, Secret, Msg).

make_key_share(Exts) ->
    case lists:keyfind(?EXT_KEY_SHARE, 1, Exts) of
        {_, KeyShares} ->
            Supported = lists:dropwhile(
                fun({Group, Key}) ->
                    not (byte_size(Key) < 128 andalso lists:member(Group,
                        [16#0017,16#0018,16#0019,16#001D,16#001E,
                         16#0100,16#0101,16#0102,16#0103,16#0104]))
                end, KeyShares),
            case Supported of
                [] -> error({protocol_error, tls_unsupported_key_shares, KeyShares});
                [{KSGroup, KSKey}|_] -> {KSGroup, crypto:strong_rand_bytes(byte_size(KSKey))}
            end;
        _ -> error({protocol_error, tls_missing_key_share_ext, Exts})
    end.

%% ============================================================================
%% ClientHello builders (full fingerprint, nothing removed)
%% ============================================================================
random_tls_profile() ->
    Profiles = ?TLS_FINGERPRINT_PROFILES,
    lists:nth(rand:uniform(length(Profiles)), Profiles).

random_grease(Count) ->
    [lists:nth(rand:uniform(length(?GREASE_VALUES)), ?GREASE_VALUES) || _ <- lists:seq(1, Count)].

shuffle_list([]) -> [];
shuffle_list(List) ->
    [X || {_, X} <- lists:sort([{rand:uniform(), X} || X <- List])].

build_cipher_suites(#{cipher_suites := Suites, grease_count := {Min, Max}} = Profile) ->
    N = Min + rand:uniform(Max - Min + 1),
    GreaseVals = random_grease(N),
    WithGrease = lists:foldl(fun(G, Acc) ->
        Pos = rand:uniform(length(Acc)+1),
        lists:sublist(Acc, Pos-1) ++ [G] ++ lists:nthtail(Pos-1, Acc)
    end, Suites, GreaseVals),
    Final = case maps:get(cipher_order_randomized, Profile, false) of
        true -> shuffle_list(WithGrease); false -> WithGrease
    end,
    << <<S:?u16>> || S <- Final >>.

build_key_share_entries(#{key_share_groups := Groups, grease_count := {Min, Max}}) ->
    N = Min + rand:uniform(Max - Min + 1),
    GreaseVals = random_grease(N),
    GreaseEntries = [<<G:?u16, 16#00, 16#01, 16#00>> || G <- GreaseVals],
    RealEntries = [begin KS = key_size_for_group(G), <<G:?u16, KS:?u16, (crypto:strong_rand_bytes(KS))/binary>> end || G <- Groups],
    All = lists:foldl(fun(G, Acc) ->
        Pos = rand:uniform(length(Acc)+1),
        lists:sublist(Acc, Pos-1) ++ [G] ++ lists:nthtail(Pos-1, Acc)
    end, RealEntries, GreaseEntries),
    iolist_to_binary(All).

key_size_for_group(16#001D) -> 32;
key_size_for_group(16#0017) -> 65;
key_size_for_group(16#0018) -> 97;
key_size_for_group(16#0019) -> 133;
key_size_for_group(16#11EC) -> 1216;
key_size_for_group(_) -> 32.

build_supported_versions_ext(#{supported_versions := Versions, grease_count := {Min, Max}} = Profile) ->
    N = Min + rand:uniform(Max - Min + 1),
    GreaseVals = random_grease(N),
    WithGrease = lists:foldl(fun(G, Acc) ->
        Pos = rand:uniform(length(Acc)+1),
        lists:sublist(Acc, Pos-1) ++ [G] ++ lists:nthtail(Pos-1, Acc)
    end, Versions, GreaseVals),
    Final = case maps:get(version_order_randomized, Profile, false) of
        true -> shuffle_list(WithGrease); false -> WithGrease
    end,
    << <<V:?u16>> || V <- Final >>.

build_sig_algos(#{sig_algorithms_count := Count}) ->
    All = [16#04,16#03, 16#05,16#03, 16#06,16#03, 16#02,16#03, 16#08,16#04,
           16#08,16#05, 16#08,16#06, 16#04,16#01, 16#05,16#01, 16#06,16#01,
           16#02,16#01, 16#04,16#02, 16#03,16#02, 16#02,16#02, 16#03,16#01],
    Sel = lists:sublist(All, Count*2),
    Shuf = shuffle_list(Sel),
    Len = Count*2,
    <<16#00,16#0d, (Len+2):?u16, Len:?u16, << <<A:8>> || A <- Shuf >>/binary>>.

build_ech(#{ech_payload_size := Sizes}) when is_list(Sizes) ->
    PayloadSize = lists:nth(rand:uniform(length(Sizes)), Sizes),
    EchRand1 = crypto:strong_rand_bytes(1),
    EchRand32 = crypto:strong_rand_bytes(32),
    EchPayload = crypto:strong_rand_bytes(PayloadSize),
    Content = <<16#00,16#00,16#01,16#00,16#01, EchRand1/binary,
                16#00,16#20, EchRand32/binary,
                (byte_size(EchPayload)):?u16, EchPayload/binary>>,
    <<16#fe,16#0d, (byte_size(Content)):?u16, Content/binary>>;
build_ech(_) -> <<>>.

build_alpn(#{alpn_protocols := Protocols}) ->
    Sel = lists:nth(rand:uniform(length(Protocols)), Protocols),
    Entries = << <<(byte_size(P)):8, P/binary>> || P <- Sel >>,
    Len = byte_size(Entries),
    <<16#00,16#10, (Len+2):?u16, Len:?u16, Entries/binary>>;
build_alpn(_) -> <<>>.

build_compress_certificate(#{compress_certificate := brotli}) ->
    <<16#00,16#1b,16#00,16#03,16#02,16#00,16#02>>;
build_compress_certificate(_) -> <<>>.

build_ec_point_formats(#{ec_point_formats := true}) ->
    <<16#00,16#0b,16#00,16#02,16#01,16#00>>;
build_ec_point_formats(_) -> <<>>.

build_supported_groups(#{key_share_groups := Groups, grease_count := {Min, Max}}) ->
    N = Min + rand:uniform(Max - Min + 1),
    GreaseVals = random_grease(N),
    With = lists:foldl(fun(G, Acc) ->
        Pos = rand:uniform(length(Acc)+1),
        lists:sublist(Acc, Pos-1) ++ [G] ++ lists:nthtail(Pos-1, Acc)
    end, Groups, GreaseVals),
    Bin = << <<G:?u16>> || G <- With >>,
    Len = byte_size(Bin),
    <<16#00,16#0a, (Len+2):?u16, Len:?u16, Bin/binary>>.

build_padding(#{padding_size := {Min, Max}}) ->
    PadSize = Min + rand:uniform(Max - Min + 1),
    if PadSize == 0 -> <<>>;
       true -> <<16#00,16#15, PadSize:?u16, (binary:copy(<<0>>, PadSize))/binary>>
    end;
build_padding(_) -> <<>>.

build_session_ticket_ext(#{session_ticket_enabled := true}) ->
    <<?EXT_SESSION_TICKET:?u16, 0:?u16>>;
build_session_ticket_ext(_) -> <<>>.

build_ocsp_stapling_ext(#{ocsp_stapling_enabled := true}) ->
    <<?EXT_STATUS_REQUEST:?u16, 0:?u16>>;
build_ocsp_stapling_ext(_) -> <<>>.

build_alps_ext(#{alps_enabled := true}) ->
    <<16#44,16#cd,16#00,16#05,16#00,16#03,16#02,$h,$2>>;
build_alps_ext(_) -> <<>>.

build_renegotiation_info_ext(#{renegotiation_info_enabled := true}) ->
    <<16#ff,16#01,16#00,16#01,16#00>>;
build_renegotiation_info_ext(_) -> <<>>.

make_sni(Domains) ->
    Items = << <<?EXT_SNI_HOST_NAME, (byte_size(D)):?u16, D/binary>> || D <- Domains >>,
    Len = byte_size(Items),
    <<?EXT_SNI:?u16, (Len+2):?u16, Len:?u16, Items/binary>>.

%% ============================================================================
%% make_client_hello – full extensions, unchanged
%% ============================================================================
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
    SupportedVersions = <<16#00,16#2b, (VersionsLen+1):?u16, VersionsLen, SupportedVersionsExt/binary>>,
    KeyShareEntries = build_key_share_entries(Profile),
    KSListLen = byte_size(KeyShareEntries),
    KeyShare = <<16#00,16#33, (KSListLen+2):?u16, KSListLen:?u16, KeyShareEntries/binary>>,
    ECH = build_ech(Profile),
    ALPN = build_alpn(Profile),
    CompCertExt = build_compress_certificate(Profile),
    EcPointExt = build_ec_point_formats(Profile),
    SessionTicketExt = build_session_ticket_ext(Profile),
    OcspStaplingExt = build_ocsp_stapling_ext(Profile),
    AlpsExt = build_alps_ext(Profile),
    RenegExt = build_renegotiation_info_ext(Profile),
    PaddingExt = build_padding(Profile),

    BaseExts = [ECH, SessionTicketExt, EcPointExt, AlpsExt, KeyShare,
                <<16#00,16#12,0:16>>, SupportedGroups, CompCertExt, RenegExt,
                SigAlgos, OcspStaplingExt,
                <<16#00,16#2d,16#00,16#02,16#01,16#01>>, ALPN, SNI,
                SupportedVersions, PaddingExt],
    NonEmpty = [E || E <- BaseExts, E =/= <<>>],
    Extensions = case maps:get(extensions_order_randomized, Profile, false) of
        true -> shuffle_list(NonEmpty); false -> NonEmpty
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
    FakeRandom = crypto:exor(Digest, <<(binary:copy(<<0>>, ?DIGEST_LEN - 4))/binary, Timestamp:32/unsigned-little>>),
    Pack(FakeRandom).

%% ============================================================================
%% parse_server_hello (unchanged, handles various record combinations)
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
parse_server_hello(<<?TLS_REC_HANDSHAKE, ?TLS_12_VERSION, HSLen:?u16, Handshake:HSLen/binary,
                     ?TLS_REC_CHANGE_CIPHER, ?TLS_12_VERSION, CCLen:?u16, ChangeCipher:CCLen/binary,
                     ?TLS_REC_DATA, ?TLS_12_VERSION, DLen:?u16, Data:DLen/binary,
                     ?TLS_REC_HANDSHAKE, ?TLS_12_VERSION, TicketLen:?u16, _Ticket:TicketLen/binary,
                     ?TLS_REC_HANDSHAKE, ?TLS_12_VERSION, CompCertLen:?u16, _CompCert:CompCertLen/binary,
                     Tail/binary>>) ->
    {Handshake, ChangeCipher, Data, Tail};
parse_server_hello(B) when byte_size(B) < 5 -> incomplete;
parse_server_hello(<<16#16, _/binary>> = B) ->
    case tls_records_complete(B, 4) of true -> {error, tls_domain_forwarding}; false -> incomplete end;
parse_server_hello(<<16#15, _/binary>>) -> {error, tls_alert};
parse_server_hello(_) -> {error, not_proxy_response}.

tls_records_complete(_, 0) -> true;
tls_records_complete(<<_T, _Mj, _Mn, Len:?u16, Rest/binary>>, N) when byte_size(Rest) >= Len ->
    <<_:Len/binary, Tail/binary>> = Rest,
    tls_records_complete(Tail, N-1);
tls_records_complete(_, _) -> false.

%% ============================================================================
%% Data stream codec
%% ============================================================================
-spec new() -> codec().
new() -> #st{}.

-spec try_decode_packet(binary(), codec()) -> {ok, binary(), binary(), codec()} | {incomplete, codec()}.
try_decode_packet(<<?TLS_12_DATA, Size:?u16, Data:Size/binary, Tail/binary>>, St) ->
    {ok, Data, Tail, St};
try_decode_packet(<<?TLS_REC_CHANGE_CIPHER, ?TLS_12_VERSION, Size:?u16, _Data:Size/binary, Tail/binary>>, St) ->
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
encode_packet(Bin, St) -> {encode_as_frames(Bin), St}.

encode_as_frames(Bin) when byte_size(Bin) =< ?MAX_OUT_PACKET_SIZE ->
    as_tls_data_frame(Bin);
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
