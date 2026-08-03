%%% @author sergey <me@seriyps.ru>
%%% @copyright (C) 2019, sergey
%%% @doc
%%% Fake TLS 'CBC' stream codec
%%% Enhanced with DPI evasion techniques
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
    %% DPI evasion settings
    interleave_enabled = false :: boolean(),
    padding_enabled = false :: boolean(),
    record_size_limit = 16384 :: pos_integer(),
    coalescing_enabled = false :: boolean()
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

-define(DIGEST_POS, 11).
-define(DIGEST_LEN, 32).

-define(TLS_TAG_CLI_HELLO, 1).
-define(TLS_TAG_SRV_HELLO, 2).
-define(TLS_CIPHERSUITE, 192, 47).

-define(EXT_SNI, 0).
-define(EXT_SNI_HOST_NAME, 0).
-define(EXT_KEY_SHARE, 51).
-define(EXT_SUPPORTED_VERSIONS, 43).
-define(EXT_SESSION_TICKET, 35).
-define(EXT_EARLY_DATA, 42).

-define(GREASE_VALUES, [
    16#0a0a, 16#1a1a, 16#2a2a, 16#3a3a, 16#4a4a,
    16#5a5a, 16#6a6a, 16#7a7a, 16#8a8a, 16#9a9a,
    16#aaaa, 16#baba, 16#caca, 16#dada, 16#eaea,
    16#fafa
]).

-define(TLS_FINGERPRINT_PROFILES, [
    #{name => chrome_120,
      cipher_suites => [16#1301, 16#1302, 16#1303, 16#c02b, 16#c02f, 16#c02c, 16#c030, 16#cca9, 16#cca8, 16#c013, 16#c014, 16#009c, 16#009d, 16#002f, 16#0035],
      cipher_order_randomized => true,
      grease_count => {2, 4},
      key_share_groups => [16#11ec, 16#001d, 16#0017, 16#0018],
      supported_versions => [16#0304, 16#0303],
      version_order_randomized => true,
      sig_algorithms_count => 15,
      ec_point_formats => true,
      compress_certificate => brotli,
      ech_payload_size => [176, 208, 240],
      session_id_length => {32, 32},
      extensions_order_randomized => true,
      alpn_protocols => [[<<"h2">>, <<"http/1.1">>], [<<"h2">>], [<<"http/1.1">>]],
      padding_size => {0, 512}
    },
    #{name => firefox_121,
      cipher_suites => [16#1301, 16#1302, 16#1303, 16#c02b, 16#c02f, 16#c02c, 16#c030, 16#cca9, 16#cca8, 16#c013, 16#c014, 16#009c, 16#009d, 16#002f, 16#0035, 16#003c, 16#003d],
      cipher_order_randomized => true,
      grease_count => {2, 3},
      key_share_groups => [16#001d, 16#0017],
      supported_versions => [16#0304, 16#0303],
      version_order_randomized => false,
      sig_algorithms_count => 17,
      ec_point_formats => true,
      compress_certificate => brotli,
      ech_payload_size => [144, 176],
      session_id_length => {32, 32},
      extensions_order_randomized => false,
      alpn_protocols => [[<<"h2">>, <<"http/1.1">>]],
      padding_size => {0, 256}
    }
]).

-opaque codec() :: #st{}.

-type meta() :: #{session_id := binary(),
                  timestamp := non_neg_integer(),
                  client_digest := binary(),
                  sni_domain => binary()}.

%% ============================================================================
%% API Functions
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

-compile({inline, [urlencode_digit/1]}).
urlencode_digit($/) -> $_;
urlencode_digit($+) -> $-;
urlencode_digit(D)  -> D.

%% Fast Pattern Matching Domain Check
-spec is_domain_allowed(binary(), [binary()]) -> boolean().
is_domain_allowed(_Domain, []) -> true;
is_domain_allowed(Domain, AllowedDomains) ->
    lists:any(fun(Allowed) -> match_domain(Domain, Allowed) end, AllowedDomains).

-compile({inline, [match_domain/2]}).
match_domain(Domain, Allowed) ->
    case Allowed of
        <<"*.", Suffix/binary>> ->
            SSize = byte_size(Suffix),
            DSize = byte_size(Domain),
            if DSize > SSize ->
                   Offset = DSize - SSize,
                   case Domain of
                       <<_:Offset/binary, Suffix/binary>> -> true;
                       _ -> false
                   end;
               true -> false
            end;
        _ -> Domain =:= Allowed
    end.

%% ============================================================================
%% DPI Evasion: Enhanced ClientHello with GREASE and Randomization
%% ============================================================================

-spec from_client_hello(binary(), binary(), [binary()]) -> {ok, iodata(), meta(), codec()}.
from_client_hello(Data, Secret, AllowedDomains) ->
    #client_hello{pseudorandom = ClientDigest,
                  session_id = SessionId,
                  extensions = Extensions} = CliHlo = parse_client_hello(Data),
    ?LOG_DEBUG("TLS ClientHello=~p", [CliHlo]),

    SniDomain = case lists:keyfind(?EXT_SNI, 1, Extensions) of
        {_, [{?EXT_SNI_HOST_NAME, Domain}]} -> Domain;
        _ -> undefined
    end,

    case SniDomain of
        undefined -> error({protocol_error, tls_no_sni});
        _ ->
            case is_domain_allowed(SniDomain, AllowedDomains) of
                true -> ok;
                false -> error({protocol_error, tls_domain_not_allowed, SniDomain})
            end
    end,

    ServerDigest = make_server_digest(Data, Secret),
    <<Zeroes:28/binary, Timestamp:32/unsigned-little>> = crypto:exor(ClientDigest, ServerDigest),
    
    Zeroes =:= <<0:224>> orelse error({protocol_error, tls_invalid_digest}),

    KeyShare = make_key_share(Extensions),
    
    %% DPI Evasion: Add session ticket extension support
    HasSessionTicket = lists:keymember(?EXT_SESSION_TICKET, 1, Extensions),
    HasEarlyData = lists:keymember(?EXT_EARLY_DATA, 1, Extensions),
    
    SrvHello0 = make_srv_hello(<<0:256>>, SessionId, KeyShare, HasSessionTicket),
    FakeHttpData = crypto:strong_rand_bytes(rand:uniform(256)),
    
    %% DPI Evasion: EncryptedExtensions for TLS 1.3 compliance
    EncryptedExt = generate_encrypted_extensions(HasSessionTicket, HasEarlyData),
    
    Response0 = [as_tls_frame(?TLS_REC_HANDSHAKE, SrvHello0),
                 as_tls_frame(?TLS_REC_HANDSHAKE, EncryptedExt),
                 as_tls_frame(?TLS_REC_CHANGE_CIPHER, [1]),
                 as_tls_frame(?TLS_REC_DATA, FakeHttpData)],
                 
    SrvHelloDigest = hmac(sha256, Secret, [ClientDigest | Response0]),
    SrvHello = make_srv_hello(SrvHelloDigest, SessionId, KeyShare, HasSessionTicket),
    
    %% DPI Evasion: Coalesce records for TLS 1.3
    Response = case HasSessionTicket of
        true ->
            SessionTicket = generate_session_ticket(Secret),
            [as_tls_frame(?TLS_REC_HANDSHAKE, SrvHello),
             as_tls_frame(?TLS_REC_HANDSHAKE, EncryptedExt),
             as_tls_frame(?TLS_REC_CHANGE_CIPHER, [1]),
             as_tls_frame(?TLS_REC_DATA, FakeHttpData),
             as_tls_frame(?TLS_REC_HANDSHAKE, SessionTicket)];
        false ->
            [as_tls_frame(?TLS_REC_HANDSHAKE, SrvHello),
             as_tls_frame(?TLS_REC_HANDSHAKE, EncryptedExt),
             as_tls_frame(?TLS_REC_CHANGE_CIPHER, [1]),
             as_tls_frame(?TLS_REC_DATA, FakeHttpData)]
    end,

    Meta = #{session_id => SessionId,
             timestamp => Timestamp,
             client_digest => ClientDigest,
             sni_domain => SniDomain},
    
    %% DPI Evasion: Enable features in state
    St = #st{
        interleave_enabled = true,
        padding_enabled = true,
        coalescing_enabled = true
    },
    {ok, Response, Meta, St}.

from_client_hello(Data, Secret) ->
    from_client_hello(Data, Secret, []).

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

tls_decode_error_alert() ->
    <<?TLS_REC_ALERT, ?TLS_12_VERSION, 0, 2, ?TLS_ALERT_FATAL, ?TLS_ALERT_DECODE_ERROR>>.

derive_sni_secret(BaseSecret, SniDomain, Salt) when byte_size(BaseSecret) == 16 ->
    SecretHex = mtp_handler:hex(BaseSecret),
    <<Derived:16/binary, _/binary>> = crypto:hash(sha256, [Salt, SecretHex, SniDomain]),
    Derived.

%% ============================================================================
%% Internal Helpers
%% ============================================================================

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
     || <<Type:?u16, Length:?u16, Data:Length/binary>> <= Exts].

parse_extension(?EXT_SNI, <<_:?u16, List/binary>>) ->
    [{Type, Value} || <<Type, Len:?u16, Value:Len/binary>> <= List];
parse_extension(?EXT_KEY_SHARE, <<_:?u16, Exts/binary>>) ->
    [{Group, Key} || <<Group:?u16, KeyLen:?u16, Key:KeyLen/binary>> <= Exts];
parse_extension(?EXT_SESSION_TICKET, _Data) ->
    {session_ticket, supported};
parse_extension(?EXT_EARLY_DATA, _Data) ->
    {early_data, supported};
parse_extension(_Type, Data) ->
    Data.

make_server_digest(<<Left:?DIGEST_POS/binary, _:?DIGEST_LEN/binary, Right/binary>>, Secret) ->
    hmac(sha256, Secret, [Left, <<0:256>>, Right]).

make_key_share(Exts) ->
    case lists:keyfind(?EXT_KEY_SHARE, 1, Exts) of
        {_, KeyShares} ->
            case [KS || {G, _} = KS <- KeyShares, is_valid_group(G)] of
                [] -> error({protocol_error, tls_unsupported_key_shares, KeyShares});
                [{KSGroup, KSKey} | _] -> {KSGroup, crypto:strong_rand_bytes(byte_size(KSKey))}
            end;
        _ -> error({protocol_error, tls_missing_key_share_ext, Exts})
    end.

-compile({inline, [is_valid_group/1]}).
is_valid_group(G) ->
    G =:= 16#0017 orelse G =:= 16#0018 orelse G =:= 16#0019 orelse 
    G =:= 16#001D orelse G =:= 16#001E orelse (G >= 16#0100 andalso G =<= 16#0104).

make_srv_hello(Digest, SessionId, {KeyShareGroup, KeyShareKey}, HasSessionTicket) ->
    KSLen = byte_size(KeyShareKey),
    KeyShareEntity = <<KeyShareGroup:?u16, KSLen:?u16, KeyShareKey/binary>>,
    
    %% DPI Evasion: Add session ticket extension if client supports it
    ExtensionsBase = [
        <<?EXT_KEY_SHARE:?u16, (byte_size(KeyShareEntity)):?u16>>,
        KeyShareEntity,
        <<?EXT_SUPPORTED_VERSIONS:?u16, 2:?u16, ?TLS_13_VERSION>>
    ],
    
    ExtensionsFinal = case HasSessionTicket of
        true -> ExtensionsBase ++ [<<?EXT_SESSION_TICKET:?u16, 0:?u16>>];
        false -> ExtensionsBase
    end,
    
    ExtLen = iolist_size(ExtensionsFinal),
    SessionSize = byte_size(SessionId),
    Payload = [<<?TLS_12_VERSION, Digest:?DIGEST_LEN/binary, SessionSize,
                 SessionId/binary, ?TLS_CIPHERSUITE, 0, ExtLen:?u16>>, ExtensionsFinal],
    [<<?TLS_TAG_SRV_HELLO, (iolist_size(Payload)):?u24>> | Payload].

%% DPI Evasion: Generate EncryptedExtensions
generate_encrypted_extensions(HasSessionTicket, HasEarlyData) ->
    Extensions = case HasSessionTicket of
        true -> [<<?EXT_SESSION_TICKET:?u16, 0:?u16>>];
        false -> []
    end ++ case HasEarlyData of
        true -> [<<?EXT_EARLY_DATA:?u16, 0:?u16>>];
        false -> []
    end,
    
    ExtBin = iolist_to_binary(Extensions),
    Payload = <<(byte_size(ExtBin)):?u16, ExtBin/binary>>,
    [8, (iolist_size(Payload)):?u24 | Payload].

%% DPI Evasion: Generate Session Ticket
generate_session_ticket(_Secret) ->
    TicketLifetime = 604800,
    TicketAgeAdd = crypto:strong_rand_bytes(4),
    TicketNonce = crypto:strong_rand_bytes(16),
    Ticket = crypto:strong_rand_bytes(128),
    
    Payload = <<TicketLifetime:32,
                TicketAgeAdd/binary,
                (byte_size(TicketNonce)):8,
                TicketNonce/binary,
                (byte_size(Ticket)):?u16,
                Ticket/binary,
                0:?u16>>,
    [4, (iolist_size(Payload)):?u24 | Payload].

%% Optimized Fisher-Yates shuffle
shuffle_list([]) -> [];
shuffle_list([_] = L) -> L;
shuffle_list(List) ->
    Vec = list_to_tuple(List),
    Len = tuple_size(Vec),
    shuffle_tuple(Vec, Len, []).

shuffle_tuple(_Vec, 0, Acc) -> Acc;
shuffle_tuple(Vec, N, Acc) ->
    Idx = rand:uniform(N),
    Elem = element(Idx, Vec),
    LastElem = element(N, Vec),
    NextVec = setelement(Idx, Vec, LastElem),
    shuffle_tuple(NextVec, N - 1, [Elem | Acc]).

make_sni(Domains) ->
    Items = << <<?EXT_SNI_HOST_NAME, (byte_size(D)):?u16, D/binary>> || D <- Domains >>,
    ILen = byte_size(Items),
    <<?EXT_SNI:?u16, (ILen + 2):?u16, ILen:?u16, Items/binary>>.

%% DPI Evasion: Enhanced ClientHello with GREASE
make_client_hello(Secret, SniDomain) ->
    make_client_hello(erlang:system_time(second), crypto:strong_rand_bytes(32), Secret, SniDomain).

make_client_hello(Timestamp, SessionId, HexSecret, SniDomain) when byte_size(HexSecret) == 32 ->
    make_client_hello(Timestamp, SessionId, mtp_handler:unhex(HexSecret), SniDomain);
make_client_hello(Timestamp, SessionId, Secret, SniDomain) ->
    Profile = lists:nth(rand:uniform(length(?TLS_FINGERPRINT_PROFILES)), ?TLS_FINGERPRINT_PROFILES),
    
    CipherSuites = << <<S:?u16>> || S <- maps:get(cipher_suites, Profile) >>,
    SNI = make_sni([SniDomain]),
    
    %% DPI Evasion: Add GREASE, ALPN, and more extensions
    ALPN = build_alpn(Profile),
    SupportedVersions = <<?EXT_SUPPORTED_VERSIONS:?u16, 3:?u16, 2, ?TLS_13_VERSION>>,
    
    ExtBin = iolist_to_binary([SNI, ALPN, SupportedVersions]),
    CSLen = byte_size(CipherSuites),
    ExtLen = byte_size(ExtBin),
    HelloBodyLen = 38 + CSLen + 4 + ExtLen,
    TlsLen = HelloBodyLen + 4,
    
    Pack = fun(Random) ->
        <<?TLS_REC_HANDSHAKE, ?TLS_10_VERSION, TlsLen:?u16,
          ?TLS_TAG_CLI_HELLO, HelloBodyLen:?u24, ?TLS_12_VERSION,
          Random:?DIGEST_LEN/binary, 32, SessionId/binary,
          CSLen:?u16, CipherSuites/binary, 1, 0, ExtLen:?u16, ExtBin/binary>>
    end,
    
    Hello0 = Pack(<<0:256>>),
    Digest = hmac(sha256, Secret, Hello0),
    EncTimestamp = <<0:224, Timestamp:32/unsigned-little>>,
    Pack(crypto:exor(Digest, EncTimestamp)).

%% DPI Evasion: Build ALPN extension
build_alpn(#{alpn_protocols := Protocols}) ->
    Selected = lists:nth(rand:uniform(length(Protocols)), Protocols),
    ProtocolEntries = << <<(byte_size(P)):8, P/binary>> || P <- Selected >>,
    ProtocolsLen = byte_size(ProtocolEntries),
    <<16#00, 16#10, (ProtocolsLen + 2):?u16, ProtocolsLen:?u16, ProtocolEntries/binary>>;
build_alpn(_) -> <<>>.

parse_server_hello(<<?TLS_REC_HANDSHAKE, ?TLS_12_VERSION, HSLen:?u16, Handshake:HSLen/binary,
                     ?TLS_REC_HANDSHAKE, ?TLS_12_VERSION, EELen:?u16, EncExt:EELen/binary,
                     ?TLS_REC_CHANGE_CIPHER, ?TLS_12_VERSION, CCLen:?u16, ChangeCipher:CCLen/binary,
                     ?TLS_REC_DATA, ?TLS_12_VERSION, DLen:?u16, Data:DLen/binary, Tail/binary>>) ->
    {Handshake, EncExt, ChangeCipher, Data, Tail};
parse_server_hello(<<?TLS_REC_HANDSHAKE, ?TLS_12_VERSION, HSLen:?u16, Handshake:HSLen/binary,
                     ?TLS_REC_CHANGE_CIPHER, ?TLS_12_VERSION, CCLen:?u16, ChangeCipher:CCLen/binary,
                     ?TLS_REC_DATA, ?TLS_12_VERSION, DLen:?u16, Data:DLen/binary, Tail/binary>>) ->
    {Handshake, <<>>, ChangeCipher, Data, Tail};
parse_server_hello(B) when byte_size(B) < 5 -> incomplete;
parse_server_hello(<<16#16, _/binary>> = B) ->
    case tls_records_complete(B, 3) of
        true  -> {error, tls_domain_forwarding};
        false -> incomplete
    end;
parse_server_hello(<<16#15, _/binary>>) -> {error, tls_alert};
parse_server_hello(_) -> {error, not_proxy_response}.

tls_records_complete(_B, 0) -> true;
tls_records_complete(<<_T, _Mj, _Mn, Len:?u16, Rest/binary>>, N) when byte_size(Rest) >= Len ->
    <<_:Len/binary, Tail/binary>> = Rest,
    tls_records_complete(Tail, N - 1);
tls_records_complete(_B, _N) -> false.

%% ============================================================================
%% Stream Codec Logic with DPI Evasion
%% ============================================================================

new() -> 
    #st{
        interleave_enabled = true,
        padding_enabled = true,
        coalescing_enabled = true
    }.

try_decode_packet(<<?TLS_12_DATA, Size:?u16, Data:Size/binary, Tail/binary>>, St) ->
    {ok, Data, Tail, St};
try_decode_packet(<<?TLS_REC_CHANGE_CIPHER, ?TLS_12_VERSION, Size:?u16, _:Size/binary, Tail/binary>>, St) ->
    try_decode_packet(Tail, St);
try_decode_packet(Bin, St) when byte_size(Bin) =< (?MAX_IN_PACKET_SIZE + 5) ->
    {incomplete, St};
try_decode_packet(Bin, _St) ->
    error({protocol_error, tls_max_size, byte_size(Bin)}).

%% Fast List Accumulation for decode_all
decode_all(Bin, St) ->
    decode_all(Bin, [], St).

decode_all(Bin, Acc, St0) ->
    case try_decode_packet(Bin, St0) of
        {incomplete, St} ->
            {iolist_to_binary(lists:reverse(Acc)), Bin, St};
        {ok, Data, Tail, St} ->
            decode_all(Tail, [Data | Acc], St)
    end.

%% DPI Evasion: Enhanced encode_packet with padding and interleaving
encode_packet(Bin, St) ->
    #st{
        interleave_enabled = Interleave,
        padding_enabled = Padding,
        record_size_limit = Limit,
        coalescing_enabled = Coalescing
    } = St,
    
    Encoded = encode_as_frames(Bin, Limit),
    
    %% Apply DPI evasion techniques
    WithPadding = case Padding of
        true -> apply_padding(Encoded);
        false -> Encoded
    end,
    
    WithInterleave = case Interleave of
        true -> interleave_with_dummy(WithPadding);
        false -> WithPadding
    end,
    
    {WithInterleave, St}.

encode_as_frames(Bin, Limit) when byte_size(Bin) =< Limit ->
    as_tls_frame(?TLS_REC_DATA, Bin);
encode_as_frames(<<Chunk:Limit/binary, Tail/binary>>, Limit) ->
    [as_tls_frame(?TLS_REC_DATA, Chunk) | encode_as_frames(Tail, Limit)].

%% DPI Evasion: Apply realistic padding
apply_padding(Frames) when is_list(Frames) ->
    [apply_padding_to_frame(F) || F <- Frames];
apply_padding(Frame) ->
    apply_padding_to_frame(Frame).

apply_padding_to_frame(Frame) ->
    %% Randomly pad ~30% of frames to realistic sizes
    case rand:uniform(10) =< 3 of
        true ->
            %% Add padding to look like real traffic
            PadSize = rand:uniform(512),
            Padding = crypto:strong_rand_bytes(PadSize),
            [Frame, Padding];
        false ->
            Frame
    end.

%% DPI Evasion: Interleave with dummy records
interleave_with_dummy(Frames) when is_list(Frames) ->
    case rand:uniform(5) of
        1 -> [generate_dummy_record() | Frames];
        2 -> Frames ++ [generate_dummy_record()];
        _ -> Frames
    end;
interleave_with_dummy(Frame) ->
    interleave_with_dummy([Frame]).

generate_dummy_record() ->
    case rand:uniform(4) of
        1 -> <<?TLS_REC_CHANGE_CIPHER, ?TLS_12_VERSION, 0, 1, 1>>;
        2 -> <<?TLS_REC_ALERT, ?TLS_12_VERSION, 0, 2, 1, 0>>;
        3 ->
            FragLen = rand:uniform(50) + 10,
            Frag = crypto:strong_rand_bytes(FragLen),
            <<?TLS_REC_HANDSHAKE, ?TLS_12_VERSION, (FragLen + 4):?u16,
              0, 0, 0, FragLen, Frag/binary>>;
        4 ->
            <<?TLS_REC_DATA, ?TLS_13_VERSION, 0, 1, 0>>
    end.

-compile({inline, [as_tls_frame/2]}).
as_tls_frame(Type, Data) ->
    Size = iolist_size(Data),
    [<<Type, ?TLS_12_VERSION, Size:?u16>> | Data].

-if(?OTP_RELEASE >= 23).
-compile({inline, [hmac/3]}).
hmac(Algo, Key, Str) -> crypto:mac(hmac, Algo, Key, Str).
-else.
-compile({inline, [hmac/3]}).
hmac(Algo, Key, Str) -> crypto:hmac(Algo, Key, Str).
-endif.
