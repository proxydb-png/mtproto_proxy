%%%-------------------------------------------------------------------
%%% @doc
%%% Highly Optimized & Advanced Dynamic Fake TLS Processor for MTProto Proxy
%%% - Fixed TLS 1.3 NewSessionTicket Handshake Framing (Tag 4 + 24-bit Length)
%%% - Corrected Record/Handshake Pattern Matching Order
%%% - Optimized Memory & GC ($O(N)$ decoding via iolists)
%%% - Advanced DPI Evasion: ECH, Post-Quantum Ciphers, GREASE, OCSP Stapling,
%%%   Dynamic Padding, and Multi-Profile Fingerprinting (Chrome, Firefox, Safari, Edge).
%%% @end
%%%-------------------------------------------------------------------
-module(mtp_fake_tls).

%% API
-export([
    new/2,
    from_client_hello/3,
    parse_client_hello/1,
    parse_server_hello/1,
    make_client_hello/3,
    make_server_hello/2,
    try_decode_packet/2,
    decode_all/2,
    is_domain_allowed/2,
    parse_sni/1
]).

%% TLS Macros & Constants
-define(TLS_12_VERSION, <<16#03, 16#03>>).
-define(TLS_13_VERSION, <<16#03, 16#04>>).

-define(TLS_REC_CHANGE_CIPHER, 20).
-define(TLS_REC_ALERT, 21).
-define(TLS_REC_HANDSHAKE, 22).
-define(TLS_REC_DATA, 23).

-define(TLS_TAG_CLIENT_HELLO, 1).
-define(TLS_TAG_SERVER_HELLO, 2).
-define(TLS_TAG_NEW_SESSION_TICKET, 4).
-define(TLS_TAG_CERT_STATUS, 11).

-define(EXT_SERVER_NAME, 0).
-define(EXT_STATUS_REQUEST, 5).
-define(EXT_SUPPORTED_GROUPS, 10).
-define(EXT_EC_POINT_FORMATS, 11).
-define(EXT_SIGNATURE_ALGORITHMS, 13).
-define(EXT_ALPN, 16).
-define(EXT_SCT, 18).
-define(EXT_PADDING, 21).
-define(EXT_ENCRYPTED_EXTS, 28).
-define(EXT_SESSION_TICKET, 35).
-define(EXT_PRE_SHARED_KEY, 41).
-define(EXT_SUPPORTED_VERSIONS, 43).
-define(EXT_COOKIE, 44).
-define(EXT_PSK_KEY_EXCHANGE_MODES, 45).
-define(EXT_CERT_COMPRESS, 27).
-define(EXT_KEY_SHARE, 51).
-define(EXT_APPLICATION_SETTINGS, 17513).
-define(EXT_ECH, 65037).

-define(u24, 24/unsigned-big-integer).
-define(u16, 16/unsigned-big-integer).

-define(GREASE_VALUES, [
    16#0A0A, 16#1A1A, 16#2A2A, 16#3A3A,
    16#4A4A, 16#5A5A, 16#6A6A, 16#7A7A,
    16#8A8A, 16#9A9A, 16#AAAA, 16#BABA,
    16#CACA, 16#DADA, 16#EAEA, 16#FAFA
]).

-define(TLS_FINGERPRINT_PROFILES, [
    #{
        name => chrome_120,
        ciphers => [
            16#1301, 16#1302, 16#1303,
            16#C02B, 16#C02F, 16#C02C, 16#C030,
            16#CCA9, 16#CCA8, 16#C013, 16#C014
        ],
        groups => [16#001D, 16#0017, 16#0018, 16#11EC], % 16#11EC: X25519MLKEM768 (PQ)
        alpn => [<<"h2">>, <<"http/1.1">>],
        has_padding => true,
        has_ech => true,
        compress_cert => [1, 2] % Brotli, Zlib
    },
    #{
        name => firefox_121,
        ciphers => [
            16#1301, 16#1302, 16#1303,
            16#C02B, 16#C02F, 16#C00A, 16#C009, 16#C013, 16#C014
        ],
        groups => [16#001D, 16#0017, 16#0018, 16#0019],
        alpn => [<<"h2">>, <<"http/1.1">>],
        has_padding => false,
        has_ech => false,
        compress_cert => [1]
    },
    #{
        name => safari_17,
        ciphers => [
            16#1301, 16#1302, 16#1303,
            16#C02B, 16#C02F, 16#C02C, 16#C030
        ],
        groups => [16#001D, 16#0017, 16#0018],
        alpn => [<<"h2">>, <<"http/1.1">>],
        has_padding => false,
        has_ech => false,
        compress_cert => []
    },
    #{
        name => edge_120,
        ciphers => [
            16#1301, 16#1302, 16#1303,
            16#C02B, 16#C02F, 16#CCA9, 16#CCA8
        ],
        groups => [16#001D, 16#0017, 16#0018, 16#11EC],
        alpn => [<<"h2">>, <<"http/1.1">>],
        has_padding => true,
        has_ech => true,
        compress_cert => [1, 2]
    }
]).

-record(st, {
    secret :: binary(),
    domain :: binary(),
    profile :: map(),
    session_id :: binary(),
    ocsp_response :: binary()
}).

%%====================================================================
%% API Functions
%%====================================================================

new(Secret, Domain) ->
    Profiles = ?TLS_FINGERPRINT_PROFILES,
    SelectedProfile = lists:nth(rand:uniform(length(Profiles)), Profiles),
    SessionId = crypto:strong_rand_bytes(32),
    OcspResp = generate_ocsp_response(Domain),
    
    #st{
        secret = Secret,
        domain = Domain,
        profile = SelectedProfile,
        session_id = SessionId,
        ocsp_response = OcspResp
    }.

from_client_hello(ClientHello, Secret, AllowedDomains) ->
    case parse_client_hello(ClientHello) of
        {ok, Domain, SessionId} ->
            case is_domain_allowed(Domain, AllowedDomains) of
                true ->
                    St = new(Secret, Domain),
                    ServerHello = make_server_hello(St, SessionId),
                    {ok, St, ServerHello};
                false ->
                    {error, domain_not_allowed}
            end;
        error ->
            {error, invalid_client_hello}
    end.

parse_client_hello(<<?TLS_REC_HANDSHAKE, ?TLS_12_VERSION, _Len:?u16,
                     ?TLS_TAG_CLIENT_HELLO, _HSLen:?u24, ?TLS_12_VERSION,
                     _Random:32/binary,
                     SessionIdLen:8, _SessionId:SessionIdLen/binary,
                     CiphersLen:?u16, _Ciphers:CiphersLen/binary,
                     CompMethodsLen:8, _CompMethods:CompMethodsLen/binary,
                     ExtsLen:?u16, Exts:ExtsLen/binary, _/binary>>) ->
    case parse_sni(Exts) of
        {ok, Domain} -> {ok, Domain, _SessionId};
        error -> error
    end;
parse_client_hello(_) ->
    error.

%% Corrected Pattern Matching: Specific (With Ticket) matched first
parse_server_hello(<<?TLS_REC_HANDSHAKE, ?TLS_12_VERSION, HSLen:?u16, Handshake:HSLen/binary,
                     ?TLS_REC_CHANGE_CIPHER, ?TLS_12_VERSION, CCLen:?u16, ChangeCipher:CCLen/binary,
                     ?TLS_REC_DATA, ?TLS_12_VERSION, DLen:?u16, Data:DLen/binary,
                     ?TLS_REC_HANDSHAKE, ?TLS_12_VERSION, TicketLen:?u16, Ticket:TicketLen/binary,
                     Tail/binary>>) ->
    {Handshake, ChangeCipher, Data, Ticket, Tail};

parse_server_hello(<<?TLS_REC_HANDSHAKE, ?TLS_12_VERSION, HSLen:?u16, Handshake:HSLen/binary,
                     ?TLS_REC_CHANGE_CIPHER, ?TLS_12_VERSION, CCLen:?u16, ChangeCipher:CCLen/binary,
                     ?TLS_REC_DATA, ?TLS_12_VERSION, DLen:?u16, Data:DLen/binary,
                     Tail/binary>>) ->
    {Handshake, ChangeCipher, Data, Tail};

parse_server_hello(_) ->
    error.

make_client_hello(#st{domain = Domain, profile = Profile, session_id = SessionId}, _Secret, _Extra) ->
    Random = crypto:strong_rand_bytes(32),
    SessionIdLen = byte_size(SessionId),
    
    CiphersBin = build_cipher_suites(maps:get(ciphers, Profile)),
    ExtsBin = build_client_extensions(Domain, Profile),
    
    HandshakeBody = [
        ?TLS_12_VERSION,
        Random,
        <<SessionIdLen:8>>, SessionId,
        <<(byte_size(CiphersBin)):?u16>>, CiphersBin,
        <<1:8, 0:8>>, % Compression Method: null
        <<(byte_size(ExtsBin)):?u16>>, ExtsBin
    ],
    
    HandshakeBodyBin = iolist_to_binary(HandshakeBody),
    HSLen = byte_size(HandshakeBodyBin),
    
    HandshakeRecord = [
        <<?TLS_TAG_CLIENT_HELLO>>,
        <<HSLen:?u24>>,
        HandshakeBodyBin
    ],
    
    HSRecordBin = iolist_to_binary(HandshakeRecord),
    RecLen = byte_size(HSRecordBin),
    
    iolist_to_binary([
        <<?TLS_REC_HANDSHAKE>>,
        ?TLS_12_VERSION,
        <<RecLen:?u16>>,
        HSRecordBin
    ]).

make_server_hello(#st{session_id = ClientSessionId, secret = Secret, ocsp_response = OcspResp}, ClientSessionId) ->
    Random = crypto:strong_rand_bytes(32),
    SessionId = case byte_size(ClientSessionId) of
        0 -> crypto:strong_rand_bytes(32);
        _ -> ClientSessionId
    end,
    
    Exts = [
        build_ext(?EXT_SUPPORTED_VERSIONS, <<2:8, 3, 4>>),
        build_ext(?EXT_KEY_SHARE, <<16#00, 16#1D, 0:?u16, 32:?u16, (crypto:strong_rand_bytes(32))/binary>>),
        build_ext(?EXT_SESSION_TICKET, <<>>),
        build_ext(?EXT_STATUS_REQUEST, <<>>)
    ],
    ExtsBin = iolist_to_binary(shuffle_list(Exts)),
    
    ServerHelloBody = [
        ?TLS_12_VERSION,
        Random,
        <<(byte_size(SessionId)):8>>, SessionId,
        <<16#13, 16#01>>, % TLS_AES_128_GCM_SHA256
        <<0:8>>,
        <<(byte_size(ExtsBin)):?u16>>, ExtsBin
    ],
    ServerHelloBin = iolist_to_binary(ServerHelloBody),
    SHLen = byte_size(ServerHelloBin),
    
    Handshake = [<<?TLS_TAG_SERVER_HELLO>>, <<SHLen:?u24>>, ServerHelloBin],
    HandshakeBin = iolist_to_binary(Handshake),
    
    Rec0 = [<<?TLS_REC_HANDSHAKE>>, ?TLS_12_VERSION, <<(byte_size(HandshakeBin)):?u16>>, HandshakeBin],
    Rec1 = [<<?TLS_REC_CHANGE_CIPHER>>, ?TLS_12_VERSION, <<1:?u16, 1:8>>],
    
    % Server First Flight Packet Expansion (512 - 1024 bytes for realistic TLS Server Certificate/Response)
    FakeHttpData = crypto:strong_rand_bytes(512 + rand:uniform(512)),
    Rec2 = [<<?TLS_REC_DATA>>, ?TLS_12_VERSION, <<(byte_size(FakeHttpData)):?u16>>, FakeHttpData],
    
    % RFC 5077 Session Ticket Handshake Frame Optimization
    SessionTicketPayload = generate_session_ticket(Secret),
    Rec3 = [<<?TLS_REC_HANDSHAKE>>, ?TLS_12_VERSION, <<(byte_size(SessionTicketPayload)):?u16>>, SessionTicketPayload],
    
    % Stapled OCSP Response Frame
    OcspFrame = generate_ocsp_handshake_frame(OcspResp),
    Rec4 = [<<?TLS_REC_HANDSHAKE>>, ?TLS_12_VERSION, <<(byte_size(OcspFrame)):?u16>>, OcspFrame],
    
    iolist_to_binary([Rec0, Rec1, Rec2, Rec3, Rec4]).

try_decode_packet(<<?TLS_REC_DATA, ?TLS_12_VERSION, Len:?u16, Data:Len/binary, Tail/binary>>, St) ->
    {ok, Data, Tail, St};
try_decode_packet(<<?TLS_REC_CHANGE_CIPHER, _/binary>>, St) ->
    {incomplete, St};
try_decode_packet(<<?TLS_REC_HANDSHAKE, _/binary>>, St) ->
    {incomplete, St};
try_decode_packet(Bin, St) when is_binary(Bin) ->
    {incomplete, St}.

%% Optimized O(N) Decoding Strategy using Iolists (Low Memory / Low GC Overhead)
decode_all(Bin, St) ->
    decode_all(Bin, [], St).

decode_all(Bin, Acc, St0) ->
    case try_decode_packet(Bin, St0) of
        {incomplete, St} ->
            {iolist_to_binary(lists:reverse(Acc)), Bin, St};
        {ok, Data, Tail, St} ->
            decode_all(Tail, [Data | Acc], St)
    end.

is_domain_allowed(Domain, AllowedDomains) ->
    lists:any(fun(Pattern) -> match_domain(Domain, Pattern) end, AllowedDomains).

parse_sni(Exts) ->
    parse_sni_exts(Exts).

%%====================================================================
%% Internal Functions
%%====================================================================

parse_sni_exts(<<?EXT_SERVER_NAME:?u16, _Len:?u16, _ListLen:?u16, 0:8, NameLen:?u16, Domain:NameLen/binary, _/binary>>) ->
    {ok, Domain};
parse_sni_exts(<<_:?u16, Len:?u16, Rest:Len/binary, Tail/binary>>) ->
    parse_sni_exts(Tail);
parse_sni_exts(<<_:?u16, Len:?u16, Tail/binary>>) when byte_size(Tail) >= Len ->
    <<_:Len/binary, Rest/binary>> = Tail,
    parse_sni_exts(Rest);
parse_sni_exts(_) ->
    error.

match_domain(Domain, Pattern) ->
    case binary:split(Pattern, <<"*">>) of
        [<<"">>, Suffix] -> binary:ends_with(Domain, Suffix);
        [Prefix] -> Domain == Prefix;
        _ -> false
    end.

build_cipher_suites(Ciphers) ->
    Grease = get_random_grease(),
    Shuffled = shuffle_list(Ciphers),
    All = [Grease | Shuffled],
    << <<C:?u16>> || C <- All >>.

build_client_extensions(Domain, Profile) ->
    SNI = build_sni_ext(Domain),
    Groups = build_supported_groups(maps:get(groups, Profile)),
    ECFormats = build_ext(?EXT_EC_POINT_FORMATS, <<1:8, 0:8>>),
    SigAlgs = build_signature_algorithms(),
    ALPN = build_alpn_ext(maps:get(alpn, Profile)),
    SupVers = build_supported_versions_ext(),
    KeyShare = build_key_share_ext(maps:get(groups, Profile)),
    PSKModes = build_ext(?EXT_PSK_KEY_EXCHANGE_MODES, <<1:8, 1:8>>),
    
    Exts0 = [SNI, Groups, ECFormats, SigAlgs, ALPN, SupVers, KeyShare, PSKModes],
    
    Exts1 = case maps:get(compress_cert, Profile) of
        [] -> Exts0;
        CompList -> [build_cert_compress_ext(CompList) | Exts0]
    end,
    
    Exts2 = case maps:get(has_ech, Profile) of
        true -> [build_ech_ext() | Exts1];
        false -> Exts1
    end,
    
    Exts3 = [build_ext(get_random_grease(), crypto:strong_rand_bytes(rand:uniform(4))) | Exts2],
    
    Exts4 = shuffle_list(Exts3),
    
    Exts5 = case maps:get(has_padding, Profile) of
        true ->
            TempBin = iolist_to_binary(Exts4),
            PadLen = max(0, 512 - (byte_size(TempBin) + 4)),
            if PadLen > 0 ->
                [build_ext(?EXT_PADDING, binary:copy(<<0>>, PadLen)) | Exts4];
               true -> Exts4
            end;
        false -> Exts4
    end,
    
    iolist_to_binary(Exts5).

build_sni_ext(Domain) ->
    NameLen = byte_size(Domain),
    ListLen = NameLen + 3,
    Data = <<ListLen:?u16, 0:8, NameLen:?u16, Domain/binary>>,
    build_ext(?EXT_SERVER_NAME, Data).

build_supported_groups(Groups) ->
    Grease = get_random_grease(),
    Shuffled = shuffle_list(Groups),
    All = [Grease | Shuffled],
    Bin = << <<G:?u16>> || G <- All >>,
    Len = byte_size(Bin),
    build_ext(?EXT_SUPPORTED_GROUPS, <<Len:?u16, Bin/binary>>).

build_signature_algorithms() ->
    Algs = [
        16#0403, 16#0804, 16#0401, 16#0501,
        16#0805, 16#0503, 16#0806, 16#0601,
        16#0201, 16#0203
    ],
    Shuffled = shuffle_list(Algs),
    Bin = << <<A:?u16>> || A <- Shuffled >>,
    Len = byte_size(Bin),
    build_ext(?EXT_SIGNATURE_ALGORITHMS, <<Len:?u16, Bin/binary>>).

build_alpn_ext(Protocols) ->
    ProtoBin = iolist_to_binary([ <<(byte_size(P)):8, P/binary>> || P <- Protocols ]),
    Len = byte_size(ProtoBin),
    build_ext(?EXT_ALPN, <<Len:?u16, ProtoBin/binary>>).

build_supported_versions_ext() ->
    Grease = get_random_grease(),
    Versions = [Grease, 16#0304, 16#0303],
    Bin = << <<V:?u16>> || V <- Versions >>,
    Len = byte_size(Bin),
    build_ext(?EXT_SUPPORTED_VERSIONS, <<Len:8, Bin/binary>>).

build_key_share_ext(Groups) ->
    Entries = build_key_share_entries(Groups),
    Len = byte_size(Entries),
    build_ext(?EXT_KEY_SHARE, <<Len:?u16, Entries/binary>>).

build_key_share_entries([Group | _]) ->
    KeyLen = case Group of
        16#001D -> 32;
        16#0017 -> 65;
        16#0018 -> 97;
        _ -> 32
    end,
    Key = crypto:strong_rand_bytes(KeyLen),
    Grease = get_random_grease(),
    GreaseKey = crypto:strong_rand_bytes(32),
    <<Grease:?u16, 32:?u16, GreaseKey/binary, Group:?u16, KeyLen:?u16, Key/binary>>.

build_cert_compress_ext(Algs) ->
    Bin = << <<A:8>> || A <- Algs >>,
    Len = byte_size(Bin),
    build_ext(?EXT_CERT_COMPRESS, <<Len:8, Bin/binary>>).

build_ech_ext() ->
    ConfigId = rand:uniform(255),
    KemId = 16#0020, % DHKEM(X25519, HKDF-SHA256)
    PubKey = crypto:strong_rand_bytes(32),
    Payload = crypto:strong_rand_bytes(rand:uniform(64) + 128),
    Data = <<ConfigId:8, KemId:?u16, PubKey/binary, (byte_size(Payload)):?u16, Payload/binary>>,
    build_ext(?EXT_ECH, Data).

build_ext(Type, Data) ->
    Len = byte_size(Data),
    <<Type:?u16, Len:?u16, Data/binary>>.

get_random_grease() ->
    Values = ?GREASE_VALUES,
    lists:nth(rand:uniform(length(Values)), Values).

shuffle_list(List) ->
    [X || {_, X} <- lists:sort([{rand:uniform(), Item} || Item <- List])].

%% Generates Standard-compliant RFC 5077 NewSessionTicket Handshake Frame
%% Correct Format: Tag(1 byte: 4) + Length(24 bits) + Ticket Payload
generate_session_ticket(_Secret) ->
    TicketAgeAdd = crypto:strong_rand_bytes(4),
    TicketNonce = crypto:strong_rand_bytes(rand:uniform(16) + 16),
    Ticket = crypto:strong_rand_bytes(rand:uniform(128) + 128),
    TicketLifetime = 604800, % 7 days
    
    Payload = <<TicketLifetime:32, TicketAgeAdd/binary, 
                (byte_size(TicketNonce)):8, TicketNonce/binary,
                (byte_size(Ticket)):?u16, Ticket/binary,
                0:?u16>>,
    
    <<?TLS_TAG_NEW_SESSION_TICKET, (byte_size(Payload)):?u24, Payload/binary>>.

generate_ocsp_response(Domain) ->
    ProducedAt = encode_generalized_time(calendar:universal_time()),
    NextUpdate = encode_generalized_time(calendar:gregorian_seconds_to_datetime(
        calendar:datetime_to_gregorian_seconds(calendar:universal_time()) + 604800
    )),
    
    CertId = crypto:strong_rand_bytes(32),
    Signature = crypto:strong_rand_bytes(256),
    
    <<0:8, % OCSPResponseStatus: successful
      48, 128, % Sequence
      130, 0, (byte_size(Domain)):8, Domain/binary,
      ProducedAt/binary,
      NextUpdate/binary,
      CertId/binary,
      Signature/binary>>.

generate_ocsp_handshake_frame(OcspResp) ->
    StatusType = 1, % ocsp
    RespLen = byte_size(OcspResp),
    Payload = <<StatusType:8, RespLen:?u24, OcspResp/binary>>,
    <<?TLS_TAG_CERT_STATUS, (byte_size(Payload)):?u24, Payload/binary>>.

encode_generalized_time({{Y, M, D}, {H, Min, S}}) ->
    Format = "~4..0B~2..0B~2..0B~2..0B~2..0B~2..0BZ",
    Str = lists:flatten(io_lib:format(Format, [Y, M, D, H, Min, S])),
    list_to_binary(Str).
