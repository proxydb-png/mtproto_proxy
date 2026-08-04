%%%===================================================================
%%% Fake TLS with strong DPI resistance - Final version
%%% Added: Certificate chain & Session Ticket for MAX evasion
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

-record(st, {
    fragment_size :: pos_integer(),
    packet_count  :: non_neg_integer(),
    change_frag_at :: non_neg_integer()
}).

-record(client_hello, {
    pseudorandom        :: binary(),
    session_id          :: binary(),
    cipher_suites       :: [non_neg_integer()],
    compression_methods :: binary(),
    extensions          :: [{non_neg_integer(), any()}]
}).

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
-define(TLS_TAG_ENCRYPTED_EXTENSIONS, 8).
-define(TLS_TAG_CERTIFICATE, 11).
-define(TLS_TAG_CERTIFICATE_VERIFY, 15).
-define(TLS_TAG_FINISHED, 20).
-define(TLS_TAG_SESSION_TICKET, 4).

-define(TLS_CIPHERSUITE, 192, 47).

-define(EXT_SNI,                 0).
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

-define(GREASE_VALUES, [
    16#0a0a, 16#1a1a, 16#2a2a, 16#3a3a, 16#4a4a,
    16#5a5a, 16#6a6a, 16#7a7a, 16#8a8a, 16#9a9a,
    16#aaaa, 16#baba, 16#caca, 16#dada, 16#eaea,
    16#fafa
]).

-opaque codec() :: #st{}.

-type meta() :: #{
    session_id     := binary(),
    timestamp      := non_neg_integer(),
    client_digest  := binary(),
    sni_domain     => binary()
}.

%%%===================================================================
%%% Secret helpers
%%%===================================================================

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
%%% Fake TLS 1.3 handshake messages
%%%===================================================================

build_encrypted_extensions() ->
    ALPNs = [<<"h2">>, <<"http/1.1">>],
    ALPN = lists:nth(rand:uniform(length(ALPNs)), ALPNs),
    ALPNExt = <<?EXT_ALPN:?u16, (byte_size(ALPN) + 1):?u16,
                (byte_size(ALPN)):8, ALPN/binary>>,
    
    ExtSize = byte_size(ALPNExt),
    <<ExtSize:?u16, ALPNExt/binary>>.

build_certificate() ->
    %% Realistic certificate chain size (800-1400 bytes)
    CertSize = 800 + rand:uniform(600),
    CertData = crypto:strong_rand_bytes(CertSize),
    <<0, (byte_size(CertData)):?u24, CertData/binary>>.

build_certificate_verify() ->
    %% Fake signature (128-256 bytes)
    SigSize = 128 + rand:uniform(128),
    <<16#0804:?u16, SigSize:?u16, (crypto:strong_rand_bytes(SigSize))/binary>>.

build_finished() ->
    %% TLS 1.3 finished message (32 bytes verify data)
    crypto:strong_rand_bytes(32).

build_session_ticket() ->
    %% Realistic session ticket
    Lifetime = 604800 + rand:uniform(86400),
    AgeAdd = crypto:strong_rand_bytes(4),
    NonceSize = 16 + rand:uniform(16),
    Nonce = crypto:strong_rand_bytes(NonceSize),
    TicketSize = 128 + rand:uniform(128),
    Ticket = crypto:strong_rand_bytes(TicketSize),
    
    <<Lifetime:32, AgeAdd/binary,
      NonceSize:8, Nonce/binary,
      TicketSize:?u16, Ticket/binary,
      0:?u16>>.

%%%===================================================================
%%% from_client_hello (server side) - WITH CERTIFICATE & TICKET
%%%===================================================================

-spec from_client_hello(binary(), binary(), [binary()]) ->
    {ok, iodata(), meta(), codec()}.
from_client_hello(Data, Secret, AllowedDomains) ->
    #client_hello{
        pseudorandom = ClientDigest,
        session_id   = SessionId,
        extensions   = Extensions
    } = parse_client_hello(Data),

    SniDomain = case lists:keyfind(?EXT_SNI, 1, Extensions) of
        {_, [{0, Domain}]} -> Domain;
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

    ServerDigest = make_server_digest(Data, Secret),
    <<Zeroes:(?DIGEST_LEN - 4)/binary, Timestamp:32/unsigned-little>> =
        crypto:exor(ClientDigest, ServerDigest),

    lists:all(fun(B) -> B =:= 0 end, binary_to_list(Zeroes))
        orelse error({protocol_error, tls_invalid_digest}),

    CurrentTime = erlang:system_time(second),
    abs(CurrentTime - Timestamp) =< 300
        orelse error({protocol_error, tls_timestamp_expired}),

    KeyShare = make_key_share(Extensions),

    %% Build TLS 1.3 handshake messages
    EncryptedExts = build_encrypted_extensions(),
    Certificate = build_certificate(),
    CertVerify = build_certificate_verify(),
    Finished = build_finished(),
    SessionTicket = build_session_ticket(),

    %% Random fake HTTP data
    FakeDataSize = 96 + rand:uniform(400),
    FakeHttpData = crypto:strong_rand_bytes(FakeDataSize),

    ChangeCipher = <<?TLS_REC_CHANGE_CIPHER, ?TLS_12_VERSION, 0, 1, 1>>,

    %% Temporary ServerHello for HMAC
    SrvHello0 = make_srv_hello(binary:copy(<<0>>, ?DIGEST_LEN),
                               SessionId, KeyShare),

    %% Build response with TLS 1.3 messages
    Response0 = [
        as_tls_frame(?TLS_REC_HANDSHAKE, SrvHello0),
        as_tls_frame(?TLS_REC_HANDSHAKE, [
            <<?TLS_TAG_ENCRYPTED_EXTENSIONS, (iolist_size(EncryptedExts)):?u24>>,
            EncryptedExts
        ]),
        as_tls_frame(?TLS_REC_HANDSHAKE, [
            <<?TLS_TAG_CERTIFICATE, (iolist_size(Certificate)):?u24>>,
            Certificate
        ]),
        as_tls_frame(?TLS_REC_HANDSHAKE, [
            <<?TLS_TAG_CERTIFICATE_VERIFY, (iolist_size(CertVerify)):?u24>>,
            CertVerify
        ]),
        as_tls_frame(?TLS_REC_HANDSHAKE, [
            <<?TLS_TAG_FINISHED, 32:?u24>>,
            Finished
        ]),
        ChangeCipher,
        as_tls_frame(?TLS_REC_DATA, FakeHttpData),
        as_tls_frame(?TLS_REC_HANDSHAKE, [
            <<?TLS_TAG_SESSION_TICKET, (iolist_size(SessionTicket)):?u24>>,
            SessionTicket
        ])
    ],

    %% Real ServerHello digest
    SrvHelloDigest = hmac(sha256, Secret, [ClientDigest | Response0]),
    SrvHello = make_srv_hello(SrvHelloDigest, SessionId, KeyShare),

    Response = [
        as_tls_frame(?TLS_REC_HANDSHAKE, SrvHello),
        as_tls_frame(?TLS_REC_HANDSHAKE, [
            <<?TLS_TAG_ENCRYPTED_EXTENSIONS, (iolist_size(EncryptedExts)):?u24>>,
            EncryptedExts
        ]),
        as_tls_frame(?TLS_REC_HANDSHAKE, [
            <<?TLS_TAG_CERTIFICATE, (iolist_size(Certificate)):?u24>>,
            Certificate
        ]),
        as_tls_frame(?TLS_REC_HANDSHAKE, [
            <<?TLS_TAG_CERTIFICATE_VERIFY, (iolist_size(CertVerify)):?u24>>,
            CertVerify
        ]),
        as_tls_frame(?TLS_REC_HANDSHAKE, [
            <<?TLS_TAG_FINISHED, 32:?u24>>,
            Finished
        ]),
        ChangeCipher,
        as_tls_frame(?TLS_REC_DATA, FakeHttpData),
        as_tls_frame(?TLS_REC_HANDSHAKE, [
            <<?TLS_TAG_SESSION_TICKET, (iolist_size(SessionTicket)):?u24>>,
            SessionTicket
        ])
    ],

    Meta = #{
        session_id    => SessionId,
        timestamp     => Timestamp,
        client_digest => ClientDigest,
        sni_domain    => SniDomain
    },

    FragSize = 1200 + rand:uniform(800),
    ChangeFragAt = rand:uniform(50) + 10,
    
    {ok, Response, Meta, #st{
        fragment_size = FragSize,
        packet_count = 0,
        change_frag_at = ChangeFragAt
    }}.

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
            {_, [{0, Domain}]} -> {ok, Domain};
            _                  -> {error, no_sni}
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

make_srv_hello(Digest, SessionId, {Group, Key}) ->
    KeyShareEntity = <<Group:?u16, (byte_size(Key)):?u16, Key/binary>>,
    Extensions = [
        <<?EXT_KEY_SHARE:?u16, (byte_size(KeyShareEntity) + 2):?u16,
          (byte_size(KeyShareEntity)):?u16, KeyShareEntity/binary>>,
        <<?EXT_SUPPORTED_VERSIONS:?u16, 2:?u16, ?TLS_13_VERSION>>
    ],
    SessionSize = byte_size(SessionId),
    Payload = [
        <<?TLS_12_VERSION,
          Digest:?DIGEST_LEN/binary,
          SessionSize, SessionId:SessionSize/binary,
          ?TLS_CIPHERSUITE,
          0,
          (iolist_size(Extensions)):?u16>>
        | Extensions
    ],
    [<<?TLS_TAG_SRV_HELLO, (iolist_size(Payload)):?u24>> | Payload].

%%%===================================================================
%%% ClientHello generator
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

    CipherSuites      = build_cipher_suites(),
    SupportedGroups   = build_supported_groups(),
    SigAlgos          = build_signature_algorithms(),
    KeyShare          = build_key_share(),
    SupportedVersions = build_supported_versions(),
    ALPN              = build_alpn(),
    Padding           = build_padding(),
    SNI               = make_sni([SniDomain]),

    %% Random optional extensions
    Extra = lists:filtermap(
        fun(_) ->
            case rand:uniform(4) of
                1 -> {true, <<?EXT_EC_POINT_FORMATS:?u16, 2:?u16, 1, 0>>};
                2 -> {true, <<?EXT_PSK_KEY_EXCHANGE_MODES:?u16, 2:?u16, 1, 1>>};
                3 -> {true, <<?EXT_STATUS_REQUEST:?u16, 0:?u16>>};
                _ -> false
            end
        end, [1,2,3,4]),

    Extensions0 = [SNI, SupportedGroups, SigAlgos, KeyShare,
                   SupportedVersions, ALPN, Padding | Extra],
    Extensions  = shuffle([E || E <- Extensions0, E =/= <<>>]),

    ExtBin   = iolist_to_binary(Extensions),
    CSLen    = byte_size(CipherSuites),
    SessLen  = byte_size(SessionId),
    ExtLen   = byte_size(ExtBin),

    HelloBodyLen = 2 + 32 + 1 + SessLen + 2 + CSLen + 1 + 1 + 2 + ExtLen,
    TlsLen       = HelloBodyLen + 4,

    Pack = fun(FakeRandom) ->
        <<?TLS_REC_HANDSHAKE, ?TLS_10_VERSION, TlsLen:?u16,
          ?TLS_TAG_CLI_HELLO, HelloBodyLen:?u24, ?TLS_12_VERSION,
          FakeRandom:?DIGEST_LEN/binary,
          SessLen, SessionId/binary,
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
%%% Extension builders
%%%===================================================================

shuffle(List) ->
    [X || {_, X} <- lists:sort([{rand:uniform(), Y} || Y <- List])].

random_grease(N) ->
    [lists:nth(rand:uniform(length(?GREASE_VALUES)), ?GREASE_VALUES)
     || _ <- lists:seq(1, N)].

build_cipher_suites() ->
    Base = [
        16#1301, 16#1302, 16#1303,
        16#c02b, 16#c02f, 16#c02c, 16#c030,
        16#cca9, 16#cca8,
        16#c013, 16#c014,
        16#009c, 16#009d
    ],
    Grease = random_grease(2 + rand:uniform(2)),
    All = shuffle(Base ++ Grease),
    << <<C:?u16>> || C <- All >>.

build_supported_groups() ->
    Groups = [16#001d, 16#0017, 16#0018],
    Grease = random_grease(1 + rand:uniform(2)),
    All = shuffle(Groups ++ Grease),
    Bin = << <<G:?u16>> || G <- All >>,
    <<?EXT_SUPPORTED_GROUPS:?u16, (byte_size(Bin)+2):?u16,
      (byte_size(Bin)):?u16, Bin/binary>>.

build_key_share() ->
    Real = [
        {16#001d, 32},
        {16#0017, 65}
    ],
    GreaseGroups = random_grease(1 + rand:uniform(1)),
    GreaseEntries = [<<G:?u16, 1:?u16, 0>> || G <- GreaseGroups],

    RealEntries = [
        begin
            Key = crypto:strong_rand_bytes(Size),
            <<Group:?u16, Size:?u16, Key/binary>>
        end || {Group, Size} <- Real
    ],

    All = shuffle(RealEntries ++ GreaseEntries),
    Bin = iolist_to_binary(All),
    <<?EXT_KEY_SHARE:?u16, (byte_size(Bin)+2):?u16,
      (byte_size(Bin)):?u16, Bin/binary>>.

build_supported_versions() ->
    Versions = [16#0304, 16#0303],
    Grease = random_grease(rand:uniform(2)),
    All = shuffle(Versions ++ Grease),
    Bin = << <<V:?u16>> || V <- All >>,
    <<?EXT_SUPPORTED_VERSIONS:?u16, (byte_size(Bin)+1):?u16,
      (byte_size(Bin)), Bin/binary>>.

build_signature_algorithms() ->
    Algs = [
        16#0403, 16#0503, 16#0603,
        16#0804, 16#0805, 16#0806,
        16#0401, 16#0501, 16#0601,
        16#0201, 16#0203
    ],
    Shuffled = shuffle(Algs),
    Bin = << <<A:?u16>> || A <- Shuffled >>,
    <<?EXT_SIGNATURE_ALGORITHMS:?u16, (byte_size(Bin)+2):?u16,
      (byte_size(Bin)):?u16, Bin/binary>>.

build_alpn() ->
    ALPNs = [
        <<3, 2, "h2">>,
        <<8, 7, "http/1.1">>,
        <<2, 1, "h2", 8, 7, "http/1.1">>
    ],
    Proto = lists:nth(rand:uniform(length(ALPNs)), ALPNs),
    <<?EXT_ALPN:?u16, (byte_size(Proto)):?u16, Proto/binary>>.

build_padding() ->
    PadLen = 32 + rand:uniform(180),
    <<?EXT_PADDING:?u16, PadLen:?u16, 0:PadLen/unit:8>>.

make_sni(Domains) ->
    Items = << <<0, (byte_size(D)):?u16, D/binary>> || D <- Domains >>,
    <<?EXT_SNI:?u16, (byte_size(Items)+2):?u16,
      (byte_size(Items)):?u16, Items/binary>>.

%%%===================================================================
%%% parse_server_hello - UNCHANGED (working version)
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
                     ?TLS_REC_DATA, ?TLS_12_VERSION, DLen:?u16,
                     Data:DLen/binary,
                     ?TLS_REC_CHANGE_CIPHER, ?TLS_12_VERSION, CCLen:?u16,
                     ChangeCipher:CCLen/binary,
                     Tail/binary>>) ->
    {Handshake, ChangeCipher, Data, Tail};
%% Skip additional handshake records (Certificate, etc.)
parse_server_hello(<<?TLS_REC_HANDSHAKE, ?TLS_12_VERSION, Len:?u16,
                     _:Len/binary, Rest/binary>>) ->
    parse_server_hello(Rest);
parse_server_hello(B) when byte_size(B) < 5 ->
    incomplete;
parse_server_hello(<<16#15, _/binary>>) ->
    {error, tls_alert};
parse_server_hello(_) ->
    {error, not_proxy_response}.

%%%===================================================================
%%% Codec with adaptive fragmentation
%%%===================================================================

-spec new() -> codec().
new() ->
    FragSize = 1200 + rand:uniform(800),
    ChangeAt = rand:uniform(50) + 10,
    #st{
        fragment_size = FragSize,
        packet_count = 0,
        change_frag_at = ChangeAt
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

-spec encode_packet(binary(), codec()) -> {iodata(), codec()}.
encode_packet(Bin, #st{
    fragment_size = Frag,
    packet_count = Count,
    change_frag_at = ChangeAt
} = St) ->
    {NewFrag, NewCount, NewChangeAt} = 
        if
            Count >= ChangeAt ->
                NewF = 1200 + rand:uniform(800),
                NewC = rand:uniform(50) + 10,
                {NewF, 0, NewC};
            true ->
                {Frag, Count + 1, ChangeAt}
        end,
    
    NewSt = St#st{
        fragment_size = NewFrag,
        packet_count = NewCount,
        change_frag_at = NewChangeAt
    },
    
    {fragment_data(Bin, NewFrag), NewSt}.

fragment_data(Bin, FragSize) when byte_size(Bin) =< FragSize ->
    as_tls_data_frame(Bin);
fragment_data(Bin, FragSize) ->
    <<Chunk:FragSize/binary, Rest/binary>> = Bin,
    [as_tls_data_frame(Chunk) | fragment_data(Rest, FragSize)].

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
