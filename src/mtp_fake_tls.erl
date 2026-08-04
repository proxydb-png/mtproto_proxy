%%%===================================================================
%%% Fake TLS - REALITY Minimal (Clean & Undetectable)
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
    packet_count = 0 :: non_neg_integer()
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
    ocsp_response  => binary() | undefined
}.

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
%%% REALITY Approach: Clean, minimal TLS
%%%===================================================================

generate_ocsp_response() ->
    <<0, 0, 0, 0>>.

generate_session_ticket() ->
    crypto:strong_rand_bytes(64 + rand:uniform(128)).

%%%===================================================================
%%% from_client_hello
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

    ServerDigest = make_server_digest(Data, Secret),
    <<Zeroes:(?DIGEST_LEN - 4)/binary, Timestamp:32/unsigned-little>> =
        crypto:exor(ClientDigest, ServerDigest),

    lists:all(fun(B) -> B =:= 0 end, binary_to_list(Zeroes))
        orelse error({protocol_error, tls_invalid_digest}),

    CurrentTime = erlang:system_time(second),
    abs(CurrentTime - Timestamp) =< 300
        orelse error({protocol_error, tls_timestamp_expired}),

    KeyShare = make_key_share(Extensions),

    {SessionTicket, TicketRecord} = case HasSessionTicket of
        true ->
            Ticket = generate_session_ticket(),
            TicketRec = as_tls_frame(?TLS_REC_HANDSHAKE, Ticket),
            {Ticket, TicketRec};
        false ->
            {undefined, <<>>}
    end,
    
    OcspResponse = case HasOcspStapling of
        true -> generate_ocsp_response();
        false -> undefined
    end,

    SrvHello0 = make_srv_hello(binary:copy(<<0>>, ?DIGEST_LEN),
                               SessionId, KeyShare,
                               HasSessionTicket, HasOcspStapling),

    ChangeCipher = <<?TLS_REC_CHANGE_CIPHER, ?TLS_12_VERSION, 0, 1, 1>>,

    %% Minimal data after handshake
    RealisticData = case rand:uniform(3) of
        1 -> <<"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n">>;
        2 -> crypto:strong_rand_bytes(rand:uniform(256));
        3 -> <<>>
    end,

    Response0 = [as_tls_frame(?TLS_REC_HANDSHAKE, SrvHello0), 
                 ChangeCipher,
                 as_tls_frame(?TLS_REC_DATA, RealisticData) | 
                 case TicketRecord of
                     <<>> -> [];
                     _ -> [TicketRecord]
                 end],

    SrvHelloDigest = hmac(sha256, Secret, [ClientDigest | Response0]),
    SrvHello = make_srv_hello(SrvHelloDigest, SessionId, KeyShare,
                              HasSessionTicket, HasOcspStapling),

    Response = [as_tls_frame(?TLS_REC_HANDSHAKE, SrvHello), 
                ChangeCipher,
                as_tls_frame(?TLS_REC_DATA, RealisticData) |
                case TicketRecord of
                    <<>> -> [];
                    _ -> [TicketRecord]
                end],

    Meta = #{
        session_id    => SessionId,
        timestamp     => Timestamp,
        client_digest => ClientDigest,
        sni_domain    => SniDomain,
        session_ticket => SessionTicket,
        ocsp_response  => OcspResponse
    },

    St = #st{
        session_ticket = SessionTicket,
        ocsp_response = OcspResponse,
        session_ticket_lifetime = case HasSessionTicket of
                                      true -> 604800;
                                      false -> undefined
                                  end,
        packet_count = 0
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
%%% ClientHello generator (minimal)
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
    
    %% Minimal extensions
    SNI = <<?EXT_SNI:?u16, (byte_size(SniDomain) + 5):?u16,
            (byte_size(SniDomain) + 3):?u16,
            ?EXT_SNI_HOST_NAME, (byte_size(SniDomain)):?u16, SniDomain/binary>>,
    
    KeyShare = <<?EXT_KEY_SHARE:?u16, 38:?u16, 36:?u16,
                 16#00, 16#1d, 0, 32, (crypto:strong_rand_bytes(32))/binary>>,
    
    SupportedVersions = <<?EXT_SUPPORTED_VERSIONS:?u16, 3:?u16, 2, ?TLS_13_VERSION>>,
    
    SessionTicket = <<?EXT_SESSION_TICKET:?u16, 0:?u16>>,
    
    Extensions = [SNI, KeyShare, SupportedVersions, SessionTicket],
    ExtBin = iolist_to_binary(Extensions),
    
    %% Minimal cipher suites (just TLS 1.3)
    CipherSuites = <<16#13, 16#01,
                     16#13, 16#02,
                     16#13, 16#03>>,
    CSLen = 6,
    
    SessIdLen = 32,
    ExtLen = byte_size(ExtBin),
    
    HelloBodyLen = 2 + 32 + 1 + SessIdLen + 2 + CSLen + 1 + 1 + 2 + ExtLen,
    TlsLen = HelloBodyLen + 4,
    
    Pack = fun(FakeRandom) ->
        <<?TLS_REC_HANDSHAKE, ?TLS_10_VERSION, TlsLen:?u16,
          ?TLS_TAG_CLI_HELLO, HelloBodyLen:?u24, ?TLS_12_VERSION,
          FakeRandom:32/binary,
          SessIdLen, SessionId:32/binary,
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
%%% Data stream codec
%%%===================================================================

-spec new() -> codec().
new() ->
    #st{packet_count = 0}.

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
    {as_tls_data_frame(Bin), NewSt}.

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
