%%%===================================================================
%%% Fake TLS - ULTRA-NUCLEAR VERSION
%%% Combining:
%%% - Advanced fingerprint profiles (Chrome/Firefox/Safari/Edge)
%%% - Session Ticket & OCSP stapling simulation
%%% - Nuclear noise injection with fake records
%%% - Adaptive fragmentation with random patterns
%%% - GREASE everywhere
%%% - Padding records between real data
%%% - Variable record sizes and ordering
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
    fragment_size :: pos_integer(),
    packet_count  :: non_neg_integer(),
    change_frag_at :: non_neg_integer(),
    fake_record_interval :: non_neg_integer(),
    session_ticket :: binary() | undefined,
    ocsp_response :: binary() | undefined,
    session_ticket_lifetime :: non_neg_integer() | undefined
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
%%% GREASE Values (RFC 8701)
%%%===================================================================

-define(GREASE_VALUES, [
    16#0a0a, 16#1a1a, 16#2a2a, 16#3a3a, 16#4a4a,
    16#5a5a, 16#6a6a, 16#7a7a, 16#8a8a, 16#9a9a,
    16#aaaa, 16#baba, 16#caca, 16#dada, 16#eaea,
    16#fafa
]).

%%%===================================================================
%%% TLS Fingerprint Profiles
%%%===================================================================

-define(TLS_FINGERPRINT_PROFILES, [
    #{name => chrome_120,
      cipher_suites => [
          16#1301, 16#1302, 16#1303,
          16#c02b, 16#c02f, 16#c02c, 16#c030,
          16#cca9, 16#cca8,
          16#c013, 16#c014,
          16#009c, 16#009d,
          16#002f, 16#0035
      ],
      cipher_order_randomized => true,
      grease_count => {2, 4},
      key_share_groups => [
          16#11ec, 16#001d, 16#0017, 16#0018
      ],
      supported_versions => [
          16#0304, 16#0303
      ],
      version_order_randomized => true,
      sig_algorithms_count => 15,
      ec_point_formats => true,
      ech_payload_size => [176, 208, 240],
      session_id_length => {32, 32},
      extensions_order_randomized => true,
      alpn_protocols => [
          [<<"h2">>, <<"http/1.1">>],
          [<<"h2">>],
          [<<"http/1.1">>]
      ],
      padding_size => {32, 512},
      session_ticket_enabled => true,
      ocsp_stapling_enabled => true
    },
    #{name => firefox_121,
      cipher_suites => [
          16#1301, 16#1302, 16#1303,
          16#c02b, 16#c02f, 16#c02c, 16#c030,
          16#cca9, 16#cca8,
          16#c013, 16#c014,
          16#009c, 16#009d,
          16#002f, 16#0035,
          16#003c, 16#003d
      ],
      cipher_order_randomized => true,
      grease_count => {2, 3},
      key_share_groups => [
          16#001d, 16#0017
      ],
      supported_versions => [
          16#0304, 16#0303
      ],
      version_order_randomized => false,
      sig_algorithms_count => 17,
      ec_point_formats => true,
      ech_payload_size => [144, 176],
      session_id_length => {32, 32},
      extensions_order_randomized => false,
      alpn_protocols => [
          [<<"h2">>, <<"http/1.1">>]
      ],
      padding_size => {32, 256},
      session_ticket_enabled => true,
      ocsp_stapling_enabled => false
    },
    #{name => safari_17,
      cipher_suites => [
          16#1301, 16#1302, 16#1303,
          16#c02b, 16#c02f, 16#c02c, 16#c030,
          16#cca9, 16#cca8,
          16#c013, 16#c014
      ],
      cipher_order_randomized => false,
      grease_count => {2, 4},
      key_share_groups => [
          16#001d, 16#0017, 16#0018, 16#0019
      ],
      supported_versions => [
          16#0304
      ],
      version_order_randomized => false,
      sig_algorithms_count => 13,
      ec_point_formats => false,
      ech_payload_size => [208, 240],
      session_id_length => {32, 32},
      extensions_order_randomized => false,
      alpn_protocols => [
          [<<"h2">>, <<"http/1.1">>]
      ],
      padding_size => {32, 512},
      session_ticket_enabled => false,
      ocsp_stapling_enabled => true
    },
    #{name => edge_120,
      cipher_suites => [
          16#1301, 16#1302, 16#1303,
          16#c02b, 16#c02f, 16#c02c, 16#c030,
          16#cca9, 16#cca8,
          16#c013, 16#c014,
          16#009c, 16#009d,
          16#002f, 16#0035
      ],
      cipher_order_randomized => true,
      grease_count => {2, 4},
      key_share_groups => [
          16#11ec, 16#001d, 16#0017
      ],
      supported_versions => [
          16#0304, 16#0303
      ],
      version_order_randomized => true,
      sig_algorithms_count => 16,
      ec_point_formats => true,
      ech_payload_size => [176, 208],
      session_id_length => {32, 32},
      extensions_order_randomized => true,
      alpn_protocols => [
          [<<"h2">>, <<"http/1.1">>],
          [<<"h2">>]
      ],
      padding_size => {32, 512},
      session_ticket_enabled => true,
      ocsp_stapling_enabled => true
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
%%% Fake data builders (Nuclear Enhanced)
%%%===================================================================

build_fake_certificate_data() ->
    CertSize = 800 + rand:uniform(600),
    crypto:strong_rand_bytes(CertSize).

build_fake_session_ticket_data() ->
    TicketSize = 150 + rand:uniform(150),
    crypto:strong_rand_bytes(TicketSize).

build_fake_padding_record() ->
    PadSize = 16 + rand:uniform(64),
    crypto:strong_rand_bytes(PadSize).

build_fake_http_data() ->
    FakeDataSize = 100 + rand:uniform(500),
    crypto:strong_rand_bytes(FakeDataSize).

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
%%% from_client_hello (server side) - ULTRA-NUCLEAR
%%%===================================================================

-spec from_client_hello(binary(), binary(), [binary()]) ->
    {ok, iodata(), meta(), codec()}.
from_client_hello(Data, Secret, AllowedDomains) ->
    #client_hello{
        pseudorandom = ClientDigest,
        session_id   = SessionId,
        extensions   = Extensions
    } = CliHlo = parse_client_hello(Data),
    
    ?LOG_DEBUG("TLS ClientHello extensions: ~p", [Extensions]),

    %% Extract SNI domain
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

    %% Check client capabilities
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

    %% Build fake records for noise
    FakeHttpData = build_fake_http_data(),
    FakeCert = build_fake_certificate_data(),
    FakeTicket = build_fake_session_ticket_data(),
    Padding1 = build_fake_padding_record(),
    Padding2 = build_fake_padding_record(),

    %% Generate real Session Ticket and OCSP response
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

    %% Temporary ServerHello for HMAC
    SrvHello0 = make_srv_hello(binary:copy(<<0>>, ?DIGEST_LEN),
                               SessionId, KeyShare,
                               HasSessionTicket, HasOcspStapling),

    ChangeCipher = <<?TLS_REC_CHANGE_CIPHER, ?TLS_12_VERSION, 0, 1, 1>>,

    %% ULTRA-NUCLEAR: 8 different ordering patterns with padding and ticket
    DataFrames = case rand:uniform(8) of
        1 -> [as_tls_frame(?TLS_REC_DATA, FakeHttpData),
              as_tls_frame(?TLS_REC_DATA, Padding1),
              as_tls_frame(?TLS_REC_DATA, FakeCert),
              as_tls_frame(?TLS_REC_DATA, FakeTicket),
              TicketRecord,
              as_tls_frame(?TLS_REC_DATA, Padding2)];
        2 -> [as_tls_frame(?TLS_REC_DATA, FakeCert),
              TicketRecord,
              as_tls_frame(?TLS_REC_DATA, FakeHttpData),
              as_tls_frame(?TLS_REC_DATA, FakeTicket),
              as_tls_frame(?TLS_REC_DATA, Padding1),
              as_tls_frame(?TLS_REC_DATA, Padding2)];
        3 -> [as_tls_frame(?TLS_REC_DATA, Padding1),
              as_tls_frame(?TLS_REC_DATA, FakeHttpData),
              as_tls_frame(?TLS_REC_DATA, Padding2),
              as_tls_frame(?TLS_REC_DATA, FakeCert),
              TicketRecord,
              as_tls_frame(?TLS_REC_DATA, FakeTicket)];
        4 -> [as_tls_frame(?TLS_REC_DATA, FakeTicket),
              TicketRecord,
              as_tls_frame(?TLS_REC_DATA, FakeCert),
              as_tls_frame(?TLS_REC_DATA, FakeHttpData),
              as_tls_frame(?TLS_REC_DATA, Padding1),
              as_tls_frame(?TLS_REC_DATA, Padding2)];
        5 -> [as_tls_frame(?TLS_REC_DATA, FakeHttpData),
              as_tls_frame(?TLS_REC_DATA, FakeTicket),
              TicketRecord,
              as_tls_frame(?TLS_REC_DATA, Padding1),
              as_tls_frame(?TLS_REC_DATA, FakeCert),
              as_tls_frame(?TLS_REC_DATA, Padding2)];
        6 -> [as_tls_frame(?TLS_REC_DATA, Padding1),
              as_tls_frame(?TLS_REC_DATA, Padding2),
              TicketRecord,
              as_tls_frame(?TLS_REC_DATA, FakeHttpData),
              as_tls_frame(?TLS_REC_DATA, FakeCert),
              as_tls_frame(?TLS_REC_DATA, FakeTicket)];
        7 -> [TicketRecord,
              as_tls_frame(?TLS_REC_DATA, Padding1),
              as_tls_frame(?TLS_REC_DATA, FakeHttpData),
              as_tls_frame(?TLS_REC_DATA, FakeCert),
              as_tls_frame(?TLS_REC_DATA, Padding2),
              as_tls_frame(?TLS_REC_DATA, FakeTicket)];
        8 -> [as_tls_frame(?TLS_REC_DATA, Padding2),
              TicketRecord,
              as_tls_frame(?TLS_REC_DATA, FakeCert),
              as_tls_frame(?TLS_REC_DATA, Padding1),
              as_tls_frame(?TLS_REC_DATA, FakeTicket),
              as_tls_frame(?TLS_REC_DATA, FakeHttpData)]
    end,

    Response0 = [as_tls_frame(?TLS_REC_HANDSHAKE, SrvHello0), ChangeCipher | DataFrames],

    %% Real ServerHello digest
    SrvHelloDigest = hmac(sha256, Secret, [ClientDigest | Response0]),
    SrvHello = make_srv_hello(SrvHelloDigest, SessionId, KeyShare,
                              HasSessionTicket, HasOcspStapling),

    Response = [as_tls_frame(?TLS_REC_HANDSHAKE, SrvHello), ChangeCipher | DataFrames],

    Meta = #{
        session_id    => SessionId,
        timestamp     => Timestamp,
        client_digest => ClientDigest,
        sni_domain    => SniDomain,
        session_ticket => SessionTicket,
        ocsp_response  => OcspResponse
    },

    %% Nuclear parameters: aggressive randomization
    FragSize = 800 + rand:uniform(1200),
    ChangeFragAt = rand:uniform(30) + 10,
    FakeRecordInterval = rand:uniform(15) + 5,
    
    {ok, Response, Meta, #st{
        fragment_size = FragSize,
        packet_count = 0,
        change_frag_at = ChangeFragAt,
        fake_record_interval = FakeRecordInterval,
        session_ticket = SessionTicket,
        ocsp_response = OcspResponse,
        session_ticket_lifetime = case HasSessionTicket of
                                      true -> 604800;
                                      false -> undefined
                                  end
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
        16#0302, 16#0202, 16#0301
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
%%% ClientHello generator (Profile-based + GREASE)
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

    %% Select random TLS fingerprint profile
    Profile = random_tls_profile(),

    %% Build all extensions based on profile
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

    %% Build extensions list
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
%%% parse_server_hello - Enhanced for Session Ticket support
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
%%% Codec with ULTRA-NUCLEAR features
%%%===================================================================

-spec new() -> codec().
new() ->
    FragSize = 800 + rand:uniform(1200),
    ChangeAt = rand:uniform(30) + 10,
    FakeInterval = rand:uniform(15) + 5,
    #st{
        fragment_size = FragSize,
        packet_count = 0,
        change_frag_at = ChangeAt,
        fake_record_interval = FakeInterval,
        session_ticket = undefined,
        ocsp_response = undefined,
        session_ticket_lifetime = undefined
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
    change_frag_at = ChangeAt,
    fake_record_interval = FakeInterval
} = St) ->
    {NewFrag, NewCount, NewChangeAt, NewFakeInterval} = 
        if
            Count >= ChangeAt ->
                NewF = 800 + rand:uniform(1200),
                NewC = rand:uniform(30) + 10,
                NewFake = rand:uniform(15) + 5,
                {NewF, 0, NewC, NewFake};
            true ->
                {Frag, Count + 1, ChangeAt, FakeInterval}
        end,
    
    NewSt = St#st{
        fragment_size = NewFrag,
        packet_count = NewCount,
        change_frag_at = NewChangeAt,
        fake_record_interval = NewFakeInterval
    },
    
    %% ULTRA-NUCLEAR: Inject fake records randomly
    Result = case NewCount rem NewFakeInterval == 0 of
        true ->
            FakeSize = 32 + rand:uniform(64),
            FakeRecord = crypto:strong_rand_bytes(FakeSize),
            [as_tls_frame(?TLS_REC_DATA, FakeRecord) | fragment_data(Bin, NewFrag)];
        false ->
            fragment_data(Bin, NewFrag)
    end,
    
    {Result, NewSt}.

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
