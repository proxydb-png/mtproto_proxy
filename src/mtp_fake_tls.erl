%% ============================================================================
%% Optimized version: High performance + DPI resistance
%% Strategy: Randomize only what matters, cache what doesn't
%% ============================================================================

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
    packet_count = 0 :: non_neg_integer(),
    profile :: map() | undefined,  % CACHED: don't regenerate each time
    % Pre-computed randomization state
    rng_state :: term() | undefined
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
-define(TLS_TAG_NEW_SESSION_TICKET, 4).
-define(TLS_CIPHERSUITE, 192, 47).

-define(EXT_SNI, 0).
-define(EXT_SNI_HOST_NAME, 0).
-define(EXT_KEY_SHARE, 51).
-define(EXT_SUPPORTED_VERSIONS, 43).
-define(EXT_SESSION_TICKET, 35).
-define(EXT_STATUS_REQUEST, 5).

%% ============================================================================
%% Pre-computed GREASE values for speed
%% ============================================================================
-define(GREASE_POOL, [
    16#0a0a, 16#1a1a, 16#2a2a, 16#3a3a, 16#4a4a,
    16#5a5a, 16#6a6a, 16#7a7a, 16#8a8a, 16#9a9a,
    16#aaaa, 16#baba, 16#caca, 16#dada, 16#eaea,
    16#fafa
]).

%% ============================================================================
%% Pre-computed cipher suites for each profile
%% ============================================================================
-define(CHROME_SUITES, [
    16#13, 16#01, 16#13, 16#02, 16#13, 16#03,
    16#c0, 16#2b, 16#c0, 16#2f, 16#c0, 16#2c,
    16#c0, 16#30, 16#cc, 16#a9, 16#cc, 16#a8,
    16#c0, 16#13, 16#c0, 16#14, 16#00, 16#9c,
    16#00, 16#9d, 16#00, 16#2f, 16#00, 16#35
]).

-define(FIREFOX_SUITES, [
    16#13, 16#01, 16#13, 16#02, 16#13, 16#03,
    16#c0, 16#2b, 16#c0, 16#2f, 16#c0, 16#2c,
    16#c0, 16#30, 16#cc, 16#a9, 16#cc, 16#a8,
    16#c0, 16#13, 16#c0, 16#14, 16#00, 16#9c,
    16#00, 16#9d, 16#00, 16#2f, 16#00, 16#35,
    16#00, 16#3c, 16#00, 16#3d
]).

-define(SAFARI_SUITES, [
    16#13, 16#01, 16#13, 16#02, 16#13, 16#03,
    16#c0, 16#2b, 16#c0, 16#2f, 16#c0, 16#2c,
    16#c0, 16#30, 16#cc, 16#a9, 16#cc, 16#a8,
    16#c0, 16#13, 16#c0, 16#14
]).

%% ============================================================================
%% Lightweight RNG using Xorshift (much faster than crypto:strong_rand_bytes)
%% ============================================================================
-record(xs_state, {a :: non_neg_integer()}).

-spec xs_init() -> #xs_state{}.
xs_init() ->
    #xs_state{a = erlang:system_time(nanosecond) bxor 
               (erlang:monotonic_time() bsl 16)}.

-spec xs_next(#xs_state{}) -> {non_neg_integer(), #xs_state{}}.
xs_next(#xs_state{a = A0}) ->
    A1 = A0 bxor (A0 bsl 13),
    A2 = A1 bxor (A1 bsr 17),
    A3 = A2 bxor (A2 bsl 5),
    {A3 band 16#7FFFFFFF, #xs_state{a = A3}}.

-spec xs_uniform(non_neg_integer(), #xs_state{}) -> {non_neg_integer(), #xs_state{}}.
xs_uniform(N, State) when N > 0 ->
    {X, NewState} = xs_next(State),
    {(X rem N) + 1, NewState}.

%% ============================================================================
%% Helper functions
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
            Base2 = case Base of
                <<".", Rest/binary>> -> Rest;
                _ -> Base
            end,
            Suffix = <<".", Base2/binary>>,
            SuffixLen = byte_size(Suffix),
            DomLen = byte_size(Domain),
            if
                DomLen > SuffixLen ->
                    EndPart = binary:part(Domain, {DomLen, -SuffixLen}),
                    EndPart =:= Suffix andalso 
                    not lists:member($., binary:part(Domain, {0, DomLen - SuffixLen}));
                true ->
                    false
            end;
        _ ->
            Domain =:= Allowed
    end.

%% ============================================================================
%% OCSP generation - optimized
%% ============================================================================
-spec generate_ocsp_response(binary()) -> binary().
generate_ocsp_response(_ServerDigest) ->
    % Use larger pre-generated chunks for speed
    OcspStatus = 0,
    ResponderId = crypto:strong_rand_bytes(20),  % Fixed size for speed
    ProducedAt = erlang:system_time(seconds) - rand:uniform(86400),
    
    ThisUpdate = ProducedAt - rand:uniform(3600),
    NextUpdate = ProducedAt + 604800 + rand:uniform(86400),
    
    CertId = crypto:strong_rand_bytes(36),  % Fixed size
    CertStatus = <<0>>,
    
    SingleResponse = <<CertId/binary, CertStatus/binary, 
                        (encode_generalized_time(ThisUpdate))/binary,
                        (encode_generalized_time(NextUpdate))/binary>>,
    
    ResponseData = <<0, ResponderId/binary, 
                     (encode_generalized_time(ProducedAt))/binary,
                     1:32, SingleResponse/binary>>,
    
    SigLen = 256,  % Fixed signature size for speed
    Signature = crypto:strong_rand_bytes(SigLen),
    BasicOcspResponse = <<ResponseData/binary, 1:24, Signature/binary>>,
    <<OcspStatus, (byte_size(BasicOcspResponse)):?u24, BasicOcspResponse/binary>>.

-spec encode_generalized_time(non_neg_integer()) -> binary().
encode_generalized_time(Timestamp) ->
    {{Y, M, D}, {H, Mi, S}} = calendar:universal_time_to_local_time(
        calendar:gregorian_seconds_to_datetime(Timestamp + 62167219200)
    ),
    Str = io_lib:format("~4..0w~2..0w~2..0w~2..0w~2..0w~2..0wZ", [Y, M, D, H, Mi, S]),
    list_to_binary(Str).

%% ============================================================================
%% Session ticket - optimized
%% ============================================================================
-spec generate_session_ticket(binary()) -> binary().
generate_session_ticket(_Secret) ->
    TicketAgeAdd = crypto:strong_rand_bytes(4),
    TicketNonce = crypto:strong_rand_bytes(16),  % Fixed reasonable size
    Ticket = crypto:strong_rand_bytes(128),      % Fixed reasonable size
    TicketLifetime = 604800,
    
    <<TicketLifetime:32, TicketAgeAdd/binary, 
      16:8, TicketNonce/binary,
      128:?u16, Ticket/binary,
      0:?u16>>.

%% ============================================================================
%% Server response - optimized with caching
%% ============================================================================
-spec from_client_hello(binary(), binary(), [binary()]) ->
                               {ok, iodata(), meta(), codec()}.
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

    HasSessionTicket = lists:keymember(?EXT_SESSION_TICKET, 1, Extensions),
    HasOcspStapling = lists:keymember(?EXT_STATUS_REQUEST, 1, Extensions),
    
    ServerDigest = make_server_digest(Data, Secret),
    <<Zeroes:(?DIGEST_LEN - 4)/binary, Timestamp:32/unsigned-little>> = XoredDigest =
        crypto:exor(ClientDigest, ServerDigest),
    lists:all(fun(B) -> B == 0 end, binary_to_list(Zeroes)) orelse
        error({protocol_error, tls_invalid_digest, XoredDigest}),
    
    % Validate timestamp
    CurrentTime = erlang:system_time(second),
    if
        abs(CurrentTime - Timestamp) > 300 ->
            error({protocol_error, tls_timestamp_expired});
        true -> ok
    end,
    
    KeyShare = make_key_share(Extensions),
    SrvHello0 = make_srv_hello(binary:copy(<<0>>, ?DIGEST_LEN), SessionId, KeyShare, 
                               HasSessionTicket, HasOcspStapling),
    
    % Reduced fake data size for speed
    FakeHttpData = crypto:strong_rand_bytes(512),
    
    {SessionTicket, TicketRecord} = case HasSessionTicket of
        true ->
            Ticket = generate_session_ticket(Secret),
            {Ticket, as_tls_frame(?TLS_REC_HANDSHAKE, Ticket)};
        false ->
            {undefined, <<>>}
    end,
    
    OcspResponse = case HasOcspStapling of
        true -> generate_ocsp_response(ServerDigest);
        false -> undefined
    end,
    
    Response0 = [_, CC, DD, ST] =
        [as_tls_frame(?TLS_REC_HANDSHAKE, SrvHello0),
         as_tls_frame(?TLS_REC_CHANGE_CIPHER, [1]),
         as_tls_frame(?TLS_REC_DATA, FakeHttpData),
         TicketRecord],
    
    SrvHelloDigest = hmac(sha256, Secret, [ClientDigest | Response0]),
    SrvHello = make_srv_hello(SrvHelloDigest, SessionId, KeyShare, 
                              HasSessionTicket, HasOcspStapling),
    
    % No extra padding records (speed optimization)
    Response = [as_tls_frame(?TLS_REC_HANDSHAKE, SrvHello),
                CC,
                DD,
                ST],
    
    Meta0 = #{session_id => SessionId,
              timestamp => Timestamp,
              client_digest => ClientDigest,
              sni_domain => SniDomain},
    Meta = Meta0#{session_ticket => SessionTicket,
                  ocsp_response => OcspResponse},
    
    St = #st{session_ticket = SessionTicket,
             ocsp_response = OcspResponse,
             session_ticket_lifetime = case HasSessionTicket of
                                          true -> 604800;
                                          false -> undefined
                                      end,
             packet_count = 0,
             profile = undefined,
             rng_state = xs_init()},
    {ok, Response, Meta, St}.

-spec from_client_hello(binary(), binary()) ->
                               {ok, iodata(), meta(), codec()}.
from_client_hello(Data, Secret) ->
    from_client_hello(Data, Secret, []).

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
    <<Derived:16/binary, _/binary>> =
        crypto:hash(sha256, [Salt, SecretHex, SniDomain]),
    Derived.

parse_client_hello(<<?TLS_REC_HANDSHAKE, ?TLS_10_VERSION, TlsFrameLen:?u16,
                     ?TLS_TAG_CLI_HELLO, HelloLen:?u24, ?TLS_12_VERSION,
                     Random:?DIGEST_LEN/binary,
                     SessIdLen, SessId:SessIdLen/binary,
                     CipherSuitesLen:?u16, CipherSuites:CipherSuitesLen/binary,
                     CompMethodsLen, CompMethods:CompMethodsLen/binary,
                     ExtensionsLen:?u16, Extensions:ExtensionsLen/binary>>
                  ) when TlsFrameLen >= 256, HelloLen >= 200 ->
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
parse_extension(?EXT_SESSION_TICKET, _Data) ->
    {session_ticket, supported};
parse_extension(?EXT_STATUS_REQUEST, <<Type, _Rest/binary>>) ->
    {ocsp_stapling, Type};
parse_extension(_Type, Data) ->
    Data.

make_server_digest(<<Left:?DIGEST_POS/binary, _:?DIGEST_LEN/binary, Right/binary>>, Secret) ->
    Msg = [Left, binary:copy(<<0>>, ?DIGEST_LEN), Right],
    hmac(sha256, Secret, Msg).

make_key_share(Exts) ->
    case lists:keyfind(?EXT_KEY_SHARE, 1, Exts) of
        {_, KeyShares} ->
            SupportedGroups = [16#0017, 16#0018, 16#001D, 16#11EC],
            SupportedKeyShares =
                lists:filter(
                  fun({Group, Key}) ->
                          byte_size(Key) < 2048 andalso
                          lists:member(Group, SupportedGroups)
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

make_srv_hello(Digest, SessionId, {KeyShareGroup, KeyShareKey}, 
               HasSessionTicket, HasOcspStapling) ->
    KeyShareEntity = <<KeyShareGroup:?u16, (byte_size(KeyShareKey)):?u16, KeyShareKey/binary>>,
    
    ExtensionsBase = [
        <<?EXT_KEY_SHARE:?u16, (byte_size(KeyShareEntity)):?u16, KeyShareEntity/binary>>,
        <<?EXT_SUPPORTED_VERSIONS:?u16, 2:?u16, ?TLS_13_VERSION>>
    ],
    
    ExtensionsWithTicket = case HasSessionTicket of
        true -> ExtensionsBase ++ [<<?EXT_SESSION_TICKET:?u16, 0:?u16>>];
        false -> ExtensionsBase
    end,
    
    ExtensionsFinal = case HasOcspStapling of
        true -> ExtensionsWithTicket ++ [<<?EXT_STATUS_REQUEST:?u16, 0:?u16>>];
        false -> ExtensionsWithTicket
    end,
    
    SessionSize = byte_size(SessionId),
    Payload = [<<?TLS_12_VERSION,
                 Digest:?DIGEST_LEN/binary,
                 SessionSize,
                 SessionId:SessionSize/binary,
                 ?TLS_CIPHERSUITE,
                 0,
                 (iolist_size(ExtensionsFinal)):?u16>>
                   | ExtensionsFinal],
    [<<?TLS_TAG_SRV_HELLO, (iolist_size(Payload)):?u24>> | Payload].

%% ============================================================================
%% OPTIMIZED: Pre-select profile at connection start
%% ============================================================================
-spec select_profile() -> map().
select_profile() ->
    Profiles = [
        #{name => chrome, suites => ?CHROME_SUITES, 
          key_share => [16#11EC, 16#001D, 16#0017, 16#0018],
          grease_min => 3, grease_max => 5,
          randomize_order => true},
        #{name => firefox, suites => ?FIREFOX_SUITES,
          key_share => [16#001D, 16#0017],
          grease_min => 2, grease_max => 4,
          randomize_order => true},
        #{name => safari, suites => ?SAFARI_SUITES,
          key_share => [16#001D, 16#0017, 16#0018],
          grease_min => 2, grease_max => 4,
          randomize_order => false}
    ],
    lists:nth(rand:uniform(length(Profiles)), Profiles).

%% ============================================================================
%% OPTIMIZED: ClientHello with pre-selected profile
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
    Profile = select_profile(),
    
    % Build cipher suites with GREASE
    #{suites := Suites, grease_min := GMin, grease_max := GMax,
      randomize_order := RandomOrder} = Profile,
    
    GreaseCount = GMin + rand:uniform(GMax - GMin + 1),
    GreaseVals = [lists:nth(rand:uniform(length(?GREASE_POOL)), ?GREASE_POOL) || 
                  _ <- lists:seq(1, GreaseCount)],
    
    % Efficient GREASE insertion
    SuitesWithGrease = interleave_random(Suites, GreaseVals),
    FinalSuites = case RandomOrder of
        true -> shuffle_list(SuitesWithGrease);
        false -> SuitesWithGrease
    end,
    CipherSuites = << <<S:?u16>> || S <- FinalSuites >>,
    
    % Build extensions
    SNI = make_sni([SniDomain]),
    
    % Pre-built signature algorithms (saves computation)
    SigAlgos = <<16#00, 16#0d, 16#00, 16#20,
                 16#00, 16#1e,
                 16#04, 16#03, 16#05, 16#03, 16#06, 16#03,
                 16#08, 16#04, 16#08, 16#05, 16#08, 16#06,
                 16#04, 16#01, 16#05, 16#01, 16#06, 16#01,
                 16#02, 16#01, 16#04, 16#02, 16#03, 16#02,
                 16#02, 16#02>>,
    
    % Key share (simplified for speed)
    #{key_share := KSGroups} = Profile,
    KeyShareEntities = [
        begin
            KeySize = case Group of
                16#001D -> 32;
                16#0017 -> 65;
                16#0018 -> 97;
                16#11EC -> 1216;
                _ -> 32
            end,
            Key = crypto:strong_rand_bytes(KeySize),
            <<Group:?u16, KeySize:?u16, Key/binary>>
        end
        || Group <- KSGroups
    ],
    
    % Add GREASE to key share
    GreaseKeys = [<<G:?u16, 0:16, 0:8>> || G <- GreaseVals],
    AllKeys = interleave_random(KeyShareEntities, GreaseKeys),
    KSData = iolist_to_binary(AllKeys),
    KeyShare = <<16#00, 16#33, (byte_size(KSData) + 2):?u16, 
                 (byte_size(KSData)):?u16, KSData/binary>>,
    
    % Supported versions
    Versions = [16#0304, 16#0303],
    VersionsWithGrease = interleave_random(Versions, GreaseVals),
    VerData = << <<V:?u16>> || V <- VersionsWithGrease >>,
    SupportedVersions = <<16#00, 16#2b, (byte_size(VerData) + 1):?u16,
                          (byte_size(VerData)):8, VerData/binary>>,
    
    % Supported groups
    GroupsWithGrease = interleave_random(KSGroups, GreaseVals),
    GrpData = << <<G:?u16>> || G <- GroupsWithGrease >>,
    SupportedGroups = <<16#00, 16#0a, (byte_size(GrpData) + 2):?u16,
                        (byte_size(GrpData)):?u16, GrpData/binary>>,
    
    % Session ticket extension
    SessionTicketExt = <<?EXT_SESSION_TICKET:?u16, 0:?u16>>,
    
    % OCSP extension
    OcspExt = <<?EXT_STATUS_REQUEST:?u16, 0:?u16>>,
    
    % Padding - variable for DPI resistance
    PadSize = rand:uniform(256) + 32,
    Padding = crypto:strong_rand_bytes(PadSize),
    PaddingExt = <<16#00, 16#15, PadSize:?u16, Padding/binary>>,
    
    Extensions = [
        SNI,
        SupportedVersions,
        KeyShare,
        SupportedGroups,
        SigAlgos,
        SessionTicketExt,
        OcspExt,
        <<16#00, 16#2d, 0:16, 1:16, 1:8>>,  % psk_key_exchange_modes
        PaddingExt
    ],
    
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
    EncTimestamp = <<(binary:copy(<<0>>, ?DIGEST_LEN - 4))/binary,
                     Timestamp:32/unsigned-little>>,
    FakeRandom = crypto:exor(Digest, EncTimestamp),
    Pack(FakeRandom).

%% ============================================================================
%% OPTIMIZED: Efficient random interleaving
%% ============================================================================
-spec interleave_random(list(), list()) -> list().
interleave_random(Base, Inserts) ->
    interleave_random(Base, Inserts, length(Base) + length(Inserts), []).

interleave_random([], [], _Total, Acc) ->
    lists:reverse(Acc);
interleave_random([B|Bs], [], _Total, Acc) ->
    interleave_random(Bs, [], 0, [B|Acc]);
interleave_random([], [I|Is], _Total, Acc) ->
    interleave_random([], Is, 0, [I|Acc]);
interleave_random([B|Bs] = BaseList, [I|Is] = InsertList, Total, Acc) ->
    case rand:uniform(Total) =< length(InsertList) of
        true ->
            interleave_random(BaseList, Is, Total - 1, [I|Acc]);
        false ->
            interleave_random(Bs, InsertList, Total - 1, [B|Acc])
    end.

%% Shuffle list
-spec shuffle_list(list()) -> list().
shuffle_list([]) -> [];
shuffle_list(List) ->
    Sorted = lists:sort([{rand:uniform(), X} || X <- List]),
    [X || {_, X} <- Sorted].

make_sni(Domains) ->
    SniListItems = << <<?EXT_SNI_HOST_NAME, (byte_size(Domain)):?u16, Domain/binary>>
                      || Domain <- Domains >>,
    ItemsLen = byte_size(SniListItems),
    <<?EXT_SNI:?u16, (ItemsLen + 2):?u16, ItemsLen:?u16, SniListItems/binary>>.

%% ============================================================================
%% ServerHello parsing
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
parse_server_hello(<<?TLS_REC_CHANGE_CIPHER, ?TLS_12_VERSION, Size:?u16, _:Size/binary, Rest/binary>>) ->
    parse_server_hello(Rest);
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

-spec tls_records_complete(binary(), non_neg_integer()) -> boolean().
tls_records_complete(_B, 0) -> true;
tls_records_complete(<<_T, _Mj, _Mn, Len:?u16, Rest/binary>>, N) when byte_size(Rest) >= Len ->
    <<_:Len/binary, Tail/binary>> = Rest,
    tls_records_complete(Tail, N - 1);
tls_records_complete(_B, _N) -> false.

%% ============================================================================
%% Data stream codec - OPTIMIZED
%% ============================================================================

-spec new() -> codec().
new() ->
    #st{packet_count = 0,
        rng_state = xs_init()}.

%% ============================================================================
%% FIXED & OPTIMIZED: Try decode packet
%% ============================================================================
-spec try_decode_packet(binary(), codec()) -> {ok, binary(), binary(), codec()}
                                                  | {incomplete, codec()}.
try_decode_packet(<<?TLS_12_DATA, Size:?u16, Data:Size/binary, Tail/binary>>, St) ->
    NewSt = St#st{packet_count = St#st.packet_count + 1},
    {ok, Data, Tail, NewSt};
try_decode_packet(<<?TLS_REC_CHANGE_CIPHER, ?TLS_12_VERSION, Size:?u16,
                    _Data:Size/binary, Tail/binary>>, St) ->
    try_decode_packet(Tail, St);
try_decode_packet(<<?TLS_REC_HANDSHAKE, ?TLS_12_VERSION, Size:?u16,
                    _Data:Size/binary, Tail/binary>>, St) ->
    try_decode_packet(Tail, St);
% Handle partial records
try_decode_packet(<<?TLS_12_DATA, Size:?u16, Rest/binary>>, St) 
  when byte_size(Rest) < Size ->
    {incomplete, St};
% Empty tail case
try_decode_packet(<<?TLS_12_DATA, Size:?u16, Data:Size/binary>>, St) ->
    NewSt = St#st{packet_count = St#st.packet_count + 1},
    {ok, Data, <<>>, NewSt};
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
%% OPTIMIZED: Encode packet - minimal overhead
%% ============================================================================
-spec encode_packet(binary(), codec()) -> {iodata(), codec()}.
encode_packet(Bin, St) ->
    % Only split large packets occasionally for DPI resistance
    case byte_size(Bin) > 2048 andalso St#st.packet_count rem 50 == 0 of
        true ->
            % Split into 2 frames occasionally (2% of large packets)
            SplitPoint = byte_size(Bin) div 2,
            <<Part1:SplitPoint/binary, Part2/binary>> = Bin,
            NewSt = St#st{packet_count = St#st.packet_count + 1},
            {[as_tls_data_frame(Part1), as_tls_data_frame(Part2)], NewSt};
        false ->
            NewSt = St#st{packet_count = St#st.packet_count + 1},
            {as_tls_data_frame(Bin), NewSt}
    end.

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
