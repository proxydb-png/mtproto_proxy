%%% @author sergey <me@seriyps.ru>
%%% @copyright (C) 2019, sergey
%%% @doc
%%% Fake TLS stream codec (DPI-hardened variant)
%%% Looks like TLS1.3 from outside, with stronger passive/active fingerprint resistance.
%%% Not real TLS cryptography.
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
          profile :: map() | undefined,
          session_ticket :: binary() | undefined,
          ocsp_response :: binary() | undefined,
          session_ticket_lifetime :: non_neg_integer() | undefined,
          out_seq = 0 :: non_neg_integer()
         }).

-record(client_hello, {
          pseudorandom :: binary(),
          session_id :: binary(),
          cipher_suites :: [non_neg_integer()],
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
-define(TLS_ALERT_WARNING, 1).
-define(TLS_ALERT_DECODE_ERROR, 50).
-define(TLS_ALERT_HANDSHAKE_FAILURE, 40).
-define(TLS_ALERT_CLOSE_NOTIFY, 0).
-define(TLS_ALERT_UNRECOGNIZED_NAME, 112).

-define(TLS_12_DATA, ?TLS_REC_DATA, ?TLS_12_VERSION).

-define(DIGEST_POS, 11).
-define(DIGEST_LEN, 32).

-define(TLS_TAG_CLI_HELLO, 1).
-define(TLS_TAG_SRV_HELLO, 2).
-define(TLS_TAG_NEW_SESSION_TICKET, 4).
-define(TLS_TAG_ENCRYPTED_EXTS, 8).
-define(TLS_TAG_CERT, 11).
-define(TLS_TAG_CERT_VERIFY, 15).
-define(TLS_TAG_FINISHED, 20).

-define(EXT_SNI, 0).
-define(EXT_SNI_HOST_NAME, 0).
-define(EXT_STATUS_REQUEST, 5).
-define(EXT_SUPPORTED_GROUPS, 10).
-define(EXT_EC_POINT_FORMATS, 11).
-define(EXT_SIG_ALGS, 13).
-define(EXT_ALPN, 16).
-define(EXT_SESSION_TICKET, 35).
-define(EXT_SUPPORTED_VERSIONS, 43).
-define(EXT_PSK_MODES, 45).
-define(EXT_KEY_SHARE, 51).
-define(EXT_COMPRESS_CERT, 27).
-define(EXT_PADDING, 21).
-define(EXT_ECH, 16#fe0d).

-define(GREASE_VALUES, [
    16#0a0a, 16#1a1a, 16#2a2a, 16#3a3a, 16#4a4a,
    16#5a5a, 16#6a6a, 16#7a7a, 16#8a8a, 16#9a9a,
    16#aaaa, 16#baba, 16#caca, 16#dada, 16#eaea,
    16#fafa
]).

%% Prefer real-looking TLS1.3 + common 1.2 suites.
-define(PREFERRED_CIPHERS, [
    16#1301, %% TLS_AES_128_GCM_SHA256
    16#1302, %% TLS_AES_256_GCM_SHA384
    16#1303, %% TLS_CHACHA20_POLY1305_SHA256
    16#c02b, %% ECDHE_ECDSA_AES128_GCM_SHA256
    16#c02f, %% ECDHE_RSA_AES128_GCM_SHA256
    16#c02c, %% ECDHE_ECDSA_AES256_GCM_SHA384
    16#c030, %% ECDHE_RSA_AES256_GCM_SHA384
    16#cca9, %% ECDHE_ECDSA_CHACHA20_POLY1305
    16#cca8  %% ECDHE_RSA_CHACHA20_POLY1305
]).

-define(TLS_FINGERPRINT_PROFILES, [
    #{name => chrome_like,
      grease_count => {2, 4},
      cipher_order_randomized => true,
      version_order_randomized => true,
      extensions_order_randomized => true,
      key_share_groups => [16#11ec, 16#001d, 16#0017, 16#0018],
      supported_versions => [16#0304, 16#0303],
      sig_algorithms_count => 15,
      ec_point_formats => true,
      compress_certificate => brotli,
      ech_payload_size => [176, 208, 240],
      alpn_protocols => [[<<"h2">>, <<"http/1.1">>], [<<"h2">>]],
      padding_size => {64, 512},
      session_ticket_enabled => true,
      ocsp_stapling_enabled => true,
      appdata_first_burst => {3, 6},
      appdata_size => {800, 1400}
     },
    #{name => firefox_like,
      grease_count => {2, 3},
      cipher_order_randomized => true,
      version_order_randomized => false,
      extensions_order_randomized => false,
      key_share_groups => [16#001d, 16#0017],
      supported_versions => [16#0304, 16#0303],
      sig_algorithms_count => 17,
      ec_point_formats => true,
      compress_certificate => brotli,
      ech_payload_size => [144, 176],
      alpn_protocols => [[<<"h2">>, <<"http/1.1">>]],
      padding_size => {0, 256},
      session_ticket_enabled => true,
      ocsp_stapling_enabled => false,
      appdata_first_burst => {2, 4},
      appdata_size => {600, 1200}
     },
    #{name => safari_like,
      grease_count => {2, 4},
      cipher_order_randomized => false,
      version_order_randomized => false,
      extensions_order_randomized => false,
      key_share_groups => [16#001d, 16#0017, 16#0018, 16#0019],
      supported_versions => [16#0304],
      sig_algorithms_count => 13,
      ec_point_formats => false,
      compress_certificate => none,
      ech_payload_size => [208, 240],
      alpn_protocols => [[<<"h2">>, <<"http/1.1">>]],
      padding_size => {0, 512},
      session_ticket_enabled => false,
      ocsp_stapling_enabled => true,
      appdata_first_burst => {2, 5},
      appdata_size => {700, 1300}
     },
    #{name => edge_like,
      grease_count => {2, 4},
      cipher_order_randomized => true,
      version_order_randomized => true,
      extensions_order_randomized => true,
      key_share_groups => [16#11ec, 16#001d, 16#0017],
      supported_versions => [16#0304, 16#0303],
      sig_algorithms_count => 16,
      ec_point_formats => true,
      compress_certificate => brotli,
      ech_payload_size => [176, 208],
      alpn_protocols => [[<<"h2">>, <<"http/1.1">>], [<<"h2">>]],
      padding_size => {32, 480},
      session_ticket_enabled => true,
      ocsp_stapling_enabled => true,
      appdata_first_burst => {3, 5},
      appdata_size => {900, 1500}
     }
]).

-opaque codec() :: #st{}.
-type meta() :: #{session_id := binary(),
                  timestamp := non_neg_integer(),
                  client_digest := binary(),
                  sni_domain => binary(),
                  selected_cipher => non_neg_integer(),
                  profile => atom(),
                  session_ticket => binary() | undefined,
                  ocsp_response => binary() | undefined}.

%%% ==================================================================
%%% Secret helpers
%%% ==================================================================

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

%%% ==================================================================
%%% Domain allow-list
%%% ==================================================================

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

%%% ==================================================================
%%% Fake OCSP / SessionTicket
%%% ==================================================================

-spec generate_ocsp_response(binary()) -> binary().
generate_ocsp_response(_ServerDigest) ->
    OcspStatus = 0,
    ResponderId = crypto:strong_rand_bytes(20),
    ProducedAt = erlang:system_time(seconds),
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

-spec encode_generalized_time(non_neg_integer()) -> binary().
encode_generalized_time(Timestamp) ->
    {{Y, M, D}, {H, Mi, S}} =
        calendar:universal_time_to_local_time(
          calendar:gregorian_seconds_to_datetime(Timestamp + 62167219200)),
    list_to_binary(
      io_lib:format("~4..0w~2..0w~2..0w~2..0w~2..0w~2..0wZ",
                    [Y, M, D, H, Mi, S])).

-spec generate_session_ticket(binary()) -> binary().
generate_session_ticket(_Secret) ->
    TicketAgeAdd = crypto:strong_rand_bytes(4),
    TicketNonce = crypto:strong_rand_bytes(16 + rand:uniform(16)),
    Ticket = crypto:strong_rand_bytes(128 + rand:uniform(160)),
    TicketLifetime = 604800,
    <<TicketLifetime:32,
      TicketAgeAdd/binary,
      (byte_size(TicketNonce)):8, TicketNonce/binary,
      (byte_size(Ticket)):?u16, Ticket/binary,
      0:?u16>>.

%%% ==================================================================
%%% Server-side ClientHello handling
%%% ==================================================================

-spec from_client_hello(binary(), binary()) ->
          {ok, iodata(), meta(), codec()} | {error, iodata()}.
from_client_hello(Data, Secret) ->
    from_client_hello(Data, Secret, []).

-spec from_client_hello(binary(), binary(), [binary()]) ->
          {ok, iodata(), meta(), codec()} | {error, iodata()}.
from_client_hello(Data, Secret, AllowedDomains) ->
    try
        do_from_client_hello(Data, Secret, AllowedDomains)
    catch
        error:{protocol_error, Reason, _Info} ->
            ?LOG_WARNING("TLS reject reason=~p", [Reason]),
            {error, anti_probe_alert(Reason)};
        error:{protocol_error, Reason} ->
            ?LOG_WARNING("TLS reject reason=~p", [Reason]),
            {error, anti_probe_alert(Reason)}
    end.

do_from_client_hello(Data, Secret, AllowedDomains) ->
    #client_hello{
       pseudorandom = ClientDigest,
       session_id = SessionId,
       cipher_suites = ClientSuites,
       extensions = Extensions
      } = parse_client_hello(Data),

    SniDomain =
        case lists:keyfind(?EXT_SNI, 1, Extensions) of
            {_, [{?EXT_SNI_HOST_NAME, Domain}]} -> Domain;
            _ -> undefined
        end,

    case SniDomain of
        undefined ->
            error({protocol_error, tls_no_sni});
        _ ->
            case is_domain_allowed(SniDomain, AllowedDomains) of
                true -> ok;
                false -> error({protocol_error, tls_domain_not_allowed, SniDomain})
            end
    end,

    HasSessionTicket = lists:keymember(?EXT_SESSION_TICKET, 1, Extensions),
    HasOcspStapling = lists:keymember(?EXT_STATUS_REQUEST, 1, Extensions),

    ServerDigest = make_server_digest(Data, Secret),
    <<Zeroes:(?DIGEST_LEN - 4)/binary, Timestamp:32/unsigned-little>> =
        crypto:exor(ClientDigest, ServerDigest),
    case lists:all(fun(B) -> B =:= 0 end, binary_to_list(Zeroes)) of
        true -> ok;
        false -> error({protocol_error, tls_invalid_digest})
    end,

    Profile = choose_profile(Extensions),
    SelectedCipher = choose_cipher(ClientSuites),
    {KeyShareGroup, KeyShareKey} = make_key_share(Extensions),

    %% First pass with zero digest for transcript MAC input.
    SrvHello0 = make_srv_hello(binary:copy(<<0>>, ?DIGEST_LEN),
                               SessionId, SelectedCipher,
                               {KeyShareGroup, KeyShareKey},
                               HasSessionTicket, HasOcspStapling),

    {SessionTicket, TicketFrame} =
        case HasSessionTicket of
            true ->
                T = generate_session_ticket(Secret),
                %% TLS1.3-style post-handshake ticket as encrypted-looking appdata later.
                {T, <<>>};
            false ->
                {undefined, <<>>}
        end,

    OcspResponse =
        case HasOcspStapling of
            true -> generate_ocsp_response(ServerDigest);
            false -> undefined
        end,

    %% Build fake encrypted handshake flight (EE + Cert + CV + Finished)
    EncFlight = fake_encrypted_handshake_flight(Profile, OcspResponse),
    FirstAppBurst = fake_initial_appdata_burst(Profile),

    CCS = as_tls_frame(?TLS_REC_CHANGE_CIPHER, [1]),

    Response0 = [as_tls_frame(?TLS_REC_HANDSHAKE, SrvHello0),
                 CCS,
                 EncFlight,
                 FirstAppBurst,
                 TicketFrame],

    SrvHelloDigest = hmac(sha256, Secret, [ClientDigest | Response0]),
    SrvHello = make_srv_hello(SrvHelloDigest, SessionId, SelectedCipher,
                              {KeyShareGroup, KeyShareKey},
                              HasSessionTicket, HasOcspStapling),

    %% Optional NewSessionTicket as separate encrypted-looking record.
    TicketRecords =
        case SessionTicket of
            undefined -> [];
            _ ->
                TicketHS = <<?TLS_TAG_NEW_SESSION_TICKET,
                             (byte_size(SessionTicket)):?u24,
                             SessionTicket/binary>>,
                [as_tls_frame(?TLS_REC_DATA, pad_like_tls13(TicketHS, 32, 96))]
        end,

    Response = [as_tls_frame(?TLS_REC_HANDSHAKE, SrvHello),
                CCS,
                EncFlight,
                FirstAppBurst
                | TicketRecords],

    Meta = #{session_id => SessionId,
             timestamp => Timestamp,
             client_digest => ClientDigest,
             sni_domain => SniDomain,
             selected_cipher => SelectedCipher,
             profile => maps:get(name, Profile, unknown),
             session_ticket => SessionTicket,
             ocsp_response => OcspResponse},

    St = #st{profile = Profile,
             session_ticket = SessionTicket,
             ocsp_response = OcspResponse,
             session_ticket_lifetime =
                 case HasSessionTicket of
                     true -> 604800;
                     false -> undefined
                 end,
             out_seq = 0},
    {ok, Response, Meta, St}.

anti_probe_alert(tls_domain_not_allowed) ->
    %% unrecognized_name is common for wrong SNI on real servers.
    <<?TLS_REC_ALERT, ?TLS_12_VERSION, 0, 2,
      ?TLS_ALERT_FATAL, ?TLS_ALERT_UNRECOGNIZED_NAME>>;
anti_probe_alert(tls_no_sni) ->
    <<?TLS_REC_ALERT, ?TLS_12_VERSION, 0, 2,
      ?TLS_ALERT_FATAL, ?TLS_ALERT_HANDSHAKE_FAILURE>>;
anti_probe_alert(_) ->
    %% Mix decode_error / handshake_failure / close_notify-looking responses.
    case rand:uniform(3) of
        1 ->
            <<?TLS_REC_ALERT, ?TLS_12_VERSION, 0, 2,
              ?TLS_ALERT_FATAL, ?TLS_ALERT_DECODE_ERROR>>;
        2 ->
            <<?TLS_REC_ALERT, ?TLS_12_VERSION, 0, 2,
              ?TLS_ALERT_FATAL, ?TLS_ALERT_HANDSHAKE_FAILURE>>;
        3 ->
            %% Some middleboxes expect alert then silence.
            <<?TLS_REC_ALERT, ?TLS_12_VERSION, 0, 2,
              ?TLS_ALERT_WARNING, ?TLS_ALERT_CLOSE_NOTIFY>>
    end.

-spec parse_sni(binary()) -> {ok, binary()} | {error, no_sni | bad_hello}.
parse_sni(Data) ->
    try
        #client_hello{extensions = Extensions} = parse_client_hello(Data),
        case lists:keyfind(?EXT_SNI, 1, Extensions) of
            {_, [{?EXT_SNI_HOST_NAME, Domain}]} -> {ok, Domain};
            _ -> {error, no_sni}
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
derive_sni_secret(BaseSecret, SniDomain, Salt) when byte_size(BaseSecret) == 16 ->
    SecretHex = mtp_handler:hex(BaseSecret),
    <<Derived:16/binary, _/binary>> =
        crypto:hash(sha256, [Salt, SecretHex, SniDomain]),
    Derived.

%%% ==================================================================
%%% ClientHello parse
%%% ==================================================================

parse_client_hello(<<?TLS_REC_HANDSHAKE, ?TLS_10_VERSION, TlsFrameLen:?u16,
                     ?TLS_TAG_CLI_HELLO, HelloLen:?u24, ?TLS_12_VERSION,
                     Random:?DIGEST_LEN/binary,
                     SessIdLen, SessId:SessIdLen/binary,
                     CipherSuitesLen:?u16, CipherSuites:CipherSuitesLen/binary,
                     CompMethodsLen, CompMethods:CompMethodsLen/binary,
                     ExtensionsLen:?u16, Extensions:ExtensionsLen/binary>>)
  when TlsFrameLen >= 300, HelloLen >= 250 ->
    #client_hello{
       pseudorandom = Random,
       session_id = SessId,
       cipher_suites = parse_suites(CipherSuites),
       compression_methods = binary_to_list(CompMethods),
       extensions = parse_extensions(Extensions)
      };
parse_client_hello(_Data) ->
    error({protocol_error, tls_bad_client_hello, bad_client_hello}).

parse_suites(Bin) ->
    [Suite || <<Suite:?u16>> <= Bin].

parse_extensions(Exts) ->
    [{Type, parse_extension(Type, Data)}
     || <<Type:?u16, Length:?u16, Data:Length/binary>> <= Exts].

parse_extension(?EXT_SNI, <<ListLen:?u16, List:ListLen/binary>>) ->
    [{Type, Value} || <<Type, Len:?u16, Value:Len/binary>> <= List];
parse_extension(?EXT_KEY_SHARE, <<Len:?u16, Exts:Len/binary>>) ->
    [{Group, Key} || <<Group:?u16, KeyLen:?u16, Key:KeyLen/binary>> <= Exts];
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
            Supported =
                [ {G, K} || {G, K} <- KeyShares,
                            byte_size(K) > 0, byte_size(K) < 2000,
                            lists:member(G, [16#0017, 16#0018, 16#0019,
                                             16#001D, 16#001E,
                                             16#0100, 16#0101, 16#0102,
                                             16#0103, 16#0104, 16#11EC]) ],
            case Supported of
                [] -> error({protocol_error, tls_unsupported_key_shares, KeyShares});
                [{G, K} | _] -> {G, crypto:strong_rand_bytes(byte_size(K))}
            end;
        _ ->
            error({protocol_error, tls_missing_key_share_ext, Exts})
    end.

choose_cipher(ClientSuites) ->
    case [C || C <- ?PREFERRED_CIPHERS, lists:member(C, ClientSuites)] of
        [C | _] -> C;
        [] when ClientSuites =/= [] ->
            %% Avoid pure GREASE if possible.
            NonGrease = [S || S <- ClientSuites, not is_grease(S)],
            case NonGrease of
                [C | _] -> C;
                [] -> hd(ClientSuites)
            end;
        [] -> 16#1301
    end.

is_grease(V) ->
    lists:member(V, ?GREASE_VALUES).

choose_profile(Exts) ->
    %% Lightweight heuristic: ALPN/ECH/keyshare richness.
    HasECH = lists:keymember(?EXT_ECH, 1, Exts) orelse lists:keymember(16#fe0d, 1, Exts),
    HasALPN = lists:keymember(?EXT_ALPN, 1, Exts),
    HasManyShares =
        case lists:keyfind(?EXT_KEY_SHARE, 1, Exts) of
            {_, L} when is_list(L), length(L) >= 3 -> true;
            _ -> false
        end,
    Pref =
        if HasECH andalso HasManyShares -> chrome_like;
           HasALPN andalso not HasECH -> firefox_like;
           true -> undefined
        end,
    case Pref of
        undefined -> random_tls_profile();
        Name ->
            case lists:filter(fun(P) -> maps:get(name, P) =:= Name end,
                              ?TLS_FINGERPRINT_PROFILES) of
                [P | _] -> P;
                [] -> random_tls_profile()
            end
    end.

make_srv_hello(Digest, SessionId, Cipher, {KeyShareGroup, KeyShareKey},
               HasSessionTicket, HasOcspStapling) ->
    KeyShareEntity = <<KeyShareGroup:?u16,
                       (byte_size(KeyShareKey)):?u16,
                       KeyShareKey/binary>>,
    Ext0 = [
        <<?EXT_KEY_SHARE:?u16, (byte_size(KeyShareEntity)):?u16, KeyShareEntity/binary>>,
        <<?EXT_SUPPORTED_VERSIONS:?u16, 2:?u16, ?TLS_13_VERSION>>
    ],
    Ext1 = case HasSessionTicket of
               true -> Ext0 ++ [<<?EXT_SESSION_TICKET:?u16, 0:?u16>>];
               false -> Ext0
           end,
    Ext2 = case HasOcspStapling of
               true -> Ext1 ++ [<<?EXT_STATUS_REQUEST:?u16, 0:?u16>>];
               false -> Ext1
           end,
    %% Occasionally shuffle server extensions a bit.
    ExtensionsFinal =
        case rand:uniform(2) of
            1 -> Ext2;
            2 -> shuffle_list(Ext2)
        end,
    SessionSize = byte_size(SessionId),
    Payload = [<<?TLS_12_VERSION,
                 Digest:?DIGEST_LEN/binary,
                 SessionSize, SessionId:SessionSize/binary,
                 Cipher:?u16,
                 0, %% compression null
                 (iolist_size(ExtensionsFinal)):?u16>>
               | ExtensionsFinal],
    [<<?TLS_TAG_SRV_HELLO, (iolist_size(Payload)):?u24>> | Payload].

%%% ==================================================================
%%% Fake encrypted handshake / appdata shape
%%% ==================================================================

%% TLS1.3 puts EE/Cert/CV/Finished into encrypted records.
%% We only mimic outer shape + plausible sizes.
fake_encrypted_handshake_flight(Profile, OcspResponse) ->
    EE = fake_encrypted_extensions(),
    Cert = fake_certificate_message(OcspResponse),
    CV = fake_certificate_verify(),
    Fin = fake_finished(),
    %% Sometimes one record, sometimes split (more realistic).
    Chunks =
        case rand:uniform(3) of
            1 -> [iolist_to_binary([EE, Cert, CV, Fin])];
            2 -> [iolist_to_binary([EE, Cert]), iolist_to_binary([CV, Fin])];
            3 -> [EE, Cert, CV, Fin]
        end,
    [as_tls_frame(?TLS_REC_DATA, pad_like_tls13(C, 16, 64)) || C <- Chunks].

fake_encrypted_extensions() ->
    %% Empty-ish EE with optional ALPN echo-looking bytes.
    Inner = case rand:uniform(2) of
                1 -> <<>>;
                2 ->
                    Proto = <<"h2">>,
                    ALPN = <<?EXT_ALPN:?u16, (2 + 1 + byte_size(Proto)):?u16,
                             (1 + byte_size(Proto)):?u16,
                             (byte_size(Proto)):8, Proto/binary>>,
                    ALPN
            end,
    <<?TLS_TAG_ENCRYPTED_EXTS, (byte_size(Inner)):?u24, Inner/binary>>.

fake_certificate_message(undefined) ->
    %% leaf + intermediate-ish sizes
    Leaf = crypto:strong_rand_bytes(500 + rand:uniform(700)),
    Inter = crypto:strong_rand_bytes(700 + rand:uniform(900)),
    CertList = <<(byte_size(Leaf)):?u24, Leaf/binary, 0:?u16,
                 (byte_size(Inter)):?u24, Inter/binary, 0:?u16>>,
    Body = <<0, (byte_size(CertList)):?u24, CertList/binary>>,
    <<?TLS_TAG_CERT, (byte_size(Body)):?u24, Body/binary>>;
fake_certificate_message(Ocsp) ->
    Leaf = crypto:strong_rand_bytes(500 + rand:uniform(700)),
    Inter = crypto:strong_rand_bytes(700 + rand:uniform(900)),
    %% Attach status_request-looking extension on leaf.
    StatusExt = <<?EXT_STATUS_REQUEST:?u16,
                  (byte_size(Ocsp) + 4):?u16,
                  1, %% ocsp
                  (byte_size(Ocsp)):?u24, Ocsp/binary>>,
    CertList = <<(byte_size(Leaf)):?u24, Leaf/binary,
                 (byte_size(StatusExt)):?u16, StatusExt/binary,
                 (byte_size(Inter)):?u24, Inter/binary, 0:?u16>>,
    Body = <<0, (byte_size(CertList)):?u24, CertList/binary>>,
    <<?TLS_TAG_CERT, (byte_size(Body)):?u24, Body/binary>>.

fake_certificate_verify() ->
    Sig = crypto:strong_rand_bytes(64 + rand:uniform(192)),
    %% ecdsa_secp256r1_sha256-looking header
    Body = <<16#0403:?u16, (byte_size(Sig)):?u16, Sig/binary>>,
    <<?TLS_TAG_CERT_VERIFY, (byte_size(Body)):?u24, Body/binary>>.

fake_finished() ->
    VerifyData = crypto:strong_rand_bytes(32),
    <<?TLS_TAG_FINISHED, (byte_size(VerifyData)):?u24, VerifyData/binary>>.

fake_initial_appdata_burst(Profile) ->
    {BMin, BMax} = maps:get(appdata_first_burst, Profile, {2, 4}),
    {SMin, SMax} = maps:get(appdata_size, Profile, {700, 1300}),
    N = BMin - 1 + rand:uniform(max(1, BMax - BMin + 1)),
    [ begin
          Sz = SMin - 1 + rand:uniform(max(1, SMax - SMin + 1)),
          as_tls_frame(?TLS_REC_DATA, crypto:strong_rand_bytes(Sz))
      end || _ <- lists:seq(1, N) ].

pad_like_tls13(Bin, MinPad, MaxPad) when is_binary(Bin) ->
    Pad = MinPad - 1 + rand:uniform(max(1, MaxPad - MinPad + 1)),
    %% TLS1.3 record padding is zeros before content-type; we only need outer size realism.
    <<Bin/binary, 0:Pad/unit:8, 23>>. %% trailing fake content-type appdata

%%% ==================================================================
%%% ClientHello builder (outbound)
%%% ==================================================================

-spec random_tls_profile() -> map().
random_tls_profile() ->
    Profiles = ?TLS_FINGERPRINT_PROFILES,
    lists:nth(rand:uniform(length(Profiles)), Profiles).

random_grease(Count) ->
    [lists:nth(rand:uniform(length(?GREASE_VALUES)), ?GREASE_VALUES)
     || _ <- lists:seq(1, Count)].

shuffle_list([]) -> [];
shuffle_list(List) ->
    [X || {_, X} <- lists:sort([{rand:uniform(), E} || E <- List])].

build_cipher_suites(#{grease_count := {GreaseMin, GreaseMax}} = Profile) ->
    Base = ?PREFERRED_CIPHERS ++ [16#c013, 16#c014, 16#009c, 16#009d, 16#002f, 16#0035],
    GreaseCount = GreaseMin - 1 + rand:uniform(max(1, GreaseMax - GreaseMin + 1)),
    WithGrease = inject_grease(Base, random_grease(GreaseCount)),
    Final = case maps:get(cipher_order_randomized, Profile, false) of
                true -> shuffle_list(WithGrease);
                false -> WithGrease
            end,
    << <<S:?u16>> || S <- Final >>.

inject_grease(List, []) -> List;
inject_grease(List, [G | Rest]) ->
    Pos = rand:uniform(length(List) + 1),
    New = lists:sublist(List, Pos - 1) ++ [G] ++ lists:nthtail(Pos - 1, List),
    inject_grease(New, Rest).

build_key_share_entries(#{key_share_groups := Groups, grease_count := {GreaseMin, GreaseMax}}) ->
    GreaseCount = GreaseMin - 1 + rand:uniform(max(1, GreaseMax - GreaseMin + 1)),
    GreaseEntries = [<<G:?u16, 1:?u16, 0>> || G <- random_grease(GreaseCount)],
    RealEntries =
        [begin
             KeySize = key_size_for_group(Group),
             Key = crypto:strong_rand_bytes(KeySize),
             <<Group:?u16, KeySize:?u16, Key/binary>>
         end || Group <- Groups],
    iolist_to_binary(inject_grease(RealEntries, GreaseEntries)).

key_size_for_group(16#001D) -> 32;
key_size_for_group(16#0017) -> 65;
key_size_for_group(16#0018) -> 97;
key_size_for_group(16#0019) -> 133;
key_size_for_group(16#11EC) -> 1216;
key_size_for_group(_) -> 32.

build_supported_versions_ext(#{supported_versions := Versions,
                               grease_count := {GreaseMin, GreaseMax}} = Profile) ->
    GreaseCount = GreaseMin - 1 + rand:uniform(max(1, GreaseMax - GreaseMin + 1)),
    WithGrease = inject_grease(Versions, random_grease(GreaseCount)),
    Final = case maps:get(version_order_randomized, Profile, false) of
                true -> shuffle_list(WithGrease);
                false -> WithGrease
            end,
    << <<V:?u16>> || V <- Final >>.

build_sig_algos(#{sig_algorithms_count := Count}) ->
    All = [16#0403, 16#0503, 16#0603, 16#0804, 16#0805, 16#0806,
           16#0401, 16#0501, 16#0601, 16#0203, 16#0201, 16#0402,
           16#0303, 16#0301, 16#0302, 16#0807, 16#0808],
    Selected = lists:sublist(shuffle_list(All), Count),
    Bin = << <<A:?u16>> || A <- Selected >>,
    <<?EXT_SIG_ALGS:?u16, (byte_size(Bin) + 2):?u16, (byte_size(Bin)):?u16, Bin/binary>>.

build_ech(#{ech_payload_size := Sizes}) when is_list(Sizes) ->
    PayloadSize = lists:nth(rand:uniform(length(Sizes)), Sizes),
    EchContent =
        <<0, 0, 1, 0, 1,
          (crypto:strong_rand_bytes(1))/binary,
          0, 32,
          (crypto:strong_rand_bytes(32))/binary,
          PayloadSize:?u16,
          (crypto:strong_rand_bytes(PayloadSize))/binary>>,
    <<?EXT_ECH:?u16, (byte_size(EchContent)):?u16, EchContent/binary>>;
build_ech(_) -> <<>>.

build_alpn(#{alpn_protocols := Protocols}) ->
    Selected = lists:nth(rand:uniform(length(Protocols)), Protocols),
    Entries = << <<(byte_size(P)):8, P/binary>> || P <- Selected >>,
    <<?EXT_ALPN:?u16, (byte_size(Entries) + 2):?u16,
      (byte_size(Entries)):?u16, Entries/binary>>;
build_alpn(_) -> <<>>.

build_compress_certificate(#{compress_certificate := brotli}) ->
    <<?EXT_COMPRESS_CERT:?u16, 3:?u16, 2, 0, 2>>;
build_compress_certificate(_) -> <<>>.

build_ec_point_formats(#{ec_point_formats := true}) ->
    <<?EXT_EC_POINT_FORMATS:?u16, 2:?u16, 1, 0>>;
build_ec_point_formats(_) -> <<>>.

build_supported_groups(#{key_share_groups := Groups, grease_count := {GreaseMin, GreaseMax}}) ->
    GreaseCount = GreaseMin - 1 + rand:uniform(max(1, GreaseMax - GreaseMin + 1)),
    WithGrease = inject_grease(Groups, random_grease(GreaseCount)),
    Bin = << <<G:?u16>> || G <- WithGrease >>,
    <<?EXT_SUPPORTED_GROUPS:?u16, (byte_size(Bin) + 2):?u16,
      (byte_size(Bin)):?u16, Bin/binary>>.

build_padding(#{padding_size := {Min, Max}}) ->
    PadSize = Min - 1 + rand:uniform(max(1, Max - Min + 1)),
    case PadSize =< 0 of
        true -> <<>>;
        false -> <<?EXT_PADDING:?u16, PadSize:?u16, 0:PadSize/unit:8>>
    end;
build_padding(_) -> <<>>.

build_session_ticket_ext(#{session_ticket_enabled := true}) ->
    <<?EXT_SESSION_TICKET:?u16, 0:?u16>>;
build_session_ticket_ext(_) -> <<>>.

build_ocsp_stapling_ext(#{ocsp_stapling_enabled := true}) ->
    %% status_request with empty responder/extensions
    <<?EXT_STATUS_REQUEST:?u16, 5:?u16, 1, 0, 0, 0, 0>>;
build_ocsp_stapling_ext(_) -> <<>>.

make_sni(Domains) ->
    Items = << <<?EXT_SNI_HOST_NAME, (byte_size(Domain)):?u16, Domain/binary>>
               || Domain <- Domains >>,
    <<?EXT_SNI:?u16, (byte_size(Items) + 2):?u16,
      (byte_size(Items)):?u16, Items/binary>>.

-spec make_client_hello(binary(), binary()) -> binary().
make_client_hello(Secret, SniDomain) ->
    make_client_hello(erlang:system_time(second),
                      crypto:strong_rand_bytes(32),
                      Secret, SniDomain).

-spec make_client_hello(non_neg_integer(), binary(), binary(), binary()) -> binary().
make_client_hello(Timestamp, SessionId, HexSecret, SniDomain)
  when byte_size(HexSecret) == 32 ->
    make_client_hello(Timestamp, SessionId, mtp_handler:unhex(HexSecret), SniDomain);
make_client_hello(Timestamp, SessionId, Secret, SniDomain)
  when byte_size(SessionId) == 32, byte_size(Secret) == 16 ->
    Profile = random_tls_profile(),
    CipherSuites = build_cipher_suites(Profile),
    SNI = make_sni([SniDomain]),
    SigAlgos = build_sig_algos(Profile),
    SupportedGroups = build_supported_groups(Profile),
    SupportedVersionsExt = build_supported_versions_ext(Profile),
    SupportedVersions =
        <<?EXT_SUPPORTED_VERSIONS:?u16,
          (byte_size(SupportedVersionsExt) + 1):?u16,
          (byte_size(SupportedVersionsExt)):8,
          SupportedVersionsExt/binary>>,
    KeyShareEntries = build_key_share_entries(Profile),
    KeyShare =
        <<?EXT_KEY_SHARE:?u16,
          (byte_size(KeyShareEntries) + 2):?u16,
          (byte_size(KeyShareEntries)):?u16,
          KeyShareEntries/binary>>,
    Extensions0 = [
        build_ech(Profile),
        build_session_ticket_ext(Profile),
        build_ec_point_formats(Profile),
        KeyShare,
        <<16#0012:?u16, 0:?u16>>, %% SCT
        SupportedGroups,
        build_compress_certificate(Profile),
        <<16#ff01:?u16, 1:?u16, 0>>, %% renegotiation_info
        SigAlgos,
        build_ocsp_stapling_ext(Profile),
        <<?EXT_PSK_MODES:?u16, 2:?u16, 1, 1>>,
        build_alpn(Profile),
        SNI,
        SupportedVersions,
        build_padding(Profile)
    ],
    NonEmpty = [E || E <- Extensions0, E =/= <<>>],
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
    Hello0 = Pack(binary:copy(<<0>>, ?DIGEST_LEN)),
    Digest = hmac(sha256, Secret, Hello0),
    EncTimestamp = <<0:(?DIGEST_LEN - 4)/unit:8, Timestamp:32/unsigned-little>>,
    Pack(crypto:exor(Digest, EncTimestamp)).

%%% ==================================================================
%%% ServerHello parse (client side)
%%% ==================================================================

parse_server_hello(<<?TLS_REC_HANDSHAKE, ?TLS_12_VERSION, HSLen:?u16, Handshake:HSLen/binary,
                     ?TLS_REC_CHANGE_CIPHER, ?TLS_12_VERSION, CCLen:?u16, ChangeCipher:CCLen/binary,
                     ?TLS_REC_DATA, ?TLS_12_VERSION, DLen:?u16, Data:DLen/binary,
                     Tail/binary>>) ->
    {Handshake, ChangeCipher, Data, skip_optional_tls_records(Tail)};
parse_server_hello(B) when byte_size(B) < 5 ->
    incomplete;
parse_server_hello(<<16#16, _/binary>> = B) ->
    case tls_records_complete(B, 3) of
        true -> {error, tls_domain_forwarding};
        false -> incomplete
    end;
parse_server_hello(<<16#15, _/binary>>) ->
    {error, tls_alert};
parse_server_hello(_) ->
    {error, not_proxy_response}.

skip_optional_tls_records(<<Type, ?TLS_12_VERSION, Len:?u16, _Data:Len/binary, Tail/binary>>)
  when Type =:= ?TLS_REC_DATA; Type =:= ?TLS_REC_HANDSHAKE; Type =:= ?TLS_REC_CHANGE_CIPHER ->
    skip_optional_tls_records(Tail);
skip_optional_tls_records(Tail) ->
    Tail.

tls_records_complete(_B, 0) -> true;
tls_records_complete(<<_T, _Mj, _Mn, Len:?u16, Rest/binary>>, N) when byte_size(Rest) >= Len ->
    <<_:Len/binary, Tail/binary>> = Rest,
    tls_records_complete(Tail, N - 1);
tls_records_complete(_B, _N) -> false.

%%% ==================================================================
%%% Stream codec
%%% ==================================================================

-spec new() -> codec().
new() -> #st{}.

-spec try_decode_packet(binary(), codec()) ->
          {ok, binary(), binary(), codec()} | {incomplete, codec()}.
try_decode_packet(<<?TLS_12_DATA, Size:?u16, Data:Size/binary, Tail/binary>>, St) ->
    %% Strip optional fake TLS1.3 inner padding marker if present.
    Clear = strip_inner_padding(Data),
    {ok, Clear, Tail, St};
try_decode_packet(<<?TLS_REC_CHANGE_CIPHER, ?TLS_12_VERSION, Size:?u16,
                    _Data:Size/binary, Tail/binary>>, St) ->
    try_decode_packet(Tail, St);
try_decode_packet(<<?TLS_REC_HANDSHAKE, ?TLS_12_VERSION, Size:?u16,
                    _Data:Size/binary, Tail/binary>>, St) ->
    %% Ignore post-handshake tickets etc.
    try_decode_packet(Tail, St);
try_decode_packet(Bin, St) when byte_size(Bin) =< (?MAX_IN_PACKET_SIZE + 5) ->
    {incomplete, St};
try_decode_packet(Bin, _St) ->
    error({protocol_error, tls_max_size, byte_size(Bin)}).

strip_inner_padding(Data) when byte_size(Data) < 2 -> Data;
strip_inner_padding(Data) ->
    %% Best-effort: if ends with zeros + 0x17, treat as padded fake TLS1.3 record body.
    case binary:last(Data) of
        23 ->
            Trimmed = trim_right_zeros(binary:part(Data, 0, byte_size(Data) - 1)),
            case Trimmed of
                <<>> -> Data;
                _ -> Trimmed
            end;
        _ -> Data
    end.

trim_right_zeros(<<>>) -> <<>>;
trim_right_zeros(Bin) ->
    case binary:last(Bin) of
        0 -> trim_right_zeros(binary:part(Bin, 0, byte_size(Bin) - 1));
        _ -> Bin
    end.

-spec decode_all(binary(), codec()) -> {binary(), binary(), codec()}.
decode_all(Bin, St) ->
    decode_all(Bin, <<>>, St).

decode_all(Bin, Acc, St0) ->
    case try_decode_packet(Bin, St0) of
        {incomplete, St} -> {Acc, Bin, St};
        {ok, Data, Tail, St} ->
            decode_all(Tail, <<Acc/binary, Data/binary>>, St)
    end.

-spec encode_packet(binary(), codec()) -> {iodata(), codec()}.
encode_packet(Bin, #st{out_seq = Seq, profile = Profile} = St) ->
    Frames = encode_as_frames(Bin, Profile, Seq),
    {Frames, St#st{out_seq = Seq + 1}}.

encode_as_frames(Bin, _Profile, _Seq) when byte_size(Bin) =< 0 ->
    [];
encode_as_frames(Bin, Profile, Seq) ->
    %% Vary record sizes to reduce fixed-length signatures.
    Max = realistic_out_size(Profile, Seq),
    case Bin of
        <<Chunk:Max/binary, Tail/binary>> ->
            [as_tls_data_frame(maybe_pad_out(Chunk)) | encode_as_frames(Tail, Profile, Seq)];
        _ ->
            [as_tls_data_frame(maybe_pad_out(Bin))]
    end.

realistic_out_size(undefined, Seq) ->
    realistic_out_size(#{}, Seq);
realistic_out_size(Profile, Seq) ->
    %% Early records smaller/medium; later can be larger.
    Base =
        case Seq of
            S when S < 3 -> 800 + rand:uniform(700);
            S when S < 10 -> 1200 + rand:uniform(2000);
            _ -> 3000 + rand:uniform(9000)
        end,
    min(?MAX_OUT_PACKET_SIZE, max(200, Base)).

maybe_pad_out(Bin) ->
    %% Occasionally add tiny padding to break exact payload length correlation.
    case rand:uniform(5) of
        1 ->
            Pad = rand:uniform(32),
            <<Bin/binary, 0:Pad/unit:8, 23>>;
        _ -> Bin
    end.

as_tls_data_frame(Bin) ->
    as_tls_frame(?TLS_REC_DATA, Bin).

-spec as_tls_frame(byte(), iodata()) -> iodata().
as_tls_frame(Type, Data) ->
    Size = iolist_size(Data),
    [<<Type, ?TLS_12_VERSION, Size:?u16>> | Data].

-if(?OTP_RELEASE >= 23).
hmac(Algo, Key, Str) -> crypto:mac(hmac, Algo, Key, Str).
-else.
hmac(Algo, Key, Str) -> crypto:hmac(Algo, Key, Str).
-endif.
