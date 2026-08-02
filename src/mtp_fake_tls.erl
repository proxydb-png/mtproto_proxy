%%% @author enhanced <enhanced@antidpi.example>
%%% @doc
%%% Maximum-evasion Fake TLS codec with advanced DPI bypass techniques
%%% Complete version with all helper functions
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
    session_ticket :: binary() | undefined,
    ocsp_response :: binary() | undefined,
    session_ticket_lifetime :: non_neg_integer() | undefined,
    connection_start :: non_neg_integer(),
    packet_count = 0 :: non_neg_integer(),
    bytes_sent = 0 :: non_neg_integer(),
    current_profile :: map(),
    record_size_pattern :: cyclic | random_walk | pareto_distributed,
    last_record_size = 0 :: non_neg_integer()
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
-define(u32, 32/unsigned-big).

-define(MAX_IN_PACKET_SIZE, 65535).
-define(MAX_OUT_PACKET_SIZE, 16384).

-define(TLS_10_VERSION, 3, 1).
-define(TLS_12_VERSION, 3, 3).
-define(TLS_13_VERSION, 3, 4).
-define(TLS_REC_CHANGE_CIPHER, 20).
-define(TLS_REC_ALERT, 21).
-define(TLS_REC_HANDSHAKE, 22).
-define(TLS_REC_DATA, 23).
-define(TLS_REC_HEARTBEAT, 24).

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
-define(EXT_STATUS_REQUEST, 5).
-define(EXT_ENCRYPTED_CLIENT_HELLO, 65037).

-define(TLS_12_DATA, ?TLS_REC_DATA, ?TLS_12_VERSION).

%% ============================================================================
%% GREASE values
%% ============================================================================
-define(GREASE_VALUES, [
    16#0a0a, 16#1a1a, 16#2a2a, 16#3a3a, 16#4a4a,
    16#5a5a, 16#6a6a, 16#7a7a, 16#8a8a, 16#9a9a,
    16#aaaa, 16#baba, 16#caca, 16#dada, 16#eaea,
    16#fafa
]).

%% ============================================================================
%% TLS Fingerprint Profiles
%% ============================================================================
-define(TLS_FINGERPRINT_PROFILES, [
    #{name => chrome_130_canary,
      weight => 15,
      cipher_suites => [
          16#1301, 16#1302, 16#1303,
          16#c02b, 16#c02f, 16#c02c, 16#c030,
          16#cca9, 16#cca8,
          16#c013, 16#c014,
          16#009c, 16#009d, 16#002f, 16#0035
      ],
      post_quantum_suites => [16#c0b0, 16#c0b1],
      include_post_quantum => 0.3,
      cipher_order_randomized => true,
      grease_count => {3, 6},
      key_share_groups => [
          16#11ec, 16#001d, 16#0017, 16#0018
      ],
      post_quantum_groups => [16#11ed, 16#11ee],
      include_post_quantum_groups => 0.4,
      supported_versions => [16#0304, 16#0303],
      version_order_randomized => true,
      sig_algorithms_count => 18,
      ec_point_formats => true,
      compress_certificate => brotli,
      ech_payload_size => [176, 208, 240],
      session_id_length => {32, 32},
      extensions_order_randomized => true,
      include_ech => true,
      alpn_protocols => [[<<"h2">>, <<"http/1.1">>], [<<"h2">>]],
      padding_size => {0, 512},
      middlebox_compat => true,
      record_size_pattern => pareto_distributed,
      preferred_record_sizes => [
          {64, 0.1}, {128, 0.15}, {256, 0.2}, {512, 0.2},
          {1024, 0.15}, {1460, 0.1}, {2048, 0.05}, {4096, 0.05}
      ],
      session_ticket_enabled => true,
      ocsp_stapling_enabled => true,
      zero_length_records_probability => 0.1
    },
    #{name => firefox_135,
      weight => 20,
      cipher_suites => [
          16#1301, 16#1302, 16#1303,
          16#c02b, 16#c02f, 16#c02c, 16#c030,
          16#cca9, 16#cca8,
          16#c013, 16#c014, 16#009c, 16#009d,
          16#002f, 16#0035
      ],
      post_quantum_suites => [16#c0b0],
      include_post_quantum => 0.5,
      cipher_order_randomized => true,
      grease_count => {2, 4},
      key_share_groups => [16#001d, 16#0017],
      post_quantum_groups => [16#11ed],
      include_post_quantum_groups => 0.3,
      supported_versions => [16#0304, 16#0303],
      version_order_randomized => false,
      sig_algorithms_count => 15,
      ec_point_formats => true,
      compress_certificate => brotli,
      ech_payload_size => [144, 176],
      session_id_length => {32, 32},
      extensions_order_randomized => false,
      include_ech => true,
      alpn_protocols => [[<<"h2">>, <<"http/1.1">>]],
      padding_size => {0, 256},
      middlebox_compat => true,
      record_size_pattern => random_walk,
      preferred_record_sizes => [
          {128, 0.15}, {256, 0.2}, {512, 0.25},
          {1024, 0.2}, {1460, 0.1}, {2048, 0.05}, {4096, 0.05}
      ],
      session_ticket_enabled => true,
      ocsp_stapling_enabled => false,
      zero_length_records_probability => 0.05
    }
]).

-opaque codec() :: #st{}.

-type meta() :: #{
    session_id := binary(),
    timestamp := non_neg_integer(),
    client_digest := binary(),
    sni_domain => binary(),
    session_ticket => binary() | undefined,
    ocsp_response => binary() | undefined,
    profile_used => atom()
}.

%% ============================================================================
%% Public API
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
%% Random profile selection
%% ============================================================================
-spec random_tls_profile() -> map().
random_tls_profile() ->
    Profiles = ?TLS_FINGERPRINT_PROFILES,
    Weights = [maps:get(weight, P, 10) || P <- Profiles],
    TotalWeight = lists:sum(Weights),
    RandomWeight = rand:uniform(TotalWeight),
    Profile = select_weighted(Profiles, Weights, RandomWeight, 0),
    ?LOG_DEBUG("Selected TLS fingerprint: ~s", [maps:get(name, Profile, unknown)]),
    Profile.

select_weighted([P | _], [W | _], Target, Acc) when Acc + W >= Target -> P;
select_weighted([_ | Ps], [W | Ws], Target, Acc) ->
    select_weighted(Ps, Ws, Target, Acc + W).

%% ============================================================================
%% GREASE and randomization helpers
%% ============================================================================
-spec random_grease(non_neg_integer()) -> [non_neg_integer()].
random_grease(Count) ->
    [lists:nth(rand:uniform(length(?GREASE_VALUES)), ?GREASE_VALUES) 
     || _ <- lists:seq(1, Count)].

-spec grease_for(map()) -> [non_neg_integer()].
grease_for(#{grease_count := {Min, Max}}) ->
    Count = Min + rand:uniform(Max - Min + 1),
    random_grease(Count).

-spec shuffle_list(list()) -> list().
shuffle_list([]) -> [];
shuffle_list(List) ->
    Sorted = lists:sort([{rand:uniform(), X} || X <- List]),
    [X || {_, X} <- Sorted].

-spec interleave_random(list(), list()) -> list().
interleave_random(List, Elems) ->
    lists:foldl(
      fun(E, Acc) ->
              Pos = rand:uniform(length(Acc) + 1),
              lists:sublist(Acc, Pos - 1) ++ [E] ++ lists:nthtail(Pos - 1, Acc)
      end, List, Elems).

%% ============================================================================
%% Post-quantum simulation
%% ============================================================================
-spec generate_post_quantum_suites(map()) -> [non_neg_integer()].
generate_post_quantum_suites(#{include_post_quantum := Prob, 
                               post_quantum_suites := Suites}) when Prob > 0 ->
    case rand:uniform() =< Prob of
        true ->
            Count = rand:uniform(min(2, length(Suites))),
            lists:sublist(shuffle_list(Suites), Count);
        false -> []
    end;
generate_post_quantum_suites(_) -> [].

-spec generate_post_quantum_groups(map()) -> [non_neg_integer()].
generate_post_quantum_groups(#{include_post_quantum_groups := Prob,
                               post_quantum_groups := Groups}) when Prob > 0 ->
    case rand:uniform() =< Prob of
        true ->
            Count = rand:uniform(min(2, length(Groups))),
            lists:sublist(shuffle_list(Groups), Count);
        false -> []
    end;
generate_post_quantum_groups(_) -> [].

%% ============================================================================
%% Key share generation
%% ============================================================================
-spec key_size_for_group(non_neg_integer()) -> non_neg_integer().
key_size_for_group(16#001d) -> 32;    % x25519
key_size_for_group(16#0017) -> 65;    % secp256r1
key_size_for_group(16#0018) -> 97;    % secp384r1
key_size_for_group(16#0019) -> 133;   % secp521r1
key_size_for_group(16#11ec) -> 1216;  % X25519MLKEM768
key_size_for_group(16#11ed) -> 1088;  % Simulated PQ
key_size_for_group(16#11ee) -> 1568;  % Simulated PQ
key_size_for_group(_) -> 32.

-spec build_key_share_entries(map()) -> binary().
build_key_share_entries(#{key_share_groups := Groups} = Profile) ->
    GreaseVals = grease_for(Profile),
    PQGroups = generate_post_quantum_groups(Profile),
    AllGroups = interleave_random(Groups, PQGroups),

    RealEntries = [
        begin
            KeySize = key_size_for_group(Group),
            Key = crypto:strong_rand_bytes(KeySize),
            <<Group:?u16, KeySize:?u16, Key/binary>>
        end || Group <- AllGroups
    ],

    GreaseEntries = [<<G:?u16, 16#0001:?u16, 16#00>> || G <- GreaseVals],
    AllEntries = interleave_random(RealEntries, GreaseEntries),
    iolist_to_binary(AllEntries).

%% ============================================================================
%% Extension builders
%% ============================================================================
-spec build_cipher_suites(map()) -> binary().
build_cipher_suites(#{cipher_suites := Suites} = Profile) ->
    PQSuites = generate_post_quantum_suites(Profile),
    AllSuites = Suites ++ PQSuites,
    GreaseVals = grease_for(Profile),
    WithGrease = interleave_random(AllSuites, GreaseVals),
    Final = case maps:get(cipher_order_randomized, Profile, false) of
        true -> shuffle_list(WithGrease);
        false -> WithGrease
    end,
    << <<S:?u16>> || S <- Final >>.

-spec build_sig_algos(map()) -> binary().
build_sig_algos(#{sig_algorithms_count := Count}) ->
    AllAlgos = [
        16#0403, 16#0503, 16#0603, 16#0804, 16#0805, 16#0806,
        16#0401, 16#0501, 16#0601, 16#0201, 16#0203, 16#0301,
        16#0302, 16#0303, 16#0402, 16#0502, 16#0602, 16#0807
    ],
    EffCount = min(Count, length(AllAlgos)),
    Selected = lists:sublist(AllAlgos, EffCount),
    Shuffled = shuffle_list(Selected),
    AlgoListLen = EffCount * 2,
    <<AlgoListLen:?u16, << <<A:?u16>> || A <- Shuffled >>/binary>>.

-spec build_ech_ext(map()) -> binary().
build_ech_ext(#{include_ech := true, ech_payload_size := Sizes}) ->
    PayloadSize = lists:nth(rand:uniform(length(Sizes)), Sizes),
    ConfigId = rand:uniform(256) - 1,
    KemId = case rand:uniform(3) of
        1 -> <<16#00, 16#20>>;
        2 -> <<16#ff, 16#01>>;
        _ -> <<16#c0, 16#b0>>
    end,
    PubKeySize = case KemId of
        <<16#00, 16#20>> -> 32;
        _ -> 1056 + rand:uniform(128)
    end,
    PubKey = crypto:strong_rand_bytes(PubKeySize),
    CipherSuite = <<16#00, 16#01>>,
    Payload = crypto:strong_rand_bytes(PayloadSize),
    ECHContent = <<
        ConfigId, KemId/binary, PubKeySize:?u16, PubKey/binary,
        CipherSuite/binary, PayloadSize:?u16, Payload/binary
    >>,
    <<?EXT_ENCRYPTED_CLIENT_HELLO:?u16, 
      (byte_size(ECHContent)):?u16, ECHContent/binary>>;
build_ech_ext(_) -> <<>>.

-spec build_alpn(map()) -> binary().
build_alpn(#{alpn_protocols := Protocols}) ->
    Selected = lists:nth(rand:uniform(length(Protocols)), Protocols),
    ProtocolEntries = << <<(byte_size(P)):8, P/binary>> || P <- Selected >>,
    ProtocolsLen = byte_size(ProtocolEntries),
    <<16#00, 16#10, (ProtocolsLen + 2):?u16, ProtocolsLen:?u16, ProtocolEntries/binary>>;
build_alpn(_) -> <<>>.

-spec build_compress_certificate(map()) -> binary().
build_compress_certificate(#{compress_certificate := brotli}) ->
    <<16#00, 16#1b, 16#00, 16#03, 16#02, 16#00, 16#02>>;
build_compress_certificate(_) -> <<>>.

-spec build_ec_point_formats(map()) -> binary().
build_ec_point_formats(#{ec_point_formats := true}) ->
    <<16#00, 16#0b, 16#00, 16#02, 16#01, 16#00>>;
build_ec_point_formats(_) -> <<>>.

-spec build_supported_groups(map()) -> binary().
build_supported_groups(#{key_share_groups := Groups} = Profile) ->
    PQGroups = generate_post_quantum_groups(Profile),
    AllGroups = interleave_random(Groups, PQGroups),
    GreaseVals = grease_for(Profile),
    WithGrease = interleave_random(AllGroups, GreaseVals),
    GroupsBin = << <<G:?u16>> || G <- WithGrease >>,
    GroupsLen = byte_size(GroupsBin),
    <<16#00, 16#0a, (GroupsLen + 2):?u16, GroupsLen:?u16, GroupsBin/binary>>.

-spec build_supported_versions_ext(map()) -> binary().
build_supported_versions_ext(#{supported_versions := Versions} = Profile) ->
    GreaseVals = grease_for(Profile),
    WithGrease = interleave_random(Versions, GreaseVals),
    Final = case maps:get(version_order_randomized, Profile, false) of
        true -> shuffle_list(WithGrease);
        false -> WithGrease
    end,
    << <<V:?u16>> || V <- Final >>.

-spec build_padding(map()) -> binary().
build_padding(#{padding_size := {Min, Max}}) ->
    PadSize = Min + rand:uniform(Max - Min + 1) - 1,
    case PadSize of
        0 -> <<>>;
        _ ->
            Padding = binary:copy(<<0>>, PadSize),
            <<16#00, 16#15, PadSize:?u16, Padding/binary>>
    end;
build_padding(_) -> <<>>.

-spec build_session_ticket_ext(map()) -> binary().
build_session_ticket_ext(#{session_ticket_enabled := true}) ->
    <<?EXT_SESSION_TICKET:?u16, 0:?u16>>;
build_session_ticket_ext(_) -> <<>>.

-spec build_ocsp_stapling_ext(map()) -> binary().
build_ocsp_stapling_ext(#{ocsp_stapling_enabled := true}) ->
    <<?EXT_STATUS_REQUEST:?u16, 0:?u16>>;
build_ocsp_stapling_ext(_) -> <<>>.

-spec make_sni([binary()]) -> binary().
make_sni(Domains) ->
    SniListItems = << <<?EXT_SNI_HOST_NAME, (byte_size(Domain)):?u16, Domain/binary>>
                      || Domain <- Domains >>,
    ItemsLen = byte_size(SniListItems),
    <<?EXT_SNI:?u16, (ItemsLen + 2):?u16, ItemsLen:?u16, SniListItems/binary>>.

%% ============================================================================
%% OCSP and Session Ticket generators
%% ============================================================================
-spec encode_generalized_time(non_neg_integer()) -> binary().
encode_generalized_time(Timestamp) ->
    {{Y, M, D}, {H, Mi, S}} = calendar:universal_time_to_local_time(
        calendar:gregorian_seconds_to_datetime(Timestamp + 62167219200)),
    Str = io_lib:format("~4..0w~2..0w~2..0w~2..0w~2..0w~2..0wZ", [Y, M, D, H, Mi, S]),
    list_to_binary(Str).

-spec generate_ocsp_response(binary()) -> binary().
generate_ocsp_response(_ServerDigest) ->
    OcspStatus = 0,
    ResponderId = crypto:strong_rand_bytes(20),
    BaseTime = erlang:system_time(seconds),
    TimeJitter = rand:uniform(7200) - 3600,
    ProducedAt = BaseTime + TimeJitter,
    ThisUpdate = ProducedAt - rand:uniform(86400),
    NextUpdate = ProducedAt + 604800 + rand:uniform(86400),
    CertId = crypto:strong_rand_bytes(36),
    CertStatus = <<0>>,
    ResponseCount = rand:uniform(3),
    Responses = <<ResponseCount:32,
                  (iolist_to_binary(
                    [<<CertId:36/binary, CertStatus/binary,
                      (encode_generalized_time(ThisUpdate))/binary,
                      (encode_generalized_time(NextUpdate))/binary>>
                     || _ <- lists:seq(1, ResponseCount)]))/binary>>,
    ResponseData = <<0, ResponderId/binary,
                     (encode_generalized_time(ProducedAt))/binary,
                     Responses/binary>>,
    SigSize = 128 + rand:uniform(384),
    Signature = crypto:strong_rand_bytes(SigSize),
    BasicOcspResponse = <<ResponseData/binary, 1:24, Signature/binary>>,
    <<OcspStatus, (byte_size(BasicOcspResponse)):?u24, BasicOcspResponse/binary>>.

-spec generate_session_ticket(binary()) -> binary().
generate_session_ticket(_Secret) ->
    TicketAgeAdd = crypto:strong_rand_bytes(4),
    TicketNonceLen = rand:uniform(32) + 16,
    TicketNonce = crypto:strong_rand_bytes(TicketNonceLen),
    TicketLen = rand:uniform(192) + 64,
    Ticket = crypto:strong_rand_bytes(TicketLen),
    TicketLifetime = 345600 + rand:uniform(691200),
    Extensions = case rand:uniform(2) of
        1 -> <<>>;
        _ -> <<(rand:uniform(5)):?u16, (rand:uniform(32)):?u16,
               (crypto:strong_rand_bytes(rand:uniform(32)))/binary>>
    end,
    ExtLen = byte_size(Extensions),
    <<TicketLifetime:?u32, TicketAgeAdd/binary,
      TicketNonceLen:8, TicketNonce/binary,
      TicketLen:?u16, Ticket/binary,
      ExtLen:?u16, Extensions/binary>>.

%% ============================================================================
%% HTTP/2 frame generators (for gap injection)
%% ============================================================================
generate_http2_settings_frame() ->
    Payload = crypto:strong_rand_bytes(36),
    Frame = <<0:?u24, 4:8, 0:8, 0:1, 0:31, Payload/binary>>,
    as_tls_frame(?TLS_REC_DATA, Frame).

generate_http2_window_update() ->
    Frame = <<0:?u24, 8:8, 0:8, 0:1, 0:31, (rand:uniform(65535)):?u32>>,
    as_tls_frame(?TLS_REC_DATA, Frame).

generate_http2_priority_frame() ->
    StreamId = rand:uniform(2147483647),
    Frame = <<0:?u24, 2:8, 0:8, 0:1, StreamId:31, (rand:uniform(256)):?u32>>,
    as_tls_frame(?TLS_REC_DATA, Frame).

generate_http2_ping_frame() ->
    PingData = crypto:strong_rand_bytes(8),
    Frame = <<0:?u24, 6:8, 0:8, 0:1, 0:31, PingData/binary>>,
    as_tls_frame(?TLS_REC_DATA, Frame).

generate_gap_records() ->
    GapCount = case rand:uniform(10) of
        N when N =< 5 -> 0;
        N when N =< 8 -> 1;
        _ -> 2
    end,
    generate_gap_records(GapCount, []).

generate_gap_records(0, Acc) -> Acc;
generate_gap_records(N, Acc) ->
    Gap = case rand:uniform(4) of
        1 -> generate_http2_settings_frame();
        2 -> generate_http2_window_update();
        3 -> generate_http2_priority_frame();
        4 -> generate_http2_ping_frame()
    end,
    generate_gap_records(N - 1, [Gap | Acc]).

%% ============================================================================
%% Record size algorithms
%% ============================================================================
pareto_record_size(PreferredSizes) ->
    Random = rand:uniform(),
    select_size_by_probability(PreferredSizes, Random, 0, 1460).

select_size_by_probability([{Size, Prob} | _], Target, Acc, _) when Acc + Prob >= Target ->
    Jitter = rand:uniform(min(128, Size div 4)) - (min(128, Size div 4) div 2),
    max(64, Size + Jitter);
select_size_by_probability([_ | Rest], Target, Acc, Default) ->
    select_size_by_probability(Rest, Target, Acc + element(2, hd(Rest)), Default);
select_size_by_probability([], _, _, Default) -> Default.

random_walk_size(LastSize, Min, Max) when LastSize == 0 ->
    Min + rand:uniform(Max - Min);
random_walk_size(LastSize, Min, Max) ->
    Step = rand:uniform(512) - 256,
    max(Min, min(Max, LastSize + Step)).

cyclic_size(Count, Sizes) ->
    lists:nth((Count rem length(Sizes)) + 1, Sizes).

%% ============================================================================
%% Domain validation
%% ============================================================================
is_domain_allowed(_Domain, []) -> true;
is_domain_allowed(Domain, AllowedDomains) ->
    lists:any(fun(Allowed) -> match_domain(Domain, Allowed) end, AllowedDomains).

match_domain(Domain, <<"*.", Base/binary>>) ->
    Suffix = <<".", Base/binary>>,
    SuffixLen = byte_size(Suffix),
    DomLen = byte_size(Domain),
    DomLen >= SuffixLen andalso binary:part(Domain, {DomLen, -SuffixLen}) =:= Suffix;
match_domain(Domain, Allowed) -> Domain =:= Allowed.

%% ============================================================================
%% ClientHello parsing
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
       cipher_suites = parse_suites(CipherSuites),
       compression_methods = parse_compression(CompMethods),
       extensions = parse_extensions(Extensions)};
parse_client_hello(_Data) ->
    error({protocol_error, tls_bad_client_hello, bad_client_hello}).

parse_suites(Bin) ->
    [Suite || <<Suite:?u16>> <= Bin].

parse_compression(Bin) -> [Bin].

parse_extensions(Exts) ->
    [{Type, parse_extension(Type, Data)}
     || <<Type:?u16, Length:?u16, Data:Length/binary>> <= Exts].

parse_extension(?EXT_SNI, <<ListLen:?u16, List:ListLen/binary>>) ->
    [{Type, Value} || <<Type, Len:?u16, Value:Len/binary>> <= List];
parse_extension(?EXT_KEY_SHARE, <<Len:?u16, Exts:Len/binary>>) ->
    [{Group, Key} || <<Group:?u16, KeyLen:?u16, Key:KeyLen/binary>> <= Exts];
parse_extension(?EXT_SESSION_TICKET, _Data) -> {session_ticket, supported};
parse_extension(?EXT_STATUS_REQUEST, <<Type, _Rest/binary>>) -> {ocsp_stapling, Type};
parse_extension(_Type, Data) -> Data.

%% ============================================================================
%% ServerHello generation
%% ============================================================================
make_server_digest(<<Left:?DIGEST_POS/binary, _:?DIGEST_LEN/binary, Right/binary>>, Secret) ->
    Msg = [Left, binary:copy(<<0>>, ?DIGEST_LEN), Right],
    hmac(sha256, Secret, Msg).

make_key_share(Exts) ->
    case lists:keyfind(?EXT_KEY_SHARE, 1, Exts) of
        {_, KeyShares} ->
            SupportedKeyShares =
                lists:dropwhile(
                  fun({Group, Key}) ->
                          not (byte_size(Key) < 128 andalso
                               lists:member(Group, [
                                   16#0017, 16#0018, 16#0019, 16#001d, 16#001e,
                                   16#0100, 16#0101, 16#0102, 16#0103, 16#0104,
                                   16#11ec, 16#11ed, 16#11ee
                               ]))
                  end, KeyShares),
            case SupportedKeyShares of
                [] -> error({protocol_error, tls_unsupported_key_shares, KeyShares});
                [{KSGroup, KSKey} | _] ->
                    {KSGroup, crypto:strong_rand_bytes(byte_size(KSKey))}
            end;
        _ -> error({protocol_error, tls_missing_key_share_ext, Exts})
    end.

make_srv_hello(Digest, SessionId, {KeyShareGroup, KeyShareKey},
               HasSessionTicket, HasOcspStapling) ->
    KeyShareEntity = <<KeyShareGroup:?u16, 
                       (byte_size(KeyShareKey)):?u16, KeyShareKey/binary>>,
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
                 (iolist_size(ExtensionsFinal)):?u16>> | ExtensionsFinal],
    [<<?TLS_TAG_SRV_HELLO, (iolist_size(Payload)):?u24>> | Payload].

%% ============================================================================
%% Main handshake processing
%% ============================================================================
from_client_hello(Data, Secret, AllowedDomains) ->
    #client_hello{pseudorandom = ClientDigest,
                  session_id = SessionId,
                  extensions = Extensions} = parse_client_hello(Data),
    
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
                false ->
                    ?LOG_WARNING("TLS domain not allowed: ~s", [SniDomain]),
                    error({protocol_error, tls_domain_not_allowed, SniDomain});
                true -> ok
            end
    end,
    
    HasSessionTicket = lists:keymember(?EXT_SESSION_TICKET, 1, Extensions),
    HasOcspStapling = lists:keymember(?EXT_STATUS_REQUEST, 1, Extensions),
    
    ServerDigest = make_server_digest(Data, Secret),
    <<Zeroes:(?DIGEST_LEN - 4)/binary, Timestamp:32/unsigned-little>> = 
        crypto:exor(ClientDigest, ServerDigest),
    lists:all(fun(B) -> B == 0 end, binary_to_list(Zeroes)) orelse
        error({protocol_error, tls_invalid_digest}),
    
    KeyShare = make_key_share(Extensions),
    SrvHello0 = make_srv_hello(binary:copy(<<0>>, ?DIGEST_LEN), SessionId, KeyShare,
                               HasSessionTicket, HasOcspStapling),
    FakeHttpData = crypto:strong_rand_bytes(rand:uniform(256)),
    
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
    Response = [as_tls_frame(?TLS_REC_HANDSHAKE, SrvHello), CC, DD, ST],
    
    Meta = #{
        session_id => SessionId,
        timestamp => Timestamp,
        client_digest => ClientDigest,
        sni_domain => SniDomain,
        session_ticket => SessionTicket,
        ocsp_response => OcspResponse,
        profile_used => undefined
    },
    
    St = #st{
        session_ticket = SessionTicket,
        ocsp_response = OcspResponse,
        session_ticket_lifetime = case HasSessionTicket of true -> 604800; false -> undefined end,
        connection_start = erlang:system_time(millisecond),
        packet_count = 0,
        bytes_sent = 0,
        current_profile = random_tls_profile()
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
%% ClientHello generation
%% ============================================================================
make_client_hello(Secret, SniDomain) ->
    make_client_hello(erlang:system_time(second),
                      crypto:strong_rand_bytes(32),
                      Secret, SniDomain).

make_client_hello(Timestamp, SessionId, HexSecret, SniDomain) when byte_size(HexSecret) == 32 ->
    make_client_hello(Timestamp, SessionId, mtp_handler:unhex(HexSecret), SniDomain);
make_client_hello(Timestamp, SessionId, Secret, SniDomain) when byte_size(SessionId) == 32,
                                                                byte_size(Secret) == 16 ->
    Profile = random_tls_profile(),
    
    CipherSuites = build_cipher_suites(Profile),
    SNI = make_sni([SniDomain]),
    ECH = build_ech_ext(Profile),
    SigAlgos = build_sig_algos(Profile),
    SupportedGroups = build_supported_groups(Profile),
    SupportedVersionsExt = build_supported_versions_ext(Profile),
    VersionsLen = byte_size(SupportedVersionsExt),
    SupportedVersions = <<16#00, 16#2b, (VersionsLen + 1):?u16, VersionsLen,
                          SupportedVersionsExt/binary>>,
    KeyShareEntries = build_key_share_entries(Profile),
    KSListLen = byte_size(KeyShareEntries),
    KeyShare = <<16#00, 16#33, (KSListLen + 2):?u16, KSListLen:?u16, KeyShareEntries/binary>>,
    ALPN = build_alpn(Profile),
    CompCertExt = build_compress_certificate(Profile),
    EcPointExt = build_ec_point_formats(Profile),
    SessionTicketExt = build_session_ticket_ext(Profile),
    OcspStaplingExt = build_ocsp_stapling_ext(Profile),
    PaddingExt = build_padding(Profile),
    PSKModes = <<16#00, 16#2d, 16#00, 16#02, 16#01, 16#01>>,
    
    ExtensionsBase = [
        ECH, SessionTicketExt, EcPointExt,
        <<16#44, 16#cd, 16#00, 16#05, 16#00, 16#03, 16#02, $h, $2>>,
        KeyShare, 
        <<16#00, 16#12, 0:16>>,
        SupportedGroups, CompCertExt,
        <<16#ff, 16#01, 16#00, 16#01, 16#00>>,
        SigAlgos, OcspStaplingExt, PSKModes, ALPN,
        SNI, SupportedVersions, PaddingExt
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
    
    FakeRandom0 = binary:copy(<<0>>, ?DIGEST_LEN),
    Hello0 = Pack(FakeRandom0),
    Digest = hmac(sha256, Secret, Hello0),
    EncTimestamp = <<(binary:copy(<<0>>, ?DIGEST_LEN - 4))/binary,
                     Timestamp:32/unsigned-little>>,
    FakeRandom = crypto:exor(Digest, EncTimestamp),
    Pack(FakeRandom).

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
parse_server_hello(B) when byte_size(B) < 5 -> incomplete;
parse_server_hello(<<16#16, _/binary>> = B) ->
    case tls_records_complete(B, 4) of
        true -> {error, tls_domain_forwarding};
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
%% Data codec with DPI evasion
%% ============================================================================
new() ->
    #st{
        connection_start = erlang:system_time(millisecond),
        current_profile = random_tls_profile(),
        record_size_pattern = pareto_distributed
    }.

try_decode_packet(<<?TLS_12_DATA, Size:?u16, Data:Size/binary, Tail/binary>>, St) ->
    {ok, Data, Tail, St};
try_decode_packet(<<?TLS_REC_CHANGE_CIPHER, ?TLS_12_VERSION, Size:?u16,
                    _Data:Size/binary, Tail/binary>>, St) ->
    try_decode_packet(Tail, St);
try_decode_packet(<<?TLS_REC_HEARTBEAT, ?TLS_12_VERSION, Size:?u16,
                    _Data:Size/binary, Tail/binary>>, St) ->
    try_decode_packet(Tail, St);
try_decode_packet(Bin, St) when byte_size(Bin) =< (?MAX_IN_PACKET_SIZE + 5) ->
    {incomplete, St};
try_decode_packet(Bin, _St) ->
    error({protocol_error, tls_max_size, byte_size(Bin)}).

decode_all(Bin, St) ->
    decode_all(Bin, <<>>, St).

decode_all(Bin, Acc, St0) ->
    case try_decode_packet(Bin, St0) of
        {incomplete, St} -> {Acc, Bin, St};
        {ok, Data, Tail, St} -> decode_all(Tail, <<Acc/binary, Data/binary>>, St)
    end.

encode_packet(Bin, #st{record_size_pattern = Pattern,
                        current_profile = Profile,
                        packet_count = Count} = St) ->
    MaxSize = maps:get(preferred_record_sizes, Profile, [{1460, 1.0}]),
    
    RecordSize = case Pattern of
        pareto_distributed -> pareto_record_size(MaxSize);
        random_walk -> random_walk_size(St#st.last_record_size, 64, 4096);
        cyclic -> cyclic_size(Count, [256, 512, 1024, 1460])
    end,
    
    Frames = encode_with_coalescing(Bin, RecordSize),
    NewSt = St#st{
        packet_count = Count + 1,
        bytes_sent = St#st.bytes_sent + byte_size(Bin),
        last_record_size = RecordSize
    },
    {Frames, NewSt}.

encode_with_coalescing(Bin, RecordSize) when byte_size(Bin) > RecordSize * 2 ->
    {First, Rest} = erlang:split_binary(Bin, RecordSize),
    FirstFrame = as_tls_data_frame(First),
    GapRecords = case rand:uniform(10) =< 5 of
        true -> generate_gap_records();
        false -> []
    end,
    RestFrames = encode_with_coalescing(Rest, RecordSize),
    [FirstFrame, GapRecords, RestFrames];
encode_with_coalescing(Bin, _RecordSize) ->
    as_tls_data_frame(Bin).

as_tls_data_frame(Bin) ->
    as_tls_frame(?TLS_REC_DATA, Bin).

as_tls_frame(Type, Data) ->
    Size = iolist_size(Data),
    [<<Type, ?TLS_12_VERSION, Size:?u16>> | Data].

-if(?OTP_RELEASE >= 23).
hmac(Algo, Key, Str) -> crypto:mac(hmac, Algo, Key, Str).
-else.
hmac(Algo, Key, Str) -> crypto:hmac(Algo, Key, Str).
-endif.
