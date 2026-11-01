#!/usr/bin/env escript
%% xval_sweep's Erlang/OTP asn1 leg: one codec stage per run.
%%
%%   erl_harness.escript decode|encode Dir Type In Out
%%
%% decode reads records framed with a 4-byte big-endian length each and
%% writes the decoded values as one external-term list; encode does the
%% reverse. Values pass between runs as terms because a BER-compiled and a
%% PER-compiled module of one ASN.1 module share a name and can't be
%% loaded into one VM. A record that fails becomes {xval_error, Reason} in
%% decode and an empty record in encode, so later records keep their
%% position; each failure is reported on stderr.
-mode(compile).

main([Mode, Dir, TypeS, In, Out]) ->
    true = code:add_patha(Dir),
    Type = list_to_atom(TypeS),
    Mod = find_module(Dir, Type),
    {ok, Bin} = file:read_file(In),
    Result = case Mode of
                 "decode" -> term_to_binary([decode(Mod, Type, R) || R <- unframe(Bin)]);
                 "encode" -> encode(Mod, Type, binary_to_term(Bin))
             end,
    ok = file:write_file(Out, Result);
main(_) ->
    io:format(standard_error, "usage: erl_harness.escript decode|encode Dir Type In Out~n", []),
    halt(2).

%% The generated module that defines Type: asn1ct exports enc_<Type>
%% from it (arity differs per codec).
find_module(Dir, Type) ->
    Enc = list_to_atom("enc_" ++ atom_to_list(Type)),
    Mods = [list_to_atom(filename:basename(F, ".beam"))
            || F <- filelib:wildcard(filename:join(Dir, "*.beam"))],
    case [M || M <- Mods, lists:keymember(Enc, 1, load(M):module_info(exports))] of
        [M | _] -> M;
        [] -> io:format(standard_error, "type ~s not found in ~s~n", [Type, Dir]), halt(1)
    end.

load(M) -> {module, M} = code:ensure_loaded(M), M.

%% Runs F, turning an exception into {error, Reason} like a codec error.
safe(F) ->
    try F() catch Class:Reason -> {error, {Class, Reason}} end.

unframe(<<Len:32, Rec:Len/binary, Rest/binary>>) -> [Rec | unframe(Rest)];
unframe(_) -> [].

decode(Mod, Type, Rec) ->
    case safe(fun() -> Mod:decode(Type, Rec) end) of
        {ok, Val} -> Val;
        {ok, Val, _Rest} -> Val;
        Err -> report(decode, Err), {xval_error, Err}
    end.

encode(Mod, Type, Vals) ->
    << <<(byte_size(R)):32, R/binary>> || R <- [encode_one(Mod, Type, V) || V <- Vals] >>.

encode_one(_Mod, _Type, {xval_error, _}) -> <<>>;
encode_one(Mod, Type, V) ->
    case safe(fun() -> Mod:encode(Type, V) end) of
        {ok, B} -> iolist_to_binary(B);
        Err -> report(encode, Err), <<>>
    end.

report(Stage, E) -> io:format(standard_error, "~s: ~0P~n", [Stage, E, 30]).
