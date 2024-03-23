-module(argon2).

-export([
    hash/1, hash/2,
    hash_with_secret/2, hash_with_secret/3,
    verify/2,
    verify_with_secret/3
]).

-on_load(init/0).

-define(APPNAME, ?MODULE).
-define(LIBNAME, "argon2").

hash(Password) ->
    hash(Password, argon2id).

hash_with_secret(Password, Secret) ->
    hash_with_secret(Password, argon2id, Secret).

hash(_, _) ->
    not_loaded(?LINE).

hash_with_secret(_, _, _) ->
    not_loaded(?LINE).

verify(_, _) ->
    not_loaded(?LINE).

verify_with_secret(_, _, _) ->
    not_loaded(?LINE).

init() ->
    SoName = get_so_name(),
    erlang:load_nif(SoName, 0).

not_loaded(Line) ->
    exit({not_loaded, [{module, ?MODULE}, {line, Line}]}).

get_so_name() ->
    case code:priv_dir(?APPNAME) of
        {error, bad_name} ->
            case
                filelib:is_dir(
                    filename:join(["..", priv])
                )
            of
                true ->
                    filename:join(["..", priv, ?LIBNAME]);
                _ ->
                    filename:join([priv, ?LIBNAME])
            end;
        Dir ->
            filename:join(Dir, ?LIBNAME)
    end.
