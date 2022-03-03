# argon2

nifs for hashing and verifying passwords using argon2

## Build

    $ rebar3 compile

## Usage

```erlang
{ok, Hash} = argon2:hash(<<"password">>).
{ok, Matched} = argon2:verify(<<"password">>, Hash).


{ok, Hash} = argon2:hash(<<"password">>, argon2d).
{ok, Matched} = argon2:verify(<<"password">>, Hash).


{ok, Hash} = argon2:hash_with_secret(<<"password">>, <<"secret">>).
{ok, Matched} = argon2:verify_with_secret(<<"password">>, Hash, <<"secret">>).


{ok, Hash} = argon2:hash_with_secret(<<"password">>, argon2i, <<"secret">>).
{ok, Matched} = argon2:verify_with_secret(<<"password">>, Hash, <<"secret">>).
```
