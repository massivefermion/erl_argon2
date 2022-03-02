# argon2

nifs for hashing and verifying passwords using argon2

## Build

    $ rebar3 compile

## Usage

```erlang
{ok, Hash} = argon2:hash(<<"password">>).

{ok, Matched} = argon2:verify(<<"password">>, Hash).
```
