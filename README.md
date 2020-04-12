# Telegram MTProxy Tester
Tested on Python 3.7. See test.py for code examples.

TL schema parsing, (de)serialization and MTProto 1.0 code are from [telepy-old](https://github.com/griganton/telepy_old), and migrated to MTProto 2.0  and newer authorization key procedure (`req_pq_multi`, see [API doc](https://core.telegram.org/mtproto/auth_key)).

`test_mtproxy` (from main.py) returns `((time_ms, public_key_fingerprint[])?, Exception?)` (`Either` structure), in which `public_key_fingerprint` is in hexadecimal string format. `test_direct` (from main.py) is used for testing direct connection to Telegram's server