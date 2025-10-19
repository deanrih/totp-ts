# 2.0.0

- add: otp uri generator utility
- feat: improved hotp moving factor to byte performance slightly
- feat: improved totp moving factor to byte performance (up to 6x faster)
- feat: improved general hash to otp code performance slightly
- chore: add bunch of tests

# 1.2.0

- fix: set the default secret encoding to `base32`

# 1.1.0

- changed: hashing algorithm now defaults to `sha1`
- fix: string secret for being only treated as ascii/utf8

# 1.0.0

- Initial release