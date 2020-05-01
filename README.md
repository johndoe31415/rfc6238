# rfc6238
[![Build Status](https://travis-ci.org/johndoe31415/rfc6238.svg?branch=master)](https://travis-ci.org/johndoe31415/rfc6238)

This is an implementation of RFC6238-compliant TOTP tokens using Python.

## Dependencies
python3-cryptography.

## Getting steamguard.json using adb

You need to have root access on your Android phone, then do:

```
$ adb shell
  > $ su
  > # cat /data/data/com.valvesoftware.android.steam.community/files/*
```

And paste the content into steamguard.json.

## License
GNU GPL-3.
