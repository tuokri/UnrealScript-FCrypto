# Testing FCrypto UnrealScript code with UDK-Lite

FCrypto UnrealScript code is tested with a lightweight build
of UDK. See the [UDK-Lite repository](https://github.com/tuokri/UDK-Lite)
for more details. UDK-Lite is included as a submodule in this repository.

**NOTE:** `UDK.exe` by default has runaway loop detection that limits the number of
loop iterations (per tick) to 1 million. This is not enough for FCrypto tests so the
`UDK_norunaway.exe` executable with runaway loop detection binary patched out,
is used instead.

## Environment variables

Before running the tests, the following environment variables should be
set or modified depending on the environment. Default values are defined
in [defaults.py](defaults.py).

| Variable              | Description                                    |
|-----------------------|------------------------------------------------|
| UDK_TEST_TIMEOUT      | script compilation and test timeout in seconds |
| UDK_LITE_TAG          | UDK-Lite repository Git tag                    |
| UDK_LITE_ROOT         | path to UDK-Lite root                          |
| UDK_LITE_RELEASE_URL  | UDK-Lite binary and package release URL        | 
| FCRYPTO_CLASSES_FILES | FCrypto .uc files, glob expression             | 

## Running the tests

```shell
pip install -r requirements.txt
pip install -r ../DevUtils/requirements.txt # for gmp_server.py
python run_udk_tests.py
```

## TODO

Ignore changes in UDK-Lite done during test runtime. Do this by updating
UDK-Lite .gitignore?

Check UDK-Lite tag/commit dynamically since it's a submodule?
