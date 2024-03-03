# TLS callback to Any

## Introduction
This is a simple project to demonstrate how to use the tls callback to Any in Python.

`iat.py` is a simple script that uses the `pefile` to obfuscate the import address table (IAT) of a PE file.

`main.py` will inject a shellcode into a PE file that will be executed before the original entry point (TLS callback).

## Environment
Only tested on Python 3.11 and Windows 11, with defaultly closed ASLR.

## Related Projects
- [d35ha/CallObfuscator](https://github.com/d35ha/CallObfuscator)
- [BorjaMerino/tlsInjector](https://github.com/BorjaMerino/tlsInjector)