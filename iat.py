import pefile


def get_iat(pe):
    iat = []
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        for imp in entry.imports:
            iat.append(imp.name)
    return iat


def set_iat(pe, original_iat, new_iat):
    """
    Set original_iat to new_iat
    """
    if len(new_iat) < len(original_iat):
        new_iat += b'\x00' * (len(original_iat) - len(new_iat))
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        for imp in entry.imports:
            if imp.name == original_iat:
                imp.name = new_iat
                return pe


def main():
    pe = pefile.PE("demo.exe")
    iat = get_iat(pe)
    print(iat)
    new_pe = set_iat(pe, b'MessageBoxA', b'GetParent')
    new_iat = get_iat(new_pe)
    print(new_iat)
    new_pe.write("demo_new.exe")


if __name__ == "__main__":
    main()
