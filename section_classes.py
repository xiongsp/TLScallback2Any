import pefile


class SectionDoublePError(Exception):
    pass


class SectionDoubleP:
    def __init__(self, pe):
        self.pe = pe

    def __adjust_optional_header(self):
        """ Recalculates the SizeOfImage, SizeOfCode, SizeOfInitializedData and
            SizeOfUninitializedData of the optional header.
        """

        # SizeOfImage = ((VirtualAddress + VirtualSize) of the new last section)
        self.pe.OPTIONAL_HEADER.SizeOfImage = (self.pe.sections[-1].VirtualAddress +
                                               self.pe.sections[-1].Misc_VirtualSize)

        self.pe.OPTIONAL_HEADER.SizeOfCode = 0
        self.pe.OPTIONAL_HEADER.SizeOfInitializedData = 0
        self.pe.OPTIONAL_HEADER.SizeOfUninitializedData = 0

        # Recalculating the sizes by iterating over every section and checking if
        # the appropriate characteristics are set.
        for section in self.pe.sections:
            if section.Characteristics & 0x00000020:
                # Section contains code.
                self.pe.OPTIONAL_HEADER.SizeOfCode += section.SizeOfRawData
            if section.Characteristics & 0x00000040:
                # Section contains initialized data.
                self.pe.OPTIONAL_HEADER.SizeOfInitializedData += section.SizeOfRawData
            if section.Characteristics & 0x00000080:
                # Section contains uninitialized data.
                self.pe.OPTIONAL_HEADER.SizeOfUninitializedData += section.SizeOfRawData

    def __add_header_space(self):
        """ To make space for a new section header a buffer filled with nulls is added at the
            end of the headers. The buffer has the size of one file alignment.
            The data between the last section header and the end of the headers is copied to
            the new space (everything moved by the size of one file alignment). If any data
            directory entry points to the moved data the pointer is adjusted.
        """

        FileAlignment = self.pe.OPTIONAL_HEADER.FileAlignment
        SizeOfHeaders = self.pe.OPTIONAL_HEADER.SizeOfHeaders

        data = b'\x00' * FileAlignment

        # Adding the null buffer.
        self.pe.__data__ = (self.pe.__data__[:SizeOfHeaders] + data +
                            self.pe.__data__[SizeOfHeaders:])

        section_table_offset = (self.pe.DOS_HEADER.e_lfanew + 4 +
                                self.pe.FILE_HEADER.sizeof() + self.pe.FILE_HEADER.SizeOfOptionalHeader)

        # Copying the data between the last section header and SizeOfHeaders to the newly allocated
        # space.
        new_section_offset = section_table_offset + self.pe.FILE_HEADER.NumberOfSections * 0x28
        size = SizeOfHeaders - new_section_offset
        data = self.pe.get_data(new_section_offset, size)
        self.pe.set_bytes_at_offset(new_section_offset + FileAlignment, data)

        # Filling the space, from which the data was copied from, with NULLs.
        self.pe.set_bytes_at_offset(new_section_offset, b'\x00' * FileAlignment)

        data_directory_offset = section_table_offset - self.pe.OPTIONAL_HEADER.NumberOfRvaAndSizes * 0x8

        # Checking data directories if anything points to the space between the last section header
        # and the former SizeOfHeaders. If that's the case the pointer is increased by FileAlignment.
        for data_offset in range(data_directory_offset, section_table_offset, 0x8):
            data_rva = self.pe.get_dword_from_offset(data_offset)

            if new_section_offset <= data_rva and data_rva < SizeOfHeaders:
                self.pe.set_dword_at_offset(data_offset, data_rva + FileAlignment)

        SizeOfHeaders_offset = (self.pe.DOS_HEADER.e_lfanew + 4 +
                                self.pe.FILE_HEADER.sizeof() + 0x3C)

        # Adjusting the SizeOfHeaders value.
        self.pe.set_dword_at_offset(SizeOfHeaders_offset, SizeOfHeaders + FileAlignment)

        section_raw_address_offset = section_table_offset + 0x14

        # The raw addresses of the sections are adjusted.
        for section in self.pe.sections:
            if section.PointerToRawData != 0:
                self.pe.set_dword_at_offset(section_raw_address_offset, section.PointerToRawData + FileAlignment)

            section_raw_address_offset += 0x28

        # All changes in this method were made to the raw data (__data__). To make these changes
        # accessbile in self.pe __data__ has to be parsed again. Since a new pefile is parsed during
        # the init method, the easiest way is to replace self.pe with a new pefile based on __data__
        # of the old self.pe.
        self.pe = pefile.PE(data=self.pe.__data__)

    def __is_null_data(self, data):
        """ Checks if the given data contains just null bytes.
        """

        for char in data:
            if char != b'\x00':
                return False
        return True

    def push_back(self, Name, VirtualSize=0x00000000, VirtualAddress=0x00000000,
                  RawSize=0x00000000, RawAddress=0x00000000, RelocAddress=0x00000000,
                  Linenumbers=0x00000000, RelocationsNumber=0x0000, LinenumbersNumber=0x0000,
                  Characteristics=0xE0000060, Data=""):
        """ Adds the section, specified by the functions parameters, at the end of the section
            table.
            If the space to add an additional section header is insufficient, a buffer is inserted
            after SizeOfHeaders. Data between the last section header and the end of SizeOfHeaders
            is copied to +1 FileAlignment. Data directory entries pointing to this data are fixed.

            A call with no parameters creates the same section header as LordPE does. But for the
            binary to be executable without errors a VirtualSize > 0 has to be set.

            If a RawSize > 0 is set or Data is given the data gets aligned to the FileAlignment and
            is attached at the end of the file.
        """

        if self.pe.FILE_HEADER.NumberOfSections == len(self.pe.sections):

            FileAlignment = self.pe.OPTIONAL_HEADER.FileAlignment
            SectionAlignment = self.pe.OPTIONAL_HEADER.SectionAlignment

            if len(Name) > 8:
                raise SectionDoublePError("The name is too long for a section.")

            if (VirtualAddress < (self.pe.sections[-1].Misc_VirtualSize +
                                  self.pe.sections[-1].VirtualAddress)
                    or VirtualAddress % SectionAlignment != 0):

                if (self.pe.sections[-1].Misc_VirtualSize % SectionAlignment) != 0:
                    VirtualAddress = \
                        (self.pe.sections[-1].VirtualAddress + self.pe.sections[-1].Misc_VirtualSize -
                         (self.pe.sections[-1].Misc_VirtualSize % SectionAlignment) + SectionAlignment)
                else:
                    VirtualAddress = \
                        (self.pe.sections[-1].VirtualAddress + self.pe.sections[-1].Misc_VirtualSize)

            if VirtualSize < len(Data):
                VirtualSize = len(Data)

            if (len(Data) % FileAlignment) != 0:
                # Padding the data of the section.
                Data += b'\x00' * (FileAlignment - (len(Data) % FileAlignment))

            if RawSize != len(Data):
                if (RawSize > len(Data)
                        and (RawSize % FileAlignment) == 0):
                    Data += b'\x00' * (RawSize - (len(Data) % RawSize))
                else:
                    RawSize = len(Data)

            section_table_offset = (self.pe.DOS_HEADER.e_lfanew + 4 +
                                    self.pe.FILE_HEADER.sizeof() + self.pe.FILE_HEADER.SizeOfOptionalHeader)

            # If the new section header exceeds the SizeOfHeaders there won't be enough space
            # for an additional section header. Besides that it's checked if the 0x28 bytes
            # (size of one section header) after the last current section header are filled
            # with nulls/ are free to use.
            if (self.pe.OPTIONAL_HEADER.SizeOfHeaders <
                    section_table_offset + (self.pe.FILE_HEADER.NumberOfSections + 1) * 0x28
                    or not self.__is_null_data(self.pe.get_data(section_table_offset +
                                                                (self.pe.FILE_HEADER.NumberOfSections) * 0x28, 0x28))):

                # Checking if more space can be added.
                if self.pe.OPTIONAL_HEADER.SizeOfHeaders < self.pe.sections[0].VirtualAddress:

                    self.__add_header_space()
                else:
                    raise SectionDoublePError("No more space can be added for the section header.")

            # The validity check of RawAddress is done after space for a new section header may
            # have been added because if space had been added the PointerToRawData of the previous
            # section would have changed.
            if (RawAddress != (self.pe.sections[-1].PointerToRawData +
                               self.pe.sections[-1].SizeOfRawData)):
                RawAddress = (self.pe.sections[-1].PointerToRawData + self.pe.sections[-1].SizeOfRawData)

            # Appending the data of the new section to the file.
            if len(Data) > 0:
                self.pe.__data__ = (self.pe.__data__[:RawAddress] + Data + self.pe.__data__[RawAddress:])

            section_offset = section_table_offset + self.pe.FILE_HEADER.NumberOfSections * 0x28

            # Manually writing the data of the section header to the file.
            self.pe.set_bytes_at_offset(section_offset, Name)
            self.pe.set_dword_at_offset(section_offset + 0x08, VirtualSize)
            self.pe.set_dword_at_offset(section_offset + 0x0C, VirtualAddress)
            self.pe.set_dword_at_offset(section_offset + 0x10, RawSize)
            self.pe.set_dword_at_offset(section_offset + 0x14, RawAddress)
            self.pe.set_dword_at_offset(section_offset + 0x18, RelocAddress)
            self.pe.set_dword_at_offset(section_offset + 0x1C, Linenumbers)
            self.pe.set_word_at_offset(section_offset + 0x20, RelocationsNumber)
            self.pe.set_word_at_offset(section_offset + 0x22, LinenumbersNumber)
            self.pe.set_dword_at_offset(section_offset + 0x24, Characteristics)

            self.pe.FILE_HEADER.NumberOfSections += 1

            # Parsing the section table of the file again to add the new section to the sections
            # list of pefile.
            self.pe.parse_sections(section_table_offset)

            self.__adjust_optional_header()
        else:
            raise SectionDoublePError("The NumberOfSections specified in the file header and the " + \
                                      "size of the sections list of pefile don't match.")

        return self.pe
