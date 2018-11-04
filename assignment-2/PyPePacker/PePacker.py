#!python3
import sys
import pefile

class PePacker(object):
    """docstring for PePacker"""
    def __init__(self, inputFileName, outputFileName):
        self.inputFileName = inputFileName
        self.outputFileName = outputFileName
        self.shellcode = [0xB8, 0xAA, 0xAA, 0xAA, 0xAA,     # mov eax, 0xAAAAAAAA #此处0xAAAAAAAA是首个需要解码的那个字节，eax用于指向需要解码的字节
                    0x89, 0xC1,                             # mov ecx, eax 
                    0x81, 0xC1, 0xAA, 0xAA, 0xAA, 0xAA,     # add ecx, 0xAAAAAAAA #此处0xAAAAAAAA是text_section的长度, ecx用于指向最后一个需要解码的字节
                    0xBA, 0xAA, 0xAA, 0xAA, 0xAA,           # mov edx, 0xAAAAAAAA #此处0xAAAAAAAA是key的内容, edx用于存储解码需要的key
                                                            # l1:
                    0x30, 0x10,                             # xor byte[eax], edx
                    0x40,                                   # inc eax
                    0x39, 0xC8,                             # cmp eax, ecx
                    0x75, 0xF9,                             # jne l1
                    0x68, 0xAA, 0xAA, 0xAA, 0xAA,           # push 0xAAAAAAAA #此处0xAAAAAAAA是真正的entrypoint
                    0xC3]
        #when debug, key is always 255
        self.key = 0xFF

        self.pe = pefile.PE(inputFileName)
        self.text_section = None
        self.last_section = None

    def GetSectionByCharacteristics(self, Characteristics):
        for section in self.pe.sections:
            if section.Characteristics & Characteristics:
                return section
        return None

    def GetLastSection(self):
        return self.pe.sections[-1]

    def EncryptBytes(self, start_address, size):
        for i in range(size):
            tmp = self.pe.get_memory_mapped_image()[start_address+i] ^ self.key
            self.pe.set_bytes_at_offset(start_address + i, 
                tmp.to_bytes(1, byteorder='little'))
            #print(self.pe.get_memory_mapped_image()[i])
        pass
    
    def PatchAtSection(self, section):
        IMAGE_SCN_CNT_CODE = 0x00000020 #The section contains executable code
        IMAGE_SCN_MEM_WRITE = 0x80000000 #The section can be written to
        IMAGE_SCN_MEM_READ = 0x40000000 #The section can be read
        section.Characteristics |= (
            IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ)

        new_eip = (section.VirtualAddress + 
            section.Misc_VirtualSize)
        old_eip = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint + self.pe.OPTIONAL_HEADER.ImageBase
        old_misc_virtualSize = section.Misc_VirtualSize
        old_raw_size = section.SizeOfRawData

        self.pe.OPTIONAL_HEADER.AddressOfEntryPoint = new_eip
        section.Misc_VirtualSize += len(self.shellcode);
        
        size = self.text_section.SizeOfRawData
        start = self.pe.OPTIONAL_HEADER.ImageBase + self.text_section.VirtualAddress

        self.pe.write(self.outputFileName)
        shellcode = ([0xB8] + list(start.to_bytes(4, byteorder='little')) + 
            [0x89, 0xC1] + 
            [0x81, 0xC1] + list(size.to_bytes(4, byteorder='little')) + 
            [0xBA] + list(self.key.to_bytes(4, byteorder='little')) + 
            [0x30, 0x10] + 
            [0x40] + 
            [0x39, 0xC8] + 
            [0x75, 0xF9] + 
            [0x68] + list(old_eip.to_bytes(4, byteorder='little')) + 
            [0xC3])

        with open(self.outputFileName, 'rb') as f1:
            tmp = f1.read()

        shellcode_data = bytes()
        for i in shellcode:
            shellcode_data += (i.to_bytes(1, byteorder='little'))

        print(shellcode_data)
        if (old_raw_size - old_misc_virtualSize - len(shellcode) >=0):
            merged = tmp[:section.PointerToRawData + old_misc_virtualSize] + shellcode_data + \
                     (0).to_bytes(old_raw_size - old_misc_virtualSize - len(shellcode_data), byteorder='little') + \
                     tmp[section.PointerToRawData + old_raw_size:]
            pass
        else:
            print("full of bullshit!")
            exit(-1)
        with open(self.outputFileName, 'wb') as f:
            f.write(merged)

        pass

    def PatchBytesByVal(self, dest_address, size_of_code, src_address):
        #set the addr is shellcode to what it should be
        #0xAAAAAAAA is used in shellcode, sizeof 0xAAAAAAAA is 4
        val_to_look_for = (0xAAAAAAAA).to_bytes(4,byteorder='little')
        for i in range(size_of_code):
            if (self.pe.get_memory_mapped_image()[
                dest_address+i:dest_address+i+4] == val_to_look_for):
                self.pe.set_bytes_at_offset(dest_address+i, 
                    self.pe.get_memory_mapped_image()[src_address:src_address+4])
                pass
            pass

    def AlignDown(self, val, align):
        return (val & ~(align -1))

    def AlignUp(self, val, align):
        return (self.AlignDown(val, align) + align) if (val & (align - 1)) else val

    def Crypt(self):
        IMAGE_SCN_CNT_CODE = 0x00000020 #The section contains executable code
        IMAGE_SCN_MEM_WRITE = 0x80000000 #The section can be written to
        IMAGE_SCN_MEM_READ = 0x40000000 #The section can be read
        self.text_section = self.GetSectionByCharacteristics(0x00000020)
        self.text_section.Characteristics |= 0x80000000
        self.EncryptBytes(self.text_section.PointerToRawData, 
            self.text_section.SizeOfRawData)

        self.PatchAtSection(self.pe.sections[-1])


def main(inputFileName, outputFileName):
    #inputFileName = "./vs2010/HelloWorld.exe"
    #outputFileName = "./vs2010/f1.exe"
    '''
    shellcode = [0xB8, 0xAA, 0xAA, 0xAA, 0xAA,      # mov eax, 0xAAAAAAAA #此处0xAAAAAAAA是首个需要解码的那个字节，eax用于指向需要解码的字节
                0x89, 0xC1,                             # mov ecx, eax 
                0x81, 0xC1, 0xAA, 0xAA, 0xAA, 0xAA,     # add ecx, 0xAAAAAAAA #此处0xAAAAAAAA是text_section的长度, ecx用于指向最后一个需要解码的字节
                0xBA, 0xAA, 0xAA, 0xAA, 0xAA,           # mov edx, 0xAAAAAAAA #此处0xAAAAAAAA是key的内容, edx用于存储解码需要的key
                                                        # l1:
                0x30, 0x10,                             # xor byte[eax], edx
                0x40,                                   # inc eax
                0x39, 0xC8,                             # cmp eax, ecx
                0x75, 0xF9,                             # jne l1
                0x68, 0xAA, 0xAA, 0xAA, 0xAA,           # push 0xAAAAAAAA #此处0xAAAAAAAA是真正的entrypoint
                0xC3]                                   # ret
    '''
    pp = PePacker(inputFileName, outputFileName)
    pp.Crypt()
    pass

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: py PePacker.py input.exe output.exe")
        sys.exit(-1)
        pass
    main(sys.argv[1], sys.argv[2])