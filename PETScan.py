import pefile
import argparse
from prettytable import PrettyTable

parser = argparse.ArgumentParser(description="Analyzes target PE file and reports various file attributes.")
parser.add_argument("filename", help="File to analyze")
parser.add_argument("-v", "--verbose", help="Increase command line output verbosity.", action="store_true")
parser.add_argument("-o", "--output", "-r", "--report", help="Output file to write results to, default is report.txt",
                    nargs="?", dest="outfile", action="store", default="report.txt", const="report.txt")
parser.add_argument("-d", "--deep", help="Conduct a much deeper analysis, loading all directories etc. "
                                         "**May be time consuming for large files**.", action="store_true")
args = parser.parse_args()

if args.verbose:
    print("Running in Verbose mode...target is " + args.filename)

sample = pefile.PE(args.filename, fast_load=True)
if args.verbose:
    print(args.filename + " opened successfully, beginning analysis...")

if args.deep:  # deep analysis, covers all directories not just NT
    if args.verbose:
        print("Parsing all Data Directories...this may take a while.")
    sample.parse_data_directories()
    if args.verbose:
        print("Done.")

else:  # Just grab the import and export directories to save time
    if args.verbose:
        print("Parsing Directories...")
    sample.parse_data_directories(directories=[
        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])

    if args.verbose:
        print("Done.")

sections = []  # List to hold section info

if args.verbose:
    print("Parsing Section info...")

for section in sample.sections:
    sections.append((section.name, section.VirtualAddress, section.SizeOfRawData))

if args.verbose:
    print("Done.")
    print("Walking Imports table...")

imports = []  # List to hold our imports

for module in sample.DIRECTORY_ENTRY_IMPORT:
    for function in module.imports:
        imports.append((module.dll, function.name))

if args.verbose:
    print("Done.")
    print("Walking Exports table...")

exports = []  # List to hold our exports

sz = 0
for dataDir in sample.OPTIONAL_HEADER.DATA_DIRECTORY:
    if dataDir.name == 'IMAGE_DIRECTORY_ENTRY_EXPORT':
        sz = dataDir.Size

if sz > 0:
    for export in sample.DIRECTORY_ENTRY_EXPORT.symbols:
        exports.append((export.ordinal, export.name, hex(sample.OPTIONAL_HEADER.ImageBase + export.address)))

if args.verbose:
    print("Done.")
    print("Checking for suspicious file attributes...")

warnings = sample.get_warnings()

if args.verbose:
    print("Done.")
    print("Preparing output...")

# Tables to hold all our stuff
WarningsTable = PrettyTable()
SectionsTable = PrettyTable(["Name", "Address (Virtual)", "Size"])
SectionsTable.align["Address (Virtual)"] = "r"
SectionsTable.align["Size"] = "r"
ImportsTable = PrettyTable(["DLL", "Function"])
ExportsTable = PrettyTable(["Ordinal", "Function", "Address"])
ExportsTable.align["Ordinal"] = "r"
ExportsTable.align["Address"] = "r"
DOSHeaderTable = PrettyTable(["Field", "val"])
FileHeaderTable = PrettyTable(["Field", "val"])
OptionalHeaderTable = PrettyTable(["Field", "val"])

if len(warnings) > 0:  # We have some warnings
    for warning in warnings:
        WarningsTable.add_row(warning)

    print(WarningsTable.get_string(title="Warnings"))

''' Blocking this out for now until we can figure out how to avoid AttributeErrors
var = 'e_magic'
val = sample.DOS_HEADER.e_magic
DOSHeaderTable.add_row([var, val])
var = 'e_cblp'
val = sample.DOS_HEADER.e_cblp
DOSHeaderTable.add_row([var, val])
var = 'e_cp'
val = sample.DOS_HEADER.e_cp
DOSHeaderTable.add_row([var, val])
var = 'e_crlc'
val = sample.DOS_HEADER.e_crlc
DOSHeaderTable.add_row([var, val])
var = 'e_cparhdr'
val = sample.DOS_HEADER.e_cparhdr
DOSHeaderTable.add_row([var, val])
var = 'e_minalloc'
val = sample.DOS_HEADER.e_minalloc
DOSHeaderTable.add_row([var, val])
var = 'e_maxalloc'
val = sample.DOS_HEADER.e_maxalloc
DOSHeaderTable.add_row([var, val])
var = 'e_ss'
val = sample.DOS_HEADER.e_ss
DOSHeaderTable.add_row([var, val])
var = 'e_sp'
val = sample.DOS_HEADER.e_sp
DOSHeaderTable.add_row([var, val])
var = 'e_csum'
val = sample.DOS_HEADER.e_csum
DOSHeaderTable.add_row([var, val])
var = 'e_ip'
val = sample.DOS_HEADER.e_ip
DOSHeaderTable.add_row([var, val])
var = 'e_cs'
val = sample.DOS_HEADER.e_cs
DOSHeaderTable.add_row([var, val])
var = 'e_lfarlc'
val = sample.DOS_HEADER.e_lfarlc
DOSHeaderTable.add_row([var, val])
var = 'e_ovno'
val = sample.DOS_HEADER.e_ovno
DOSHeaderTable.add_row([var, val])
var = 'e_res'
val = sample.DOS_HEADER.e_res
DOSHeaderTable.add_row([var, val])
var = 'e_oemid'
val = sample.DOS_HEADER.e_oemid
DOSHeaderTable.add_row([var, val])
var = 'e_oeminfo'
val = sample.DOS_HEADER.e_oeminfo
DOSHeaderTable.add_row([var, val])
var = 'e_res2'
val = sample.DOS_HEADER.e_res2
DOSHeaderTable.add_row([var, val])
var = 'e_lfanew'
val = sample.DOS_HEADER.e_lfanew
DOSHeaderTable.add_row([var, val])
var = 'Machine'
val = sample.FILE_HEADER.Machine
FileHeaderTable.add_row([var, val])
var = 'NumberOfSections'
val = sample.FILE_HEADER.NumberOfSections
FileHeaderTable.add_row([var, val])
var = 'TimeDateStamp'
val = sample.FILE_HEADER.TimeDateStamp
FileHeaderTable.add_row([var, val])
var = 'PointerToSymbolTable'
val = sample.FILE_HEADER.PointerToSymbolTable
FileHeaderTable.add_row([var, val])
var = 'NumberOfSymbols'
val = sample.FILE_HEADER.NumberOfSymbols
FileHeaderTable.add_row([var, val])
var = 'SizeOfOptionalHeader'
val = sample.FILE_HEADER.SizeOfOptionalHeader
FileHeaderTable.add_row([var, val])
var = 'Characteristics'
val = sample.FILE_HEADER.Characteristics
FileHeaderTable.add_row([var, val])
var = 'Flags'
val = sample.FILE_HEADER.Flags
FileHeaderTable.add_row([var, val])

var = 'Magic'
val = sample.OPTIONAL_HEADER.Magic
OptionalHeaderTable.add_row([var, val])
var = 'MajorLinkerVersion'
val = sample.OPTIONAL_HEADER.MajorLinkerVersion
OptionalHeaderTable.add_row([var, val])
var = 'MinorLinkerVersion'
val = sample.OPTIONAL_HEADER.MinorLinkerVersion
OptionalHeaderTable.add_row([var, val])
var = 'SizeOfCode'
val = sample.OPTIONAL_HEADER.SizeOfCode
OptionalHeaderTable.add_row([var, val])
var = 'SizeOfInitializedData'
val = sample.OPTIONAL_HEADER.SizeOfInitializedData
OptionalHeaderTable.add_row([var, val])
var = 'SizeOfUninitializedData'
val = sample.OPTIONAL_HEADER.SizeOfUninitializedData
OptionalHeaderTable.add_row([var, val])
var = 'AddressOfEntryPoint'
val = sample.OPTIONAL_HEADER.AddressOfEntryPoint
OptionalHeaderTable.add_row([var, val])
var = 'BaseOfCode'
val = sample.OPTIONAL_HEADER.BaseOfCode
OptionalHeaderTable.add_row([var, val])
var = 'BaseOfData'
val = sample.OPTIONAL_HEADER.BaseOfData
OptionalHeaderTable.add_row([var, val])
var = 'ImageBase'
val = sample.OPTIONAL_HEADER.ImageBase
OptionalHeaderTable.add_row([var, val])
var = 'SectionAlignment'
val = sample.OPTIONAL_HEADER.SectionAlignment
OptionalHeaderTable.add_row([var, val])
var = 'FileAlignment'
val = sample.OPTIONAL_HEADER.FileAlignment
OptionalHeaderTable.add_row([var, val])
var = 'MajorOperatingSystemVersion'
val = sample.OPTIONAL_HEADER.MajorOperatingSystemVersion
OptionalHeaderTable.add_row([var, val])
var = 'MinorOperatingSystemVersion'
val = sample.OPTIONAL_HEADER.MinorOperatingSystemVersion
OptionalHeaderTable.add_row([var, val])
var = 'MajorImageVersion'
val = sample.OPTIONAL_HEADER.MajorImageVersion
OptionalHeaderTable.add_row([var, val])
var = 'MinorImageVersion'
val = sample.OPTIONAL_HEADER.MinorImageVersion
OptionalHeaderTable.add_row([var, val])
var = 'MajorCheckSumVersion'
val = sample.OPTIONAL_HEADER.MajorCheckSumVersion
OptionalHeaderTable.add_row([var, val])
var = 'MinorCheckSumVersion'
val = sample.OPTIONAL_HEADER.MinorCheckSumVersion
OptionalHeaderTable.add_row([var, val])
var = 'Reserved1'
val = sample.OPTIONAL_HEADER.Reserved1
OptionalHeaderTable.add_row([var, val])
var = 'SizeOfImage'
val = sample.OPTIONAL_HEADER.SizeOfImage
OptionalHeaderTable.add_row([var, val])
var = 'SizeOfHeaders'
val = sample.OPTIONAL_HEADER.SizeOfHeaders
OptionalHeaderTable.add_row([var, val])
var = 'CheckSum'
val = sample.OPTIONAL_HEADER.CheckSum
OptionalHeaderTable.add_row([var, val])
var = 'Subsystem'
val = sample.OPTIONAL_HEADER.Subsystem
OptionalHeaderTable.add_row([var, val])
var = 'DllCharacteristics'
val = sample.OPTIONAL_HEADER.DllCharacteristics
OptionalHeaderTable.add_row([var, val])
var = 'SizeOfStackReserve'
val = sample.OPTIONAL_HEADER.SizeOfStackReserve
OptionalHeaderTable.add_row([var, val])
var = 'SizeOfStackCommit'
val = sample.OPTIONAL_HEADER.SizeOfStackCommit
OptionalHeaderTable.add_row([var, val])
var = 'SizeOfHeapReserve'
val = sample.OPTIONAL_HEADER.SizeOfHeapReserve
OptionalHeaderTable.add_row([var, val])
var = 'SizeOfHeapCommit'
val = sample.OPTIONAL_HEADER.SizeOfHeapCommit
OptionalHeaderTable.add_row([var, val])
var = 'LoaderFlags'
val = sample.OPTIONAL_HEADER.SizeOfHeapReserve
OptionalHeaderTable.add_row([var, val])
var = 'NumberOfRvaAndSizes'
val = sample.OPTIONAL_HEADER.SizeOfHeapCommit
OptionalHeaderTable.add_row([var, val])

print(DOSHeaderTable.get_string(title="DOS Header"))
print(FileHeaderTable.get_string(title="File Header"))
print(OptionalHeaderTable.get_string(title="Optional Header"))
'''

#  PLACEHOLDER TO GET INFO FROM HEADERS UNTIL WE CAN MAKE PRETTYTABLES WORK #
print(sample.DOS_HEADER)
print(sample.FILE_HEADER)
print(sample.OPTIONAL_HEADER)

if len(sections) > 0:
    for section in sections:
        name, addr, size = section
        SectionsTable.add_row([name, hex(addr), size])
print(SectionsTable.get_string(title="PE File Sections"))

if len(imports) > 0:
    for item in imports:
        dll, func = item
        ImportsTable.add_row([dll.decode('ascii'), func.decode('ascii')])
print(ImportsTable.get_string(title="PE File Imports"))

if len(exports) > 0:
    for export in exports:
        ordinal, name, addr = section
        ExportsTable.add_row([ordinal, name.decode('ascii'), hex(addr)])
print(ExportsTable.get_string(title="PE File Exports"))
