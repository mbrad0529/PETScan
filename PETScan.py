import argparse
import hashlib
import pefile
import re
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

# Tables to hold all our stuff
WarningsTable = PrettyTable()
AlertsTable = PrettyTable()
SectionsTable = PrettyTable(["Name", "Address (Virtual)", "Size", "Entropy"])
SectionsTable.align["Address (Virtual)"] = "r"
SectionsTable.align["Size"] = "r"
ImportsTable = PrettyTable(["DLL", "Function"])
ExportsTable = PrettyTable(["Ordinal", "Function", "Address"])
ExportsTable.align["Ordinal"] = "r"
ExportsTable.align["Address"] = "r"
DOSHeaderTable = PrettyTable(["Field", "val"])
FileHeaderTable = PrettyTable(["Field", "val"])
OptionalHeaderTable = PrettyTable(["Field", "val"])

# updated version from: http://code.google.com/p/peframe/
alert_functions = ['accept', 'AddCredentials', 'bind', 'CertDeleteCertificateFromStore', 'CheckRemoteDebuggerPresent', 'closesocket', 'connect', 'ConnectNamedPipe', 'CopyFile', 'CreateFile', 'CreateProcess', 'CreateToolhelp32Snapshot', 'CreateFileMapping', 'CreateRemoteThread', 'CreateDirectory', 'CreateService', 'CreateThread', 'CryptEncrypt', 'DeleteFile', 'DeviceIoControl', 'DisconnectNamedPipe', 'DNSQuery', 'EnumProcesses', 'ExitThread', 'FindWindow', 'FindResource', 'FindFirstFile', 'FindNextFile', 'FltRegisterFilter', 'FtpGetFile', 'FtpOpenFile', 'GetCommandLine', 'GetThreadContext', 'GetDriveType', 'GetFileSize', 'GetFileAttributes', 'GetHostByAddr', 'GetHostByName', 'GetHostName', 'GetModuleHandle', 'GetProcAddress', 'GetTempFileName', 'GetTempPath', 'GetTickCount', 'GetUpdateRect', 'GetUpdateRgn', 'GetUserNameA', 'GetUrlCacheEntryInfo', 'GetComputerName', 'GetVersionEx', 'GetModuleFileName', 'GetStartupInfo', 'GetWindowThreadProcessId', 'HttpSendRequest', 'HttpQueryInfo', 'IcmpSendEcho', 'IsDebuggerPresent', 'InternetCloseHandle', 'InternetConnect', 'InternetCrackUrl', 'InternetQueryDataAvailable', 'InternetGetConnectedState', 'InternetOpen', 'InternetQueryDataAvailable', 'InternetQueryOption', 'InternetReadFile', 'InternetWriteFile', 'LdrLoadDll', 'LoadLibrary', 'LoadLibraryA', 'LockResource', 'listen', 'MapViewOfFile', 'OutputDebugString', 'OpenFileMapping', 'OpenProcess', 'Process32First', 'Process32Next', 'recv', 'ReadProcessMemory', 'RegCloseKey', 'RegCreateKey', 'RegDeleteKey', 'RegDeleteValue', 'RegEnumKey', 'RegOpenKey', 'send', 'sendto', 'SetKeyboardState', 'SetWindowsHook', 'ShellExecute', 'Sleep', 'socket', 'StartService', 'TerminateProcess', 'UnhandledExceptionFilter', 'URLDownload', 'VirtualAlloc', 'VirtualProtect', 'VirtualAllocEx', 'WinExec', 'WriteProcessMemory', 'WriteFile', 'WSASend', 'WSASocket', 'WSAStartup', 'ZwQueryInformation']

alert_libraries = ['ntoskrnl.exe', 'hal.dll', 'ndis.sys']

# legit entry point sections
good_entry_locations = ['.text', '.code', 'CODE', 'INIT', 'PAGE']

sections = []  # List to hold section info


f = open(args.filename, 'rb')
data = f.read()
print("Filename: " + args.filename)
print("MD5: " + hashlib.md5(data).hexdigest())
print("SHA1: " + hashlib.sha1(data).hexdigest())
print("imphash: " + sample.get_imphash())


if args.verbose:
    print("Parsing Section info...")

for section in sample.sections:
    sections.append((section.name, section.VirtualAddress, section.SizeOfRawData, section.get_entropy()))

    # Alert if the EP section is not in a known good section
    name = ''
    ep = sample.OPTIONAL_HEADER.AddressOfEntryPoint
    pos = 0

    if (ep >= section.VirtualAddress) and (ep < (section.VirtualAddress + section.Misc_VirtualSize)):
        name = section.Name
        break
    else:
        pos += 1

    if name not in good_entry_locations:
        print("Suspicious code entry point detected at position: " + pos)

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

crc_given = sample.OPTIONAL_HEADER.CheckSum
crc_actual = sample.generate_checksum()
if crc_given != crc_actual:
    AlertsTable.add_row("Checksum mismatch, declared: " + crc_given + " vs actual: " + crc_actual)


for lib in sample.DIRECTORY_ENTRY_IMPORT:
    for entry in alert_libraries:
        if re.search(lib.dll.decode(), entry, re.I):
            AlertsTable.add_row("Suspicious DLL loaded: " + entry)
    for imp in lib.imports:
        if imp.name is not None:
            for alert in alert_functions:
                if imp.name.decode().startswith(alert):
                    print("Potentially dangerous function imported: " + alert)
'''
signatures = peutils.SignatureDatabase('sigs.txt')
matches = signatures.match(sample, ep_only=True)
if matches:
    for match in matches:
        print("Binary may be packed, " + match + " signature detected.")
'''

# print(AlertsTable.get_string(title="Alerts"))

if len(warnings) > 0:  # We have some warnings
    for warning in warnings:
        WarningsTable.add_row(warning)

    print(WarningsTable.get_string(title="Warnings"))

#  PLACEHOLDER TO GET INFO FROM HEADERS UNTIL WE CAN MAKE PRETTYTABLES WORK #
print(sample.DOS_HEADER)
print(sample.FILE_HEADER)
print(sample.OPTIONAL_HEADER)

if len(sections) > 0:
    for section in sections:
        name, addr, size, entropy = section
        SectionsTable.add_row([name, hex(addr), size, entropy])
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
