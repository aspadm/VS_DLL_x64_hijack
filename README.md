# VS DLL x64 hijack
Simple script that generates Visual Studio project with x86_64 DLL that used for hijacking existing DLL.
One of the usage of this project is creation game mods/patches that does not replace or modify files on drive because do it on the fly.

## Installing
`python -m pip install -r requirements.txt`

## Usage
`generate_hijack.py path_to_lib.dll VS_project_name`

## Read more
https://silentbreaksecurity.com/adaptive-dll-hijacking/