# Loadr

*Why waste time injecting our code in another process, when we can just be the process, and load the game/target into our own?*

This project attempts to implement a fully fledged pe executable loader - mainly for .exe files, but also for .dll files. The loader is designed to be as simple as possible, and to be able to load any executable file, without a dependency on the cpp standard library features or CRT.

This is pretty cool for a few reasons:
- You can patch the code of a module you want to load before the entry point is called [Thats my main motivation for making this library]
- You control the memory layout of the module, so you can load it in a way that is compatible with your own process (e.g. no ASLR, no DEP, etc)
- You can load a module into your own process, and then use the module as if it was loaded normally (e.g. GetProcAddress, GetModuleHandleEx, etc)
- You can control which imports of the target are actually loaded and also swap out the imports for your own functions without messing with the IAT (Import Address Table) of the target module later.

> This repository is not intended for any nefarious purposes. So don't ask me for any support for cheating and so on.

Features:

- DRM friendly - works with steam CEG and denuvo protected executables
- Supports insertion into the module list - So that GetModuleHandleEx and other functions work as expected
- Supports loading of .exe and .dll files
- Supports TLS
- Supports relocation