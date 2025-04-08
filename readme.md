# NTLoader-NG

Why waste time injecting our code in another process, when we can just be the process, and load the game/target into our own?

This project attempts to implement a fully fledged pe executable loader - mainly for .exe files, but also for .dll files. The loader is designed to be as simple as possible, and to be able to load any executable file, without a dependency on any cpp standard library features or CRT.

Features:

- DRM friendly - works with steam CEG and denuvo protected executables