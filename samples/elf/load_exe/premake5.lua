project("load_exe")
    language("C++")
    kind("ConsoleApp")
    files({
        "*.cc",
    })
    includedirs({
        "../../..",
    })
    links({ "elfloader" })
