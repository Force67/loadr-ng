project("load_so")
    language("C++")
    kind("ConsoleApp")
    files({
        "*.cc",
    })
    includedirs({
        "../../..",
    })
    links({ "elfloader", "dl" })
