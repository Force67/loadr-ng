project("SampleSo")
    language("C")
    kind("SharedLib")
    files({
        "*.c",
    })
    buildoptions({ "-fPIC", "-fvisibility=hidden", "-nostdlib" })
    linkoptions({ "-nostdlib" })
