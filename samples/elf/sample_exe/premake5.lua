project("SampleExe")
    language("C")
    kind("ConsoleApp")
    files({
        "*.c",
    })
    buildoptions({ "-fPIC", "-nostdlib", "-fno-stack-protector" })
    linkoptions({ "-nostdlib", "-static-pie" })
