project("ntloader")
    language("C++")
    kind("StaticLib")
    files({
        "*.cc",
        "*.h"
    })
    includedirs({
        ".",
    })