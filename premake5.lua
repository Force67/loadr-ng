-- Copyright (C) 2025 Vincent Hengel.
-- For licensing information see LICENSE at the root of this distribution.
require("premake", ">=5.0-beta3")

architecture("x86_64")

filter("architecture:x86_64")
    targetsuffix("_64")

filter("configurations:Debug")
    defines("TK_DBG")

filter("configurations:Release")
    runtime("Release")
    optimize("Speed")

filter("language:C or C++")
    vectorextensions("SSE4.1")
    staticruntime("on")

filter("language:C++")
    cppdialect("C++20")
    
workspace("Loadr")
    configurations({
      "Debug",
      "Release",
      "Shipping",
    })
    flags {
      "MultiProcessorCompile"
    }
    defines("NOMINMAX")
    include("./ntloader")
    include("./samples")