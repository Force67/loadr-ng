project "SampleDll"
    language "C++"
    kind "SharedLib"
	optimize "Speed"

    vpaths
    {
        ["*"] = "premake5.lua"
    }

    includedirs
    {
        ".",
        "../../../",
    }

    links
    {
		"ntloader"
    }

    files
    {
        "premake5.lua",
        "**.h",
        "**.cc",
        "**.rc"
    }