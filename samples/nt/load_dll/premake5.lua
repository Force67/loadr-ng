project "DllHost"
    language "C++"
    kind "WindowedApp"
	optimize "Speed"
	flags "NoManifest"
    optimize("Off")
	editandcontinue "Off" -- this breaks our custom section ordering in the launcher, and is kind of annoying otherwise
    flags { "NoIncrementalLink" } 
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