project "DllHost"
    language "C++"
    kind "WindowedApp"
	optimize "Speed"
	flags "NoManifest"
	editandcontinue "Off" -- this breaks our custom section ordering in the launcher, and is kind of annoying otherwise
	buildoptions { "/O2" }

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