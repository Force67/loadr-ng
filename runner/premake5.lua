project "Host"
    language "C++"
    kind "WindowedApp"
	optimize "Speed"
	flags "NoManifest"
	flags { "NoIncrementalLink" } 
	editandcontinue "Off" -- this breaks our custom section ordering in the launcher, and is kind of annoying otherwise
	buildoptions { "/O2" }
	targetname (FX_NAME)

	linkoptions "/IGNORE:4254 /DYNAMICBASE:NO /STACK:\"2097152\" /SAFESEH:NO /LARGEADDRESSAWARE /LAST:.zdata"

    vpaths
    {
        ["*"] = "premake5.lua"
    }

    includedirs
    {
        ".",
        "../"
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