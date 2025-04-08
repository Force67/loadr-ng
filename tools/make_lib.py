import os
import subprocess
import argparse
from pathlib import Path


def generate_lib_from_dll(dll_path: str, output_dir: str = None, machine: str = "X64"):
    """
    Generate a .lib file from a DLL's exports using Microsoft's lib.exe

    Args:
        dll_path: Path to the input DLL file
        output_dir: Directory to save the .lib file (default: same as DLL)
        machine: Target architecture ("X64", "X86", "ARM", "ARM64")
    """
    dll_path = Path(dll_path).absolute()
    if not dll_path.exists():
        raise FileNotFoundError(f"DLL not found: {dll_path}")

    # Default output dir is the DLL's directory
    if output_dir is None:
        output_dir = dll_path.parent
    else:
        output_dir = Path(output_dir).absolute()
        output_dir.mkdir(parents=True, exist_ok=True)

    lib_path = output_dir / f"{dll_path.stem}.lib"

    # Find lib.exe from VS installation
    vswhere_path = (
        r"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe"
    )
    if not os.path.exists(vswhere_path):
        raise FileNotFoundError(
            "vswhere.exe not found - Visual Studio may not be installed"
        )

    # Get latest VS installation path
    result = subprocess.run(
        [vswhere_path, "-latest", "-property", "installationPath"],
        capture_output=True,
        text=True,
        check=True,
    )
    vs_path = Path(result.stdout.strip())
    print(f"Visual Studio path: {vs_path}")
    lib_exe = (
        vs_path
        / "VC"
        / "Tools"
        / "MSVC"
        / "14.43.34808"
        / "bin"
        / f"Hostx64"
        / machine
        / "lib.exe"
    )

    if not lib_exe.exists():
        raise FileNotFoundError(f"lib.exe not found at: {lib_exe}")

    # Run lib.exe to generate the .lib file
    cmd = [str(lib_exe), f"/DEF:{dll_path}", f"/OUT:{lib_path}", f"/MACHINE:{machine}"]

    print(f"Generating {lib_path} from {dll_path}...")
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print("Error generating .lib file:")
        print(result.stderr)
        raise RuntimeError("lib.exe failed")

    print(f"Successfully generated: {lib_path}")
    return lib_path


def generate_lib_from_def(def_path: str, output_dir: str = None, machine: str = "X64"):
    """
    Generate a .lib file from a .def file using Microsoft's lib.exe
    """
    def_path = Path(def_path).absolute()
    if not def_path.exists():
        raise FileNotFoundError(f".def file not found: {def_path}")

    if output_dir is None:
        output_dir = def_path.parent
    else:
        output_dir = Path(output_dir).absolute()
        output_dir.mkdir(parents=True, exist_ok=True)

    lib_path = output_dir / f"{def_path.stem}.lib"

    # Find lib.exe (same as above)
    vswhere_path = (
        r"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe"
    )
    result = subprocess.run(
        [vswhere_path, "-latest", "-property", "installationPath"],
        capture_output=True,
        text=True,
        check=True,
    )
    vs_path = Path(result.stdout.strip())
    lib_exe = (
        vs_path / "VC" / "Tools" / "MSVC" / "bin" / f"Hostx64" / machine / "lib.exe"
    )

    if not lib_exe.exists():
        raise FileNotFoundError(f"lib.exe not found at: {lib_exe}")

    # Run lib.exe with the .def file
    cmd = [str(lib_exe), f"/DEF:{def_path}", f"/OUT:{lib_path}", f"/MACHINE:{machine}"]

    print(f"Generating {lib_path} from {def_path}...")
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print("Error generating .lib file:")
        print(result.stderr)
        raise RuntimeError("lib.exe failed")

    print(f"Successfully generated: {lib_path}")
    return lib_path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate .lib file from DLL exports or .def file"
    )
    parser.add_argument("input", help="Path to DLL or .def file")
    parser.add_argument("-o", "--output", help="Output directory for .lib file")
    parser.add_argument(
        "-m",
        "--machine",
        default="X64",
        choices=["X64", "X86", "ARM", "ARM64"],
        help="Target architecture (default: X64)",
    )

    args = parser.parse_args()

    try:
        if args.input.lower().endswith(".def"):
            generate_lib_from_def(args.input, args.output, args.machine)
        elif args.input.lower().endswith(".dll"):
            generate_lib_from_dll(args.input, args.output, args.machine)
        else:
            print("Error: Input file must be .dll or .def")
    except Exception as e:
        print(f"Error: {e}")
        exit(1)
