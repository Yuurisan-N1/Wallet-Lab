#!/usr/bin/env python3
"""gen_nuget_native.py — emit a native (C++/MSVC) static-lib NuGet package for
UltrafastSecp256k1, in the exact convention libbitcoin already consumes for its
`secp256k1_vc143` dependency.

WHY THIS EXISTS
---------------
libbitcoin-system (evoskuil) builds on Windows/MSVC against NuGet packages it
maintains. Its `builds/msvc/vs2022/libbitcoin-system/packages.config` references:

    <package id="secp256k1_vc143" version="0.6.1" targetFramework="Native" />

and the vcxproj imports

    secp256k1_vc143.0.6.1\\build\\native\\secp256k1_vc143.targets

to pull in the include dir + the right static `.lib` (selected by Platform /
PlatformToolset / Configuration / Linkage-secp256k1). evoskuil's request, to let
@pmienk wire UltrafastSecp256k1 in as a `secp256k1` backend behind `WITH_ULTRAFAST`:

    "visual studio with vc++ dependencies ... would be greatly facilitated by
     vc145 and vc143 native intel and arm NuGet packages."

This generator produces that package for OUR libsecp256k1-ABI static lib (the
shim compiled into `fastsecp256k1`), so the only change libbitcoin needs is the
package id + import path (gated on WITH_ULTRAFAST). The consumer-facing surface
is identical to `secp256k1_vc143`:
  * headers: `<secp256k1.h>` etc. (libsecp256k1 ABI),
  * project property: `Linkage-secp256k1` (static / ltcg / dynamic),
  * link: handled entirely by the package `.targets` (the consumer never names
    the `.lib`), so our versioned lib name is an internal detail.

It deliberately mirrors the *generated* structure of evoskuil's package (see the
reference saved under workingdocs/nuget_ref/). Layout produced:

    <staging>/
      <id>.nuspec
      build/native/<id>.targets
      build/native/package.xml
      build/native/include/secp256k1*.h
      build/native/bin/ultrafast_secp256k1-<plat>-<toolset>-<rt>-<ver>.<linkage>.lib

`.targets` link conditions are derived from the `.lib` files actually present in
build/native/bin — so a package never references a lib it does not ship (no
dangling AdditionalDependencies).

LIB FILENAME CONVENTION (mirrors secp256k1-x64-v143-mt-s-0_6_1_0.static.lib):
    ultrafast_secp256k1-<plat>-<toolset>-<rt>-<ver4>.<linkage>.lib
      plat    : x86 | x64 | arm64
      toolset : v143 | v145
      rt      : mt-s  (Release, /MT static runtime)
              | mt-sgd (Debug,  /MTd static debug runtime)
      ver4    : dotted version with dots -> underscores, 4 components (1_2_3_0)
      linkage : static | ltcg

Usage:
    python3 gen_nuget_native.py \
        --staging out/nuget-native/ultrafast_secp256k1_vc143 \
        --toolset v143 --version 4.1.0
    # then: nuget pack <staging>/ultrafast_secp256k1_vc143.nuspec -OutputDirectory <dst>
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

# plat token (in lib name) -> MSBuild $(Platform) value
PLATFORM_MSBUILD = {"x86": "Win32", "x64": "x64", "arm64": "ARM64"}
# runtime token (in lib name) -> MSBuild $(Configuration) substring test
RUNTIME_CONFIG = {"mt-s": "Release", "mt-sgd": "Debug"}

# NOTE on the two toolset spellings (mirrors the secp256k1_vc143 convention):
#   * package id + .targets filename + --toolset flag use the 'vc'-prefixed form: vc143 / vc145
#   * the .lib filename token AND the MSBuild $(PlatformToolset) value use the
#     plain 'v'-prefixed form: v143 / v145
# So a .lib must be named ...-v143-... (NOT ...-vc143-...) or parse_libs drops it.
LIB_RE = re.compile(
    r"^ultrafast_secp256k1-(?P<plat>x86|x64|arm64)-(?P<toolset>v\d+)-"
    r"(?P<rt>mt-s|mt-sgd)-(?P<ver>[0-9_]+)\.(?P<linkage>static|ltcg)\.lib$"
)


def parse_libs(bin_dir: Path) -> list[dict]:
    """Return one descriptor per recognised .lib file in bin_dir."""
    libs: list[dict] = []
    for p in sorted(bin_dir.glob("*.lib")):
        m = LIB_RE.match(p.name)
        if not m:
            print(f"  warn: skipping unrecognised lib name: {p.name}", file=sys.stderr)
            continue
        d = m.groupdict()
        d["file"] = p.name
        d["msbuild_platform"] = PLATFORM_MSBUILD[d["plat"]]
        d["config"] = RUNTIME_CONFIG[d["rt"]]
        libs.append(d)
    return libs


def nuspec_xml(pkg_id: str, version: str) -> str:
    return f"""﻿<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/01/nuspec.xsd">
  <metadata minClientVersion="2.5">
    <id>{pkg_id}</id>
    <version>{version}</version>
    <title>{pkg_id}</title>
    <authors>UltrafastSecp256k1 Contributors</authors>
    <owners>shrec</owners>
    <requireLicenseAcceptance>false</requireLicenseAcceptance>
    <licenseUrl>https://github.com/shrec/UltrafastSecp256k1/blob/main/LICENSE</licenseUrl>
    <projectUrl>https://github.com/shrec/UltrafastSecp256k1</projectUrl>
    <description>UltrafastSecp256k1 packaged as a libsecp256k1-ABI static library \
for a specific Visual Studio toolset. Drop-in for the secp256k1 NuGet dependency \
(same headers, same Linkage-secp256k1 project property); selected in libbitcoin \
behind WITH_ULTRAFAST. Experimental — use at your own risk.</description>
    <summary>libsecp256k1-ABI static library for MSVC, packaged for a specific \
Visual Studio toolset.</summary>
    <releaseNotes>https://github.com/shrec/UltrafastSecp256k1/blob/main/CHANGELOG.md</releaseNotes>
    <copyright>(c) UltrafastSecp256k1 Contributors — MIT</copyright>
    <tags>native secp256k1 elliptic curve ecdsa schnorr bitcoin C++</tags>
  </metadata>
</package>
"""


def package_xml() -> str:
    """The Linkage UI dropdown. Property name `Linkage-secp256k1` is deliberate:
    it matches the upstream secp256k1 NuGet package so a project's existing
    Linkage-secp256k1 setting works unchanged (true drop-in). The two packages
    are mutually exclusive — exactly one is referenced, chosen by WITH_ULTRAFAST."""
    return """<?xml version="1.0" encoding="utf-8"?>
<ProjectSchemaDefinitions xmlns="clr-namespace:Microsoft.Build.Framework.XamlTypes;assembly=Microsoft.Build.Framework">
  <Rule Name="Linkage-ultrafast-secp256k1-uiextension" PageTemplate="tool" DisplayName="NuGet Dependencies" SwitchPrefix="/" Order="1">
    <Rule.Categories>
      <Category Name="secp256k1" DisplayName="secp256k1 (UltrafastSecp256k1)" />
    </Rule.Categories>
    <Rule.DataSource>
      <DataSource Persistence="ProjectFile" ItemType="" />
    </Rule.DataSource>
    <EnumProperty Name="Linkage-secp256k1" DisplayName="Linkage" Description="How NuGet secp256k1 (UltrafastSecp256k1) will be linked into the output of this project" Category="secp256k1">
      <EnumValue Name="" DisplayName="Not linked" />
      <EnumValue Name="static" DisplayName="Static (LIB)" />
      <EnumValue Name="ltcg" DisplayName="Static using link time compile generation (LTCG)" />
    </EnumProperty>
  </Rule>
</ProjectSchemaDefinitions>
"""


def _link_condition(lib: dict) -> str:
    # Configuration.IndexOf('Release'/'Debug') is a SUBSTRING test, intentionally
    # mirroring the upstream secp256k1_vc143 convention — correct for the standard
    # Debug/Release configs. Do not "fix" it into an exact-equality test.
    return (
        f"'$(Platform)' == '{lib['msbuild_platform']}' And "
        f"'$(PlatformToolset)' == '{lib['toolset']}' And "
        f"'$(Linkage-secp256k1)' == '{lib['linkage']}' And "
        f"$(Configuration.IndexOf('{lib['config']}')) != -1"
    )


def targets_xml(pkg_id: str, libs: list[dict]) -> str:
    head = f"""<?xml version="1.0" encoding="utf-8"?>
<!-- GENERATED by gen_nuget_native.py — do not edit by hand. -->
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">

  <!-- user interface (Linkage-secp256k1 dropdown) -->
  <ItemGroup>
    <PropertyPageSchema Include="$(MSBuildThisFileDirectory)package.xml" />
  </ItemGroup>

  <!-- general: headers + lib search dir -->
  <ItemDefinitionGroup>
    <ClCompile>
      <AdditionalIncludeDirectories>$(MSBuildThisFileDirectory)include\\;%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories>
    </ClCompile>
    <Link>
      <AdditionalLibraryDirectories>$(MSBuildThisFileDirectory)bin\\;%(AdditionalLibraryDirectories)</AdditionalLibraryDirectories>
    </Link>
  </ItemDefinitionGroup>
  <ItemDefinitionGroup Condition="'$(Linkage-secp256k1)' == 'static' Or '$(Linkage-secp256k1)' == 'ltcg'">
    <ClCompile>
      <PreprocessorDefinitions>SECP256K1_STATIC;%(PreprocessorDefinitions)</PreprocessorDefinitions>
    </ClCompile>
  </ItemDefinitionGroup>
"""
    blocks = []
    # emit one block per shipped lib (static + ltcg, all platforms/configs present)
    for lib in libs:
        blocks.append(
            f"""  <ItemDefinitionGroup Condition="{_link_condition(lib)}">
    <Link>
      <AdditionalDependencies>{lib['file']};%(AdditionalDependencies)</AdditionalDependencies>
    </Link>
  </ItemDefinitionGroup>"""
        )
    tail = "\n\n</Project>\n"
    return head + "\n  <!-- per-configuration static/ltcg libraries -->\n" + "\n".join(blocks) + tail


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    toolset_help = ("package-id toolset suffix (vc143/vc145); the MSBuild "
                    "$(PlatformToolset) and lib-name token is the same without the "
                    "'c' (v143/v145), matching the secp256k1_vc143 convention")
    ap.add_argument("--staging", required=True, type=Path, metavar="DIR",
                    help="staging dir with build/native/{bin,include}")
    ap.add_argument("--toolset", required=True, choices=["vc143", "vc145"], help=toolset_help)
    ap.add_argument("--version", required=True, help="package version, e.g. 4.1.0")
    ap.add_argument("--id", default=None, metavar="ID",
                    help="override package id (default ultrafast_secp256k1_<toolset>)")
    args = ap.parse_args()

    pkg_id = args.id or f"ultrafast_secp256k1_{args.toolset}"
    # secp256k1_vc143.nuspec  ->  PlatformToolset 'v143' / lib '...-v143-...'
    msbuild_toolset = args.toolset.replace("vc", "v")
    staging: Path = args.staging
    bin_dir = staging / "build" / "native" / "bin"
    inc_dir = staging / "build" / "native" / "include"

    if not bin_dir.is_dir():
        print(f"ERROR: {bin_dir} not found (build the static libs first)", file=sys.stderr)
        return 1
    if not inc_dir.is_dir() or not any(inc_dir.glob("secp256k1*.h")):
        print(f"ERROR: {inc_dir} missing libsecp256k1 headers", file=sys.stderr)
        return 1

    libs = parse_libs(bin_dir)
    libs = [l for l in libs if l["toolset"] == msbuild_toolset]
    if not libs:
        print(f"ERROR: no '{msbuild_toolset}' .lib files found in {bin_dir}", file=sys.stderr)
        return 1

    (staging / f"{pkg_id}.nuspec").write_text(nuspec_xml(pkg_id, args.version), encoding="utf-8")
    (staging / "build" / "native" / "package.xml").write_text(package_xml(), encoding="utf-8")
    (staging / "build" / "native" / f"{pkg_id}.targets").write_text(
        targets_xml(pkg_id, libs), encoding="utf-8")

    print(f"generated {pkg_id} (v{args.version}, {args.toolset}) with {len(libs)} lib(s):")
    for l in libs:
        print(f"  {l['msbuild_platform']:6} {l['config']:8} {l['linkage']:6} -> {l['file']}")
    print(f"nuspec : {staging / (pkg_id + '.nuspec')}")
    print(f"targets: {staging / 'build' / 'native' / (pkg_id + '.targets')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
