{ pkgs, projectName }:

let
  python = pkgs.python313;
  pythonPackages = python.pkgs;

  fs = pythonPackages.buildPythonPackage rec {
    pname = "fs";
    version = "2.4.16";
    pyproject = true;

    src = pythonPackages.fetchPypi {
      inherit pname version;
      hash = "sha256-rpfH1RIT9LcLapWCklMCiQkN46fhWEHhCPvhRPBp0xM=";
    };

    build-system = with pythonPackages; [
      setuptools
    ];

    dependencies = with pythonPackages; [
      appdirs
      pytz
      setuptools
      six
    ];

    postPatch = ''
      grep -rl 'pkg_resources.*declare_namespace' fs \
        | xargs sed -i '/pkg_resources.*declare_namespace/d'
      substituteInPlace fs/opener/registry.py \
        --replace-fail "import pkg_resources" '
      import importlib.metadata


      class _EntryPointCompat:
          @staticmethod
          def iter_entry_points(group, name=None):
              entry_points = importlib.metadata.entry_points()
              if hasattr(entry_points, "select"):
                  selected = entry_points.select(group=group)
              else:
                  selected = entry_points.get(group, [])
              for entry_point in selected:
                  if name is None or entry_point.name == name:
                      yield entry_point


      pkg_resources = _EntryPointCompat()
      '
    '';

    pythonImportsCheck = [
      "fs"
    ];

    doCheck = false;
  };

  anisetteLibsRaw = pkgs.fetchurl {
    url = "https://anisette.dl.mikealmel.ooo/libs?arch=arm64-v8a";
    hash = "sha256-WfahBO898eZjDIXeclBy9agPJt9DyD34VS4NVd0e6WY=";
  };

  anisette = pythonPackages.buildPythonPackage rec {
    pname = "anisette";
    version = "1.2.4";
    pyproject = true;

    src = pythonPackages.fetchPypi {
      pname = "anisette";
      inherit version;
      hash = "sha256-Bhhm8F/b3imQ0uJhdFcmSiDKEmeSF5Qbs4tf7+9JLmI=";
    };

    build-system = with pythonPackages; [
      setuptools
      setuptools-scm
    ];

    dependencies =
      with pythonPackages;
      [
        certifi
        pyelftools
        typing-extensions
        unicorn
        urllib3
      ]
      ++ [
        fs
      ];

    pythonImportsCheck = [
      "anisette"
    ];

    doCheck = false;
  };

  anisetteLibs =
    pkgs.runCommand "anisette-libs.tar"
      {
        nativeBuildInputs = [
          (python.withPackages (_: [
            anisette
          ]))
        ];
      }
      ''
        python -c 'from anisette import Anisette; Anisette.init("${anisetteLibsRaw}").save_libs("${placeholder "out"}")'
      '';

  findmy = pythonPackages.buildPythonPackage rec {
    pname = "findmy";
    version = "0.10.1";
    pyproject = true;

    src = pythonPackages.fetchPypi {
      pname = "findmy";
      inherit version;
      hash = "sha256-/cnqYSLr3HWoxOniP2N4gSEWMqC7v6C4r5ncbR2jNr4=";
    };

    build-system = with pythonPackages; [
      setuptools
      setuptools-scm
    ];

    dependencies = with pythonPackages; [
      aiohttp
      beautifulsoup4
      bleak
      cryptography
      srp
      typing-extensions
      anisette
    ];

    pythonRelaxDeps = [
      "bleak"
    ];

    pythonImportsCheck = [
      "findmy"
    ];

    doCheck = false;
  };

  pypush = pythonPackages.buildPythonPackage rec {
    pname = "pypush";
    version = "2.0.0.dev20260314";
    pyproject = true;

    src = pkgs.fetchFromGitHub {
      owner = "JJTech0130";
      repo = "pypush";
      rev = "71aa2e4442061596f75e6b02dfad613330127b5b";
      hash = "sha256-RqLEMFK8dkr61Tfyo11o7f+RlDOYoyw2bSHNp58IJpA=";
    };

    build-system = with pythonPackages; [
      setuptools
      setuptools-scm
    ];

    dependencies = with pythonPackages; [
      anyio
      cryptography
      exceptiongroup
      h2
      httpx
      importlib-metadata
      typing-extensions
    ];

    SETUPTOOLS_SCM_PRETEND_VERSION = version;

    pythonImportsCheck = [
      "pypush"
    ];

    doCheck = false;
  };

  onitrack = pythonPackages.buildPythonApplication {
    pname = projectName;
    version = "0.1.0";
    pyproject = true;

    src = ../.;

    build-system = with pythonPackages; [
      setuptools
    ];

    dependencies = [
      findmy
      pypush
    ];

    nativeCheckInputs = [
      pythonPackages.pytest
      pkgs.age
    ];

    pythonImportsCheck = [
      "onitrack"
    ];

    checkPhase = ''
      runHook preCheck
      pytest
      runHook postCheck
    '';

    makeWrapperArgs = [
      "--set"
      "ONITRACK_ANISETTE_LIBS_TEMPLATE"
      "${anisetteLibs}"
      "--prefix"
      "PATH"
      ":"
      "${pkgs.lib.makeBinPath [ pkgs.age ]}"
    ];
  };
in
{
  inherit
    anisetteLibs
    findmy
    onitrack
    pypush
    python
    pythonPackages
    ;
}
