# SPDX-FileCopyrightText: 2026 Stef Halmans, Niklas Höher
# SPDX-License-Identifier: LicenseRef-RUB-SecEng

# Simulation environment for the artifact.
#
#   nix-shell                      # interactive shell
#   nix-shell --run 'make -C rtl/sign/tb sign_kat KAT_COUNT=1'
#
# nixpkgs is pinned to a fixed revision, so every machine gets the same tool
# versions (Verilator 5.044, Python 3.13, cocotb 2.0.1, pycryptodome 3.23).
# Vivado is not part of this environment (see README.md, "Synthesis").
let
  nixpkgs = builtins.fetchTarball {
    url = "https://github.com/NixOS/nixpkgs/archive/a82ccc39b39b621151d6732718e3e250109076fa.tar.gz";
    sha256 = "1664s8ffaa3hcvz4d4hwca2l6xl25j8dvzxwmd2ckcskcncq1zc1";
  };
  pkgs = import nixpkgs { config = { }; overlays = [ ]; };
  python = pkgs.python3.withPackages (ps: [
    ps.cocotb
    ps.pycryptodome
    ps.pytest
  ]);
in
pkgs.mkShell {
  packages = [
    pkgs.verilator
    pkgs.zlib
    pkgs.gnumake
    pkgs.which
    python
  ];

  shellHook = ''
    echo "SDitH-v2 sign artifact: $(verilator --version | cut -d' ' -f1-2), cocotb $(cocotb-config --version)"
  '';
}
