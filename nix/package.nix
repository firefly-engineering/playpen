# The playpen binary, built from this tree with nixpkgs' Rust. Its tests are not run here: the
# enforcement suite confines real processes, which a build sandbox cannot host, and CI runs it.
{ lib, rustPlatform }:
let
  cargo = (lib.importTOML ../Cargo.toml).package;
in
rustPlatform.buildRustPackage {
  pname = cargo.name;
  inherit (cargo) version;
  src = lib.fileset.toSource {
    root = ../.;
    # Cargo reads every target the manifest declares, tests and examples included, before
    # building any.
    fileset = lib.fileset.unions [
      ../Cargo.toml
      ../Cargo.lock
      ../src
      ../tests
      ../examples
    ];
  };
  cargoLock = {
    lockFile = ../Cargo.lock;
    outputHashes."nono-0.79.0" = "sha256-WG9pfWAeJnwUmYrbRhvWyDY6enE1s82OEAO4geyW//w=";
  };
  doCheck = false;
  meta = {
    inherit (cargo) description;
    license = lib.licenses.asl20;
    mainProgram = "playpen";
  };
}
