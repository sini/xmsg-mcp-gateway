{
  description = "xmsg-mcp-gateway: OAuth-protected MCP gateway for xmsg";

  inputs = {
    nixpkgs.url = "https://channels.nixos.org/nixos-unstable/nixexprs.tar.xz";
    crane.url = "github:ipetkov/crane";
  };

  outputs =
    {
      self,
      nixpkgs,
      crane,
    }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
      packages = forAllSystems (
        pkgs:
        let
          craneLib = crane.mkLib pkgs;
          src = nixpkgs.lib.cleanSourceWith {
            src = ./.;
            filter =
              path: _type:
              let
                relative = nixpkgs.lib.removePrefix ((toString ./.) + "/") (toString path);
              in
              (
                relative == "Cargo.toml"
                || relative == "Cargo.lock"
                || relative == "ci"
                || relative == "ci/xmsg-pin.toml"
                || relative == "src"
                || nixpkgs.lib.hasPrefix "src/" relative
                || relative == "tests"
                || nixpkgs.lib.hasPrefix "tests/" relative
              )
              && !nixpkgs.lib.hasSuffix ".py" relative;
          };
          commonArgs = {
            pname = "xmsg-mcp-gateway";
            version = "0.2.0";
            inherit src;
            strictDeps = true;
            CARGO_PROFILE = "release";
            __darwinAllowLocalNetworking = true;
          };
          cargoArtifacts = craneLib.buildDepsOnly commonArgs;
        in
        {
          inherit cargoArtifacts;

          default = craneLib.buildPackage (
            commonArgs
            // {
              inherit cargoArtifacts;
              # Full Rust/Clippy/trybuild/mutant suites run in .github/workflows/ci.yml on pinned Rust 1.95.0;
              # run library unit tests here on the pure Rust source tree (no phase1 Python).
              cargoTestExtraArgs = "--lib";
              doCheck = true;
              meta = {
                description = "OAuth-protected MCP gateway for xmsg";
                mainProgram = "xmsg-mcp-gateway";
                license = nixpkgs.lib.licenses.mit;
              };
            }
          );

          image = pkgs.dockerTools.buildLayeredImage {
            name = "ghcr.io/sini/xmsg-mcp-gateway";
            tag = "latest";
            contents = [
              pkgs.cacert
              packages.${pkgs.stdenv.hostPlatform.system}.default
            ];
            extraCommands = ''
              mkdir -p -m 1777 tmp
              mkdir -p -m 0755 var/lib/xmsg-mcp-gateway
              mkdir -p -m 0755 etc/xmsg-mcp-gateway
            '';
            config = {
              User = "10001:10001";
              Entrypoint = [ "${packages.${pkgs.stdenv.hostPlatform.system}.default}/bin/xmsg-mcp-gateway" ];
              Cmd = [
                "serve"
                "--config"
                "/etc/xmsg-mcp-gateway/serving.json"
              ];
              WorkingDir = "/var/lib/xmsg-mcp-gateway";
              Env = [
                "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
              ];
            };
          };
        }
      );
    in
    {
      inherit packages;

      checks = forAllSystems (
        pkgs:
        nixpkgs.lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
          image =
            pkgs.runCommand "check-image-oracle"
              {
                nativeBuildInputs = [ pkgs.python3 ];
              }
              ''
                "${packages.${pkgs.stdenv.hostPlatform.system}.default}/bin/xmsg-mcp-gateway" --version
                python3 ${./nix/check_image.py} ${packages.${pkgs.stdenv.hostPlatform.system}.image}
                touch $out
              '';
        }
      );

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = [
            pkgs.cargo
            pkgs.rustc
            pkgs.clippy
            pkgs.rustfmt
            pkgs.rust-analyzer
          ];
        };
      });
    };
}
