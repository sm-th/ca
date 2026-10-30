{
  description = "Personal S/MIME CA: issue encryption and signing certificates with OpenSSL 3";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs =
    { self, nixpkgs }:
    let
      forAllSystems = nixpkgs.lib.genAttrs [
        "aarch64-darwin"
        "x86_64-darwin"
        "aarch64-linux"
        "x86_64-linux"
      ];
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = pkgs.writeShellApplication {
            name = "smime-ca";
            runtimeInputs = [
              pkgs.openssl
              pkgs.coreutils
              pkgs.nss.tools
            ];
            text = builtins.readFile ./smime-ca.sh;
          };
        }
      );

      apps = forAllSystems (system: {
        default = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/smime-ca";
        };
      });
    };
}
