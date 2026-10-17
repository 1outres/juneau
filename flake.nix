{
  description = "Juneau development shell";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
  };

  outputs = { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forEachSystem = f:
        builtins.listToAttrs (map (system: {
          name = system;
          value = f system;
        }) systems);

      # The eBPF objects are committed, so every build host must produce the
      # same bytes. The kernel types and headers they are compiled against
      # therefore always come from x86_64-linux; only the tools that run
      # during the build come from the host system.
      bpfTargetPkgs = import nixpkgs { system = "x86_64-linux"; };
      bpfKernel = bpfTargetPkgs.linuxPackages_6_12.kernel;
    in {
      packages = forEachSystem (system:
        let
          pkgs = import nixpkgs { inherit system; };
          clang = pkgs.llvmPackages.clang-unwrapped;
        in rec {
          vmlinux-h = pkgs.runCommand "vmlinux-h-${bpfKernel.version}" {
            nativeBuildInputs = [ pkgs.bpftools ];
          } ''
            mkdir -p $out/include
            bpftool btf dump file ${bpfKernel.dev}/vmlinux format c > $out/include/vmlinux.h
          '';
          bpf-clang = pkgs.writeShellScriptBin "bpf-clang" ''
            exec ${clang}/bin/clang \
              -resource-dir ${clang.lib}/lib/clang/${pkgs.lib.versions.major clang.version} \
              -I ${vmlinux-h}/include \
              -I ${bpfTargetPkgs.libbpf}/include \
              -I ${bpfTargetPkgs.linuxHeaders}/include \
              "$@"
          '';
          bpf-llvm-strip = pkgs.writeShellScriptBin "bpf-llvm-strip" ''
            exec ${pkgs.llvmPackages.bintools-unwrapped}/bin/llvm-strip "$@"
          '';
        });

      devShells = forEachSystem (system:
        let
          pkgs = import nixpkgs { inherit system; };
          controllerGen = pkgs.writeShellScriptBin "controller-gen" ''
            exec go run sigs.k8s.io/controller-tools/cmd/controller-gen@v0.17.2 "$@"
          '';
          crddoc = pkgs.writeShellScriptBin "crddoc" ''
            exec go run github.com/theunrepentantgeek/crddoc@latest "$@"
          '';
          setupEnvtest = pkgs.writeShellScriptBin "setup-envtest" ''
            exec go run sigs.k8s.io/controller-runtime/tools/setup-envtest@release-0.20 "$@"
          '';
          protocGenGo = pkgs.writeShellScriptBin "protoc-gen-go" ''
            exec go run google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.10 "$@"
          '';
          protocGenGoGrpc = pkgs.writeShellScriptBin "protoc-gen-go-grpc" ''
            exec go run google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.5.1 "$@"
          '';
        in {
          default = pkgs.mkShell {
            packages = with pkgs; [
              go_1_25
              python3
              python3Packages.pip
              python3Packages.mkdocs
              python3Packages.mkdocs-material
              python3Packages.mkdocs-minify-plugin
              gopls
              golangci-lint
              tilt
              kustomize
              kind
              kubebuilder
              protobuf
              clang
              llvmPackages.bintools
              bpftools
              git
              docker
              controllerGen
              crddoc
              setupEnvtest
              protocGenGo
              protocGenGoGrpc
              self.packages.${system}.bpf-clang
              self.packages.${system}.bpf-llvm-strip
            ];

            shellHook = ''
              export GOWORK="$PWD/go.work"
              export PATH="$PWD/bin:$PATH"
              echo "juneau devShell: Go $(go version | awk '{ print $3 }'), tilt $(tilt version | awk 'NR==1 { print $2 }')"
              echo "Use 'make -C daemon generate-bpf' for eBPF bindings."
            '';
          };
        });
    };
}
