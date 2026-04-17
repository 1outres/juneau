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
    in {
      devShells = forEachSystem (system:
        let
          pkgs = import nixpkgs { inherit system; };
          controllerGen = pkgs.writeShellScriptBin "controller-gen" ''
            exec go run sigs.k8s.io/controller-tools/cmd/controller-gen@v0.17.2 "$@"
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
          bpf2go = pkgs.writeShellScriptBin "bpf2go" ''
            exec go run github.com/cilium/ebpf/cmd/bpf2go@v0.20.0 "$@"
          '';
          bpfClang = pkgs.writeShellScriptBin "bpf-clang" ''
            exec ${pkgs.llvmPackages.clang-unwrapped}/bin/clang \
              -resource-dir ${pkgs.llvmPackages.clang-unwrapped.lib}/lib/clang/${pkgs.lib.versions.major pkgs.llvmPackages.clang-unwrapped.version} \
              -I ${pkgs.libbpf}/include \
              -I ${pkgs.linuxHeaders}/include \
              "$@"
          '';
          bpfLlvmStrip = pkgs.writeShellScriptBin "bpf-llvm-strip" ''
            exec ${pkgs.llvmPackages.bintools-unwrapped}/bin/llvm-strip "$@"
          '';
          generateVmlinuxHeader = pkgs.writeShellScriptBin "juneau-gen-vmlinux" ''
            set -euo pipefail
            out="''${1:-daemon/bpf/vmlinux.h}"
            mkdir -p "$(dirname "$out")"
            exec bpftool btf dump file /sys/kernel/btf/vmlinux format c > "$out"
          '';
        in {
          default = pkgs.mkShell {
            packages = with pkgs; [
              go_1_24
              gopls
              golangci-lint
              tilt
              kustomize
              kind
              protobuf
              clang
              llvmPackages.bintools
              bpftools
              git
              docker
              controllerGen
              setupEnvtest
              protocGenGo
              protocGenGoGrpc
              bpf2go
              bpfClang
              bpfLlvmStrip
              generateVmlinuxHeader
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
