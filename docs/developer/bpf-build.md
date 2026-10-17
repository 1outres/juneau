# eBPFプログラムをビルドする

daemonのeBPFプログラムは`daemon/bpf/*.c`に書き、bpf2goでGoのバインディングとオブジェクトに変換します。生成物はgitにコミットしています。このページでは、生成物を作り直す手順と、生成物がソースと一致しているかを確かめる手順をまとめます。

## 生成物

`daemon/internal/daemon/bpf/gen.go`の`//go:generate`が、7つのプログラムをリトルエンディアンとビッグエンディアンの両方でビルドします。

| ソース | 生成物 |
|---|---|
| `daemon/bpf/<name>.c` | `daemon/internal/daemon/bpf/<ident>_bpfel.{go,o}`, `<ident>_bpfeb.{go,o}` |

daemonのイメージビルドと`make test`は、コミット済みのオブジェクトをそのまま使います。そのため、`.c`や`.h`を変えたら、同じコミットで生成物も更新してください。

## 固定しているツールチェーン

どのマシンで生成しても同じバイト列になるように、生成に使うものはすべてリポジトリの中で固定しています。

| 対象 | 固定している場所 |
|---|---|
| clang 19 (`bpf-clang`)、`bpf-llvm-strip` | `flake.nix`、`flake.lock` |
| libbpf 1.5.0のヘッダ、linux-headers 6.12 | `flake.nix`、`flake.lock` |
| `vmlinux.h` | `flake.nix`の`vmlinux-h`パッケージ |
| bpf2go | `daemon/go.mod`の`tool`ディレクティブ |

`vmlinux.h`は、nixpkgsの`linuxPackages_6_12`カーネルが持つBTFから`bpftool`で作ります。ビルドするマシンのカーネル(`/sys/kernel/btf/vmlinux`)は使いません。ビルドするマシンがaarch64でも、x86_64のカーネルのBTFを使います。`vmlinux.h`はnixのストアに置かれ、`bpf-clang`のインクルードパスから読まれます。リポジトリには置きません。

以前の手順で作った`daemon/bpf/vmlinux.h`が残っていれば削除してください。ソースは`#include <vmlinux.h>`で読み込むので、残っていてもビルドには使われません。

## 生成する

```sh
make daemon-generate-bpf
```

Linuxでは、`nix develop`の中でこのコマンドを実行します。

macOSでは、同じコマンドがDockerの`nixos/nix`コンテナの中で同じflakeを使って生成します。Dockerが動いていれば、nixをmacOSに入れる必要はありません。コンテナの`/nix`とGoのキャッシュはDockerのボリューム(`juneau-bpf-nix-<Nixのバージョン>`と`juneau-bpf-cache`)に残ります。ツールチェーンのダウンロードは初回だけで、2回目からは10秒ほどで終わります。

生成したら、verifierの命令数も確かめてください。

```sh
make daemon-verifier-check
```

## 生成物がソースと一致しているか確かめる

```sh
make daemon-verify-bpf
```

生成し直したあとに`daemon/internal/daemon/bpf`に差分があれば失敗します。CIの`bpf`ジョブも、`nix develop .#bpf -c make daemon-verify-bpf`で同じ確認をしています。`.#bpf`は、生成に必要なものだけを入れたdev shellです。

## 生成物が衝突したとき

生成物の衝突は、どちらかの版を選んで解決しないでください。両方のブランチの`.c`の変更を含むオブジェクトは、どちらの版にもないためです。

`.gitattributes`で生成物に`-merge`を付けているので、両方のブランチが同じ生成物を変えると、gitは必ず衝突として止まります。次の順で解決します。

1. `daemon/bpf/`と`gen.go`の衝突を解決する
2. `make daemon-generate-bpf`で生成し直す
3. `git add daemon/internal/daemon/bpf`で生成物を解決済みにする

`make daemon-verify-bpf`が通れば、生成物はソースと一致しています。

## ツールチェーンを上げる

`flake.lock`を更新するか、`flake.nix`のカーネル(`linuxPackages_6_12`)を変えたら、生成し直して、更新した生成物を同じコミットに含めてください。bpf2goは`daemon/go.mod`の`github.com/cilium/ebpf`と同じバージョンにそろえます。

```sh
cd daemon && go get -tool github.com/cilium/ebpf/cmd/bpf2go@<version>
```

## Tiltで開発する

`tilt up`では、`juneau-bpf-generate`リソースが`daemon/bpf/`の`.c`と`.h`、`gen.go`を監視しています。`.c`を保存すると生成し直され、続けて`juneau-daemon-compile`がdaemonをビルドし直します。

## エディタ

clangdで`vmlinux.h`やlibbpfのヘッダを見つけるには、`bpf-clang`のインクルードパスを含む`compile_commands.json`が必要です。Linuxでは、dev shellの中で次のコマンドを実行すると作れます。

```sh
bear --output daemon/compile_commands.json -- make -C daemon generate-bpf
```
