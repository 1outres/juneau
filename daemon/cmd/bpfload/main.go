// bpfload は daemon の各 TC eBPF プログラム（pod_egress / pod_ingress /
// vxlan_ingress / node_ingress）を実機カーネルへ単独でロードし、
// verifier の判定だけを高速に確認するための開発用ツールです。
//
// 目的:
//   - eBPF コードを書き換えたあと「verifier に通るか」だけを daemon /
//     e2e クラスタを起動せずに確かめたい場合の最短経路。
//   - verifier が拒否した場合は、そのエラー文・処理した命令数・スタック
//     深さなどをそのまま表示するので、状態爆発／スタック超過／infinite
//     loop 検出といった原因切り分けに使えます。
//   - バイナリは ELF 上の生成済み bpf2go オブジェクトをそのまま読むので、
//     `make -C daemon generate-bpf` を実行した直後の .o の状態を検証で
//     きます。
//
// 使い方:
//
//  1. eBPF を再生成: `make -C daemon generate-bpf-linux`
//  2. ビルド:        `cd daemon && go build -o /tmp/bpfload ./cmd/bpfload`
//  3. 実行 (root 権限必要): `sudo /tmp/bpfload`
//
// 出力例（成功時）:
//
//	=== PodEgress ===
//	  program tc_pod_egress: 9899 instructions
//	  OK
//
// 出力例（verifier 失敗時）:
//
//	=== PodEgress ===
//	  verifier error: load program: permission denied: ...
//	    <verifier log lines>
//
// 内部動作:
//   - 各プログラムを `LogDisabled: true` で 1 回だけロード試行します
//     （cilium/ebpf のデフォルトは失敗時にログ付きで再試行する仕様で、
//     再試行時は verifier がより多くの状態を探索するため数値がぶれます。
//     ここでは re-entrant な探索を避けて kernel が一発で出す結果を
//     固定したいので無効化しています）。
//   - `*ebpf.VerifierError` を受け取った場合は内部の `Log` をそのまま
//     行ごとに表示します。それ以外（CO-RE 不整合・関数重複など）は
//     プログラム単位で個別にロードしなおして局在化します。
//   - 各プログラムが必要とする pin 用ディレクトリは
//     `/sys/fs/bpf/bpfload-*` に毎回作成し、終了時に消します。
//     daemon が同時に動いている場合と pin 名が衝突しないようにする
//     ためで、テスト目的に閉じています。
//
// 制約:
//   - bpffs (`/sys/fs/bpf`) がマウント済みであることが前提。
//   - root 権限が必要（BPF_PROG_LOAD と pin に CAP_BPF / CAP_SYS_ADMIN
//     が要る）。
//   - 機能テスト（実際にパケットを流す）は行わない。あくまで verifier
//     のチェックだけです。それ以降の検証は e2e (`make e2e`) で。
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"

	bpf "github.com/1outres/juneau/daemon/internal/daemon/bpf"
)

func tryLoad(name string, fn func() (*ebpf.CollectionSpec, error)) {
	fmt.Printf("=== %s ===\n", name)
	spec, err := fn()
	if err != nil {
		fmt.Printf("  spec load failed: %v\n", err)
		return
	}
	for pname, pspec := range spec.Programs {
		fmt.Printf("  program %s: %d instructions\n", pname, len(pspec.Instructions))
	}
	pinDir, err := os.MkdirTemp("/sys/fs/bpf", "bpfload-*")
	if err != nil {
		fmt.Printf("  mktemp error: %v\n", err)
		return
	}
	defer os.RemoveAll(pinDir)
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Maps:     ebpf.MapOptions{PinPath: pinDir},
		Programs: ebpf.ProgramOptions{LogDisabled: true},
	})
	if err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			fmt.Printf("  verifier error: %s\n", verr.Error())
			for _, line := range verr.Log {
				fmt.Println("    " + line)
			}
		} else {
			fmt.Printf("  load error (type %T): %+v\n", err, err)
			// Try loading each program individually to localize the failure
			for progName, progSpec := range spec.Programs {
				prog, perr := ebpf.NewProgramWithOptions(progSpec, ebpf.ProgramOptions{LogLevel: ebpf.LogLevelInstruction, LogSizeStart: 1 << 24})
				if perr == nil {
					fmt.Printf("    [program %s OK]\n", progName)
					prog.Close()
					continue
				}
				var pverr *ebpf.VerifierError
				if errors.As(perr, &pverr) {
					fmt.Printf("    [program %s] verifier error:\n", progName)
					for _, line := range pverr.Log {
						fmt.Println("      " + line)
					}
				} else {
					fmt.Printf("    [program %s] error (type %T): %+v\n", progName, perr, perr)
				}
			}
		}
		return
	}
	defer coll.Close()
	fmt.Printf("  OK\n")
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		fmt.Printf("rlimit error: %v\n", err)
		os.Exit(1)
	}
	tryLoad("PodEgress", bpf.LoadPodEgress)
	tryLoad("PodIngress", bpf.LoadPodIngress)
	tryLoad("VxlanIngress", bpf.LoadVxlanIngress)
	tryLoad("NodeIngress", bpf.LoadNodeIngress)
}
