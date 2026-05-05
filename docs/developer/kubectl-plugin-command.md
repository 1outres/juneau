# kubectl-juneau に新コマンドを実装する

`kubectl-juneau` は Juneau のトラブルシューティング用 kubectl プラグインで、Kubernetes API サーバから読み取れる宣言的状態だけを使って動きます。本ガイドは、このプラグインに新しいサブコマンドを追加したい開発者向けに、どこに何を書くか、既存の層との繋ぎ方、テストや出力フォーマットの規約をまとめたものです。

## 前提

- `kubectl-juneau` の場所は repo 直下 `kubectl-juneau/`、go.work のメンバ
- 配布形態は単体バイナリ。`kubectl` がプラグインを発見するための命名規則 (`kubectl-<name>`) に依存しているので、バイナリ名は変更しない
- CLI は cobra、kubectl 互換のグローバルフラグは `k8s.io/cli-runtime` の `genericclioptions.ConfigFlags` 経由で配線済み
- ビジネスロジックは Kubernetes 型 (`controller-runtime` の typed client) を直接触らず、`internal/topology/View` インタフェース越しにのみアクセスする

## 何が用意されているか

新コマンドの実装者がゼロから書く必要のないものを先に挙げます。

| 機能 | 提供箇所 |
|---|---|
| プロセス境界 (argv / IOStreams / 終了コード) | `cmd/kubectl-juneau/main.go` |
| cobra root + kubectl 互換のグローバルフラグ | `internal/cmd/root.go` |
| Kubernetes クライアント生成と scheme 登録 | `internal/factory/kube.go` |
| 宣言型 → tree / JSON / YAML レンダラ切替 | `internal/output/` |
| 1 行ツリー組み立て API (`Node.Child`, `WriteTree`) | `internal/output/tree.go` |
| CRD 横断アクセスと per-invocation メモ化 | `internal/topology/view.go`, `kubeview.go` |
| 共通 DTO (`PodContext`, `VpcContext`, `RouteSummary` など) と `summarise*` ヘルパ | `internal/topology/types.go`, `routing.go` |
| 将来の Tier 2 用 Node 内 daemon クライアント席 | `internal/factory/nodeagent/` |

つまり、新コマンドの典型作業は次の 3 つに集約されます。

1. **コマンド本体** を `internal/cmd/<group>/<kind>.go` に書く
2. **必要なら domain 層 (`internal/topology` か `internal/<area>`) を拡張**して、コマンドが扱う DTO とリゾルバを足す
3. **親コマンドに登録**して、テストとドキュメントを足す

## 層の責務をもう一度

```
cmd/kubectl-juneau/main.go      プロセス境界のみ。ロジック禁止
   ↓
internal/cmd/<group>            cobra 配線、フラグ解析、orchestration
   ↓
internal/topology               純粋ロジック (View 越しにしか I/O しない)
internal/<future areas>          policy / reachability / prober など
   ↓
internal/factory                k8s と外界への唯一の seam
internal/output                 表示 (tree / json / yaml)
```

依存方向は厳密に上 → 下。**`internal/topology` 配下から `internal/cmd` を import するのは禁止**。逆方向 (`cmd` から `topology`) のみ許可します。出力層は domain 型を受け取るが、domain 型を生成しません。

## ステップバイステップ: 新サブコマンドを追加する

例として、`kubectl juneau topology list-vpcs` のようなクラスタ内全 Vpc を一覧表示するコマンドを追加するシナリオで進めます。

### Step 1. コマンドの "DTO" を決める

cmd 層が出力するデータ型を最初に固めます。新規 DTO は `internal/topology/types.go` に追加するのが基本です (既存の `VpcContext` などと同じファイル)。

```go
// internal/topology/types.go の末尾に追加
type VpcListContext struct {
    Vpcs []VpcSummary `json:"vpcs,omitempty"`
}

type VpcSummary struct {
    Name                  string `json:"name"`
    VpcID                 uint32 `json:"vpcID,omitempty"`
    EnableService         bool   `json:"enableService,omitempty"`
    EnforceSecurityGroups bool   `json:"enforceSecurityGroups,omitempty"`
    SubnetCount           int    `json:"subnetCount"`
}
```

DTO の設計上守るべきこと:

- **JSON タグを必ず付ける**。`-o json` / `-o yaml` がそのまま動く
- フィールドは presenter にとって扱いやすい形にする。生 CRD struct を持ち回すと presenter が `subnet.Status.VNI` のように深いパスを書くハメになる
- 値が無いケース (CRD が存在しない、ID 未割当) は `nil` ポインタや `0` で表現し、presenter が `(none)` / `-` に変換する

### Step 2. 既存リゾルバで足りなければ View / リゾルバを拡張する

`View` は既に多くの "by name" / "by Vpc" メソッドを持っています。一覧系が必要なら `View` にメソッドを足し、`kubeView` と stub 実装の両方に追従します。

```go
// internal/topology/view.go
type View interface {
    // ...既存
    AllVpcs(ctx context.Context) ([]juneauv1alpha1.Vpc, error)
}

// internal/topology/kubeview.go
func (v *kubeView) AllVpcs(ctx context.Context) ([]juneauv1alpha1.Vpc, error) {
    var list juneauv1alpha1.VpcList
    if err := v.cl.List(ctx, &list); err != nil {
        return nil, err
    }
    return list.Items, nil
}
```

リゾルバ本体は `internal/topology/<topic>_context.go` を新設して書きます。pod / vpc / subnet / service と同じ命名規則です。

```go
// internal/topology/vpc_list_context.go
package topology

import "context"

func ResolveVpcListContext(ctx context.Context, v View) (*VpcListContext, error) {
    vpcs, err := v.AllVpcs(ctx)
    if err != nil {
        return nil, err
    }
    out := &VpcListContext{Vpcs: make([]VpcSummary, 0, len(vpcs))}
    for i := range vpcs {
        subnets, err := v.SubnetsByVpc(ctx, vpcs[i].Name)
        if err != nil {
            return nil, err
        }
        out.Vpcs = append(out.Vpcs, VpcSummary{
            Name:                  vpcs[i].Name,
            VpcID:                 vpcs[i].Status.VpcID,
            EnableService:         vpcs[i].Spec.EnableService,
            EnforceSecurityGroups: vpcs[i].Spec.EnforceSecurityGroups,
            SubnetCount:           len(subnets),
        })
    }
    return out, nil
}
```

リゾルバ実装上の規約:

- 入口は `Resolve<X>Context(ctx, view, ...) (*XContext, error)` で統一
- ネットワーク I/O は **必ず** `View` を経由。`client.Client` を直接受け取るシグネチャを増やさない
- "not found" は error にしない。`View` の契約は `(nil, nil)` を返す。リゾルバ側もそれを引き継ぎ、上位レイヤで "(not found)" 表示にする
- ループ中で `v.X(ctx, k)` を多重呼び出しても、`kubeView` がメモ化するので per-invocation のリクエスト数は最小化される

### Step 3. cmd ファイルを書く

`internal/cmd/<group>/<kind>.go` のテンプレートはこれです。Complete / Validate / Run のトリアドが kubectl 標準の書き方なので外さない。

```go
// internal/cmd/topology/list_vpcs.go
package topologycmd

import (
    "context"
    "fmt"
    "io"

    "github.com/spf13/cobra"

    "github.com/1outres/juneau/kubectl-juneau/internal/factory"
    "github.com/1outres/juneau/kubectl-juneau/internal/output"
    "github.com/1outres/juneau/kubectl-juneau/internal/topology"
)

type listVpcsOptions struct {
    Factory    factory.Factory
    PrintFlags *output.PrintFlags
}

func newListVpcsCommand(f factory.Factory) *cobra.Command {
    o := &listVpcsOptions{Factory: f, PrintFlags: output.NewPrintFlags()}
    cmd := &cobra.Command{
        Use:   "list-vpcs",
        Short: "List every Vpc in the cluster",
        Args:  cobra.NoArgs,
        RunE: func(c *cobra.Command, _ []string) error {
            if err := o.Validate(); err != nil {
                return err
            }
            return o.Run(c.Context())
        },
    }
    o.PrintFlags.AddFlags(cmd)
    return cmd
}

func (o *listVpcsOptions) Validate() error {
    _, err := o.PrintFlags.Format()
    return err
}

func (o *listVpcsOptions) Run(ctx context.Context) error {
    cl, err := o.Factory.Kube()
    if err != nil {
        return err
    }
    view := topology.NewKubeView(cl)

    ctxData, err := topology.ResolveVpcListContext(ctx, view)
    if err != nil {
        return err
    }

    renderer, err := output.ResolveRenderer[*topology.VpcListContext](
        o.PrintFlags,
        output.RendererFunc[*topology.VpcListContext](presentVpcListTree),
    )
    if err != nil {
        return err
    }
    return renderer.Render(o.Factory.Streams().Out, ctxData)
}

func presentVpcListTree(w io.Writer, c *topology.VpcListContext) error {
    root := output.NewNode(fmt.Sprintf("Vpcs  (%d)", len(c.Vpcs)))
    for _, v := range c.Vpcs {
        flags := ""
        if v.EnableService {
            flags += " enableService"
        }
        if v.EnforceSecurityGroups {
            flags += " enforceSecurityGroups"
        }
        root.Childf("%s  (vpcID: %d, subnets: %d%s)", v.Name, v.VpcID, v.SubnetCount, flags)
    }
    return output.WriteTree(w, root)
}
```

書き方の規約:

- `Options` 構造体に `Factory`、`PrintFlags`、解析済みフラグだけを持たせる。中間状態 (cluster からの取得結果) は持たせない
- フラグの **解析** は `Complete(args)`、フラグの **整合性チェック** は `Validate()`、本処理は `Run(ctx)`。3 つを混ぜない
- presenter (`present<Kind>Tree`) は副作用のない純関数にする。引数の DTO だけから出力が決まるようにすると golden test が容易
- `output.RendererFunc` で tree presenter を渡せば、`-o json` / `-o yaml` は自動で動く。各コマンドが JSON 整形を書く必要はない

### Step 4. 親コマンドに登録する

新サブコマンドが既存の `describe` 等の下に入るならその親ファイルに 1 行追加するだけ:

```go
// internal/cmd/describe/describe.go
cmd.AddCommand(newPodCommand(f))
// ...
cmd.AddCommand(newListVpcsCommand(f)) // 例
```

新しいコマンドグループを作るなら親パッケージを `internal/cmd/<group>/<group>.go` で作り、`internal/cmd/root.go` に登録します。例えば `topology` グループとして:

```go
// internal/cmd/topology/topology.go
package topologycmd

import (
    "github.com/spf13/cobra"

    "github.com/1outres/juneau/kubectl-juneau/internal/factory"
)

func NewCommand(f factory.Factory) *cobra.Command {
    cmd := &cobra.Command{
        Use:   "topology",
        Short: "List Juneau resources across the cluster",
        Args:  cobra.NoArgs,
    }
    cmd.AddCommand(newListVpcsCommand(f))
    return cmd
}
```

```go
// internal/cmd/root.go
import topologycmd "github.com/1outres/juneau/kubectl-juneau/internal/cmd/topology"
// ...
root.AddCommand(topologycmd.NewCommand(f))
```

### Step 5. テストを書く

最低 2 種類用意するとレビューが楽です。

- **リゾルバの単体テスト**: `internal/topology/<file>_test.go`。`stubView` (実例: `routing_test.go`) を継承するか自作して、`View` の各メソッドに固定値を返させる。fake k8s client は不要
- **presenter の golden test**: 渡す DTO を構築 → tree presenter を呼ぶ → 期待文字列と比較。`internal/output/tree_test.go` のスタイルが参考になります

```go
func TestResolveVpcListContext(t *testing.T) {
    view := &stubView{
        // 必要なフィールドだけ埋める
    }
    got, err := ResolveVpcListContext(context.Background(), view)
    if err != nil { t.Fatal(err) }
    // ... assertions
}
```

cluster 結合テストは `test/e2e/` に kind ベースで足せます。golden file との比較は VNI / GroupID など controller が動的に振るフィールドが入る場合は **正規表現や per-field マッチング** に切り替えてください。

## 出力フォーマットの規約

`-o tree` (default) / `-o json` / `-o yaml` の 3 つを必ず通すこと。実装は `output.ResolveRenderer` に渡す tree presenter のみで、JSON / YAML は domain 型の JSON タグから自動生成されます。

- tree 出力は **読み手の脳に階層が入る順序** で書く: 上位概念 (Vpc / Subnet) → そこに属する詳細 (RouteTable / SG)
- 値の不在は `(none)`、空文字は `-`、リソースが見つからなかった場合は `(not found)` で統一
- 数値は単位付きで補完しすぎない (presenter で勝手に "ms" / "MB" を付けない)。DTO 側に raw な uint32 を入れて、表示でフォーマット
- **色付け / 強調は当面入れない**。CI ログで grep されることを優先

## 拡張点と禁則

### 禁止事項

- `cmd/` 配下から `controller-runtime`、`client-go`、`k8s.io/api*` を直接 import すること
  → `factory.Factory` または `topology.View` 経由でのみアクセス
- リゾルバ関数で `client.Client` を引数に取ること
  → `View` を取る
- presenter 内で I/O すること
  → `Run` で取得した DTO だけを引数に
- 機能フラグや `--no-color` を個別コマンドで再定義すること
  → 必要なら `internal/output/printflags.go` に追加して全コマンドで共有

### Tier 2 / 3 を見据えた書き方

- BPF map や CT を読みたい新コマンドは、当面 `factory.NodeAgent()` が `nodeagent.ErrNotImplemented` を返すことを前提に **データプレーン依存部を `nodeagent.Client` の interface 越し** に書く
  → 後で gRPC client を実装したときに、コマンド側は無変更で動く
- `--with-bpf` のような既存コマンドへの拡張フラグは、`InterfaceContext` などの DTO に optional フィールドを追加し、リゾルバが NodeAgent 不在時はそのフィールドを nil のままにする方針で
- 横断的に再利用できる純粋ロジック (例: ACL/SG ポリシー評価) は `internal/policy` のように **専用パッケージ** にして、cmd を跨いで使える形にする。`topology/` には CRD グラフ走査だけを残す

## チェックリスト

PR 提出前に確認:

- [ ] DTO 型に JSON タグを付けた
- [ ] `-o tree` / `-o json` / `-o yaml` がいずれも動く
- [ ] エラー時に内部スタックトレースを露出していない (`fmt.Errorf("...: %w", err)` で wrap)
- [ ] presenter は副作用なし、ユニットテストを書いた
- [ ] リゾルバは `View` のみに依存、stubView でユニットテストを書いた
- [ ] `make -C kubectl-juneau test` が pass
- [ ] `make -C kubectl-juneau build` で binary が生成できる
- [ ] README.md にコマンドの 1 行説明と出力例を追加した
- [ ] `kubectl juneau <new>` を kind 上で実走させ、想定通りの tree が出ることを目視で確認した
