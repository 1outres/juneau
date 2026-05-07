# LoadBalancer の Owner Redirection を理解する

`Service.type=LoadBalancer` で外部から到達可能なVIPを公開するとき、上流ルータは複数のJuneau NodeにECMPでパケットを散らします。L4ハッシュポリシー (5-tuple基準) でECMPするルータは「同じTCPコネクション内のパケット」も別のNodeに送り得るので、素朴にNode単位でSNAT / DNAT / CT installすると、SYNがNode A、ACKがNode Bに着いた瞬間に別々のSNAT portが割り当てられてbackendから見ると別々のコネクションに見え、TCP RSTが起きます。

JuneauはMaglev consistent hashing による **owner redirection** で、この問題を上流ルータの設定に依存せず内部で吸収しています。このドキュメントは、その仕組みの実装メモを開発者向けにまとめたものです。

## 全体図

```
                ┌────────────────────────────┐
                │ 上流ルータ (任意 ECMP hash) │
                └─────┬──────┬──────┬────────┘
                  SYN │ ACK  │ ...  │
                      ▼      ▼      ▼
                 ┌────────┬────────┬────────┐
                 │ Node A │ Node B │ Node C │
                 └───┬────┴───┬────┴───┬────┘
                     │ owner=B│ owner=B│ owner=B
                     │redirect│        │redirect
                     └────┬───┘  ↓     │
                          └──→ Node B ←┘
                               │ ←── owner も B (一貫)
                               ▼
                       SNAT/DNAT/CT install (Node B ローカル)
                               │
                          backend Pod
                               │ reply (dst=NodeB.IP)
                               ▼
                          Node B (受信)
                               │ CT 反転
                               ▼
                          外部クライアント
```

要点:

1. すべてのNodeが**同一のスロットテーブル**を保持する。テーブルは「flowハッシュ → ownerのunderlay IP」のマッピング。
2. 自分がownerでないNodeは、**元のフレームをそのままVXLANカプセル化** してownerに転送する。
3. ownerだけがSNAT / DNAT / CT installを行う。同じflowは必ず同じownerに集約されるので、CT entryも一意に決まる。
4. backend応答はSNAT先のIP (= ownerのunderlay IP) を宛先に持つので、自然にownerに戻り、CT反転で外部クライアントへ届く。

## スロットテーブル: Maglev consistent hashing

スロット数 `M = 4093` (素数) は `daemon/bpf/maps.h::MAX_LB_OWNER_TABLE` で定義し、Go側の `daemon/internal/daemon/dataplane/maglev` でMaglevアルゴリズムを実装しています。

性質:

- **決定論性**: 同じ Node集合 → 同じテーブル。各Nodeが独立に計算しても同じ結果に収束する (cluster-wide coordinationが不要)
- **均等性**: `max(slots/Node) - min(slots/Node) ≤ 1` (M ≥ N の場合)
- **最小再分配**: Node 1個追加 / 削除で `≈ M/N` のスロットしか動かない (Maglev論文 §3.4 の理論値)

スロットテーブル更新は `daemon/internal/daemon/dataplane/reconciler/lb_owner.go` の **LBOwner reconciler** が担当します。シングルトンキー駆動で、NetworkEndpointのKind=Node集合を informer から取得 → Maglev でテーブル再構築 → 直前のテーブルとの差分だけBPF map (`lb_owner_table`) に書き込み。差分書き込みなのでNode churnのコストは `O(差分スロット数)` です。

## データプレーンのフロー

外部から到達可能なVIPは以下の順で識別 / 転送されます (`daemon/bpf/node_ingress.c::handle_l3`):

1. `bgp_address_pools` LPM trie でVIPがJuneauの広報レンジにあるか判定
2. `service_map` で `SVC_FLAG_LOAD_BALANCER` が立っているService entryを引く
3. `lb_resolve_owner(saddr, daddr, sport, dport, proto)` (`daemon/bpf/lb.h`) でMaglevテーブルを引き、ownerのunderlay IPを得る
4. ownerが自分なら `lb_forward` を実行 (Pod backend選択 → SNAT / DNAT / CT install → fdb 経由で配送)
5. ownerが他Nodeなら `forward_underlay_to_peer` (`daemon/bpf/forward.h`) でVXLANカプセル化 + `bpf_redirect` してそのまま転送

`forward_underlay_to_peer` は `tunnel_id = VNI_UNDERLAY (1)` で書き込みます。`VNI_UNDERLAY` は user-facing Subnet には allocator が払い出さない予約値で (`subnet-vni` AllocationPoolの `Min=2`)、`maps.h::VNI_UNDERLAY` で定義しています。

owner Node側の受け入れは `daemon/bpf/vxlan_ingress.c` の `tc_vxlan_ingress` が `tunnel_id == VNI_UNDERLAY` を見て、subnet / fdb のロジックを完全にスキップしてそのまま `lb_forward` を呼びます。元フレームは外部クライアント → VIPの状態で温存されているので、`lb_forward` から見ると「直接main interface に着信した」のと等価です。

## ループ防止

`vxlan_ingress` ではowner再判定を意図的に行いません。reconciler convergence中に2つのNodeのテーブル snapshot が一時的に食い違っても、最悪「自分が思うownerと違うNodeに着いて新規CTがinstallされる」だけで、TCPはSYN再送でrecoverできます。redirect loopは絶対に発生しません。

## CT entry の一貫性

Forward leg:

- `ct_map[(HOST, client, VIP, sport, dport, proto)] = LB_OUT (rewrite to nodeB.IP:alloc_port → backend.IP:backend_port)`
- `ct_map[(HOST, backend.IP, nodeB.IP, backend_port, alloc_port, proto)] = LB_IN (rewrite to VIP:dport → client:sport)`

ownerだけがCTをinstallするので、port-collisionはNodeローカルなprobe loopで解決でき、cluster全体で `alloc_port` の一意性を担保する必要がありません。

Reverse leg:

- backend → `(src=backend.IP, dst=nodeB.IP, sport=backend_port, dport=alloc_port)` で送信
- Node B の `node_ingress` でCT_ACTION_LB_INに マッチ、`(src=VIP, dst=client, sport=dport, dport=sport)` に書き戻し
- kernel FIB lookup で外部に出る

backend Podが Node B 以外にあっても、`pod_egress` 側が `node_underlay` map を引いて「これは peer Nodeのunderlay IPだから VPC fabric ではなく underlay経由」と認識して main interface に redirect するので、回り道なくNode Bに届きます。

## 観測性

ownerまわりの動きはBPF traceで可視化されます:

- `TRACE_REASON_LB_REDIRECT_TO_OWNER (406)` — node_ingress が encap した瞬間
- `TRACE_REASON_LB_OWNER_RECEIVED_VIA_UNDERLAY (407)` — owner が VNI_UNDERLAY で decap して LB処理に入った瞬間

スロットテーブルの実状は `kubectl-juneau` から確認できます:

```console
$ kubectl juneau bpf dump lb_owner_table --all-nodes
```

各Nodeで同じテーブルが見えていれば収束しています。Node churn直後はreconcilerの収束待ちで一瞬だけ食い違うことがありますが、informerイベント1回分で収束します。

## 関連コード

| ファイル | 役割 |
|---|---|
| `daemon/bpf/maps.h` | `lb_owner_table` / `MAX_LB_OWNER_TABLE` / `VNI_UNDERLAY` の定義 |
| `daemon/bpf/lb.h` | `hash_lb_tuple` / `lb_resolve_owner` / `lb_forward` (forward leg) |
| `daemon/bpf/forward.h` | `forward_l2` / `forward_underlay_to_peer` |
| `daemon/bpf/node_ingress.c` | LB matchとowner判定 / encap redirect / LB_IN reverse |
| `daemon/bpf/vxlan_ingress.c` | `VNI_UNDERLAY` decap分岐 |
| `daemon/internal/daemon/dataplane/maglev/` | Maglevアルゴリズム |
| `daemon/internal/daemon/dataplane/reconciler/lb_owner.go` | テーブルの差分更新 |
