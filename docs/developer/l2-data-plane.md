# L2Networkの転送を追う

L2NetworkのフレームはIPを一切見ずに転送されます。宛先MACアドレスを学習テーブルで引き、当たれば1つのポートへ、外れれば他の全ポートへ複製します。スイッチと同じ動きです。

このドキュメントはその実装を説明します。利用者向けの手順は[L2Networkで自由なセグメントを作る](../guides/l2-network.md)と[L2Network](../resources/l2network.md)にあります。

## プログラムの配置

L2用に2本のプログラムを新設し、VXLANデバイス側は既存の`vxlan_ingress`に分岐を足しました。

| プログラム | アタッチ先 | ソース |
|---|---|---|
| `l2_egress` | L2 NICのhost側vethのTCX ingress | `daemon/bpf/l2_egress.c` |
| `l2_ingress` | 同じvethのTCX egress | `daemon/bpf/l2_ingress.c` |
| `vxlan_ingress`のL2分岐 | VXLANデバイスのTCX ingress | `daemon/bpf/vxlan_ingress.c` |

転送の中身は`daemon/bpf/l2.h`に置いてあり、`l2_egress`とVXLAN側で共有しています。

`pod_egress`を拡張しなかった理由はverifierの命令数です。`tc_pod_egress`は58.1%を使っていて、`policy-data-plane.md`には「巨大な`tc_pod_egress`にインライン展開された経路の途中からスタックポインタを引数に取るBPF-to-BPF callを出すと状態探索が爆発する」という実測記録があります。BUM複製のループは`bpf_clone_redirect`を呼ぶたびにパケット境界の検証をやり直させるので、まさにこの形です。新しいプログラムなら予算をゼロから使えて、SecurityGroupもNATもconntrackも一切含みません。

VXLANデバイス側だけは別プログラムにしませんでした。同じhookに2本付けると、先に走る方が`TC_ACT_UNSPEC`を返したときだけ後ろが走ります。どちらがフレームを決めるかがアタッチ順に依存することになり、順序を間違えるとL2のフレームが理由も出さずに全部落ちます。`vxlan_ingress`は3,760命令しか使っていなかったので、L2分岐を足しても余裕があります。

アタッチ先を選ぶのは`daemon/internal/daemon/dataplane/link/attacher.go`です。NetworkEndpointの`spec.l2Network`が空でなければL2の2本を、そうでなければ`pod_egress`と`pod_ingress`を貼ります。判定にオブジェクトの取得を挟んでいないので、L2Networkが先に消えても付いているプログラムを正しく外せます。

## 経路

```
[Pod X] ──▶ host側veth(X)                        host側veth(Y) ──▶ [Pod Y]
            TCX ingress: l2_egress               TCX egress: l2_ingress
            src MACを学習                             │
                  │                                   ▲
                  ├── ローカル: bpf_redirect ─────────┤
                  └── 別Node: set_tunnel_key ─────────┘
                      → VXLAN → vxlan_ingressのL2分岐
```

`l2_ingress`はポリシーを評価せず、書き換えもしません。traceに配送を記録するだけです。これが無いと、trace上ではフレームをredirectしたhookで記録が終わり、届いたのかどうかが読めません。

## MAC学習

controllerはL2Networkのfdbを一切書きません。全てデータプレーンが学習します。

```
l2_fdb: HASH_OF_MAPS
  outer key: VNI (u32)
  inner: LRU_HASH
    key:   MAC (6 bytes)
    value: { u32 ifindex; u32 vtep_ip; u64 last_seen_ns }
```

`ifindex`と`vtep_ip`はどちらか一方だけが入ります。ローカルのvethならifindex、別Nodeが持っているMACならそのNodeのunderlayアドレスです。

学習する場所は2つです。

- `l2_egress`はローカルのワークロードが出したフレームの送信元MACを、そのvethのifindexに紐付けます
- `vxlan_ingress`のL2分岐は、`bpf_skb_get_tunnel_key`で得たremote VTEPのアドレスに紐付けます

inner mapをVNIごとに分けているのは、1つのLRUを全L2Networkで共有すると、大量のMACを出したテナントが隣のテナントのエントリを追い出してしまうからです。追い出された側は再学習までフラッドし続けるので、性能の劣化が隣に伝播します。

MACの移動は`BPF_ANY`の上書きでそのまま追従します。移動先のNodeでそのホストが最初のフレームを出した瞬間に、そのNodeは自分のローカルポートとして学習します。他のNodeは次の通信で新しいVTEPを学習します。エージング待ちにならないのは、L2の移動が必ず送信を伴うからです。

同じ場所に居続けるMACについては、`last_seen_ns`の書き換えを1秒に1回までに抑えています(`L2_FDB_REFRESH_NS`)。これが無いと、通信中のポートは全フレームでmapを書くことになります。

MACのspoofingは許容します。L2Networkはユーザが自分で作るセグメントで、その中で誰がどのMACを名乗るかはユーザの責任だという判断です。NICの後ろでbridgeを組んだりnested VMを動かしたりすると、NIC自身のMACではないアドレスが必ず出てくるので、制限を入れると使い道が消えます。

### エージング

エージングは300秒固定です(`L2_FDB_AGING_NS`)。一般的なスイッチの既定値に合わせました。

掃除は`daemon/internal/daemon/dataplane/l2/fdb_gc.go`のtickerが30秒ごとに回します。MACが黙ったことを知らせるKubernetesのイベントは存在しないので、`reconciler/service/affinity_gc.go`と同じ形です。時刻の読み取りには`internal/monotonic.Ns`を使っています。wall clockで比べるとNTPの調整でTTLの比較が静かに壊れます。

LRUなのでテーブルが溢れても正しさは壊れません。掃除が足すのは、Juneauから見えない場所へ移ったMACが、エージング時間を過ぎたら古い場所へ送られなくなるという性質です。

## BUMフラッディング

ブロードキャスト、未知ユニキャスト、マルチキャストの3つとも複製します。宛先MACの第1オクテットの最下位ビットで判定するので、`ff:ff:ff:ff:ff:ff`もIPv4マルチキャストの`01:00:5e:*`もIPv6の`33:33:*`も1つの条件で拾えます。

未知ユニキャストをフラッドしないと学習前の通信が成立しません。マルチキャストはIGMP snoopingなしの全ポートフラッドが素のスイッチの挙動です。副産物としてNDPが通るので、セグメント内のIPv6は追加実装なしで動きます。

複製先はVNIごとに、しかもローカルとリモートを分けて持ちます。

```
l2_bum_local:  HASH_OF_MAPS  outer: VNI, inner: HASH  key: ローカルvethのifindex
l2_bum_remote: HASH_OF_MAPS  outer: VNI, inner: HASH  key: リモートVTEPのIPv4
```

分けるのは必須です。`bpf_skb_set_tunnel_key`したskbをtunnel metadataに対応していないデバイスにredirectするとカーネルがcrashします([cilium#19428](https://github.com/cilium/cilium/issues/19428))。1つのループで混ぜると踏みます。`l2_flood`はローカルを先に、リモートを後に回します。リモートの回で初めてトンネルキーが載るので、載ったフレームがvethへ渡ることはありません。

ループは`bpf_for_each_map_elem`で回します。`#pragma unroll`とbounded loopは反復回数がverifierの複雑度に直乗りします。`bpf_clone_redirect`は`bpf_helper_changes_pkt_data`に登録されていて、呼ぶたびに`data`と`data_end`の境界チェックが無効化されて再検証が入るので、unrollだと爆発します。JuneauはTCXでカーネル6.6以上を要求しているので、5.13から入った`bpf_for_each_map_elem`は問題なく使えます。同じ構成の参考実装がCiliumの`bpf/lib/mcast.h`にあります。

コールバックは0(継続)か1(打ち切り)以外を返すとverifierに拒否されます。`l2_flood_local_cb`と`l2_flood_remote_cb`は、`bpf_clone_redirect`が失敗しても0を返して次のポートへ進みます。1つのポートが受け取れないことは、残りのポートに配らない理由になりません。

複製が終わったら元のフレームは`TC_ACT_SHOT`で捨てます。見るべきポートは全部自分のコピーを受け取っているので、コピー元が残る必要はありません。

### split horizon

VXLAN経由で受けたフレームは、ローカルポートにだけ配ってリモートには再送しません。送信元のNodeが既に配り終えているからです。忘れるとVNI内でフレームが無限に増殖します。

規則はBUMだけのものではありません。宛先MACを学習済みでも、その居場所が別のNodeなら`vxlan_ingress`は転送しません。送信元のNodeはそのNodeに直接届けられるので、中継するとフレームがVXLANを2回通り、しかも受け取った先が送信元MACの居場所をこのNodeだと学習してしまいます。この場合はローカルへのフラッドに落とします。転送先を決められなかったフレームの扱いと同じです。

実装上は`struct l2_port`の`from_overlay`1つで、`l2_flood`と`l2_forward_unicast`の両方が読みます。

### 入ってきたポートへは戻さない

宛先MACの居場所が、そのフレームが入ってきたポートそのものだった場合は捨てます。スイッチが必ずやるフィルタリングで、これを忘れるとNICの後ろでbridgeを組んだワークロードとの間でフレームが往復し続けます。trace上は`L2_HAIRPIN_DROP`として出ます。

## リモートVTEPとローカルポートの集約

`l2_bum_local`と`l2_bum_remote`の中身は、`daemon/internal/daemon/dataplane/reconciler/l2_port.go`がNetworkEndpointから作ります。

自Nodeのエンドポイントはローカルポートになり、`l2_ifindex`にVNIを書いてから`l2_bum_local`に加わります。他Nodeのエンドポイントは`status.nodeIP`が`l2_bum_remote`に加わります。

両方とも参照カウントで管理しています。1つのセグメントの複数のエンドポイントが同じNodeに乗るのは普通のことで、そのNodeは1回だけリストに入り、最後の1つが消えるまで残らなければなりません。ローカル側も同じ仕組みにしてあるので、再起動したワークロードがvethを引き継ぐ間もリストから抜けません。

L2Networkの側は`reconciler/l2_network.go`が見ます。`l2_network_map`にVNIとvpc_idを書き、3つのper-VNIテーブルを作ります。テーブルの作成と破棄には`dataplane/l2/table.go`の`Table`を使います。`policy/rotator.go`と同じ「新しいinnerを作ってouterにアトミックにswapし、古いinnerをClose」という形ですが、swapは1回だけです。policyのinner mapは毎回まるごと書き直すものなので回転させて構いませんが、L2のinner mapはデータプレーンが書いたものと1エンドポイントずつ足したものが入っているので、回転させると全部消えます。

どちらのreconcilerも`Ensure`を呼ぶので、L2NetworkのイベントとNetworkEndpointのイベントのどちらが先に来ても構いません。

## 既存reconcilerの除外

`reconciler/arp.go`と`reconciler/fdb.go`と`reconciler/pod_iface.go`は、`spec.subnet`が空のNetworkEndpointをスキップします。完全学習方式なのでcontrollerが静的エントリを書いてはいけません。`fdb.go`はキー`{vni, mac}`を所有者を確認せずに`Delete`するので、混ぜると学習エントリを踏み潰します。

`ifindex_subnet`もL2では書きません。あのmapの`ipv4`はpolicyがNICを引くためのもので、L2NetworkのNICはアドレスを持たないことがあります。0を書けば別のNICとして読まれるので、L2は`l2_ifindex`という別のmapを持ちます。

## map一覧

| map | 型 | キー | 値 | 書く側 |
|---|---|---|---|---|
| `l2_network_map` | HASH | VNI | vpc_id | `reconciler/l2_network.go` |
| `l2_ifindex` | HASH | ifindex | VNI | `reconciler/l2_port.go` |
| `l2_fdb` | HASH_OF_MAPS | VNI → MAC | ifindex / vtep_ip / last_seen_ns | データプレーン |
| `l2_bum_local` | HASH_OF_MAPS | VNI → ifindex | 1 | `reconciler/l2_port.go` |
| `l2_bum_remote` | HASH_OF_MAPS | VNI → VTEP IPv4 | 1 | `reconciler/l2_port.go` |

`l2_bum_remote`のinner mapは`l2_bum_local`のものと中身が同じですが、別のstructとして定義してあります。1つのmap-def structを2つの`__array(values, ...)`メンバから参照すると、clangがBTF forward declarationを吐いてロード時に`can't get size of BTF key: type is unsized`で落ちます。`fib_inner_map`と`tgw_fib_inner_map`が分かれているのと同じ理由です。

5つとも`dataplane/mapinventory/register.go`に登録してあるので、`kubectl juneau bpf dump`で読めます。

```console
$ kubectl juneau bpf dump l2_fdb --inner-key vni=4242
```

学習できているのかフラッドし続けているのかは、これを見ないと外から分かりません。`bridge fdb show`に相当する基本的な運用手段です。

## trace

L2固有のreasonを追加しました。

| reason | 番号 | 意味 |
|---|---|---|
| `ENTER_L2_EGRESS` | 104 | `l2_egress`に入った |
| `ENTER_L2_INGRESS` | 105 | `l2_ingress`に入った |
| `MISS_L2_PORT` | 212 | `l2_ifindex`にvethが無い |
| `MISS_L2_NETWORK` | 213 | `l2_network_map`にVNIが無い |
| `MISS_L2_FDB` | 214 | 宛先MACを学習していない |
| `L2_LEARNED` | 600 | 送信元MACの居場所を記録した |
| `L2_FLOOD` | 601 | 複製した(aux1が複製数) |
| `L2_SPLIT_HORIZON` | 602 | VXLAN経由のフレームをローカルにだけ複製した |
| `L2_HAIRPIN_DROP` | 603 | 宛先MACが、そのフレームが入ってきたポートに居た |

hookは`TRACE_HOOK_L2_EGRESS`(5)と`TRACE_HOOK_L2_INGRESS`(6)です。

L2 NICを追うには、どのNICの話なのかとアドレスの両方を渡します。

```console
$ kubectl juneau trace --from-pod default/lab-a --interface eth1 --from-ip 192.168.60.1 \
    --to-pod default/lab-b --to-interface eth1 --to-ip 192.168.60.2 --proto icmp
```

`--interface`が無いとPodのeth0が対象になり、そのSubnetのvpc_idでセッションが作られます。L2 hookは所属L2Networkのvpc_idでeventを出すので、`trace_make_key`が一致せず何も表示されません。CIDRを持たないL2NetworkではJuneauがアドレスを知らないので、`--from-ip`と`--to-ip`も必須です。

traceが拾えるのはIPv4のフレームだけです。TraceSessionはIPv4の5-tupleでセッションを定義するので、ARPやIPv6のフレームはtrace idが解決できず、emitは何もしません。EtherTypeごとの分岐にreasonを足すことも考えましたが、一度も発火しない定数が増えるだけなので入れていません。同じ理由で`TRACE_REASON_POLICY_ETHERTYPE_DROP`も現状は発火しない、と`trace.h`に書いてあります。

## verifier予算

`make -C daemon verifier-check`の実測値です。カーネル6.18、x86_64。

```
OK   pod_egress: tc_pod_egress processed 581483 insns (limit 1000000, 58.1% used)
OK   pod_ingress: tc_pod_ingress processed 101533 insns (limit 1000000, 10.2% used)
OK   vxlan_ingress: tc_vxlan_ingress_entry processed 5166 insns (limit 1000000, 0.5% used)
OK   node_ingress: tc_node_ingress processed 70965 insns (limit 1000000, 7.1% used)
OK   l2_egress: tc_l2_egress processed 2277 insns (limit 1000000, 0.2% used)
OK   l2_ingress: tc_l2_ingress processed 511 insns (limit 1000000, 0.1% used)
```

`vxlan_ingress`はL2分岐を入れる前が3,760命令(0.4%)でした。増えたのは1,406命令です。`pod_egress`は581,483命令のまま変わっていません。

`bpf/`の下を触ったらこれを回してください。命令数が上限を超えてもコンパイラは何も言わず、次に分かるのはdaemonがcrashloopに入ったときです。実行にはrootとマウント済みのbpffsが要ります。

## テスト

`daemon/internal/daemon/dataplane/bpftest`が`BPF_PROG_TEST_RUN`でフレームを注入する基盤です。mapに状態を書き、プログラムに1つフレームを渡し、戻り値とmapの両方を読みます。

カーネルがプログラムを本当に実行するので、呼ばれたヘルパーも本当に動きます。`bpf_clone_redirect`は指定したデバイスに実際にコピーを渡すので、テストは自分でデバイスを作ってそこに何個届いたかを数えます。フラッドの検証はこれで成立します。

```go
ports := newL2EgressPorts(t)
frame := bpftest.Frame(t, bpftest.Broadcast, bpftest.MAC(1), bpftest.EtherTypeARP, nil)
watched := ports.watch(t)
bpftest.Run(t, ports.program, frame, ports.pod1)

// pod2とpod3は1つずつ受け取り、入ってきたpod1には戻らない
```

デバイスはテストごとに専用のnetwork namespaceを作ってその中に置きます。`BPF_PROG_TEST_RUN`は呼び出したスレッドのnamespaceを見るので、goroutineはスレッドに固定します。デバイスの送信カウンタは差分で読みます。上がってきたばかりのデバイスは自分でIPv6の探索フレームを出すので、絶対値で数えると誰も送っていないポートが送ったことになります。

`bpf_redirect`だけは例外で、`BPF_PROG_TEST_RUN`は戻り値で止まりフレームを運びません。redirectを選んだことは分かりますが、どこへ向けたかは分かりません。そこが効く箇所では、mapに候補を1つだけ置いて戻り値で判定しています。

VXLAN側は`BPF_PROG_TEST_RUN`では駆動できません。プログラムがフレームからトンネルキーを読むのに、テストが直接渡したフレームは何も持っていないからです。そこでVXLANデバイスを本当に作り、daemonと同じ場所にプログラムを貼り、自分宛にカプセル化したフレームを送ります。出てくるのは本番と同じskbで、しかも本物のアタッチなので`bpf_redirect`も実際にフレームを運びます。split horizonの検証はこちらで行っています。

rootが要るテストは`bpftest.Require`が入口で止めます。`go test -short`とroot以外の実行ではskipします。
