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
| `l2_gateway` | gateway vethのTCX egress | `daemon/bpf/l2_gateway.c` |

gateway vethのTCX ingressには`pod_egress`をそのまま貼っています。詳しくは[gateway](#gateway)の節を読んでください。

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
    value: { u32 ifindex; u32 vtep_ip; u64 last_seen_ns; u32 flags }
```

`ifindex`と`vtep_ip`はどちらか一方だけが入ります。ローカルのvethならifindex、別Nodeが持っているMACならそのNodeのunderlayアドレスです。

`flags`が入るエントリは1つだけで、gatewayのMACです。詳しくは[gateway](#gateway)の節にあります。

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

## gateway

`spec.gateway`を書いたL2Networkには、出口が生えます。Juneauはそれを、セグメントに繋がった1つのポートとして実装しました。ポートの実体はhost namespaceに立てたveth pairで、その両端ではなく、**片方のvethの2つのhook**に別々のプログラムを付けています。

| 方向 | 経路 |
|---|---|
| セグメント → Vpc | `l2_egress`が学習テーブルでgateway MACを引く → gw vethへ`bpf_redirect(ifindex, BPF_F_INGRESS)` → gw vethのTCX ingressの`pod_egress`が`handle_l3`以降を処理 |
| Vpc → セグメント | `pod_egress`の`handle_l3`が`FIB_ROUTE_TYPE_L2_GATEWAY`でgw vethへredirect → gw vethのTCX egressの`l2_gateway`が宛先MACを解決してL2転送 |

この形にした理由は、gatewayから先を作らなくて済むからです。gw vethのingressに`pod_egress`が付いている以上、セグメントから出ていく方向はRouteTableもNATGatewayもElasticIPもClusterIP ServiceもSubnetのときと同じコードを通ります。`pod_egress`への変更は`fib_val.type`を1つ足した分岐だけで、命令数は581,483から581,856に増えました。

帰ってくる方向は同じようにはいきませんでした。`pod_ingress`が担っている書き戻しがどこにも無いからです。Serviceの応答は`l2_gateway`が戻し、NATGatewayの応答は`node_ingress`が戻してからgatewayポートへ渡します。詳しくは[Serviceの応答](#service)にあります。

### BPF_F_INGRESSが必須です

`bpf_redirect`のflagsを0にすると、gw vethのTCX *egress*が走った後に`veth_xmit`でpeerへ抜け、host stackに上がってしまいます。`BPF_F_INGRESS`を渡すと`skb_do_redirect` → `__bpf_rx_skb` → `dev_forward_skb_nomtu` → `netif_rx_internal` → backlog → `__netif_receive_skb_core` → `sch_handle_ingress` → `tcx_run`という経路になり、`veth_xmit`を通りません。このフラグを使うのはgatewayへの2箇所だけで、残りの13箇所の`bpf_redirect`はすべて0のままです。

`bpf_redirect_peer`は使えません。`skb_do_redirect`にpeerが別のnetnsにあることを要求する条件があり、gw vethは両端がhost netnsなので黙って落とされます。

ブロードキャストの複製がgw vethのingressに渡ると、`pod_egress`は`handle_arp`でそのフレームを書き換えます。cloneへの直接書き込みが安全なのは、`bpf_clone_redirect`がcloneを作った直後に元のskbのheadを`bpf_try_make_head_writable`で複製し直すからです。元のskbが新しいバッファへ移るので、送り出されたcloneが古いバッファを単独で持ちます。

### anycast

gatewayを宣言したL2Networkでは、**そのセグメントにポートを持つ各Nodeが自分のgw vethを立てます**。アドレスもMACも全Nodeで同じです。ワークロードは自Nodeのgatewayを使うので、L3の通信のためにVXLANを跨ぎません。既存のSubnetが`subnet_map.gw_mac`を全Nodeで共有しているのと同じ考え方です。

ポートを1つも持たないNodeは何も立てません。セグメントごとNodeごとにvethを作ると、クラスタの全Nodeに使われないポートが並びます。

anycastなので、gateway宛のフレームは絶対にoverlayを渡ってはいけません。そのために、learning tableのgateway MACのエントリだけはuser spaceが書きます。

```
l2_fdb[vni][gateway MAC] = { ifindex: 自Nodeのgw veth, flags: L2_FDB_FLAG_GATEWAY }
```

`flags`は3つのことを同時に言っています。このMACを送信元に名乗ったフレームがエントリを奪えないこと、エージングの掃除がこれを消さないこと、そして転送先がポートのegressではなくingressだということです。1つ目が無いと、ワークロードがgateway MACを名乗るだけでセグメントの出口を自分に向けられます。

BUMのフラッド先リストでも、gatewayのエントリは`L2_PORT_FLAG_GATEWAY`を持ちます。ブロードキャストのコピーがingressに渡るのはこのフラグのおかげで、gatewayが自分のアドレスへのARPに答えられるのもこれがあるからです。

overlayから届いたBUMは、gatewayには配りません。送信元のNodeが自分のgatewayに既に配り終えているので、ここでも配ると1つのARPリクエストにNodeの数だけ返事が返ります。

### ARP snooping

Vpcからセグメントの中のホストへパケットを送るとき、gatewayは宛先のMACを知る必要があります。学習方式なのでcontrollerはMACを知りませんし、gatewayは自分からARPを出しません。

そこで`l2_egress`と`vxlan_ingress`のL2分岐が、通過するARPの送信者を記録します。

```
l2_arp: HASH_OF_MAPS
  outer key: VNI
  inner: LRU_HASH   key: IPv4 (host byte order), value: MAC
```

opcodeは見ません。リクエストもリプライもGARPも送信者のペアを持っていて、引っ越したホストは何を送るより先に自分を名乗るからです。`vxlan_ingress`でも記録するのは、別Nodeのホストがブロードキャストで名乗るのがこのNodeにとって唯一の学習の機会だからです。

既存の`arp_table`とは分けました。あちらは131072エントリのplain HASHをノード全体で共有していて、セグメントが大量のアドレスを覚えると`reconciler/arp.go`の`Update`が`E2BIG`で失敗し、正規のSubnetのARP代理応答が壊れます。読む側は`l2_network_map`を引いてどちらのテーブルを使うか決めます。missしたらもう一方も見る、という書き方はしていません。

**セグメントの中のARPは素通しのままです。**代理応答を持ち込むと、GARPによるMAC移動の通知も、ユーザが立てたDHCPサーバも、重複アドレス検出も壊れます。`pod_egress`の`handle_arp`が答えるのはgateway自身のアドレスへのリクエストだけで、それ以外はgw vethに届いたコピーを捨てます。元のリクエストは既に全ポートへ複製されているので、答えるべきホストが自分で答えます。

### gw vethのegressプログラム

`l2_gateway`が扱うフレームは2種類だけです。

IPv4のパケットは経路がここへ送ったもので、まだ受け取ったhopのアドレス宛のままです。`l2_arp`で宛先アドレスをMACに解決し、宛先MACをそれに、送信元MACをgatewayのものに書き換えてから、セグメントの学習テーブルで転送します。解決できないアドレスは落とします。フラッドすると1ホスト宛のパケットが全ポートに乗るからです。

ARPのフレームは`pod_egress`がgatewayのアドレスのために作った返事で、既に正しいMACのペアを持っています。書き換えずにそのまま転送します。

それ以外のEtherTypeは落とします。router portが出すものではありませんし、このhookに来る残りはpeerの向こうのhost stackが出したものです。

宛先MACを解決できても学習テーブルに居場所が無い場合はフラッドします。フレームは既に宛先のMACを持っているので、受け取るのはそのホストだけです。スイッチが未知のユニキャストにする扱いと同じです。

### Serviceの応答

L2NetworkのNICからClusterIP Serviceを叩けます。往路は`pod_egress`がgw vethのingressで`handle_service`まで走るので、Subnetから叩いたときと1行も違いません。

復路だけが違います。ServiceのDNATを戻すのは`pod_ingress`で、叩いた側のvethのegressに付いています。L2NetworkのNICに付いているのは`l2_egress`と`l2_ingress`で、どちらもアドレスを読みません。応答はbackendのアドレスのままワークロードに届き、書いた覚えのない相手からの返事として捨てられます。

そこで`l2_gateway`が書き戻します。応答がセグメントに入る唯一のhookで、往路の`pod_egress`が`ct_map`に置いた逆向きエントリはそこから引けます。エントリのscopeは`subnet_map[VNI].vpc_id`、`l2_gateway`が使うのは`l2_network_map[VNI].vpc_id`で、どちらも同じVpcの`status.vpcID`から来ているので一致します。書き戻し自体は`nat.h`の`nat_apply_reverse_snat`で、`pod_ingress`と同じものです。

gw vethのegressに`pod_ingress`を並べて付ける手は使えません。TCXは前のプログラムが`TC_ACT_UNSPEC`を返したときだけ次を走らせますが、`pod_ingress`は`TC_ACT_OK`か`TC_ACT_SHOT`を返すので、`l2_gateway`に届きません。

NATGatewayの応答は経路が違います。`node_ingress`の`handle_napt_in`がアドレスを戻し、宛先MACの解決だけをgatewayポートに任せます。セグメントのMACは`arp_table`ではなく`l2_arp`にあり、それを読むのは`l2_gateway`だからです。

### ループを止める

ingressへのredirectには、カーネル側の再帰上限が存在しません。`XMIT_RECURSION_LIMIT`は送信パス専用で、受信パスは何も数えません。`bpf_redirect`はIPのTTLも減らしません。gatewayとセグメント上のルータVMの間で経路がループすると、softirqを焼き続けます。

そこで`skb->mark`の24〜27ビットにホップ数を持たせ、`L2_GW_MAX_HOPS`(4)を超えたフレームを落とします。同じnetns内のredirectでは`skb_scrub_packet`の`xnet`引数がfalseになるので、markは保たれます。

Juneauが`skb->mark`を読み書きするのはここだけです。ビットを上位に置いたのは、gatewayがhost stackへ返したパケットがそのままnetfilterに入るからで、kube-proxyが使う0x4000と0x8000には触れません。

### 収束

ポートを立てるのは`daemon/internal/daemon/dataplane/reconciler/l2_gateway.go`です。アドレスとMACはcontrollerが`L2Network.status`に書いたものを読むだけで、daemonは自分で決めません。`bootstrap/junode_iface.go`が`juneau_node`に対してやっていることと同じ形です。

vethとプログラムの世話は`dataplane/link/l2_gateway.go`が持ちます。vethはpair名`l2gw<VNI>`と`l2gw<VNI>_h`で、MACはBPF側の端に付けます。gateway宛のフレームがingressに渡るとき、カーネルが`eth_type_trans`でそのMACを見て`skb->pkt_type`を決めるからです。両端のIPv6は切ってあります。切らないと、アドレスを持たないpeerの側からrouter solicitationがテナントのセグメントに出ていきます。

1つのポートが占める場所は6つです。

| map | 中身 |
|---|---|
| `l2_gateway` | VNI → { gw vethのifindex, gateway MAC } |
| `subnet_map` | VNI → RouteTableのtable_id、vpc_id、gateway MAC、gatewayアドレス、マスク、acl_id |
| `ifindex_subnet` | gw vethのifindex → { VNI, gatewayアドレス } |
| `l2_ifindex` | gw vethのifindex → VNI |
| `l2_fdb` | gateway MACの静的エントリ |
| `l2_bum_local` | gw vethのifindex(gatewayフラグ付き) |

`subnet_map`と`ifindex_subnet`はSubnetのためのテーブルですが、gw vethのingressで走るのは`pod_egress`なので、そこで必要になるものは同じです。VNIはSubnetと同じプールから出ているので、キーがぶつかることはありません。

書く順番はフレームが通る順の逆です。vethとプログラムが先で、`l2_gateway`が最後です。あれは経路が辿るエントリなので、それを書くまでは誰もこのポートにパケットを送りません。落とすときは逆順で、`l2_gateway`から消します。

### policy

gw vethのingressで`pod_egress`が走るので、そこを通る方向のNetworkACLとSecurityGroupは既存のまま効きます。ACLは`subnet_map.acl_id`から、SecurityGroupは`sg_membership_map`をパケットの送信元アドレスで引いて、です。

`apply_policy`が「自分」として見るのはNICではなくパケットのアドレスなので、L2NetworkのNICに付けたSecurityGroupはgatewayを跨ぐ通信で参照されます。`reconciler/sg_membership.go`はL2NetworkのNICのVpcをL2Network経由で解決するようにしました。ただしgatewayを持たないセグメントのNICは`sg_membership_map`に書きません。読む側が存在しないので、書いても誰も見ないエントリが増えるだけです。webhookも同じ理由で、gatewayを持たないセグメントのNICにSecurityGroupを付けることを拒否します。

**評価されるのはegress方向だけです。**`apply_policy`を呼ぶのは`pod_egress`で、gw vethではセグメントから出ていくフレームがそこを通ります。セグメントへ入る方向が通るのは`l2_gateway`で、こちらは`apply_policy`を呼びません。ACLのingressルールとSecurityGroupのingressルールは、L2Networkに対しては今のところ何もしません。セグメントの側から張った接続はegress方向の評価で判定されて`policy_ct_map`に載るので意図通りですが、Vpcの側から張った接続は素通りします。埋めるなら`l2_gateway`に`apply_policy(POLICY_HOOK_POD_INGRESS, ...)`を足すことになります。

セグメントの中の通信には、どちらの方向も一切効きません。L2のプログラムはpolicyを読まないからです。

### 分かっている穴

ARPを一度も出していないホストへは、Vpcから届きません。gatewayは`l2_arp`にあるアドレスしか解決できないからです。L2上のホストは外と話す前に必ずgatewayへARPを打つので、実用上は埋まりますが、外から先に叩きに行くと最初のパケットは落ちます。落ちたことは`kubectl juneau trace`の`MISS_L2_ARP`で見えます。

IPv6はセグメントの中ならBUMのフラッドで動きますが、gatewayは越えられません。`l2_arp`がIPv4専用で、NDPのsnoopingを持っていないためです。

gatewayはIPのTTLを減らしません。既存のSubnetの`handle_l3`も減らしていないので揃えましたが、セグメント上に置いたルータVMと経路がループした場合、TTLでは止まらず`skb->mark`のホップ数で止まります。

ACLとSecurityGroupのingressルールは効きません。上の[policy](#policy)にある通りです。

gatewayポートを立てるのは、そのセグメントにポートを持つNodeだけです。ClusterIPのbackendがそういうNodeに乗っていない場合、応答の経路が`FIB_ROUTE_TYPE_L2_GATEWAY`を引いた先に何も無く、`MISS_L2_GATEWAY`で落ちます。セグメントのポートを持つNodeにbackendが乗っている限り起きませんが、条件としては暗黙です。

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
| `l2_arp` | HASH_OF_MAPS | VNI → IPv4 | MAC | データプレーン |
| `l2_gateway` | HASH | VNI | gw vethのifindex / gateway MAC | `reconciler/l2_gateway.go` |

`l2_gateway`だけがNodeごとに違う値を持ちます。vethのifindexはそのNodeのものなので、あるNodeでのdumpは他のNodeについて何も言いません。

`l2_bum_remote`のinner mapは`l2_bum_local`のものと中身が同じですが、別のstructとして定義してあります。1つのmap-def structを2つの`__array(values, ...)`メンバから参照すると、clangがBTF forward declarationを吐いてロード時に`can't get size of BTF key: type is unsized`で落ちます。`fib_inner_map`と`tgw_fib_inner_map`が分かれているのと同じ理由です。

7つとも`dataplane/mapinventory/register.go`に登録してあるので、`kubectl juneau bpf dump`で読めます。

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
| `ENTER_L2_GATEWAY` | 106 | `l2_gateway`に入った |
| `MISS_L2_PORT` | 212 | `l2_ifindex`にvethが無い |
| `MISS_L2_NETWORK` | 213 | `l2_network_map`にVNIが無い |
| `MISS_L2_FDB` | 214 | 宛先MACを学習していない |
| `MISS_L2_ARP` | 215 | 宛先アドレスからMACを引けない |
| `MISS_L2_GATEWAY` | 216 | このNodeにそのセグメントのgatewayが無い |
| `L2_LEARNED` | 600 | 送信元MACの居場所を記録した |
| `L2_FLOOD` | 601 | 複製した(aux1が複製数) |
| `L2_SPLIT_HORIZON` | 602 | VXLAN経由のフレームをローカルにだけ複製した |
| `L2_HAIRPIN_DROP` | 603 | 宛先MACが、そのフレームが入ってきたポートに居た |
| `L2_GW_LOOP_DROP` | 604 | gatewayを渡った回数が上限を超えた |

hookは`TRACE_HOOK_L2_EGRESS`(5)、`TRACE_HOOK_L2_INGRESS`(6)、`TRACE_HOOK_L2_GATEWAY`(7)です。

L2 NICを追うには、どのNICの話なのかとアドレスの両方を渡します。

```console
$ kubectl juneau trace --from-pod default/lab-a --from-interface eth1 --from-ip 192.168.60.1 \
    --to-pod default/lab-b --to-interface eth1 --to-ip 192.168.60.2 --proto icmp
```

`--from-interface`が無いとPodのeth0が対象になり、そのSubnetのvpc_idでセッションが作られます。L2 hookは所属L2Networkのvpc_idでeventを出すので、`trace_make_key`が一致せず何も表示されません。CIDRを持たないL2NetworkではJuneauがアドレスを知らないので、`--from-ip`と`--to-ip`も必須です。

`--from-ip`には、そのPodが実際にそのアドレスから送るものを書いてください。probeはPodの中で`ping`や`nc`を実行するだけで、送信元アドレスはPodのルーティングが選びます。送信元を縛る指定は入れていません。busyboxの`nc`は`-s`を持たないので、環境によっては黙ってパケットが出なくなるからです。セグメント宛のアドレスなら経路はそのNICになるので、普通は一致します。

traceが拾えるのはIPv4のフレームだけです。TraceSessionはIPv4の5-tupleでセッションを定義するので、ARPやIPv6のフレームはtrace idが解決できず、emitは何もしません。EtherTypeごとの分岐にreasonを足すことも考えましたが、一度も発火しない定数が増えるだけなので入れていません。同じ理由で`TRACE_REASON_POLICY_ETHERTYPE_DROP`も現状は発火しない、と`trace.h`に書いてあります。

## verifier予算

`make -C daemon verifier-check`の実測値です。カーネル6.18、x86_64。

```
OK   pod_egress: tc_pod_egress processed 581856 insns (limit 1000000, 58.2% used)
OK   pod_ingress: tc_pod_ingress processed 101533 insns (limit 1000000, 10.2% used)
OK   vxlan_ingress: tc_vxlan_ingress_entry processed 5282 insns (limit 1000000, 0.5% used)
OK   node_ingress: tc_node_ingress processed 109544 insns (limit 1000000, 11.0% used)
OK   l2_egress: tc_l2_egress processed 2786 insns (limit 1000000, 0.3% used)
OK   l2_ingress: tc_l2_ingress processed 511 insns (limit 1000000, 0.1% used)
OK   l2_gateway: tc_l2_gateway processed 4631 insns (limit 1000000, 0.5% used)
```

gatewayを入れる前は`pod_egress`が581,483命令、`vxlan_ingress`が5,166命令、`l2_egress`が2,277命令、`node_ingress`が70,965命令でした。`pod_egress`が373命令増えたのは`fib_val.type`の分岐で、`vxlan_ingress`と`l2_egress`が増えたのはARP snoopingです。`node_ingress`が109,544命令になったのはNATGatewayの応答をgatewayポートへ渡す分岐で、`l2_gateway`が2,709から4,631になったのはServiceの応答の書き戻しです。`vxlan_ingress`はL2分岐を入れる前が3,760命令(0.4%)でした。

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

gatewayについては、`BPF_PROG_TEST_RUN`では`BPF_F_INGRESS`のredirectが本当にingressへ届いたかを見せられません。dummyデバイスは受信側のカウンタを持たないので、届かなかった場合と区別が付かないからです。`TestGatewayAnswersArpFromTheSegment`はそこを一往復まるごとで確かめます。`pod_egress`、`l2_egress`、`l2_gateway`を1つのpin pathに読み込んでmapを共有させ、gateway vethの両hookにdaemonと同じプログラムを貼り、セグメントのポートからgatewayのアドレス宛のARPリクエストを流します。返事がリクエストを出したポートに届けば、複製がingressに渡って`pod_egress`が答え、その答えが`l2_gateway`を通って戻ってきたということです。この経路以外にそのポートへフレームが届く道はありません。

`TestGatewayCarriesAClusterIPFlowBothWays`は同じ足回りでServiceの往復を通します。往路は`pod_egress`をgw vethのifindexで走らせてDNATと逆向きエントリの記録まで、復路は`l2_gateway`に応答を渡してアドレスが戻ることまでです。2つのプログラムは`ct_map`でしか出会わないので、片方だけのテストでは「同じscopeを見ているか」が確かめられません。1つのpin pathに両方を読み込むのはそのためです。

セグメントのテーブルを作るのも、`newL2Segment`が`reconciler.L2Network`にReconcileさせています。テストが自分でテーブルを並べていたときは、reconcilerが`l2_arp`を作り忘れていることに誰も気付けませんでした。

rootが要るテストは`bpftest.Require`が入口で止めます。`go test -short`とroot以外の実行ではskipします。
