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

`l2_ingress`は、セグメントの中で完結するフレームには何もしません。traceに配送を記録するだけです。これが無いと、trace上ではフレームをredirectしたhookで記録が終わり、届いたのかどうかが読めません。

gatewayが置いたフレームだけは別で、NATの書き戻しとpolicyの評価をここで行います。理由は[Serviceの応答](#service)にあります。見分けるのは送信元MACで、gatewayのMACで署名されているかどうかです。

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

帰ってくる方向は同じようにはいきませんでした。`pod_ingress`が担っている書き戻しがどこにも無いからです。Serviceの応答は`l2_ingress`が戻し、NATGatewayの応答は`node_ingress`が戻してからgatewayポートへ渡します。詳しくは[Serviceの応答](#service)にあります。

### BPF_F_INGRESSが必須です

`bpf_redirect`のflagsを0にすると、gw vethのTCX *egress*が走った後に`veth_xmit`でpeerへ抜け、host stackに上がってしまいます。`BPF_F_INGRESS`を渡すと`skb_do_redirect` → `__bpf_rx_skb` → `dev_forward_skb_nomtu` → `netif_rx_internal` → backlog → `__netif_receive_skb_core` → `sch_handle_ingress` → `tcx_run`という経路になり、`veth_xmit`を通りません。このフラグを使うのはgatewayへの2箇所だけで、残りの13箇所の`bpf_redirect`はすべて0のままです。

`bpf_redirect_peer`は使えません。`skb_do_redirect`にpeerが別のnetnsにあることを要求する条件があり、gw vethは両端がhost netnsなので黙って落とされます。

ブロードキャストの複製がgw vethのingressに渡ると、`pod_egress`は`handle_arp`でそのフレームを書き換えます。cloneへの直接書き込みが安全なのは、`bpf_clone_redirect`がcloneを作った直後に元のskbのheadを`bpf_try_make_head_writable`で複製し直すからです。元のskbが新しいバッファへ移るので、送り出されたcloneが古いバッファを単独で持ちます。

### anycast

gatewayを宣言したL2Networkでは、**全Nodeが自分のgw vethを立てます**。アドレスもMACも全Nodeで同じです。ワークロードは自Nodeのgatewayを使うので、L3の通信のためにVXLANを跨ぎません。既存のSubnetが`subnet_map.gw_mac`を全Nodeで共有しているのと同じ考え方です。

セグメントのポートを持つNodeだけ、にはしていません。gatewayを宣言した時点でそのセグメントはVpcのルーティングに参加していて、そこ宛のパケットがどのNodeで経路を引かれるかは、セグメントのエンドポイントがどのNodeに乗っているかと関係がないからです。SubnetのPodがL2のPodへ送るときも、Serviceの応答がbackendから返るときも、経路を引くのはそのワークロードが動いているNodeです。そこにポートが無ければ落ちます。

コストはNode数×gateway付きL2Network数のvethです。gatewayを宣言していないセグメントは、これまで通り何も立てません。

anycastなので、gateway宛のフレームは絶対にoverlayを渡ってはいけません。そのために、learning tableのgateway MACのエントリだけはuser spaceが書きます。

```
l2_fdb[vni][gateway MAC] = { ifindex: 自Nodeのgw veth, flags: L2_FDB_FLAG_GATEWAY }
```

`flags`は3つのことを同時に言っています。このMACを送信元に名乗ったフレームがエントリを奪えないこと、エージングの掃除がこれを消さないこと、そして転送先がポートのegressではなくingressだということです。1つ目が無いと、ワークロードがgateway MACを名乗るだけでセグメントの出口を自分に向けられます。

BUMのフラッド先リストでも、gatewayのエントリは`L2_PORT_FLAG_GATEWAY`を持ちます。ブロードキャストのコピーがingressに渡るのはこのフラグのおかげで、gatewayが自分のアドレスへのARPに答えられるのもこれがあるからです。

overlayから届いたBUMは、gatewayには配りません。送信元のNodeが自分のgatewayに既に配り終えているので、ここでも配ると1つのARPリクエストにNodeの数だけ返事が返ります。

### ARP snooping

Vpcからセグメントの中のホストへパケットを送るとき、gatewayは宛先のMACを知る必要があります。学習方式なのでcontrollerはMACを知りません。

そこで`l2_egress`と`vxlan_ingress`のL2分岐が、通過するARPの送信者を記録します。

```
l2_arp: HASH_OF_MAPS
  outer key: VNI
  inner: LRU_HASH   key: IPv4 (host byte order), value: MAC
```

opcodeは見ません。リクエストもリプライもGARPも送信者のペアを持っていて、引っ越したホストは何を送るより先に自分を名乗るからです。`vxlan_ingress`でも記録するのは、別Nodeのホストがブロードキャストで名乗るのがこのNodeにとって唯一の学習の機会だからです。

既存の`arp_table`とは分けました。あちらは131072エントリのplain HASHをノード全体で共有していて、セグメントが大量のアドレスを覚えると`reconciler/arp.go`の`Update`が`E2BIG`で失敗し、正規のSubnetのARP代理応答が壊れます。読む側は`l2_network_map`を引いてどちらのテーブルを使うか決めます。missしたらもう一方も見る、という書き方はしていません。

### 控えているアドレス

snoopingだけでは足りないNodeがあります。セグメントのポートを1つも持たないNodeです。gatewayポート自体は全Nodeにありますが、そのNodeは`l2_egress`が見るローカルのARPも、overlayが運んでくるARPも見ません。他のNodeの`l2_bum_remote`にそのNodeが載るのはエンドポイントがある場合だけだからです。`l2_arp`が空のまま、gatewayは誰も呼べません。

controllerは足りない分を知っています。gatewayを持つセグメントは必ずCIDRを持つので、NICには必ずアドレスがあり、それを名乗るNetworkEndpointにMACも載っています。それを書いておくのが`reconciler/l2_arp.go`です。

書き方が2つとも片側通行になっています。書き込みは`Table.PutIfAbsent`で、そのキーに何も無いときだけ入ります。取り消しは`Table.RemoveIfEqual`で、自分が書いた値がまだそこにあるときだけ消します。つまりsnoopingは常にseedを上書きでき、seedは決してsnoopingを上書きし返しません。NICの後ろでbridgeを組んだワークロードが自分のMACでアドレスを名乗ると、最初のフレームで訂正されて、その訂正が残ります。

controllerが転送テーブルを書き始めたわけではありません。`l2_fdb`は完全学習のままです。あちらはNICが持っていないMACが必ず出てくるテーブルで、`l2_arp`はjuneauが自分で作ったポートの近隣解決テーブルです。gateway MACを静的エントリにしたのと同じ理屈が通ります。

seedが効けば残りは既に動きます。アドレスさえ引ければ、`l2_fdb`が空でも`l2_flood`がoverlay越しにポートを持つNodeへ送り、そこで配送されます。

### gatewayから聞きに行く

snoopingとseedの2つを足しても、まだ届かないアドレスがあります。Podの中でIPAMの払い出しとは別のアドレスを自分で振った場合と、NICの後ろのbridgeやnested VMの向こうにいるホストです。どちらもNetworkEndpointには載らないのでseedの材料になりませんし、相手が自発的に喋るまでsnoopingも拾えません。自由にアドレスを振れることと、中でbridgeを組めることがL2Networkを使う理由なので、ここは埋める価値があります。

`l2_gateway`は`l2_arp`を引けなかったとき、元のパケットをARPリクエストに書き換えてセグメントにフラッドし、`TC_ACT_SHOT`を返します。`l2_flood`が`bpf_clone_redirect`でコピーを配るので、元のskbは手元に残ります。それを捨てれば「ARPを出して、それを必要としたパケットは捨てた」形になります。普通のルータと同じ挙動で、違うのは解決待ちのパケットを持たない点だけです。BPFにskbを退避しておく手段が無いので、**1発目は必ず落ちます**。TCPなら再送で繋がりますが、単発のICMPやUDPは1つ目が消えます。

書き換えるのは元のフレームです。BPFのプログラムは自分で新しいフレームを作れず、フラッドは渡されたskbを複製するだけだからです。Ethernet+ARPは42バイトなので、`bpf_skb_change_tail`で長さを合わせます。パディング済みの60バイトのフレームなら縮み、host stackを経由せずに来た34バイトのフレームなら伸びます。このヘルパーを呼ぶと`data`と`data_end`が無効になるので、呼んだ後に必ず取り直します。

宛先はブロードキャスト、送信元とsender MACはgatewayのMAC、sender IPは`subnet_map[VNI].gw_addr`、target IPは元のパケットの宛先です。target MACは0で埋めます。

gatewayポート自身には配りません。`l2_flood`は入ってきたポートを飛ばすので、`in_ifindex`にgw vethを渡すだけで済みます。配ってしまうと、そのコピーが`l2_egress`に渡り、まだ探している最中のアドレスの持ち主としてgatewayのMACが記録されます。

**聞きに行くのはセグメントのprefixの中だけです。**ルータが解決するのは自分が乗っているリンクの隣人だけで、それ以外のアドレスにはここの誰も答えられません。この判定が無いと、間違って向けられた経路が運んでくるパケット1つごとに全ポートへリクエストが乗ります。

#### レート制限

これが無いとgatewayはブロードキャストの増幅器になります。未解決の宛先に毎秒数千パケットが来れば、そのたびにARPがセグメント全体へフラッドされます。

同じアドレスへ聞くのは1秒に1回までにしました。ルータが解決できない隣人に対して自分に許す間隔と同じです。

```
l2_arp_probe: HASH_OF_MAPS
  outer key: VNI
  inner: LRU_HASH   key: IPv4 (host byte order), value: asked_ns
```

時刻は`bpf_ktime_get_ns`、つまり`CLOCK_MONOTONIC`です。GCはLRU任せで、聞かれなくなったアドレスは表が詰まったときに落ちます。`ipv4_frag_map`と`virtual_service_flow_map`が同じ形です。

VNIごとに分けたのは`l2_fdb`や`l2_arp`と同じ理由です。ノード全体で1つのLRUにすると、大量のアドレスを聞いて回るセグメントが他のセグメントのエントリを追い出します。追い出された側は次のパケットでまた聞き直すので、この表が防ぐはずのフラッドが、何もしていないテナントの側で起きます。単一のLRUでも「レート制限が緩む」だけでセグメントは越えない、という見方もできますが、緩んだ先で起きるのがまさにブロードキャストストームなので分けました。

同時に2つのCPUが同じアドレスを通してしまうことはあります。余分なフレームが1つセグメントに乗るだけで、抑えたい量とは桁が違うので、ロックは置いていません。

#### 返事を全Nodeに配る

gatewayが出したリクエストへの返事は、宛先がgateway MACのユニキャストARPリプライです。`l2_egress`と`vxlan_ingress`は全opcodeを見ているので、通れば`l2_arp`に入ります。

問題は誰が受け取るかです。**返事が戻るのは聞いたNodeとは限りません。**gatewayはanycastで、全Nodeが同じMACで答えます。ホストは宛先MACにそのMACを入れて返しますが、`l2_fdb`のgatewayエントリは各Nodeが自分のgw vethを指して持っているので、返事はホストが乗っているNodeのgatewayに渡り、そのNodeの`l2_arp`だけが埋まります。一方、Vpcから来たパケットの経路が引かれるのは送信元ワークロードのNodeです。この2つが食い違うと、聞いたNodeは答えを永遠に受け取りません。

e2eでは対称的に外れました。worker2のPodからworkerにいる`10.92.0.200`へpingすると8発とも落ち、その間tcpdumpには毎秒ARPリクエストが出てホストが毎回答えていました。機構は動いていて、答えが違うNodeの表に入るだけです。失敗した試行が間違ったNodeを温める、という副作用まで出ました。workerが`.230`を聞いて失敗した後、答えを受け取っていたworker2からは1発目で通りました。

そこで`l2_egress`は、**gateway MAC宛のARPリプライだけを`l2_bum_remote`にも複製します**。`l2_flood_answer`がローカルのgatewayと他のNodeの両方に配り、元のフレームは落とします。「gateway MAC宛のフレームは必ずローカル」という前提に対する唯一の例外で、前提そのものは残ります。

配る順番はローカルが先で他Nodeが後です。他Nodeへの複製はフレームにトンネルキーを押すので、押した後のフレームをvethに渡すとカーネルが落ちます([cilium#19428](https://github.com/cilium/cilium/issues/19428))。ローカルのgatewayに`bpf_redirect`で渡してから複製する形は書けません。`l2_flood`が元から守っている順番をそのまま使っています。

受け取った側の`vxlan_ingress`は**snoopingとMAC学習だけして捨てます**。`l2_arp`にアドレスが入り、`l2_fdb`に「そのMACはあのNodeにいる」が入るので、次のパケットは未知ユニキャストのフラッドではなくoverlay越しのユニキャストで出ます。ローカルのgatewayには渡しません。送信元Nodeで既に渡し済みで、全Nodeが同じアドレスのgatewayを持っている以上、渡すと1つの質問にNodeの数だけ答えることになります。受け取った側は転送しないので、ループもしません。

複製が走るのは未解決アドレスの初回解決のときだけです。解決してしまえば`l2_arp`に載るのでリクエスト自体が出ません。

#### 聞いたNodeへ返す

共有だけでは届かないNodeが残ります。`l2_bum_remote`に載るのは`reconciler/l2_port.go`がNetworkEndpointから集めたNodeだけで、gatewayポートはNetworkEndpointを作りません。**gatewayしか持たないNodeは、どのNodeの`l2_bum_remote`にも載りません。**

そこで、聞いてきたNodeを覚えておいて、そこへ返します。

```
l2_arp_asker: HASH_OF_MAPS
  outer key: VNI
  inner: LRU_HASH   key: IPv4 (host byte order), value: { vtep_ip, asked_ns }
```

書くのは`vxlan_ingress`のL2分岐です。overlayから来たARPリクエストの送信元MACがgateway MACだったら、`{VNI, target IP}`に`bpf_skb_get_tunnel_key`の`remote_ipv4`を書きます。質問と、その質問を出したNodeの両方が見えるhookはここだけです。

読むのは`l2_egress`で、gateway MAC宛のリプライを見つけたときに`{VNI, sender IP}`を引きます。当たれば、そのVTEPへ`bpf_skb_set_tunnel_key`してから`bpf_clone_redirect`で1つだけ送ります。`l2_flood_answer`の中で、`l2_bum_remote`への複製が終わった後に走ります。トンネルキーを押した後のフレームをvethに渡せない制約は共有の複製と同じなので、順番は「ローカル → 共有 → 聞いたNode」で固定です。

`l2_bum_remote`に既に載っているNodeへは送りません。共有の複製が同じフレームを運んでいるので、2通目は無駄です。

**共有はやめていません。**2つは目的が違います。共有は「まだ聞いていないNodeにも答えを配る」ためのもので、これがあるおかげで別のNodeが解決したアドレスへの1発目のパケットが落ちません。ユニキャストは「聞いたのに載っていないNode」に限って届けるものです。共有をやめると、記録が上書きされたときや期限切れのときに戻る先がこのPR以前の状態になり、しかも初回解決の1発目が落ちる範囲が広がります。共有が流れるのは未解決アドレスの初回解決のときだけなので、常時のコストはありません。

記録の寿命は5秒です(`L2_ARP_ASKER_TTL_NS`)。レート制限が1秒間隔なので、質問と返事の往復には十分足ります。**期限切れの記録は使いません。**聞くのをやめたNodeへ答えを送ることになり、今聞いているNodeはもう1ラウンド待たされます。時刻は`l2_arp_probe`と同じく`bpf_ktime_get_ns`です。

1アドレスにつき1Nodeだけ覚えます。2つのNodeがほぼ同時に同じアドレスを聞くと後から聞いた方で上書きされ、先に聞いた方はそのラウンドの答えを受け取りません。1秒後に聞き直すので次のラウンドで解決します。Nodeのリストを持つ案は、フラッドを避けるための経路に2つ目のフラッド先リストを置くことになるので採りませんでした。

VNIごとに分けたのは他のL2テーブルと同じ理由です。溢れたときの被害はこのPR以前の状態に戻るだけで`l2_arp_probe`より軽いのですが、軽い被害でも隣のテナントのせいで起きるのは筋が違います。加えて、per-VNIなら`l2/table.go`の`Table`がそのまま使えて、L2Networkの生成と削除に合わせた後始末が他のテーブルと同じ1箇所で済みます。単一のLRUだと、消えたL2Networkのエントリを掃く仕組みを別に持つことになります。

**セグメントの中のARPは素通しのままです。**代理応答を持ち込むと、GARPによるMAC移動の通知も、ユーザが立てたDHCPサーバも、重複アドレス検出も壊れます。`pod_egress`の`handle_arp`が答えるのはgateway自身のアドレスへのリクエストだけで、それ以外はgw vethに届いたコピーを捨てます。元のリクエストは既に全ポートへ複製されているので、答えるべきホストが自分で答えます。

### gw vethのegressプログラム

`l2_gateway`が扱うフレームは2種類だけです。

IPv4のパケットは経路がここへ送ったもので、まだ受け取ったhopのアドレス宛のままです。`l2_arp`で宛先アドレスをMACに解決し、宛先MACをそれに、送信元MACをgatewayのものに書き換えてから、セグメントの学習テーブルで転送します。解決できないアドレスには「gatewayから聞きに行く」の通りARPリクエストを出し、そのパケットは落とします。

ARPのフレームは`pod_egress`がgatewayのアドレスのために作った返事で、既に正しいMACのペアを持っています。書き換えずにそのまま転送します。

それ以外のEtherTypeは落とします。router portが出すものではありませんし、このhookに来る残りはpeerの向こうのhost stackが出したものです。

宛先MACを解決できても学習テーブルに居場所が無い場合はフラッドします。フレームは既に宛先のMACを持っているので、受け取るのはそのホストだけです。スイッチが未知のユニキャストにする扱いと同じです。

### Serviceの応答

L2NetworkのNICからClusterIP Serviceを叩けます。往路は`pod_egress`がgw vethのingressで`handle_service`まで走るので、Subnetから叩いたときと1行も違いません。

復路だけが違います。ServiceのDNATを戻すのは`pod_ingress`で、叩いた側のvethのegressに付いています。L2NetworkのNICにはそれが付いていません。応答はbackendのアドレスのままワークロードに届き、書いた覚えのない相手からの返事として捨てられます。

書き戻すのは`l2_ingress`です。宛先ワークロードのvethのegress、つまりフレームがワークロードに入る直前で、`nat.h`の`nat_apply_reverse_snat`を呼びます。`pod_ingress`が呼ぶのと同じ関数です。

**なぜgatewayポートではないのか。**最初はそこに置きました。「応答がセグメントに入る唯一のhook」だと思ったからですが、それはノード単位でしか正しくありませんでした。Vpcからセグメントへ向かうパケットは、宛先エンドポイントのいるノードではなく、**経路が引かれたノード**でセグメントに入ります。応答の経路を引くのはbackendが動いているノードなので、gatewayポートで書き戻すと、そのフローの`ct_map`を持たないノードで書き戻そうとすることになります。同一ノードなら通り、クロスノードでは黙って素通しになりました。

`l2_ingress`は必ず宛先ワークロード自身のノードで走ります。フローを開いたのもそのノードなので、`ct_map`も`policy_ct_map`もそこにあります。

エントリのscopeは`subnet_map[VNI].vpc_id`、`l2_ingress`が使うのは`l2_network_map[VNI].vpc_id`で、どちらも同じVpcの`status.vpcID`から来ているので一致します。

**gatewayが置いたフレームの見分け方**は送信元MACです。gatewayのMACで署名されているものだけが対象で、そのMACは`l2_gateway[vni]`にあります。セグメントの中で完結するフレームは別のMACで来るので、これまで通りアドレスもpolicyも読まれません。「L2セグメントの中は素通し、gatewayを跨ぐときだけ効く」がそのまま保たれます。`l2_egress`はgateway MACを送信元にしたフレームで学習エントリが動くのを拒否するので、ワークロードがそのアドレスを乗っ取ることはできません。自分の送るフレームにそのMACを入れることはできますが、それは自分の通信を審査してもらう側に回るだけで、抜け道にはなりません。

vethのegressに`pod_ingress`を並べて付ける手は使えません。TCXは前のプログラムが`TC_ACT_UNSPEC`を返したときだけ次を走らせますが、`pod_ingress`は`TC_ACT_OK`か`TC_ACT_SHOT`を返すので、後ろのプログラムに届きません。

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
| `subnet_map` | VNI → RouteTableのtable_id、vpc_id、gateway MAC、gatewayアドレス、マスク、acl_id。両方向のpolicyがここからACLを引きます |
| `ifindex_subnet` | gw vethのifindex → { VNI, gatewayアドレス } |
| `l2_ifindex` | gw vethのifindex → VNI |
| `l2_fdb` | gateway MACの静的エントリ |
| `l2_bum_local` | gw vethのifindex(gatewayフラグ付き) |

`subnet_map`と`ifindex_subnet`はSubnetのためのテーブルですが、gw vethのingressで走るのは`pod_egress`なので、そこで必要になるものは同じです。VNIはSubnetと同じプールから出ているので、キーがぶつかることはありません。

書く順番はフレームが通る順の逆です。vethとプログラムが先で、`l2_gateway`が最後です。あれは経路が辿るエントリなので、それを書くまでは誰もこのポートにパケットを送りません。落とすときは逆順で、`l2_gateway`から消します。

### policy

両方向とも`apply_policy`が評価します。出ていく方向はgw vethのingressの`pod_egress`が`POLICY_HOOK_POD_EGRESS`で、入ってくる方向はワークロードのvethのegressの`l2_ingress`が`POLICY_HOOK_POD_INGRESS`で呼びます。どちらもワークロードのノードで走ります。ACLは`subnet_map.acl_id`から、SecurityGroupは`sg_membership_map`をパケットのアドレスで引いて、です。境界を書いた`subnet_map`のエントリは1つなので、2つのhookが同じACLと同じmembershipを見ます。

`apply_policy`が「自分」として見るのはNICではなくパケットのアドレスなので、L2NetworkのNICに付けたSecurityGroupはgatewayを跨ぐ通信で参照されます。`reconciler/sg_membership.go`はL2NetworkのNICのVpcをL2Network経由で解決するようにしました。ただしgatewayを持たないセグメントのNICは`sg_membership_map`に書きません。読む側が存在しないので、書いても誰も見ないエントリが増えるだけです。webhookも同じ理由で、gatewayを持たないセグメントのNICにSecurityGroupを付けることを拒否します。

#### hookの名前を借りている理由

`l2_ingress`が`POLICY_HOOK_POD_INGRESS`を名乗るのは、`policy_ct_map`のキーにhookが入っているからです。`policy_ct_install`は許可を2回書きます。判断したhookのキーと、同じフローを反対側から見たhookのキーです。gw vethのingressの`pod_egress`にとっての反対側がこのプログラムなので、独自のhook番号を作ると、セグメント発のフローの応答が再評価されます。ingressを全部拒否するACLを書いた瞬間、セグメントから出ていくフローが全部死にます。

ペアリング自体は正しくても、参照するノードを間違えると同じことが起きます。`policy_ct_map`はノードごとなので、gatewayポートで評価していたときはクロスノードの戻りだけが記録の無いノードで判定され、落ちていました。

Subnet同士の通信で`pod_egress`と`pod_ingress`が別々のNICに付いていても成立しているのは同じ仕組みで、L2のgatewayはその2つを1本のvethの表と裏に載せ替えただけです。

順番も効いています。`l2_ingress`ではServiceの書き戻しを先に、policyを後に走らせます。`pod_ingress`が同じ順にしているのと同じ理由で、CTのエントリはワークロードが書いた宛先で作られているので、応答がそのアドレスに戻ってからでないと引けません。逆にすると、ingressを拒否するACLの下でServiceの応答が落ちます。`TestGatewayLetsTheReplyOfAFlowTheSegmentOpenedBackIn`がそこを押さえています。

#### 命令数

`apply_policy`はそのまま呼ぶと重すぎました。gatewayポートに置いていたときの実測で、`handle()`にインライン展開すると622,171命令、BPF-to-BPFのsubprogramに包むと132,527命令です。手前のNAT書き戻しがパケットポインタの状態をいくつも残していて、展開するとverifierがルール評価をその数だけ歩き直します。`l2_ingress_policy`も同じ形で、引数は全てスカラーです。`policy-data-plane.md`にある「スタックポインタを引数に取るnoinline callで爆発する」の裏返しで、渡すものがスカラーだけならverifierは本体を1回だけ歩きます。

セグメントの中の通信には、どちらの方向も一切効きません。L2のプログラムはpolicyを読まないからです。

### 分かっている穴

未解決のアドレスへの1発目のパケットは必ず落ちます。gatewayはARPリクエストを出しますが、返事を待つ間そのパケットを持っておく手段がありません。TCPは再送で繋がるので実用上ほぼ透明で、単発のICMPやUDPは1つ目が消えます。Linuxのルータでも解決待ちのキューが溢れれば同じことが起きます。落ちたことは`kubectl juneau trace`の`MISS_L2_ARP`と`L2_ARP_ASKED`の並びで見えます。

IPv6はセグメントの中ならBUMのフラッドで動きますが、gatewayは越えられません。`l2_arp`がIPv4専用で、NDPのsnoopingを持っていないためです。

gatewayはIPのTTLを減らしません。既存のSubnetの`handle_l3`も減らしていないので揃えましたが、セグメント上に置いたルータVMと経路がループした場合、TTLでは止まらず`skb->mark`のホップ数で止まります。

セグメントにNICを1枚も持たないNodeのgatewayも、手で振ったアドレスやbridgeの向こうのホストへ届きます。`l2_arp_asker`が「聞いてきたNode」を覚えていて、答えがそこへ返るからです。かつてはここが穴でした。返事の共有先が`l2_bum_remote`だけだった頃は、control-planeのPodから手で振ったアドレスへ100% loss、seed済みのIPAMアドレスへ0% lossという分かれ方をしていました。

残っているのは、2つのNodeがほぼ同時に同じアドレスを聞いたときの1ラウンドです。記録は1アドレスにつき1Nodeなので、先に聞いた方はそのラウンドの答えを受け取りません。1秒後に聞き直して次のラウンドで解決します。記録がLRUから溢れた場合と5秒の期限を過ぎた場合も同じで、どちらも次のラウンドで拾い直します。

セグメントのprefixの外のアドレスへは、gatewayから届きません。聞きに行かないので`l2_arp`が埋まる道がありません。セグメントの上にルータVMを置いてその先へ出す使い方は、next hopの概念が無いので今のところ成立しません。

## リモートVTEPとローカルポートの集約

`l2_bum_local`と`l2_bum_remote`の中身は、`daemon/internal/daemon/dataplane/reconciler/l2_port.go`がNetworkEndpointから作ります。

自Nodeのエンドポイントはローカルポートになり、`l2_ifindex`にVNIを書いてから`l2_bum_local`に加わります。他Nodeのエンドポイントは`status.nodeIP`が`l2_bum_remote`に加わります。

両方とも参照カウントで管理しています。1つのセグメントの複数のエンドポイントが同じNodeに乗るのは普通のことで、そのNodeは1回だけリストに入り、最後の1つが消えるまで残らなければなりません。ローカル側も同じ仕組みにしてあるので、再起動したワークロードがvethを引き継ぐ間もリストから抜けません。

L2Networkの側は`reconciler/l2_network.go`が見ます。`l2_network_map`にVNIとvpc_idを書き、`l2_fdb`と`l2_bum_local`と`l2_bum_remote`と`l2_arp`と`l2_arp_probe`と`l2_arp_asker`のper-VNIテーブルを作ります。まとめて作るのは、一部だけあるセグメントをデータプレーンが壊れたものとして扱うからです。フラッド先のリストを見つけられなかったフレームは、どのテーブルが無かったのかを何も言わずに落ちます。テーブルの作成と破棄には`dataplane/l2/table.go`の`Table`を使います。`policy/rotator.go`と同じ「新しいinnerを作ってouterにアトミックにswapし、古いinnerをClose」という形ですが、swapは1回だけです。policyのinner mapは毎回まるごと書き直すものなので回転させて構いませんが、L2のinner mapはデータプレーンが書いたものと1エンドポイントずつ足したものが入っているので、回転させると全部消えます。

どちらのreconcilerも`Ensure`を呼ぶので、L2NetworkのイベントとNetworkEndpointのイベントのどちらが先に来ても構いません。

## 既存reconcilerの除外

`reconciler/arp.go`と`reconciler/fdb.go`と`reconciler/pod_iface.go`は、`spec.subnet`が空のNetworkEndpointをスキップします。完全学習方式なのでcontrollerが静的エントリを書いてはいけません。`fdb.go`はキー`{vni, mac}`を所有者を確認せずに`Delete`するので、混ぜると学習エントリを踏み潰します。

`ifindex_subnet`もL2では書きません。あのmapの`ipv4`はpolicyがNICを引くためのもので、L2NetworkのNICはアドレスを持たないことがあります。0を書けば別のNICとして読まれるので、L2は`l2_ifindex`という別のmapを持ちます。

## map一覧

| map | 型 | キー | 値 | 書く側 |
|---|---|---|---|---|
| `l2_network_map` | HASH | VNI | vpc_id | `reconciler/l2_network.go` |
| `l2_ifindex` | HASH | ifindex | VNI | `reconciler/l2_port.go` |
| `l2_fdb` | HASH_OF_MAPS | VNI → MAC | ifindex / vtep_ip / last_seen_ns / flags | データプレーンと`reconciler/l2_gateway.go`(gateway MACの1件だけ) |
| `l2_bum_local` | HASH_OF_MAPS | VNI → ifindex | 1 | `reconciler/l2_port.go` |
| `l2_bum_remote` | HASH_OF_MAPS | VNI → VTEP IPv4 | 1 | `reconciler/l2_port.go` |
| `l2_arp` | HASH_OF_MAPS | VNI → IPv4 | MAC | データプレーンと`reconciler/l2_arp.go` |
| `l2_arp_probe` | HASH_OF_MAPS | VNI → IPv4 | asked_ns | データプレーン |
| `l2_arp_asker` | HASH_OF_MAPS | VNI → IPv4 | vtep_ip / asked_ns | データプレーン |
| `l2_gateway` | HASH | VNI | gw vethのifindex / gateway MAC | `reconciler/l2_gateway.go` |

`l2_gateway`だけがNodeごとに違う値を持ちます。vethのifindexはそのNodeのものなので、あるNodeでのdumpは他のNodeについて何も言いません。

`l2_bum_remote`のinner mapは`l2_bum_local`のものと中身が同じですが、別のstructとして定義してあります。1つのmap-def structを2つの`__array(values, ...)`メンバから参照すると、clangがBTF forward declarationを吐いてロード時に`can't get size of BTF key: type is unsized`で落ちます。`fib_inner_map`と`tgw_fib_inner_map`が分かれているのと同じ理由です。

9つとも`dataplane/mapinventory/register.go`に登録してあるので、`kubectl juneau bpf dump`で読めます。

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
| `L2_ARP_ASKED` | 605 | ARPリクエストを出してパケットを落とした(aux1が聞いたアドレス) |
| `L2_ARP_HELD` | 606 | 直前に聞いたばかりなのでARPを出さずに落とした(aux1が聞かなかったアドレス) |

**返事の共有もユニキャストもtraceに出ません。**607と608を一度置きましたが、1回も発火しませんでした。traceのidはIPv4のタプルから引きます。ARPフレームにはタプルが無いので`trace_classify_and_emit_enter`が0を返し、その下の`trace_emit_*`は全て何も書かずに戻ります。共有が実際に起きている最中に完全なtraceを取っても、`enter`と`address miss`と`arp request sent`しか出ませんでした。発火しない定数を残しても読む人を惑わせるだけなので消しました。同じ理由で、聞いたNodeへのユニキャストにもreasonを足していません。

どちらが効いたかはmapで見てください。答えが届いたかどうかは、聞いたNode側の`l2_arp`です。

```console
$ kubectl juneau bpf dump l2_arp --inner-key vni=4243
```

手で振ったアドレスが載っていれば答えが届いています。答えを運ぶ側、つまりホストが乗っているNodeでは`l2_arp_asker`を見ます。

```console
$ kubectl juneau bpf dump l2_arp_asker --inner-key vni=4243
VNI   IPV4         VTEP_IP     ASKED_NS
4243  10.92.0.204  10.89.0.11  882431907714
```

`VTEP_IP`が答えの送り先です。ここが空のまま聞いたNode側の`l2_arp`も空なら、質問がこのNodeまで来ていません。

`L2_ARP_ASKED`と`L2_ARP_HELD`はIPv4パケットの経路で出るので発火します。この2つは、フレームを書き換える前に出しています。`trace_emit_l3`はイベントを作るときにフレームからアドレスを読み直すので、書き換えた後に出すと42バイトのARPフレームをIPv4ヘッダとして読んだ値が乗ります。`174.105.10.92:0->0.1.0.0:0`のような、実在しないのにそれらしく見えるタプルになります。

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
OK   vxlan_ingress: tc_vxlan_ingress_entry processed 5945 insns (limit 1000000, 0.6% used)
OK   node_ingress: tc_node_ingress processed 109544 insns (limit 1000000, 11.0% used)
OK   l2_egress: tc_l2_egress processed 3455 insns (limit 1000000, 0.3% used)
OK   l2_ingress: tc_l2_ingress processed 43781 insns (limit 1000000, 4.4% used)
OK   l2_gateway: tc_l2_gateway processed 3484 insns (limit 1000000, 0.3% used)
```

gatewayを入れる前は`pod_egress`が581,483命令、`vxlan_ingress`が5,166命令、`l2_egress`が2,277命令、`node_ingress`が70,965命令でした。`pod_egress`が373命令増えたのは`fib_val.type`の分岐で、`vxlan_ingress`と`l2_egress`が増えたのはARP snoopingです。`node_ingress`が109,544命令になったのはNATGatewayの応答をgatewayポートへ渡す分岐です。`l2_ingress`が511から43,781になったのは、Serviceの書き戻しとpolicyの評価です。`l2_gateway`はその2つを一度預かって132,527まで行きましたが、ノードを間違えていたので`l2_ingress`へ移し、2,709に戻りました。そこから3,488になったのは能動的なARPの分です。`l2_egress`が2,786から3,493、`vxlan_ingress`が5,282から5,785になったのは、gateway宛のARPリプライを他のNodeへ配る分と、受け取った側で捨てる分です。

聞いたNodeへのユニキャストを入れて、`vxlan_ingress`が5,785から5,945、`l2_gateway`が3,488から3,484、`l2_egress`が3,493から**3,455**になりました。**2本は減っています。**`l2_arp_snoop`が返り値をやめて`struct l2_arp_view`に書くようになり、リモートへの複製が`l2_send_over_overlay`に切り出されたので、verifierの歩き方が変わったためです。`vxlan_ingress`は発火しないtraceのemitを消したときにも5,675から増えました。呼び出しが1つ減って分岐が単純な`return`になり、後続を歩き直す形が変わったためです。**命令数は書いた行数では決まりません。**増減に驚かず、上限に収まっているかだけを見てください。`vxlan_ingress`はL2分岐を入れる前が3,760命令(0.4%)でした。

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

聞いたNodeへのユニキャストにも同じ問題があります。ダミーデバイスはフレームの数を数えるだけで、押されたトンネルキーについては何も言いません。`TestTheAnswerCrossesTheOverlayToTheNodeThatAsked`は`l2_egress`と`vxlan_ingress`を1つのpin pathに読み込み、本物のVXLANデバイスを`127.0.0.1`に向けて質問と答えを一周させます。`l2_bum_remote`は空にしてあるので、overlayに出る道はユニキャスト1つだけです。答えが戻ってくると`vxlan_ingress`がホストのMACを「あのNodeにいる」と学習し直すので、`l2_fdb`のそのエントリがローカルのifindexからVTEPに変わったことが、トンネルキーが記録どおりのNodeとVNIを指していた証拠になります。

`TestGatewayCarriesAClusterIPFlowBothWays`は同じ足回りでServiceの往復を通します。往路は`pod_egress`をgw vethのifindexで走らせてDNATと逆向きエントリの記録まで、復路は`l2_ingress`にワークロードのポートで応答を渡してアドレスが戻ることまでです。2つのプログラムは`ct_map`でしか出会わないので、片方だけのテストでは「同じscopeを見ているか」が確かめられません。1つのpin pathに両方を読み込むのはそのためです。

`l2_ingress`側のテストは、記録が無い状態も明示的に通します。gateway由来のフレームが`ct_map`にも`policy_ct_map`にも何も無いまま来たら、書き戻しは起きず、ingressルールが素で判定します。これがクロスノードの不具合が取っていた形で、同一ノードのテストだけでは一度も出ませんでした。セグメントの中のフレームが同じルールで落ちないことも並べて押さえてあります。

セグメントもgatewayポートも、テストが自分で並べるのをやめました。`newL2Segment`は`reconciler.L2Network`に、`StandUpGatewayPort`は`reconciler.L2Gateway`にReconcileさせています。前者は`l2_arp`を作り忘れているのを誰も見つけられなかったから、後者は`subnet_map`を書き忘れたまま`l2_gateway`がそれを読み始めて、IPv4のテストが揃って落ちたからです。どちらもテストが本番と同じ経路でmapを用意していれば出なかった話です。

rootが要るテストは`bpftest.Require`が入口で止めます。`go test -short`とroot以外の実行ではskipします。
