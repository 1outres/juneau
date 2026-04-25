- Podから出るパケットを見る
- Podのveth peerのingressにアタッチするが、実質podのegressを見る形になる
- ドロップすると書かれている場合、TC_ACT_SHOTを返す。

# Functions

## tc_pod_egress

1. handle_l2関数を呼び出し、その関数の返り値を返す

## handle_l2

1. L2ヘッダーのパースを行う
2. ifindex_subnet mapを引く(key: skb->ifindex)
3. subnet_mapを引く
4. ARPリクエストの場合、handle_arp関数を呼び出し、その関数の返り値を返す（handle_arp関数にはsubnet_idとsubnet_mapのvalも渡す）
5. subnet_idが1の場合、host_iface mapを引いて、ifindexにbpf_redirectする
6. subnet_idが1以外、IPv4の場合、apply_conntrack_dnatを呼び出す
   - DNATが適用されたらdispatch_after_dnatに渡して終了(dst IPが書き換わったのでFIB再lookup必要)
   - DNAT非該当(CT miss、もしくはCT actionがDNAT以外) → fall through
7. もし対象がgw_macだったらhandle_l3関数を呼び出し、その関数の返り値を返す(subnet_idとsubnet_mapのvalも渡す)
8. そうじゃなかったらforward_l2関数を呼び出し、その返り値を返す(subnet_idとsubnet_mapのvalも渡す)

## apply_conntrack_dnat

forward方向(caller→ClusterIP)のDNATのみを担当する。reverse SNATはpod_ingress側で行う(同一node・別nodeを問わず宛先veth上で発火)。

1. TCP/UDP以外は0を返す(rewriteしない)
2. ct_mapをパケットの5-tuple (vpc_id=subnet->vpc_id, saddr, daddr, sport, dport, proto) で引く
3. miss、もしくは action != DNAT → 0
4. cv->last_seen_ns更新、dst IPとdst portを書き換え、1を返す
5. rewrite失敗で-1を返す

## forward_l2

1. fdb mapを引く(macは宛先macaddr)
2. fdp mapになかったらドロップ
3. ifindexが0じゃなかったら、そのifindexにbpf_redirect
4. ifindexが0だったら
5. vxlan_ifindex mapを引く
6. vtep_ipを使ってbpf_skb_set_tunnel_key（VNIはsubnet_id）して、vxlan ifindexにbpf_redirectする

## handle_arp

1. ARPペイロードのパースを行う
2. 対象のIPアドレスが範囲内かどうか、gw_addrとmaskを使って範囲判定する。範囲外の場合ドロップする。
3. subnet_idが1の場合、gw_macをARPレスポンスとして返す(bpf_redirectを使う)
  - dst macをrequester mac, source macをgw_mac
  - thaをrequester mac, tpaをrequester ip, shaをgw_mac, spaを元のtpa
4. subnet_idが1以外の場合、もし対象がgw_addrだったらgw_macをARPレスポンスとして返す(bpf_redirectを使う)
5. そうじゃなかったらarp_table mapを引く
6. arp_tableに見つからない場合ドロップ
7. エントリが見つかった場合、ARPレスポンスとして返す(bpf_redirectを使う)

## handle_l3

1. IPヘッダーのパースを行う
2. fib_mapをlongest matchで引く(table_idはifindex_subnet mapにあるやつ、宛先ipaddr)
3. 見つからなかったらドロップ
4. fib_val.type が CONNECTED の場合、宛先ipaddrのarp mapを引く(ここのsubnet_idは、mapを引いたvalのsubnet_idを使う)
5. arp mapに見つからなかったらドロップ
6. パケットのdmacをarp mapの結果で書き換える
7. パケットのsmacをfib_val.smacで書き換える
8. forward_l2にfib_val.subnet_idを渡す
9. fib_val.type が ENDPOINT の場合、パケットのdmacをfib_val.dmacで書き換える
10. パケットのsmacをfib_val.smacで書き換える
11. forward_l2にfib_val.subnet_idを渡す
12. fib_val.type が INTERNET_GATEWAY の場合、handle_snatに渡す
13. fib_val.type が SERVICE の場合、handle_serviceに渡す

## handle_service

1. パケットからsport/dportを読む
2. service_mapを (cluster_ip=daddr, port=dport, proto) で引く
3. 見つからない、もしくは sv->owner_vpc_id != caller_vpc_id ならドロップ
4. backend_count が 0 ならドロップ
5. 5-tupleからhashを計算し、idx = hash % backend_count を求める
6. backend_mapを (cluster_ip, port, proto, idx) で引く
7. 見つからなかったらドロップ
8. ct_mapに forward(=DNAT) と reverse(=SNAT) のエントリを登録する
9. パケットの宛先IP/portをbackendに書き換える
10. dispatch_after_dnatに渡す(table_idは subnet->table_id、宛先IPはbackendのIP)

## dispatch_after_dnat

1. fib_mapをbackend宛先で再lookup
2. fv->type に応じて CONNECTED / ENDPOINT / INTERNET_GATEWAY の処理を行う(SERVICEヒットはドロップ)

## handle_snat

1. nat_snat_mapを引く(送信元IPアドレスとsubnet_id)
2. 見つからなかったらTC_ACT_SHOT
3. 送信元IPアドレスをaddrで置き換える
4. ifindex_host_macを引いて、dmacを置き換える
5. OSに渡す(TC_ACT_OK)
