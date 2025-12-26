- Podから出るパケットを見る
- Podのveth peerのingressにアタッチするが、実質podのegressを見る形になる
- ドロップすると書かれている場合、TC_ACT_SHOTを返す。

# Functions

## tc_pod_egress

1. handle_l2関数を呼び出し、その関数の返り値を返す

## handle_l2

1. L2ヘッダーのパースを行う
2. ifindex_subnet mapを引く(key: skb->ifindex)
3. ARPリクエストの場合、handle_arp関数を呼び出し、その関数の返り値を返す（handle_arp関数にはifindex_subnet mapのvalも渡す）
4. subnet_idが1の場合、host_iface mapを引いて、ifindexにbpf_redirectする
5. subnet_idが1以外の場合、もし対象がgw_macだったらhandle_l3関数を呼び出し、その関数の返り値を返す(ifindex_subnet mapのvalも渡す)
6. そうじゃなかったらforward_l2関数を呼び出し、その返り値を返す(ifindex_subnet mapのvalも渡す)

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
2. fib_mapをlongest matchで引く(subnet_idと宛先ipaddr)
3. 見つからなかったらドロップ
4. dmacが0だったら、宛先ipaddrのarp mapを引く(ここのsubnet_idは、mapを引いたvalのsubnet_idを使う)
5. パケットのdmacを、dmac(0じゃなかった場合)もしくはarp mapの結果で書き換える
6. パケットのsmacを、smacで書き換える
7. dmacが0じゃなかった場合、oifにbpf_redirectする。0だったら、forward_l2に渡す
