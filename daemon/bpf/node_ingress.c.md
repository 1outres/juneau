- Nodeのメインのインターフェースにつく
- ExternalNetwork(AddressPools)のグローバルIPアドレスに対する通信が来る想定
- BGP ECMPでルーティングされている

# Functions

## tc_node_ingress

1. handle_l2関数を呼び出し、その返り値を返す

## handle_l2

1. L2ヘッダーのパースを行う
2. ARPパケットだったら、handle_external_arp関数を呼び出し、その返り値を返す
3. IPv4パケット以外だったら、TC_ACT_OKを返す
4. handle_l3関数を呼び出し、その返り値を返す

## handle_external_arp

1. Ethernet/IPv4のARP Requestとしてパースする。それ以外のARPだったらTC_ACT_OK
2. external_arp_table mapを(skb->ifindex, 要求されたIPアドレス)で引く
3. 見つからなかったらTC_ACT_OK
4. 見つかったら、そのMACアドレスでARP Replyに書き換えてskb->ifindexにbpf_redirect

マップミスをTC_ACT_SHOTにしない理由: このプログラムは物理NICにつく。
SHOTするとノード自身のInternalIP宛のARPまで落ちてノードが到達不能になる。
juneauが引き受けないアドレスはホストスタックに委ねる。

traceイベントを出さない理由: trace_emit_*_l3はL3タプル(protocol/saddr/daddr/port)を
前提としており、ARPフレームには対応する値がない。
プログラミング内容の確認は `kubectl juneau bpf dump external_arp_table` で行う。

## handle_l3

1. L3ヘッダーのパースを行う
2. 宛先IPアドレスでexternal_address_pools mapを引く
3. 見つからないもしくはvalueが0だったらTC_ACT_OK
4. nat_dnat_mapを引く
5. 見つからなかったらTC_ACT_SHOT
6. nat_dnat_mapを引いた結果も含めてhandle_dnatに渡す

## handle_dnat
1. subnet_mapを引く
2. 宛先IPアドレスを結果のaddrに書き換える
3. arp_table mapを引く
4. エントリが見つからなかった場合はTC_ACT_SHOT
5. 宛先MACアドレスを結果のmacに書き換える
6. 送信元MACアドレスをgw_macで書き換える
7. forward_l2に渡す

## forward_l2

1. fdb mapを引く(macは宛先macaddr)
2. fdp mapになかったらドロップ
3. ifindexが0じゃなかったら、そのifindexにbpf_redirect
4. ifindexが0だったら
5. vxlan_ifindex mapを引く
6. vtep_ipを使ってbpf_skb_set_tunnel_key（VNIはsubnet_id）して、vxlan ifindexにbpf_redirectする

