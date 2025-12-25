- ホストのifaceから出るパケットを見る（ホストからコンテナネットワークへの疎通性を確保するためのiface）
- Host ifaceのveth peerのingressにアタッチするが、実質hostのegressを見る形になる
- ドロップすると書かれている場合、TC_ACT_SHOTを返す。

# Functions

## tc_host_egress

1. handle_l2関数を呼び出し、その関数の返り値を返す

## handle_l2

1. L2ヘッダーのパースを行う
2. ARPリクエストの場合、handle_arp関数を呼び出し、その関数の返り値を返す
3. fdb mapを引く(subnet_idは1、macは宛先macaddr)
4. fdb mapになかったらドロップ
5. ifindexが0じゃなかったら、そのifindexにbpf_redirect
6. ifindexが0だったら
7. vxlan_ifindex mapを引く
8. vtep_ipを使ってbpf_skb_set_tunnel_key（VNIは1）して、vxlan ifindexにbpf_redirectする

## handle_arp

1. ARPペイロードのパースを行う
2. arp_table mapを引く(subnet_idは1、ipaddrはARP対象のIP)
3. arp_tableにみつからない場合ドロップ
4. エントリが見つかった場合、ARPレスポンスとして返す(bpf_redirectを使う)
