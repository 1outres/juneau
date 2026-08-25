- Podから出るパケットを見る
- Podのveth peerのingressにアタッチするが、実質podのegressを見る形になる
- 送信元Pod側のpolicy (NetworkACL egress / SecurityGroup egress) を評価する
- ドロップすると書かれている場合、TC_ACT_SHOTを返す。

# Functions

## tc_pod_egress

1. handle_l2関数を呼び出し、その関数の返り値を返す

## handle_l2

1. L2ヘッダーのパースを行う
2. ifindex_subnet mapを引く(key: skb->ifindex)
3. subnet_mapを引く
4. ARPリクエストの場合、handle_arp関数を呼び出し、その関数の返り値を返す（handle_arp関数にはsubnet_idとsubnet_mapのvalも渡す）
5. IPv4の場合、reverse系のconntrack (SVC_NAPT_IN、SVC_SHARED_IN、LB_REV_NAT) を先に処理する。ヒットしたらそこで終了
6. apply_policyにhook = POLICY_HOOK_POD_EGRESSで渡す。apply_conntrack_dnatより前に呼ぶので、各layerはPodが指定した5-tuple (Service宛ならClusterIP) を評価する
   - 戻り値が負ならTC_ACT_SHOT。-1ならACL_DROP、-3ならSG_DROP、-2ならDROP_SHOTをtraceに出す
7. apply_conntrack_dnatを呼び出す
   - DNATが適用されたらdispatch_after_dnatに渡して終了(dst IPが書き換わったのでFIB再lookup必要)
   - DNAT非該当(CT miss、もしくはCT actionがDNAT以外) → fall through
8. もし対象がgw_macだったらhandle_l3関数を呼び出し、その関数の返り値を返す(subnet_idとsubnet_mapのvalも渡す)
9. そうじゃなかったらforward_l2関数を呼び出し、その返り値を返す(subnet_idとsubnet_mapのvalも渡す)

## apply_policy (policy.h、pod_ingressと共通)

NetworkACL → SecurityGroup → CT install を1本にまとめたステージ。hookは呼び出し側で定数なので、hookによる分岐はコンパイル時に畳まれる。

hookが決めるのは4つだけで、残りは両hook共通:

| | POLICY_HOOK_POD_EGRESS | POLICY_HOOK_POD_INGRESS |
| --- | --- | --- |
| self (守る側のPod) | saddr | daddr |
| peer (相手) | daddr | saddr |
| ACL direction | ACL_DIR_EGRESS | ACL_DIR_INGRESS |
| SG direction | SG_DIR_EGRESS | SG_DIR_INGRESS |

1. iphを読む。読めなければ-2
2. TCP/UDPならsport/dportを読む。読めなければ0(policy対象外)。TCP/UDP/ICMP以外も0
3. policy_epoch_map[0]を読み、policy_ct_mapを (epoch, hook, vpc_id, saddr, daddr, sport, dport, proto) で引く
4. ヒットしたら短絡する。last_seen_nsを更新し、TCPならflagsを取り込んで状態を進め(CLOSEDになったらこのhookが入れた2エントリを消す)、0を返す
5. missなら以下の評価に進む
6. MISS_CONNTRACKをtraceに出す
7. acl_evaluateをacl_id、hookに応じたdirection、peerのIPで呼ぶ。DENYなら-1
8. acl_id != 0 ならACL_PASSをtraceに出す
9. sg_membership_mapでselfとpeerのSGリストを引く。selfにSGが1つも付いていなければSGは評価しない(=PASS)
10. sg_evalがDENYなら-3
11. selfにSGが付いていればSG_PASSをtraceに出す
12. acl_id == 0 かつ selfにSGなし(=どのlayerもenforceしていない)なら、CTを入れず0を返す
13. TCPならflagsを読んで初期stateを決める(SYNならNEW、それ以外はESTABLISHED)
14. policy_ct_installで2エントリ書き、1を返す

ルールが変わってepochが動くと、前の世代のエントリはkeyの先頭が違うので 3 のlookupが必ずmissする。data planeはそれを消さない。どのhookからも引けなくなっているだけなので、user spaceのGCが30秒ごとの走査で回収する。消す処理をここに足すとverifierの命令数上限 (1,000,000) を超えてtc_pod_egressがロードできなくなる。理由は policy.h のコメントに書いてある。

## policy_ct_map の keyspace

keyに hook が入るので、enforcement point ごとに別のkeyspaceになる。これが無いと、同一node上のPod間通信で送信元のegressが書いたエントリを宛先のingressが引いてしまい、宛先Podのingress ruleが一度も評価されない。

- Xのegress admission → (POD_EGRESS, X→Y) と (POD_INGRESS, Y→X) を書く
- Yのingress admission → (POD_INGRESS, X→Y) と (POD_EGRESS, Y→X) を書く

同一nodeなら初回パケットは4つのlayer (X egress ACL/SG、Y ingress ACL/SG) を全部通り、応答は各hookが自分で入れた逆向きエントリで短絡する。別nodeでも各nodeに2エントリずつできるだけで、判定結果は同じになる。

keyの先頭には epoch も入っている。ルールを変えるとdaemonがこのカウンタを進めるので、以後のlookupは誰も書いていないkeyを組み立てることになり、admission済みのフローが全部評価し直しになる。

NAT用のct_mapとは別のmapである点も重要で、handle_service系がct_mapを BPF_ANY で上書きしてもpolicyのエントリは壊れない。

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
3. もし対象がgw_addrだったらsubnet->gw_macをARPレスポンスとして返す(bpf_redirectを使う)
4. そうじゃなかったらarp_table mapを引く
5. arp_tableに見つからない場合ドロップ
6. エントリが見つかった場合、ARPレスポンスとして返す(bpf_redirectを使う)

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
14. fib_val.type が HOST_GATEWAY の場合、host_iface mapからcni_hostのMAC/ifindexを取得し、dst_macを書き換えてbpf_redirect(host->ifindex)する。host network stackの routing + iptables MASQUERADEに委譲する経路（default VPCの外部疎通用、暫定的な仕様）

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
4. forward_via_host_fibに渡す

## forward_via_host_fib

VPCの外に出るパケットをhost network stackに渡す共通処理。handle_snat、handle_napt、handle_service_host_remote、LBフローの応答レグ、リモートNodeのunderlay IP宛の応答が使う。

1. bpf_fib_lookupでnext hopを引く(BPF_FIB_LOOKUP_OUTPUTは付けない。付けるとoifがPod側のvethに固定され、そのifindexに対するルートが無いため)
2. SUCCESS と NO_NEIGH 以外はTC_ACT_SHOT
3. SUCCESSの場合、dmacとsmacを書き換えてegress ifindexにbpf_redirect
4. NO_NEIGHの場合、bpf_redirect_neighでkernelのneighborサブシステムに渡す(ARPを送り、応答が来るまでパケットを保持してくれる)

NO_NEIGHでTC_ACT_OKを返してはいけない。Podはフレームの宛先MACにSubnetのgw_macを入れているので、kernelはPACKET_OTHERHOSTとしてルーティング前に捨ててしまう。ARPは送られず、再送しても同じ経路を通るため通信が復旧しない。
