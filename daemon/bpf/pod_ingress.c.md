- Pod の host 側 veth peer の egress (= Pod に向かうパケット) にアタッチする
- Service の reverse SNAT を一手に担う(forward DNAT は pod_egress 側)
- ドロップすると書かれている場合、TC_ACT_SHOT を返す
- 非対象 (CT miss、IPv4 でない、TCP/UDP でない、subnet/vpc 解決不可) のパケットは TC_ACT_OK で通過させる

# Functions

## tc_pod_ingress

1. handle 関数を呼び出し、その返り値を返す

## handle

1. L2 ヘッダーをパース。IPv4 でなければ TC_ACT_OK
2. ifindex_subnet → subnet_id → subnet_map で vpc_id を解決(失敗なら TC_ACT_OK)
3. apply_reverse_snat に渡す
4. apply_reverse_snat の戻り値が -1 なら TC_ACT_SHOT、それ以外は TC_ACT_OK

## apply_reverse_snat

1. パケットから iph と L4 port を読む
2. TCP/UDP 以外、もしくはポート読み取り失敗なら 0 を返す(SNAT なし)
3. ct_map を 5-tuple (vpc_id, saddr, daddr, sport, dport, proto) で引く
4. miss、もしくは action が CT_ACTION_SNAT 以外なら 0 を返す
5. cv->last_seen_ns を更新し、cv の new_saddr / new_sport を読み取り
6. nat_rewrite_ipv4_addr で src IP を書き換え、nat_rewrite_l4_port で src port を書き換え
7. いずれかの rewrite 失敗で -1 を返す
