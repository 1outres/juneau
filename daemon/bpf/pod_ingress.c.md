- Pod の host 側 veth peer の egress (= Pod に向かうパケット) にアタッチする
- Service の reverse SNAT を一手に担う(forward DNAT は pod_egress 側)
- 宛先 Pod 側の policy (NetworkACL ingress / SecurityGroup ingress) を評価する
- ドロップすると書かれている場合、TC_ACT_SHOT を返す
- 非対象 (IPv4 でない、subnet/vpc 解決不可、TCP/UDP/ICMP のいずれでもない) のパケットは TC_ACT_OK で通過させる
- CT miss は reverse SNAT が起きないだけで、policy の評価はそのまま走る

# Functions

## tc_pod_ingress

1. handle 関数を呼び出し、その返り値を返す

## handle

1. L2 ヘッダーをパース。IPv4 でなければ TC_ACT_OK
2. ifindex_subnet → subnet_id → subnet_map で vpc_id を解決(失敗なら TC_ACT_OK)
3. apply_reverse_snat に渡す
4. apply_reverse_snat の戻り値が -1 なら TC_ACT_SHOT
5. apply_policy に hook = POLICY_HOOK_POD_INGRESS で渡す。reverse SNAT の後に呼ぶので、policy は Pod から見える peer (Service 応答なら書き戻された ClusterIP) を評価する
6. apply_policy の戻り値が負なら TC_ACT_SHOT、それ以外は TC_ACT_OK

## apply_reverse_snat

1. パケットから iph と L4 port を読む
2. TCP/UDP 以外、もしくはポート読み取り失敗なら 0 を返す(SNAT なし)
3. ct_map を 5-tuple (vpc_id, saddr, daddr, sport, dport, proto) で引く
4. miss、もしくは action が CT_ACTION_SNAT 以外なら 0 を返す
5. cv->last_seen_ns を更新し、cv の new_saddr / new_sport を読み取り
6. nat_rewrite_ipv4_addr で src IP を書き換え、nat_rewrite_l4_port で src port を書き換え
7. いずれかの rewrite 失敗で -1 を返す

## apply_policy (policy.h、pod_egress と共通)

pod_egress と同じ関数で、hook 引数だけが違う。hook は呼び出し側で定数なので、hook による分岐はコンパイル時に畳まれる。

hook = POLICY_HOOK_POD_INGRESS のとき、self (守る側の Pod) は daddr、peer は saddr。ACL は ACL_DIR_INGRESS、SG は SG_DIR_INGRESS で評価する。

手順は pod_egress.c.md の apply_policy を参照。
