# NetworkACLとSecurityGroupの評価を追う

JuneauのNetworkACLとSecurityGroupは、どちらもPodのNICのところでeBPFが評価します。このドキュメントでは、その評価がどこで何回走るのか、conntrackがどうステートフル性を作っているのか、ルールを書き換えたときに既存フローがどう扱われるのかを説明します。

利用者向けの手順は[SecurityGroupでPodの通信を制限する](../guides/security-group.md)と[NetworkACLでSubnet境界を制御する](../guides/network-acl.md)にあります。ここではその下で動いているものだけを扱います。

## 2つのenforcement point

policyを評価する場所は2つだけです。どちらもPodのhost側vethに付いているので、評価はPodのNIC単位になります。

| enforcement point | アタッチ先 | 見るパケット | ソース |
|---|---|---|---|
| `pod_egress` | Podのhost側vethのTC ingress | そのPodから出ていくパケット | `daemon/bpf/pod_egress.c` |
| `pod_ingress` | Podのhost側vethのTC egress | そのPodに入っていくパケット | `daemon/bpf/pod_ingress.c` |

Pod間の通信では、1つのパケットが送信元Podのegressと宛先Podのingressの両方を通ります。同一Nodeでも別Nodeでも同じで、別Nodeの場合はあいだにVXLANが挟まるだけです。`vxlan_ingress`は宛先Podのvethに`bpf_redirect(ifindex, 0)`で渡すため、そのvethのegress側、つまり`pod_ingress`を経由します。

```
[Pod X] ──▶ host側veth(X)                        host側veth(Y) ──▶ [Pod Y]
            TC ingress: pod_egress               TC egress: pod_ingress
            ACL egress → SG egress               ACL ingress → SG ingress
                  │                                    ▲
                  ├── 同一Node: bpf_redirect ──────────┤
                  └── 別Node: VXLAN → vxlan_ingress ───┘
```

相手がPodでない場合 (外部アドレス、host networkのbackendなど) は、Pod側の1か所しか通りません。NATGateway経由で外に出る通信は送信元の`pod_egress`だけで判定されます。

評価の本体は`daemon/bpf/policy.h`の`apply_policy`1つで、2つのhookで共有しています。hookが決めるのは次の4点だけです。

| | `POLICY_HOOK_POD_EGRESS` | `POLICY_HOOK_POD_INGRESS` |
|---|---|---|
| self (守る側のPod) | saddr | daddr |
| peer (相手) | daddr | saddr |
| ACLのdirection | egress | ingress |
| SGのdirection | egress | ingress |

hookは呼び出し側で定数なので、この分岐はコンパイル時に畳まれます。生成されるのはhookごとの分岐の無い一本道のコードで、実行時にhookを見て分かれることはありません。

## 評価順とdefaultの違い

`apply_policy`はNetworkACLを先に、SecurityGroupを後に評価します。粗い方から順に落とす形です。どちらかがDENYを返した時点でパケットは捨てられ、trace上ではACLとSGのどちらが落としたかが区別されます。

NetworkACLはSubnetに紐付いていて、`subnet_map.acl_id`から引きます。

- `acl_id == 0` (Subnetに紐付いていない) ならPASS。mapは一切引きません
- そのdirectionにルールが1つも無い (`has_ingress_rules` / `has_egress_rules`が0) ならdefault-allowでPASS
- ルールがある場合はそのdirectionの区画をpriority昇順に前から走査し、最初にマッチしたルールのverdictで確定します。どれにもマッチしなければ暗黙のdeny

SecurityGroupはNICに紐付いていて、`sg_membership_map`を`(vpc_id, pod_ip)`で引きます。

- selfにSGが1つも付いていなければ評価自体をスキップします (PASS)
- 付いているSGのいずれかのルールがマッチしてallowならALLOW
- ingressは、マッチするルールが無ければDENY。ルールが0件でもDENYです
- egressは、付いているSGのどれもegressルールを持っていなければdefault-allowでPASS。1つでも持っていて、かつマッチしなければDENY

ルールが0件のときの結論が層で違う点に注意してください。ACLはdirectionごとにルールの有無でdefaultが変わります。SGのingressはルールが0件でもdenyのままで、egressだけがAWSのdefault-allowに合わせてあります。

マッチ条件も層で違います。ACLはpeerのIPとdportとprotocolだけを見ます。SGはCIDRに加えてpeerのSecurityGroup参照 (`securityGroupRef`) をマッチできます。peerのSG集合は`sg_membership_map`をpeerのIPで引いて得るので、peerがPodでなければSG参照ルールはマッチしません。

## ルール配列と方向ごとの区画

ユーザが書くルールと、data planeが持つエントリは1対1ではありません。ルール配列に入るのは「1つのprotocol、1つのport (または範囲)、1つのpeer」だけを見る平坦なエントリで、daemonはルールをその直積に展開してから書き込みます。

- NetworkACLのルールはCIDRを1つとportのリストを持つので、portの数だけ展開されます
- SecurityGroupのルールはpeerのリストとportのリストを持つので、その両方で展開されます

portを省略したルールは「全port」の1エントリ、peerを省略したルールは「全peer」の1エントリになります。どちらも0にはならないので、コストは`max(1, ...)`を掛け合わせた値です。

配列はdirectionごとに区画が分かれています。ingressがスロット`[0, PER_DIR)`、egressが`[PER_DIR, PER_DIR * 2)`です。

| | 1directionあたり | 配列全体 |
|---|---|---|
| NetworkACL (`MAX_ACL_RULES_PER_DIR`) | 16 | 32 |
| SecurityGroup (`MAX_SG_RULES_PER_DIR`) | 8 | 16 |

`acl_evaluate`と`sg_eval_one_sg`はdirectionから`base`を決めて、`base + i`のスロットを`meta`のdirection別カウントの分だけ走査します。自分の区画しか見ないので、エントリ側の`direction`フィールドを見て弾く必要はありません (フィールド自体は`bpftool map dump`の可読性のために残してあります)。ループの上限は`MAX_*_PER_DIR`のままなので、配列が倍になってもverifierが歩く経路の数は増えていません。

区画に分ける前は1本の配列を両方向で共有していました。`ExpandNetworkACL`がdirection昇順に並べるのでingressが先に埋まり、ingressが16エントリ使うとegressのエントリは配列に入りきらずに切り落とされます。それでも`egress_count`は元の値のままなので、評価側はegressのルールを1つも見つけられないまま終端のdenyに落ちます。CRDは`Ready=True`のまま、そのSubnetのegressだけが黙って全遮断になる、というのがissue #52です。

いまは3か所で塞いであります。

1. 上限を超えるNetworkACL / SecurityGroupは、作成・更新の時点でwebhookが拒否します。数え方は`controller/api/v1alpha1/policy_capacity.go`に1つだけ置いてあり、webhookもcontrollerもdaemonも同じ関数を見ます
2. storeは切り落としをしません。区画に入らないdirectionはfail-closedで入れます。エントリは0本、ただし「このdirectionはルールを持っている」という状態にするので、評価側はそのdirectionだけ終端のdenyに落ちます。もう片方のdirectionは普通に入ります
3. `Apply`は書き込んだあとに`CapacityError`を返します。reconcilerはError levelでログに出してから`nil`を返します。入らない仕様は恒久的な状態で、rate limiterで再試行しても直らないからです

SGのegressをfail-closedにするには`has_egress_rules = 1`と`egress_count = 0`の組が要ります。`sg_meta_val`にingress側のフラグは無いのですが、SGのingressは元からdeny-by-defaultなので`ingress_count = 0`がそのままfail-closedになります。

SGの1directionあたり8という数字は測って決めたものです。16に上げると`tc_pod_egress`が1,000,000命令を超えてロード自体に失敗します。1つのNICには`MAX_SGS_PER_NIC`個のSGを付けられるので、SGの走査量は`MAX_SGS_PER_NIC * MAX_SG_RULES_PER_DIR`で効きます。Subnetに紐付くACLは1つなので、ACL側は16でも収まる、という差です。上げたくなったらまず`make -C daemon verifier-check`を回してください。

## policy_ct_mapによるステートフル化

admissionが成立すると、`apply_policy`は`policy_ct_install`を呼んで`policy_ct_map`に2エントリ書きます。

- 順方向: `(epoch, hook, vpc_id, saddr, daddr, sport, dport, proto)`
- 逆方向: tupleを反転し、hookを相手側のenforcement pointに置き換えたもの

keyにhookが入っているので、エントリは「このenforcement pointがこのフローを許可した」という意味を持ちます。他のhookが書いたエントリを拾うことはありません。次のパケットからは、そのhookでのlookupがヒットして層ごとのルール走査を飛ばします。応答パケットは、それを許可したhookが自分で書いた逆向きエントリで短絡します。

短絡したときにやるのは`last_seen_ns`の更新と、TCPならflagsの取り込みと状態遷移だけです。CLOSEDまで進んだら、そのhookが入れた2エントリをその場で消します。他方のhookのエントリには触りません。相手側のhookは同じhandshakeを自分で見て、自分のエントリを閉じます。

エントリを書く条件は「どちらかの層がenforcingであること」で、`acl_id != 0` または selfにSGが1つ以上付いている、のいずれかです。どちらも該当しないフローにはエントリを作りません。誰も取り締まっていないフローの状態を持っても引くことがないからです。

この条件は層が付いているかどうかだけで決まります。ルールがallowを返したかどうかは見ていません。SGが付いていてegressルールが1つも無いPodは、egressの判定こそdefault-allowのPASSですが、CTは書かれます。書かないと、応答パケットが自分の`pod_ingress`でingressのdefault-denyに当たって落ちてしまいます。

## なぜkeyにhookが要るのか

これがIssue #51の中身です。同一Node上のPod同士が通信すると、2つのenforcement pointが同じconntrackテーブルを共有します。keyがhookを持っていないと、次のことが起きます。

1. XのegressがX→Yを許可し、`(X→Y)`と`(Y→X)`を書く
2. 同じパケットがYの`pod_ingress`に届く
3. Yのingressが`(X→Y)`を引いてヒットする。Xのegressが書いたエントリなのに、Yのingressは「自分が既に許可したフロー」として短絡する
4. Yのingressルールは一度も評価されない

別Nodeなら受信側Nodeのテーブルには何も無いので、Yのingressルールが正しく走ってDENYになります。つまりPodの配置によってpolicyの結果が変わっていました。同一Nodeなら通り、別Nodeなら落ちる、というスケジューラ依存の挙動です。

keyにhookを入れると、同じフローについて誰が書いたのかが分かれた4エントリになります。

| key | 書いた側 | 使われる場面 |
|---|---|---|
| `(POD_EGRESS, X→Y)` | Xのegress admission | X→Yの後続パケットがXのegressで短絡する |
| `(POD_INGRESS, Y→X)` | Xのegress admission | Y→Xの応答がXのingressで短絡する |
| `(POD_INGRESS, X→Y)` | Yのingress admission | X→Yの後続パケットがYのingressで短絡する |
| `(POD_EGRESS, Y→X)` | Yのingress admission | Y→Xの応答がYのegressで短絡する |

同一Nodeなら4エントリが1つのテーブルに並び、初回パケットはX egressのACL/SGとY ingressのACL/SGの4層を全部通ります。別Nodeなら送信側Nodeに上2行、受信側Nodeに下2行ができます。どちらでも判定結果は同じです。

同一Nodeで1フローあたり4エントリ、別Nodeで各Node2エントリという見積もりが、`MAX_POLICY_CT_MAP` (262144) の根拠になっています。ルールを変えた直後だけは、前の世代のエントリと新しい世代のエントリがGC1周分 (30秒) だけ同居します。

## NAT用のct_mapと分けている理由

`policy_ct_map`はNATの`ct_map`とは別のmapです。同居させない理由が2つあります。

1つ目は上書きです。`ct_map`はNATの書き換え状態を持つテーブルで、Serviceのforward DNATやreverse SNAT、NAPT、LoadBalancerの各経路が`BPF_ANY`で更新します。policyのadmissionが同じkeyspaceにいると、そのフローがNATも必要になった瞬間にpolicyのエントリが上書きされて消えます。

2つ目は、その上書きを見越した握り潰しです。以前は`CT_ACTION_POLICY_PASS`という専用のactionでpolicyのadmissionを`ct_map`に入れていましたが、`ct_map`のlookupがヒットした場合はactionが何であっても評価をスキップして戻っていました。Serviceのエントリを引いた場合も許可済みとして扱う形です。これでpolicyのエントリがNATに潰されても通信は落ちなくなりますが、代わりにNATが絡むフローがpolicyの評価をすり抜けます。

テーブルを分けたことで、どちらの問題も消えました。`CT_ACTION_POLICY_PASS`だった9番は欠番にしてあります。古いmap dumpに9が残っているので再利用してはいけません。

TCPの状態機械は`daemon/bpf/ct.h`に1つだけ置いて両方のテーブルで共有しています。stateの意味が揃っているので、ユーザ空間のGCも1つで両方を掃除できます。

## ルールを変えたときの既存フロー

`policy_ct_map`のエントリはadmission時点の判定結果です。ルールを書き換えたら、それを捨てなければ古い判定が残り続けます。エントリを全部走査せずにこれをやるのが`policy_epoch_map`です。

`policy_epoch_map`はindex 0に`__u32`を1つ持つだけのARRAYで、data planeが今どの世代のルールを適用しているかを表します。この値は`policy_ct_key`の先頭フィールドでもあり、admissionもlookupもその時点の世代を含んだkeyを組み立てます。世代を1つ進めると、以後のlookupは誰も書いていないkeyを引くことになるので、それ以前のadmissionが全部まとめて無効になります。

daemon側で世代を進める (bumpする) のは次の場合です。

- NetworkACLのルール内容が変わった / NetworkACLが消えた (`policy/aclstore.go`)
- SecurityGroupのルール内容が変わった / SecurityGroupが消えた (`policy/sgstore.go`)
- SGのmembershipが変わった / 消えた (`policy/membership.go`)

順番が決まっていて、ルールをmapに反映してからbumpします。`Rotator`が新しいinner mapを作って`HASH_OF_MAPS`のスロットを丸ごと差し替えるので、data planeが中途半端なrulesetを見ることはありません。その後でbumpするため、再評価は必ず新しいルールに対して行われます。

informerのresyncは同じ`RuleSet`を定期的に流し直します。ここでbumpするとNode上の全フローが意味もなく再評価されるので、`invalidator`が前回インストールした内容と比較して、同じなら何もしません。membershipも同様にowner単位のsnapshotと比較します。deleteだけは内容比較せず常にbumpします。ルールが減るのは確実で、頻度も低いからです。

bump後の最初のパケットは新しい世代のkeyで引くので、必ずmissします。層の評価をやり直して、まだ許可されるなら新しい世代のkeyで2エントリを書き直します。DENYになった場合とどの層もenforcingでなくなった場合は、何も書かずに終わります。

前の世代のエントリにはdata planeから触りません。どのhookからも引けないので判定に影響せず、`reconciler.Conntrack`のGCが次の走査で消します。パケットが二度と来ないフローも同じ扱いなので、ゴミの寿命はGC間隔で頭打ちになります。

daemonの再起動時は`Manager.Start`がpin pathごと消してからprogramをロードするので、mapは作り直されます。それでも`NewEpoch`はカウンタを読んでから`previous + 1`を発行します。pinが生き残る構成になったとしても、前のdaemonが許可したフローを引き継がないようにするためです。daemonが落ちているあいだにルールが変わっていたかもしれないので、捨てる側に倒してあります。

## なぜepochをkeyに入れるのか

最初はepochを`policy_ct_val`に持たせていました。lookupがヒットしたあとに値を比較して、世代が違えばmiss扱いにし、再評価でDENYになったらそのエントリをその場で消す、という形です。読む分にはこちらの方が素直で、ゴミも即座に消えます。ただしverifierが通りませんでした。

BPFのverifierは1プログラムあたり1,000,000命令まで探索します。`tc_pod_egress`はIssue #51に着手する前の時点で643,497命令、hookごとのkeyspaceを入れて662,664命令なので、余裕はもともと3割ほどしかありません。ここに「古いエントリを引いた」というフラグを足すと、ACLとSGの評価区間を通してそのフラグが生きるため、verifierがその区間を2回歩きます。`tc_pod_ingress`が364,672から704,657に増えました。削除処理をnoinlineのsubprogramに切り出す形も試しましたが、こちらは`tc_pod_egress`が1,000,000を超えてロード自体に失敗しました。巨大な`tc_pod_egress`にインライン展開された経路の途中から、スタックポインタを引数に取るBPF-to-BPF callを出すと状態探索が爆発します。e2eクラスタではCNI daemonがcrashloopしました。

epochをkeyに移すと、古い世代のエントリはlookupがそのままmissします。比較も削除も要らないので、data planeの分岐は1つも増えません。当時の実測は`tc_pod_egress`が662,664命令、`tc_pod_ingress`が366,103命令で、value側epochを入れる前と変わりませんでした。引き換えに到達不能なエントリが残りますが、その回収はGCに任せました。

「ここで消した方が綺麗では」と思ったら、先に数字を測ってください。`make -C daemon verifier-check`が4つのプログラムを実機カーネルにロードして、消費した命令数を出します。`bpf/`以下を触ったら実行してください。

## いまのverifier予算

directionごとの区画に分けたあとの実測です。上限は1プログラムあたり1,000,000命令です。

| object | 命令数 | 上限に対する割合 |
|---|---|---|
| `pod_egress` | 682,460 | 68.2% |
| `pod_ingress` | 247,476 | 24.7% |
| `vxlan_ingress` | 3,760 | 0.4% |
| `node_ingress` | 70,965 | 7.1% |

`pod_egress`が一番きつく、ここが天井に当たるかどうかで判断します。`MAX_SG_RULES_PER_DIR`を8から16に上げる案はこの数字で落ちました。

## エントリの寿命

`policy_ct_map`は`BPF_MAP_TYPE_HASH`です。LRUではないので、埋まってもカーネルが古いエントリを追い出すことはありません。回収は`reconciler.Conntrack`のGCが唯一の経路です。

GCは`ConntrackGCInterval` (30秒) ごとに`ct_map`と`policy_ct_map`の両方を走査し、`ctstate.ShouldEvict`が真になったエントリを消します。TTL判定は両テーブル共通です。

`policy_ct_map`にはもう1つ判定があって、keyの`epoch`が現在の世代と違うエントリはTTLの残りに関係なく落とします。到達不能になったエントリを、TTL (established TCPなら1時間) まで抱えないためです。走査は元から全エントリを回っているので、追加コストは比較1回分です。

| 状態 | TTL |
|---|---|
| `CT_STATE_CLOSED` | 即時 |
| TCP `CT_STATE_NEW` | 120秒 |
| TCP `CT_STATE_ESTABLISHED` | 1時間 |
| TCP `CT_STATE_FIN_WAIT` | 60秒 |
| UDP | 60秒 (stateによらず) |
| ICMP | 30秒 |
| その他 (GRE、ESPなど) | 120秒 (stateによらず) |

`last_seen_ns`は`bpf_ktime_get_ns`、GC側は`clock_gettime(CLOCK_MONOTONIC)`で、同じ時計を見ています。短絡するたびに`last_seen_ns`が更新されるので、流れているフローがTTLで消えることはありません。

CLOSEDになったTCPのエントリは、FINやRSTを見たhookが`policy_ct_observe_tcp`の中で消します。GCが拾うのはその取りこぼしと、片方向しか閉じなかったフローです。

mapが埋まると新しいフローはエントリを持てません。順方向はパケットごとに層の評価が走るだけですが、応答パケットは短絡できなくなるので、ingressがdeny-by-defaultのPodでは応答が落ちます。

## 観測する

`policy_ct_map`はmap inventoryに登録してあるので、そのままdumpできます。

```console
$ kubectl juneau bpf dump policy_ct_map --node worker-1
```

keyの`hook`列に`POLICY_HOOK_POD_EGRESS` / `POLICY_HOOK_POD_INGRESS`が出るので、どのenforcement pointが書いたエントリかが分かります。同一Node上のPod間フローなら、前述の4エントリが揃っているはずです。

絞り込みには`--filter name=value`を使います。

```console
$ kubectl juneau bpf dump policy_ct_map --filter hook=POLICY_HOOK_POD_INGRESS --filter daddr=10.80.0.10
```

enum列 (`hook`、`proto`、`state`、`scope`) はラベル文字列でしか比較できません。`proto=TCP`は効きますが、`hook=2`のような数値は一致しません。`scope`はvpc_idに対応するラベルを持たない (0の`CT_SCOPE_HOST`だけ) ので、Vpcで絞りたいときは`saddr`か`daddr`を使ってください。`--node`を付けなければ到達できる全daemonに問い合わせて集約します。

世代カウンタも同じように読めます。

```console
$ kubectl juneau bpf dump policy_epoch_map
```

index 0のエントリが1つ出るだけです。ルールを変更したあとにこの値が動いていなければ、daemonがbumpしていません。値が動いているのに古い判定のままなら、`policy_ct_map`のdumpでkeyの`epoch`列を見てください。短絡に使われているエントリは必ず現在の世代の値を持っています。

パケット単位で追いたい場合はTraceSessionを使います。

```console
$ kubectl juneau trace pod default/curl-allowed \
    --to-pod default/nginx --proto tcp --port 80 --observe-only
```

policyの層ごとのイベント (`acl pass`、`acl drop`、`sg pass`、`sg drop`) がhook付きで出るので、送信元の`pod_egress`と宛先の`pod_ingress`を1つのタイムラインで並べて見ることができます。イベント行の先頭にはNode名とhook名が出ます。

1つ落とし穴があります。`apply_policy`はCTで短絡した時点で戻るので、admission済みのフローではpolicyのイベントが1つも出ません。層の評価を見たいときは新しいフローを張ってください。評価パスに入ったことは`conntrack miss`イベントで確認できます。

## 実装の入口

- `daemon/bpf/policy.h`: `apply_policy`。ACL → SG → CT installの本体
- `daemon/bpf/policy_ct.h`: `policy_ct_map`の読み書き。key構築、両方向install、TCP観測とCLOSE時の削除
- `daemon/bpf/maps.h`: `policy_ct_key` / `policy_ct_val` / `policy_epoch_map`の定義と`POLICY_HOOK_*`、`MAX_ACL_RULES_PER_DIR` / `MAX_SG_RULES_PER_DIR`
- `daemon/bpf/acl.h`、`daemon/bpf/sg.h`: 層ごとのルール走査
- `controller/api/v1alpha1/policy_capacity.go`: エントリ数の数え方とdirectionごとの上限。webhook、controller、daemonが共有する唯一の定義
- `daemon/internal/daemon/dataplane/policy/`: ルールの反映 (`aclstore.go`、`sgstore.go`、`membership.go`、`rotator.go`)、容量判定とfail-closed (`capacity.go`)、世代管理 (`epoch.go`、`invalidator.go`)
- `daemon/internal/daemon/dataplane/reconciler/conntrack.go`、`daemon/internal/daemon/dataplane/ctstate/ttl.go`: GC、TTL、世代の外れたエントリの回収
- `daemon/internal/daemon/dataplane/mapinventory/register.go`: `kubectl juneau bpf`に見せているスキーマ
- `daemon/cmd/verifiercheck/`: `make -C daemon verifier-check`の中身。verifierの命令数を実機で測る
