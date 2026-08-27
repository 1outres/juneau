# NetworkACL

NetworkACLは、Subnet単位で適用するステートフルな通信制御ルールの集合です。
SecurityGroupがPod (NetworkInterface) 単位で細かく許可リストを書くのに対し、NetworkACLはSubnetの境界で出入りするトラフィックをまとめて評価します。

各NetworkACLは1つのVpcに属し、SubnetとVpcは同じVpcに属する必要があります。
Subnetに対しては最大1つのNetworkACLを `spec.networkACL` で指定して紐付けます。
両方が有効なときは、まずNetworkACL、続いてSecurityGroupの順で評価され、どちらも通過したトラフィックだけがPodに届きます。

## ルールの基本形

`spec.ingress` はSubnetに**入ってくる**トラフィック、`spec.egress` はSubnetから**出ていく**トラフィックの可否を決めます。各ルールは優先度 (`priority`)、アクション (`action`)、プロトコル、CIDR、ポートで構成されます。

```yaml
apiVersion: juneau.loutres.me/v1alpha1
kind: NetworkACL
metadata:
  name: web-acl
spec:
  vpc: app-vpc
  ingress:
    - priority: 100
      action: allow
      protocol: tcp
      cidr: 10.0.0.0/24
      ports:
        - port: 80
        - portRange:
            from: 8000
            to: 8999
    - priority: 200
      action: deny
      protocol: all
      cidr: 0.0.0.0/0
  egress:
    - priority: 100
      action: allow
      protocol: all
      cidr: 0.0.0.0/0
```

`priority` は1〜65535の整数で、各方向 (`ingress` / `egress`) の中で重複は許されません。番号が小さいルールから順に評価され、最初にマッチしたルールの `action` が確定します。

`action` は `allow` か `deny` のいずれかです。`deny` を明示的に書けるため、特定の宛先だけを除外したい場合や、優先度の高いdenyで例外を作りたい場合に便利です。

`protocol` には、キーワードか0から255のIPプロトコル番号を書きます。キーワードは `all` / `icmp` / `tcp` / `udp` / `sctp` / `gre` / `esp` / `ah` の8つです。キーワードは番号に名前を付けただけのもので、`tcp` と `6` は同じルールになります。番号は引用符を付けずに整数で書いてください。`"47"` のように引用符を付けると文字列として読まれ、その綴りのキーワードは無いので拒否されます。`all` は全てのIPプロトコルにマッチします。

`ports` を書けるのは `tcp` と `udp` のルールだけです。他のプロトコルにポートを書くと、作成や更新の時点でwebhookが拒否します。SCTPにもポート番号はありますが、data planeがSCTPヘッダを読まないので、`sctp` もポートを書けない側に入れてあります。

`cidr` はIPv4のCIDR表記で、ピアアドレスを指定します。`0.0.0.0/0` で任意のアドレスにマッチします。
NetworkACLはアドレスベースのルールのみを扱います (Pod単位の指定はSecurityGroupで行ってください)。

## 既定動作

各方向には3つの状態があり、SecurityGroupと同じ規則で挙動が決まります。

- `spec.ingress` を**省略**: その方向は無制限 (default-allow)。Subnet境界での評価をスキップし、すべてのトラフィックがSecurityGroup層に流れます
- `spec.ingress: []` (明示的に空): その方向はdeny-by-default。マッチするルールが無いので全パケットが落ちます
- `spec.ingress` に1つ以上のルール: 優先度の小さい順に評価し、最初にマッチした `action` で確定。どれにもマッチしなかった場合は終端のdenyに落ちます

`spec.egress` も同じ規則です。

NetworkACLはステートフルです。許可された送信に対する応答は、戻り方向にルールが無くても通過します (CTで一致したフローを短絡します)。

以前は、TCPとUDPとICMP以外のIPプロトコルがNetworkACLの評価を素通りしていました。いまは全てのIPプロトコルが評価されます。TCPのルールしか書いていないNetworkACLを紐付けたSubnetには、GREやESPは入ってきません。トンネルやIPsecがそのSubnetを通っているなら、そのプロトコルを許可するルールを足してください。NetworkACLを紐付けていないSubnetは以前と変わりません。

ルールを書いた方向では、L4ヘッダを読めないパケットも落とします。ポートが分からないと、ルールと突き合わせようがないからです。fragmentに分かれたTCPとUDPは、先頭のfragmentが持っていたポートを使って後続のfragmentも判定するので、普段はこれに当たりません。当たるのは、fragmentが順番どおりに着かなかった場合です。ルールを書いていない方向はdefault-allowのままなので、この判定にも入りません。

IPv4以外のフレームも同じ扱いです。juneauが扱うのはIPv4だけなので、NetworkACLが効いているSubnetのPodはIPv6で通信できません。ARPだけは例外で、落とすとPodのネットワークが成立しないため常に通します。

これらはどれも、NetworkACLを紐付けていないSubnetには関係ありません。そこのPodにSecurityGroupも付いていなければ、これまでどおりの動きです。

## ルールの上限

上限はルールの本数ではなく、data planeが持つ**エントリ数**で数えます。1つのルールはポートごとに1エントリへ展開されるので、1ルールのコストは次のとおりです。

```
エントリ数 = max(1, ports の要素数)
```

`ports` を省略したルールは全ポートにマッチする1エントリです。`tcp` と `udp` 以外のプロトコルは `ports` を書けないので、必ず1エントリになります。`ports` を4つ書いたルールは4エントリを使います。

この予算は**方向ごとに独立**しています。`ingress` と `egress` はBPFのルール配列の別々の区画を使うので、片方を使い切ってももう片方は影響を受けません。両方向の合計で数えることはありません。

NetworkACLは1方向あたり**16エントリ**までです。同じ方向に `ports` を4つ書いたルールを4つ並べると、ルールは4本でも16エントリになり上限に達します。1つの `ports` に書ける要素数も16なので、1本のルールだけでその方向を埋めることはあっても、あふれさせることはありません。

上限を超えるNetworkACLは、作成・更新の時点でwebhookが拒否します。つまり存在しているNetworkACLは、data planeがルールを全て保持できるものだけです。

いま何エントリ使っているかは `status.ingressEntryCount` / `status.egressEntryCount` に出ます。上限に近づいているかを見たいときは、ルール本数ではなくこちらを見てください。

## Subnetへの紐付け

Subnetの `spec.networkACL` にNetworkACLの名前を入れると、そのSubnetの境界で評価されるようになります。1つのSubnetに紐付けられるNetworkACLは最大1つです。

```yaml
apiVersion: juneau.loutres.me/v1alpha1
kind: Subnet
metadata:
  name: app-subnet
spec:
  vpc: app-vpc
  cidr: 10.0.0.0/24
  networkACL: web-acl
```

紐付けたNetworkACLは、SubnetのVpcと同じVpcに属していなければなりません (webhookで検証されます)。

`spec.networkACL` を空にすると、そのSubnetは再びdefault-allowに戻ります。

## SecurityGroupとの関係

両方を併用した場合、トラフィックは次の順で評価されます。

1. 送信側Subnetに紐付いたNetworkACLが `egress` を評価
2. 送信側PodのSecurityGroupが `egress` を評価
3. 受信側Subnetに紐付いたNetworkACLが `ingress` を評価
4. 受信側PodのSecurityGroupが `ingress` を評価

途中のいずれかでdenyになるとその時点で遮断されます。すべての段階を通過したフローだけが届きます。
SubnetにNetworkACLが紐付いていない / Podに該当するSecurityGroupが付いていない段階はスキップされ、評価は次の段階に進みます。

## status

`status.aclID` は、このNetworkACLに割り当てられたクラスタ内で一意の番号です。Subnetの `status.networkACL.aclID` に展開され、ルールの伝達に使われます。

`status.ingressRuleCount` / `status.egressRuleCount` は `spec.ingress` / `spec.egress` に書いたルールの本数です。

`status.ingressEntryCount` / `status.egressEntryCount` は、そのルールがdata planeで消費するエントリ数です。上限と突き合わせるのはこちらの値です。

`status.hasIngressRules` / `status.hasEgressRules` は、各方向が `spec` に明示的に指定されているか (省略はfalse、空リストや非空リストはtrue) を示します。

`status.attachedSubnets` は、現時点でこのNetworkACLを参照しているSubnetの一覧です。

`status.rulesetVersion` は、内部的にルール内容が変わるたびに増加する値です。

## Conditions

- `Ready`: NetworkACLが正常に解決され、ルールが適用可能な状態になっていれば `True`
- `RulesValid`: `spec` のルールがすべて正しく解決でき、どちらの方向もエントリ数の上限に収まっていれば `True`

## 制限事項

- ピアの指定はCIDRのみです。SubnetやSecurityGroupを直接参照することはできません
- 1方向に書けるエントリ数は16までです。超えるNetworkACLはwebhookが拒否するので、作成や更新そのものが失敗します。数え方は「ルールの上限」を参照してください
- IPv6には対応していません
- 削除を試みたNetworkACLがSubnetから参照されている場合、削除は拒否されます。先に該当Subnetの `spec.networkACL` を空にしてください
- `spec.vpc` は変更できません
