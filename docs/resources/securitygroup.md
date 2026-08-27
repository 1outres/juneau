# SecurityGroup

SecurityGroupは、Podに適用するステートフルな許可ルール (allow-list) の集合です。
`juneau.loutres.me/security-groups` annotationで対象Podに付与すると、そのPodの送受信トラフィックがルールで制限されます。

各SecurityGroupは1つのVpcに属し、同じVpc内のPodおよびSecurityGroup同士でのみ参照できます。

## ルールの基本形

`spec.ingress`は、このSecurityGroupに属するPodが**受信**して良いトラフィックを記述します。
`spec.egress`は、このSecurityGroupに属するPodが**送信**して良いトラフィックを記述します。

各ルールは、対向となるピア (`from` / `to`)、プロトコル、宛先ポートで構成されます。

```yaml
apiVersion: juneau.loutres.me/v1alpha1
kind: SecurityGroup
metadata:
  name: web-sg
spec:
  vpc: app-vpc
  ingress:
    - from:
        - cidr: 10.0.0.0/24
        - securityGroupRef:
            name: client-sg
      protocol: tcp
      ports:
        - port: 80
        - portRange:
            from: 8000
            to: 8999
  egress:
    - to:
        - cidr: 0.0.0.0/0
      protocol: all
```

ピアの指定方法は2種類で、どちらか一方をルールごとに選びます。

- `cidr`: IPv4 CIDRで対向アドレス範囲を指定
- `securityGroupRef.name`: 対向側に付与されたSecurityGroupの名前を指定。同じVpcに属するSecurityGroupだけが参照できます

`protocol`には、キーワードか0から255のIPプロトコル番号を書きます。キーワードは`all` / `icmp` / `tcp` / `udp` / `sctp` / `gre` / `esp` / `ah`の8つです。

キーワードは番号に名前を付けただけのもので、`tcp`と`6`は同じルールになります。番号は引用符を付けずに整数で書いてください。`"47"`のように引用符を付けると文字列として読まれ、その綴りのキーワードは無いので拒否されます。`all`は全てのIPプロトコルにマッチします。

`ports`を書けるのは`tcp`と`udp`のルールだけです。他のプロトコルにポートを書くと、作成や更新の時点でwebhookが拒否します。SCTPにもポート番号はありますが、data planeがSCTPヘッダを読まないので、書けても効かないルールになります。それで`sctp`はポートを書けない側に入れてあります。

`ports[].port`で単一ポート、`ports[].portRange.from` / `to`で範囲を指定できます。
`ports`を省略した場合は、そのプロトコルの全ポートにマッチします。

## 既定動作

- `spec.ingress`を省略 / 空にすると、受信は全て遮断されます (deny-by-default)。1つでも受信を許可したいピアがある場合は、それを明示するルールを追加してください
- `spec.egress`を省略すると、送信は全て許可されます (default-allow)。送信を制限したい場合は明示的に`spec.egress`を書いてください
- どのSecurityGroupにも属さないPodは、SecurityGroupによる制限を受けません

ステートフルなので、許可された送信に対する応答は受信ルールに無くても通過します。受信側についても同様です。

以前は、TCPとUDPとICMP以外のIPプロトコルがSecurityGroupの評価を素通りしていました。いまは全てのIPプロトコルが評価されます。TCPのルールしか書いていないSecurityGroupを付けたPodには、GREやESPは届きません。トンネルやIPsecを張っているPodがあれば、そのプロトコルを許可するルールを足してください。SecurityGroupを付けていないPodは以前と変わりません。

SecurityGroupを付けたPodは、L4ヘッダを読めないパケットも落とします。ポートが分からないと、ルールと突き合わせようがないからです。fragmentに分かれたTCPとUDPは、先頭のfragmentが持っていたポートを使って後続のfragmentも判定するので、普段はこれに当たりません。当たるのは、fragmentが順番どおりに着かなかった場合です。

IPv4以外のフレームも落とします。juneauが扱うのはIPv4だけなので、SecurityGroupを付けたPodの間でIPv6は使えません。ARPだけは例外で、落とすとPodのネットワークが成立しないため常に通します。

これらはどれも、SecurityGroupを付けていないPodには関係ありません。SubnetにNetworkACLも紐付いていなければ、これまでどおりの動きです。

## ルールの上限

上限はルールの本数ではなく、data planeが持つ**エントリ数**で数えます。SecurityGroupのルールはピアとポートの直積に展開されるので、1ルールのコストは次のとおりです。

```
エントリ数 = max(1, from / to の要素数) * max(1, ports の要素数)
```

`ports`を省略したルールは全ポートにマッチする1エントリ分として数えます。ピアを3つ、ポートを2つ書いたルールは6エントリを使います。

この予算は**方向ごとに独立**しています。`ingress`と`egress`はBPFのルール配列の別々の区画を使うので、片方を使い切ってももう片方は影響を受けません。両方向の合計で数えることはありません。

SecurityGroupは1方向あたり**8エントリ**までです。NetworkACLの16より小さいのは、1つのPodに複数のSecurityGroupを付けられるからです。1パケットあたりの走査量は付いているSecurityGroupの数だけ増えるので、1つあたりの本数を抑えてあります。Subnetに紐付くNetworkACLは最大1つなので、そちらは倍を許せます。

`from` / `to` / `ports`に書ける要素数もそれぞれ8までです。ただしこれは1つのリストの上限なので、ピアを8つとポートを8つ書いたルールは64エントリになり、1本だけで上限を超えます。

上限を超えるSecurityGroupは、作成・更新の時点でwebhookが拒否します。つまり存在しているSecurityGroupは、data planeがルールを全て保持できるものだけです。

`securityGroupRef`で指定したピアが解決できなかった場合、そのピアは展開時に落とされます。実際に使われるエントリ数はここで数えた値以下になり、超えることはありません。

## Podへの付与

PodのannotationでSecurityGroupを指定します。複数のSecurityGroupはカンマ区切りで列挙できます。

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: web
  annotations:
    juneau.loutres.me/security-groups: web-sg,monitoring-sg
spec:
  containers:
    - name: nginx
      image: nginx:1.27
```

複数のSecurityGroupを付けた場合、それぞれのルールはOR (許可のいずれか1つに合致すれば通過) で評価されます。

1つのPodに付与できるSecurityGroupの個数には上限があります。`juneau.loutres.me/security-groups` annotationで上限を超える数を指定すると、そのPodは作成できません。

参照するSecurityGroupは、Podが属するSubnetのVpcと同じVpcのSecurityGroupでなければなりません。

## Vpcによる強制

Vpcに`spec.enforceSecurityGroups: true`を設定すると、そのVpc配下のSubnetに作られるPodは少なくとも1つのSecurityGroupを付与しなければ作成できません。
セキュリティ要件が厳しい環境で「全てのPodに必ずSecurityGroupを付ける」ポリシーを強制したい場合に使います。

## status

`status.groupID`は、このSecurityGroupに割り当てられたクラスタ内で一意の番号です。Pod側 (NetworkInterfaceのstatus) に展開され、ルールの伝達に使われます。

`status.ingressRuleCount` / `status.egressRuleCount`は、`spec.ingress` / `spec.egress`に書いたルールの本数です。

`status.ingressEntryCount` / `status.egressEntryCount`は、そのルールをピアとポートの直積に展開したあとのエントリ数です。上限と突き合わせるのはこちらの値です。

`status.hasEgressRules`は、`spec.egress`が明示的に指定されているかを示します。指定されていない場合は送信が全許可 (default-allow) として扱われます。

`status.attachedInterfaces`は、現時点でこのSecurityGroupを参照しているNetworkInterfaceの一覧です。

`status.rulesetVersion`は、内部的にルール内容が変わるたびに増加する値です。

## Conditions

- `Ready`: SecurityGroupが正常に解決され、ルールが適用可能な状態になっていれば`True`
- `RulesValid`: `spec`のルールがすべて正しく解決できていれば`True`。参照したSecurityGroupが存在しない、どちらかの方向がエントリ数の上限を超えているなどの場合に`False`になります

## 制限事項

- ルールはallow-listです。明示的なdeny指定は現在サポートしていません
- ルールの優先度はありません。複数SecurityGroupおよび複数ルールの評価結果はORで合成されます
- 1方向に書けるエントリ数は8までです。超えるSecurityGroupはwebhookが拒否するので、作成や更新そのものが失敗します。数え方は「ルールの上限」を参照してください
- IPv6には対応していません
- 削除を試みたSecurityGroupがNetworkInterfaceから参照されている場合、削除は拒否されます。先に該当Podを削除してください
