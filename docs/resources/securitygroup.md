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

`protocol`は`tcp` / `udp` / `icmp` / `all`から選びます。
`all`または`icmp`を指定したルールでは`ports`を空にする必要があります。

`ports[].port`で単一ポート、`ports[].portRange.from` / `to`で範囲を指定できます。
`ports`を省略した場合は、そのプロトコルの全ポートにマッチします。

## 既定動作

- `spec.ingress`を省略 / 空にすると、受信は全て遮断されます (deny-by-default)。1つでも受信を許可したいピアがある場合は、それを明示するルールを追加してください
- `spec.egress`を省略すると、送信は全て許可されます (default-allow)。送信を制限したい場合は明示的に`spec.egress`を書いてください
- どのSecurityGroupにも属さないPodは、SecurityGroupによる制限を受けません

ステートフルなので、許可された送信に対する応答は受信ルールに無くても通過します。受信側についても同様です。

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

`status.ingressRuleCount` / `status.egressRuleCount`は、`spec.ingress` / `spec.egress`を実際の許可エントリに展開したあとの件数です。
ピアやポートのリストを書くと自動的に直積に展開されるため、spec上の見かけよりも数が増えます。

`status.hasEgressRules`は、`spec.egress`が明示的に指定されているかを示します。指定されていない場合は送信が全許可 (default-allow) として扱われます。

`status.attachedInterfaces`は、現時点でこのSecurityGroupを参照しているNetworkInterfaceの一覧です。

`status.rulesetVersion`は、内部的にルール内容が変わるたびに増加する値です。

## Conditions

- `Ready`: SecurityGroupが正常に解決され、ルールが適用可能な状態になっていれば`True`
- `RulesValid`: `spec`のルールがすべて正しく解決できていれば`True`。参照したSecurityGroupが存在しない、ルール件数が上限を超えているなどの場合に`False`になります

## 制限事項

- ルールはallow-listです。明示的なdeny指定は現在サポートしていません
- ルールの優先度はありません。複数SecurityGroupおよび複数ルールの評価結果はORで合成されます
- 1つのSecurityGroupに記述できるルールの件数 (展開後) には上限があります。`status.ingressRuleCount` / `status.egressRuleCount`が上限を超えると`RulesValid=False`になり、超過分は適用されません
- IPv6には対応していません
- 削除を試みたSecurityGroupがNetworkInterfaceから参照されている場合、削除は拒否されます。先に該当Podを削除してください
