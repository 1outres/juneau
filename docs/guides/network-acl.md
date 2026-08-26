# NetworkACLでSubnet境界を制御する

JuneauのNetworkACLは、Subnetに入ってくる / Subnetから出ていくトラフィックを優先度付きのルールで制御します。
SecurityGroupが「Podごとの細かい許可リスト」だとすると、NetworkACLは「Subnetの入口・出口で守る粗いガード」と捉えるとわかりやすいです。両者は同時に有効化でき、両方を通過したトラフィックだけが通ります。

このガイドでは、

1. backend用Subnetに対するingress NetworkACLで、許可するクライアントSubnetだけを通す
2. priorityとdenyルールを組み合わせて例外を作る
3. NetworkACLを外して挙動を元に戻す

までの流れを示します。

## このガイドで構築するもの

- 専用Vpc (`app-vpc`) と Subnet 2つ
    - `app-subnet` (`10.80.0.0/24`): backend Pod配置先
    - `client-subnet` (`10.80.1.0/24`): クライアントPod配置先
- backend Subnet向けNetworkACL (`web-acl`)
- backend Pod (nginx) と クライアントPod (curl)
- `client-subnet` のCIDRからの通信のみが backend Subnet に届くこと

## 前提条件

- Juneauのcontroller/daemonが動作しているクラスター
- kubectlが利用可能なこと

## 手順

### 1. Vpcと2つのSubnetを作成

```yaml
apiVersion: juneau.loutres.me/v1alpha1
kind: Vpc
metadata:
  name: app-vpc
---
apiVersion: juneau.loutres.me/v1alpha1
kind: Subnet
metadata:
  name: app-subnet
spec:
  vpc: app-vpc
  cidr: 10.80.0.0/24
---
apiVersion: juneau.loutres.me/v1alpha1
kind: Subnet
metadata:
  name: client-subnet
spec:
  vpc: app-vpc
  cidr: 10.80.1.0/24
```

詳細は[Vpc](../resources/vpc.md) / [Subnet](../resources/subnet.md)を参照してください。

### 2. NetworkACLを作成

`client-subnet` (`10.80.1.0/24`) からのTCP/80だけを受け入れるルールを書きます。

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
      cidr: 10.80.1.0/24
      ports:
        - port: 80
```

`spec.ingress` に1つ以上のルールを書くと、その方向はdeny-by-defaultになります。明示的に許可したCIDR以外からの通信は遮断されます。

```console
$ kubectl get networkacl
NAME      VPC       ACLID   INGRESS   EGRESS   READY
web-acl   app-vpc   1       1                  True
```

`READY: True` であれば反映済みです。詳細は[NetworkACL](../resources/networkacl.md)を参照してください。

### 3. backend SubnetにNetworkACLを紐付ける

`spec.networkACL` でNetworkACLを指定します。

```yaml
apiVersion: juneau.loutres.me/v1alpha1
kind: Subnet
metadata:
  name: app-subnet
spec:
  vpc: app-vpc
  cidr: 10.80.0.0/24
  networkACL: web-acl
```

```console
$ kubectl get subnet app-subnet -o jsonpath='{.status.networkACL}'
{"name":"web-acl","aclID":1,"rulesetVersion":1}
```

`status.networkACL.aclID` が0でない値になればdaemon側に伝達されています。

### 4. backend Podをデプロイ

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx
spec:
  replicas: 1
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
      annotations:
        juneau.loutres.me/subnet: app-subnet
    spec:
      containers:
        - name: nginx
          image: nginx:1.27
```

### 5. クライアントPodをデプロイ

`client-subnet` 上のクライアントPodと、別のSubnet上にもう1つPodを置いて挙動を比較します。今回は同じSubnetからの2つのPod (片方は許可、もう片方も同じCIDRなので許可される) ではなく、後段で priority と deny を使った例外を試すため、まずは標準的なクライアントPodを1つ用意します。

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: curl-allowed
  annotations:
    juneau.loutres.me/subnet: client-subnet
spec:
  containers:
    - name: curl
      image: curlimages/curl:8.7.1
      command: ["sleep", "infinity"]
```

### 6. 通信を確認

```console
$ BACKEND=$(kubectl get pod -l app=nginx -o jsonpath='{.items[0].status.podIP}')
$ kubectl exec curl-allowed -- curl -sS --max-time 5 http://$BACKEND/
<!DOCTYPE html>
...
<h1>Welcome to nginx!</h1>
```

`client-subnet` のCIDRが許可されているので、応答が返ります。

## priorityとdenyを組み合わせる

NetworkACLの強みは「先に評価されたルールの結果が確定する」点にあります。たとえば「クライアントSubnetからは原則許可するが、`10.80.1.42` だけは拒否したい」という要件は次のように書けます。

```yaml
apiVersion: juneau.loutres.me/v1alpha1
kind: NetworkACL
metadata:
  name: web-acl
spec:
  vpc: app-vpc
  ingress:
    - priority: 50
      action: deny
      protocol: tcp
      cidr: 10.80.1.42/32
      ports:
        - port: 80
    - priority: 100
      action: allow
      protocol: tcp
      cidr: 10.80.1.0/24
      ports:
        - port: 80
```

`priority: 50` のdenyが先に評価されるため、後続のallowルールにかかわらず `10.80.1.42` からの通信は遮断されます。
このようにdenyを優先度の小さい値で先頭に置くと、広めの許可ルールに対する例外を簡潔に表現できます。

## ルールに書けるプロトコル

`protocol` に指定できるのは `tcp` / `udp` / `icmp` / `all` の4つです。`all` はこの3つをまとめて指す書き方なので、SCTPやGRE、ESP、AH、IPIP、OSPF、IGMP、VRRPには、allowもdenyも書けません。

書けないプロトコルのパケットは、SubnetにNetworkACLを紐付けているかどうかに関係なく、PodのNICで落ちます。`spec.ingress` を省略してdefault-allowにしておいても通りません。SecurityGroupも同じ4つしか受け付けないので、そちらで拾い直すこともできません。

以前のJuneauは、両方の層とも素通りさせていました。アップグレードすると、`protocol: all` のallowルールで通っていたつもりのSCTPやESPが落ちるようになります。

落ちたことを `kubectl juneau trace` で確かめる手段は、いまのところありません。TraceSessionの `protocol` が `TCP` / `UDP` / `ICMP` しか受け付けないので、SCTPやESPのパケットを掴むセッションを作れないからです。パケットの側から `tcpdump -ni eth0 ip proto 132` のように見てください。

## NetworkACLを外す

Subnetの `spec.networkACL` を空にすると、そのSubnetは再びdefault-allowに戻ります。

```console
$ kubectl patch subnet app-subnet --type=merge -p '{"spec":{"networkACL":""}}'
```

`status.networkACL` が空になり、daemon側でも紐付けが解除されます。
NetworkACL自体を削除したい場合は、参照しているSubnetを先に外してから削除してください (Subnetが参照したまま削除しようとするとwebhookで拒否されます)。

## SecurityGroupとの組み合わせ

NetworkACLとSecurityGroupは同時に有効化できます。

- NetworkACL: Subnetの境界で評価される (アドレスベース)
- SecurityGroup: Pod (NetworkInterface) の境界で評価される (CIDR / SecurityGroup参照)

両方が有効なときは、Subnetの入口・出口の両方で評価が走り、どちらかがdenyを返した時点でトラフィックは落ちます。
たとえば「Subnetに入る大きな通り道は NetworkACL で広めに許可しつつ、特定のbackend Pod群はさらに SecurityGroup で絞る」といった重ね合わせができます。

詳細はそれぞれのリファレンスを参照してください。

- [SecurityGroupでPodの通信を制限する](security-group.md)
- [NetworkACLとSecurityGroupの評価を追う](../developer/policy-data-plane.md)
- [SecurityGroup](../resources/securitygroup.md)

## うまくいかないとき

1. **NetworkACLを付けた途端、想定外に通信が落ちる**
    - `spec.ingress` または `spec.egress` を1つでも書くと、その方向はdeny-by-defaultになります。クラスタ内DNSや外部サービスに到達する必要がある場合は、それらに合致するallowルールも追加してください
    - 戻りトラフィックはステートフルにCTで通過するため、戻り方向のallowを書く必要はありません
2. **`status.aclID` が0のまま**
    - `kubectl describe networkacl <name>` でConditionを確認してください。`Ready=False` で `Allocating` 表示なら一時的な状態です
3. **Subnetに紐付けたのに反映されない**
    - `kubectl get subnet <name> -o jsonpath='{.status.networkACL}'` で `aclID` が0でないことを確認
    - NetworkACLとSubnetが同じVpcに属している必要があります
4. **NetworkACLを削除できない**
    - 参照しているSubnetが残っているとwebhookで拒否されます。`kubectl get subnet -o jsonpath='{range .items[?(@.spec.networkACL=="<name>")]}{.metadata.name}{"\n"}{end}'` で参照Subnetを洗い出し、`spec.networkACL` を空にしてから削除してください
5. **priorityで意図しないルールがマッチする**
    - 同じ方向内でpriorityが重複しているとwebhookで拒否されます。マッチ順を厳密に固定したい場合は十分に間隔を空けた priority (10, 20, 30 など) を使うと後から間に挿入しやすくなります
6. **TCPとUDPとICMPは通るのに、別のプロトコルだけ通らない**
    - ルールに書けるプロトコルは `tcp` / `udp` / `icmp` / `all` だけで、`all` もこの3つを指します。SCTPやESPを許可する方法はありません。上の「ルールに書けるプロトコル」を参照してください
7. **フラグメント化したUDPだけが届かない**
    - 後続フラグメントが先頭より先に着くと、ポートを復元できないので落ちます。ルールにポートを書いているかどうかは関係ありません。NATGateway越しやClusterIP宛てのフラグメントも落ちます。詳しくは[NetworkACLとSecurityGroupの評価を追う](../developer/policy-data-plane.md)を参照してください

## 参照

- [NetworkACL](../resources/networkacl.md)
- [SecurityGroup](../resources/securitygroup.md)
- [Vpc](../resources/vpc.md)
- [Subnet](../resources/subnet.md)
- [NetworkACLとSecurityGroupの評価を追う](../developer/policy-data-plane.md) (データプレーン側の解説)
