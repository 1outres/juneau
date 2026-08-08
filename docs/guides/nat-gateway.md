# NATGatewayでVPC外への通信を成立させる

Juneauでは、NATGatewayを使うことでVpc内のPodがVpc外（クラスタ外を含む）へN:1のソースNATで出ていくegress経路を構築できます。各Nodeに1つずつNAPTソースIPアドレスが払い出され、Pod がVpc外へ通信する際は配置されているNodeに対応するアドレスがソースIPとして利用されます。

このガイドでは、custom Vpcに対してBGPベースのNATGatewayを構築し、Podがクラスタ外まで疎通する手順を一通り示します。

## このガイドで構築するもの

- NAPTソースIP用のAddressPool (`nat-pool`, `10.225.53.0/24`)
- 上流ルータ (AS 65002, `10.225.32.1`) とのBGPピアリング
- BGPで広報するExternalNetwork (`nat-net`)
- 専用Vpc (`egress-vpc`) とSubnet (`egress-subnet`, `10.90.0.0/24`)
- NATGateway (`egress-natgw`)
- VpcのRouteTableに`0.0.0.0/0`を`via.type: natGateway`で追加
- Podから`curl https://1.1.1.1/cdn-cgi/trace`で外部に到達し、戻ってきた`ip=`行がNATGatewayの払い出したNAPTソースIPと一致
- Podから`ping`と`traceroute`が外部まで到達

## 前提条件

- Juneauのcontroller/daemon/bgp-speakerが動作しているクラスター
- クラスターのAS番号（本ガイドでは **65001**）
- 上流BGPルータ側でJuneauクラスターを受け入れる設定（AS **65002**、Juneauノード各IPとのピアリング）
- 広報に使うCIDRが上流ネットワークで未使用であること（本ガイドでは `10.225.53.0/24`）
- Pod がインターネットに出るための上流側の経路設定

## 手順

### 1. AddressPoolを作成

NAPTソースIPを払い出すためのCIDRを定義します。

```yaml
apiVersion: juneau.loutres.me/v1alpha1
kind: AddressPool
metadata:
  name: nat-pool
spec:
  advertiseMode: bgp
  addresses:
    - 10.225.53.0/24
```

`advertiseMode: bgp`は変更不可です。詳細は[AddressPool](../resources/addresspool.md)を参照してください。

### 2. BGPPeerを作成

上流ルータを宣言します。

```yaml
apiVersion: juneau.loutres.me/v1alpha1
kind: BGPPeer
metadata:
  name: upstream
spec:
  myASN: 65001
  peerASN: 65002
  peerAddress: 10.225.32.1
```

この時点で各Nodeのbgp-speakerが`10.225.32.1`にBGPセッションを張りに行きます。詳細は[BGPPeer](../resources/bgppeer.md)を参照してください。

### 3. BGPセッションの確立を確認

```console
$ kubectl get bgpnodestate
NAME       READY   BIRD   BMP    AGE
worker-1   True    True   True   2m
worker-2   True    True   True   2m
```

すべての列が`True`になっていれば、そのNode上でbgp-speakerが正常に動作し、上流とのセッションが確立しています。詳細は[BGPNodeState](../resources/bgpnodestate.md)を参照してください。

### 4. ExternalNetworkを作成

AddressPoolを1つの論理的な外部ネットワークとしてまとめます。

```yaml
apiVersion: juneau.loutres.me/v1alpha1
kind: ExternalNetwork
metadata:
  name: nat-net
spec:
  type: bgp
  addressPools:
    - nat-pool
```

`type: bgp`の場合、参照するAddressPoolは`advertiseMode: bgp`である必要があります。詳細は[ExternalNetwork](../resources/externalnetwork.md)を参照してください。

### 5. Vpc/Subnetを作成

NATGateway経由で外部に出るPodを置く専用のVpcとSubnetを用意します。

```yaml
apiVersion: juneau.loutres.me/v1alpha1
kind: Vpc
metadata:
  name: egress-vpc
---
apiVersion: juneau.loutres.me/v1alpha1
kind: Subnet
metadata:
  name: egress-subnet
spec:
  vpc: egress-vpc
  cidr: 10.90.0.0/24
```

詳細は[Vpc](../resources/vpc.md) / [Subnet](../resources/subnet.md)を参照してください。

### 6. NATGatewayを作成

Vpcと出口となるExternalNetworkを参照するNATGatewayを作成します。

```yaml
apiVersion: juneau.loutres.me/v1alpha1
kind: NATGateway
metadata:
  name: egress-natgw
spec:
  vpc: egress-vpc
  externalNetwork: nat-net
```

```console
$ kubectl get natgateway
NAME           VPC          EXTERNALNETWORK   GATEWAYID   READY
egress-natgw   egress-vpc   nat-net           1           True
```

`Ready: True`になればNATGatewayの基本的な準備は完了です。詳細は[NATGateway](../resources/natgateway.md)を参照してください。

### 7. RouteTableに`0.0.0.0/0`ルートを追加

VpcのメインRouteTableは自動生成されますが、Vpc外への経路はデフォルトでは含まれません。NATGateway向けのデフォルトルートを追記します。

```yaml
apiVersion: juneau.loutres.me/v1alpha1
kind: RouteTable
metadata:
  name: egress-vpc
spec:
  vpc: egress-vpc
  routes:
    - dst: 0.0.0.0/0
      via:
        type: natGateway
        natGateway: egress-natgw
```

RouteTableのメタ名はVpc名と同じです。このルートが無いとVpc内のPodからVpc外への経路が成立しません。詳細は[RouteTable](../resources/routetable.md)を参照してください。

### 8. ExternalNetworkAttachmentが払い出されたことを確認

NATGatewayを作成すると、対象ExternalNetworkに対してNodeごとに1つずつExternalNetworkAttachmentが自動的に作成され、それぞれにNAPTソースIPアドレスが割り当てられます。各assignedIPはBGPで上流に広報され、戻り通信が正しいNodeへ届くようになります。

```console
$ kubectl get externalnetworkattachment
NAME                EXTERNALNETWORK   NODE       ASSIGNEDIP     READY
nat-net--worker-1   nat-net           worker-1   10.225.53.5    True
nat-net--worker-2   nat-net           worker-2   10.225.53.6    True
```

すべてのNodeに対して`READY: True`、`ASSIGNEDIP`が埋まっていれば、NAPTソースIPの払い出しは完了です。詳細は[ExternalNetworkAttachment](../resources/externalnetworkattachment.md)を参照してください。

### 9. Podをデプロイ

`egress-subnet`にcurl用のPodを配置します。

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: curl
  annotations:
    juneau.loutres.me/subnet: egress-subnet
spec:
  containers:
    - name: curl
      image: curlimages/curl:8.7.1
      command: ["sleep", "infinity"]
```

### 10. 外部からの送信元IPを確認

Podから外部に出るときのソースIPアドレスを、外部の応答サービスで確認します。custom VpcのPodからはCoreDNSが利用できないため、IP直指定で叩ける応答サービスを使います。

```console
$ kubectl exec curl -- curl -sS https://1.1.1.1/cdn-cgi/trace
fl=...
h=1.1.1.1
ip=10.225.53.5
ts=...
visit_scheme=https
uag=curl/8.7.1
...
```

応答の`ip=`行が、Podが動作しているNodeに対応するExternalNetworkAttachmentの`status.assignedIP`と一致していれば、NATGateway経由のN:1 NAPTで外部に出ている状態です。

### 11. ICMPの疎通を確認

NATGatewayはTCPとUDPに加えてICMPもNAPTします。`ping`と`traceroute`を持つイメージでPodをもう1つ用意します。

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nettools
  annotations:
    juneau.loutres.me/subnet: egress-subnet
spec:
  containers:
    - name: nettools
      image: nicolaka/netshoot:v0.16
      command: ["sleep", "infinity"]
```

まずEcho Requestを外部に送ります。

```console
$ kubectl exec nettools -- ping -c 3 1.1.1.1
PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.
64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=8.21 ms
64 bytes from 1.1.1.1: icmp_seq=2 ttl=57 time=7.94 ms
64 bytes from 1.1.1.1: icmp_seq=3 ttl=57 time=8.02 ms
```

ICMPにはポートが無いので、NATGatewayはICMPヘッダのIdentifierをポート相当として払い出します。Echo Replyは同じIdentifierを返すため、応答がPodまで戻ってきていればNAPTの往復が成立しています。

経路上のルータが返すICMPエラーメッセージも書き換えるので、`traceroute`が使えます。

```console
$ kubectl exec nettools -- traceroute -n 1.1.1.1
traceroute to 1.1.1.1 (1.1.1.1), 30 hops max, 46 byte packets
 1  10.225.32.1  0.512 ms  0.418 ms  0.399 ms
 2  ...
```

1ホップ目の`10.225.32.1`は上流ルータがTime Exceededを返したものです。このメッセージが内包しているのはNAPT後のパケット、つまりソースがNAPTソースIPになったヘッダです。ホップが表示されたということは、内包されたヘッダがPod自身のアドレスに戻された状態でPodに届いていることを意味します。

Path MTU Discoveryも同じ仕組みで動きます。経路の途中に小さいMTUのリンクがある場合、DFを立てた大きなパケットに対してFragmentation Neededが返り、Podはそれを受け取ることができます。

```console
$ kubectl exec nettools -- ping -M do -s 1300 -c 1 198.18.0.2
PING 198.18.0.2 (198.18.0.2) 1300(1328) bytes of data.
From 10.225.32.1 icmp_seq=1 Frag needed and DF set (mtu = 1280)
```

Podのカーネルはこの報告を受けて、宛先に対する経路MTUをキャッシュします。以降のTCP通信もこのMTUに収まるように分割されます。

## うまくいかないとき

1. **NATGatewayが`Ready=False`のまま**
    - `spec.vpc`で参照したVpcが存在するか
    - `spec.externalNetwork`で参照したExternalNetworkが存在するか
2. **`kubectl get externalnetworkattachment`が空、または対象NodeのAttachmentが無い**
    - NATGatewayが`Ready=True`になっているか（Attachmentは、NATGatewayから参照されているExternalNetworkに対してのみ作成されます）
    - 対象Nodeがクラスターに登録されているか
3. **Attachmentの`assignedIP`が払い出されない（`READY=False`のまま）**
    - 参照しているAddressPoolの`advertiseMode`が`bgp`か
    - AddressPoolにIP在庫が残っているか（Node数より多くのIPが必要）
4. **Podから外部に出られない**
    - PodのSubnetが、NATGatewayと同じVpcに属しているか
    - VpcのRouteTableに`0.0.0.0/0`を`via.type: natGateway`とするルートが入っているか
    - `via.natGateway`の名前が、対象NATGatewayのname と一致しているか
    - `kubectl get bgpnodestate`で、各NodeのassignedIPに対応する`/32`が`status.advertisements[].prefixes`に乗っているか
5. **送信元IPが期待値と違う**
    - Pod が動作しているNodeに対応するExternalNetworkAttachmentの`assignedIP`を改めて確認
    - 上流ルータで、該当`/32`がそのNodeを次ホップに学習しているか
6. **`curl`は通るのに`ping`が返ってこない**
    - PodにSecurityGroupを付けている場合、`spec.egress`を明示的に書いていると`protocol: icmp`か`all`のルールが無い限りEcho Requestは出られません。SecurityGroupのegressは省略時のみdefault-allowです
    - SubnetにNetworkACLを付けている場合も同様に、ICMPを許可するルールがあるか確認
    - 宛先がEcho Replyを返す設定になっているか。ICMPを落とすホストは珍しくありません
7. **`traceroute`の途中のホップが`* * *`のまま**
    - そのホップのルータがICMPを返していない可能性があります。TCPやUDPが通っているなら経路自体は成立しています
    - NATGatewayが書き換えるのはEchoと5種類のICMPエラーメッセージだけです。それ以外のICMPタイプは破棄されます。詳細は[NATGateway](../resources/natgateway.md)の対応プロトコルを参照してください

## 参照

- [AddressPool](../resources/addresspool.md)
- [BGPPeer](../resources/bgppeer.md)
- [BGPNodeState](../resources/bgpnodestate.md)
- [ExternalNetwork](../resources/externalnetwork.md)
- [ExternalNetworkAttachment](../resources/externalnetworkattachment.md)
- [NATGateway](../resources/natgateway.md)
- [Vpc](../resources/vpc.md)
- [Subnet](../resources/subnet.md)
- [RouteTable](../resources/routetable.md)
