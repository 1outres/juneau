# VpcPeeringで2つのVPCを接続する

Juneauでは、VpcPeeringを使うことで2つのVpcを直接つなぎ、別々のVpcにいるPod同士を通信させることができます。

このガイドでは、2つのVpcを作ってピアリングし、双方向でPodが疎通するまでの手順を示します。

## このガイドで構築するもの

- Vpc `shop-vpc` とSubnet `shop-subnet` (`10.70.0.0/24`)
- Vpc `payment-vpc` とSubnet `payment-subnet` (`10.71.0.0/24`)
- 2つを接続するVpcPeering (`shop-payment`)
- 両VpcのメインRouteTableに、対向Subnet宛の`via.type: vpcPeering`ルート
- `shop-subnet`のPodから`payment-subnet`のPodへHTTPで到達

## 前提条件

- Juneauのcontroller/daemonが動作しているクラスター
- 接続する2つのVpcの間で、SubnetのCIDRが重複していないこと

## 手順

### 1. VpcとSubnetを作成

```yaml
apiVersion: juneau.loutres.me/v1alpha1
kind: Vpc
metadata:
  name: shop-vpc
---
apiVersion: juneau.loutres.me/v1alpha1
kind: Vpc
metadata:
  name: payment-vpc
---
apiVersion: juneau.loutres.me/v1alpha1
kind: Subnet
metadata:
  name: shop-subnet
spec:
  vpc: shop-vpc
  cidr: 10.70.0.0/24
---
apiVersion: juneau.loutres.me/v1alpha1
kind: Subnet
metadata:
  name: payment-subnet
spec:
  vpc: payment-vpc
  cidr: 10.71.0.0/24
```

詳細は[Vpc](../resources/vpc.md) / [Subnet](../resources/subnet.md)を参照してください。

### 2. VpcPeeringを作成

```yaml
apiVersion: juneau.loutres.me/v1alpha1
kind: VpcPeering
metadata:
  name: shop-payment
spec:
  requester:
    vpc: shop-vpc
  accepter:
    vpc: payment-vpc
```

```console
$ kubectl get vpcpeering
NAME           REQUESTER   ACCEPTER      READY
shop-payment   shop-vpc    payment-vpc   True
```

`Ready: True`は、両側のVpcが存在してCIDRが重複していないことを表します。ここまでではまだ通信は成立しません。詳細は[VpcPeering](../resources/vpcpeering.md)を参照してください。

### 3. 両方のRouteTableにルートを追加

VpcのメインRouteTableはVpc名と同じ名前で自動生成されます。それぞれに対向Subnetへのルートを追記します。

```yaml
apiVersion: juneau.loutres.me/v1alpha1
kind: RouteTable
metadata:
  name: shop-vpc
spec:
  vpc: shop-vpc
  routes:
    - dst: 10.71.0.0/24
      via:
        type: vpcPeering
        vpcPeering: shop-payment
---
apiVersion: juneau.loutres.me/v1alpha1
kind: RouteTable
metadata:
  name: payment-vpc
spec:
  vpc: payment-vpc
  routes:
    - dst: 10.70.0.0/24
      via:
        type: vpcPeering
        vpcPeering: shop-payment
```

`dst`は対向Vpcに存在するSubnetのCIDRと完全に一致させてください。`10.70.0.0/16`のようなスーパーネットでは宛先Subnetが定まらず、ルートは解決されません。

ルートを書いた方向にしか通らないため、双方向で通信するには両方に書く必要があります。

### 4. ルートが解決されたことを確認

```console
$ kubectl get routetable shop-vpc -o jsonpath='{.status.routes[?(@.dst=="10.71.0.0/24")]}'
{"dst":"10.71.0.0/24","subnet":"payment-subnet","via":{"type":"vpcPeering","vpcPeering":"shop-payment"}}
```

`subnet`に対向Subnetの名前が入っていれば解決済みです。この名前をもとにデータプレーンが転送先を決めます。

### 5. Podをデプロイ

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: payment
  annotations:
    juneau.loutres.me/subnet: payment-subnet
spec:
  containers:
    - name: nginx
      image: nginx:1.27
---
apiVersion: v1
kind: Pod
metadata:
  name: shop
  annotations:
    juneau.loutres.me/subnet: shop-subnet
spec:
  containers:
    - name: curl
      image: curlimages/curl:8.7.1
      command: ["sleep", "infinity"]
```

### 6. 疎通を確認

custom VpcのPodからはCoreDNSが使えないため、宛先のPod IPを直接指定します。

```console
$ PAYMENT=$(kubectl get pod payment -o jsonpath='{.status.podIP}')
$ kubectl exec shop -- curl -sS --max-time 5 http://$PAYMENT/
<!DOCTYPE html>
...
<h1>Welcome to nginx!</h1>
```

## SecurityGroupを併用する場合

SecurityGroupのpeer参照は同じVpcの中でだけ有効です。SecurityGroupの所属判定はVpc単位で行われるため、対向VpcのPodは`securityGroupRef`のルールにマッチしません。対向Vpcからの通信を許可する場合は`cidr`のルールを書いてください。

```yaml
apiVersion: juneau.loutres.me/v1alpha1
kind: SecurityGroup
metadata:
  name: payment-sg
spec:
  vpc: payment-vpc
  ingress:
    - from:
        - cidr: 10.70.0.0/24
      protocol: tcp
      ports:
        - port: 80
```

別VpcのSecurityGroupを`securityGroupRef`で参照するルールはwebhookで拒否されます。

NetworkACLはアドレスベースで評価されるので、対向Vpcからの通信にもそのままルールが効きます。

## 3つ以上のVpcを繋ぐ場合

ピアリングは推移しません。`shop-vpc`と`payment-vpc`、`payment-vpc`と`audit-vpc`をピアリングしても、`shop-vpc`から`audit-vpc`へは到達できません。

Vpcが増えて組み合わせを管理しきれなくなったら、[TransitGatewayでハブ&スポーク構成を作る](transit-gateway.md)を参照してください。

## うまくいかないとき

1. **VpcPeeringが`Ready=False`のまま**
    - `spec.requester.vpc`と`spec.accepter.vpc`のVpcが存在するか
    - 両Vpc間でSubnetのCIDRが重複していないか (`CIDRConflict`)
2. **RouteTableが`Ready=False`で`no Subnet in Vpc ... has CIDR ...`と出る**
    - `dst`が対向Vpcの既存SubnetのCIDRと完全に一致しているか
3. **片方向しか通らない**
    - 戻り方向のVpcのRouteTableにもルートを書いたか
4. **RouteTableは解決済みなのにPodから届かない**
    - 宛先PodのSecurityGroupがCIDRルールで送信元Subnetを許可しているか
    - 宛先SubnetにNetworkACLが付いている場合、送信元CIDRを許可しているか
5. **VpcPeeringを削除できない**
    - `via.vpcPeering`でこのVpcPeeringを参照しているRouteTableが残っています。先にルートを外してください

## 参照

- [VpcPeering](../resources/vpcpeering.md)
- [RouteTable](../resources/routetable.md)
- [Vpc](../resources/vpc.md)
- [Subnet](../resources/subnet.md)
- [SecurityGroup](../resources/securitygroup.md)
