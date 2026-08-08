# TransitGatewayでハブ&スポーク構成を作る

VpcPeeringはVpcが増えると組み合わせの数が増えていきます。TransitGatewayを使うと、各Vpcをハブに1本ずつ接続するだけで済み、どのVpcからどのVpcへ通すかをルートテーブルで一括して決めることができます。

このガイドでは、共有サービスを置くハブVpcと、2つの業務用スポークVpcを1つのTransitGatewayにつなぎます。スポークはハブに到達し、スポーク同士は到達しない構成にします。

## このガイドで構築するもの

- TransitGateway (`corp-tgw`) と、自動生成されるdefault route table (`corp-tgw`)
- スポーク用のTransitGatewayRouteTable (`corp-tgw-spoke`)
- Vpc 3つ
    - `hub-vpc` とSubnet `hub-subnet` (`10.72.0.0/24`)
    - `spoke-a-vpc` とSubnet `spoke-a-subnet` (`10.73.0.0/24`)
    - `spoke-b-vpc` とSubnet `spoke-b-subnet` (`10.74.0.0/24`)
- 3つのTransitGatewayAttachment
- 各VpcのRouteTableに`via.type: transitGateway`のルート
- スポークからハブへ到達し、スポーク同士は到達しないこと

## 前提条件

- Juneauのcontroller/daemonが動作しているクラスター
- 接続するVpcの間で、SubnetのCIDRが重複していないこと

## 手順

### 1. VpcとSubnetを作成

```yaml
apiVersion: juneau.loutres.me/v1alpha1
kind: Vpc
metadata:
  name: hub-vpc
---
apiVersion: juneau.loutres.me/v1alpha1
kind: Vpc
metadata:
  name: spoke-a-vpc
---
apiVersion: juneau.loutres.me/v1alpha1
kind: Vpc
metadata:
  name: spoke-b-vpc
---
apiVersion: juneau.loutres.me/v1alpha1
kind: Subnet
metadata:
  name: hub-subnet
spec:
  vpc: hub-vpc
  cidr: 10.72.0.0/24
---
apiVersion: juneau.loutres.me/v1alpha1
kind: Subnet
metadata:
  name: spoke-a-subnet
spec:
  vpc: spoke-a-vpc
  cidr: 10.73.0.0/24
---
apiVersion: juneau.loutres.me/v1alpha1
kind: Subnet
metadata:
  name: spoke-b-subnet
spec:
  vpc: spoke-b-vpc
  cidr: 10.74.0.0/24
```

### 2. TransitGatewayを作成

```yaml
apiVersion: juneau.loutres.me/v1alpha1
kind: TransitGateway
metadata:
  name: corp-tgw
```

```console
$ kubectl get transitgateway
NAME       DEFAULTROUTETABLE   READY
corp-tgw   corp-tgw            True
```

TransitGatewayと同じ名前のTransitGatewayRouteTableが自動的に作成されます。このガイドではこれをハブ用のルートテーブルとして使います。詳細は[TransitGateway](../resources/transitgateway.md)を参照してください。

### 3. スポーク用のルートテーブルを作成

```yaml
apiVersion: juneau.loutres.me/v1alpha1
kind: TransitGatewayRouteTable
metadata:
  name: corp-tgw-spoke
spec:
  transitGateway: corp-tgw
```

```console
$ kubectl get transitgatewayroutetable
NAME             TRANSITGATEWAY   TABLEID   READY
corp-tgw         corp-tgw         1         True
corp-tgw-spoke   corp-tgw         2         True
```

`TABLEID`が払い出されればデータプレーンから参照できる状態です。詳細は[TransitGatewayRouteTable](../resources/transitgatewayroutetable.md)を参照してください。

### 4. 3つのVpcをアタッチ

`association`は、そのVpcから届いたトラフィックの宛先を引くルートテーブルです。
`propagations`は、そのVpcのSubnetを載せるルートテーブルの一覧です。

ハブは自分のSubnetをスポーク用テーブルに載せ、宛先はdefault route tableで引きます。スポークは逆に、自分のSubnetをdefault route tableに載せ、宛先はスポーク用テーブルで引きます。

```yaml
apiVersion: juneau.loutres.me/v1alpha1
kind: TransitGatewayAttachment
metadata:
  name: hub-attachment
spec:
  transitGateway: corp-tgw
  vpc: hub-vpc
  association: corp-tgw
  propagations:
    - corp-tgw-spoke
---
apiVersion: juneau.loutres.me/v1alpha1
kind: TransitGatewayAttachment
metadata:
  name: spoke-a-attachment
spec:
  transitGateway: corp-tgw
  vpc: spoke-a-vpc
  association: corp-tgw-spoke
  propagations:
    - corp-tgw
---
apiVersion: juneau.loutres.me/v1alpha1
kind: TransitGatewayAttachment
metadata:
  name: spoke-b-attachment
spec:
  transitGateway: corp-tgw
  vpc: spoke-b-vpc
  association: corp-tgw-spoke
  propagations:
    - corp-tgw
```

```console
$ kubectl get transitgatewayattachment
NAME                 TRANSITGATEWAY   VPC           ASSOCIATION      READY
hub-attachment       corp-tgw         hub-vpc       corp-tgw         True
spoke-a-attachment   corp-tgw         spoke-a-vpc   corp-tgw-spoke   True
spoke-b-attachment   corp-tgw         spoke-b-vpc   corp-tgw-spoke   True
```

詳細は[TransitGatewayAttachment](../resources/transitgatewayattachment.md)を参照してください。

### 5. ルートテーブルの中身を確認

アタッチメントが広報したSubnetが、それぞれのルートテーブルに載っているか確認します。

```console
$ ROUTES='{range .status.routes[*]}{.dst}{"\t"}{.subnet}{"\t"}{.origin}{"\n"}{end}'
$ kubectl get transitgatewayroutetable corp-tgw -o jsonpath="$ROUTES"
10.73.0.0/24	spoke-a-subnet	propagated
10.74.0.0/24	spoke-b-subnet	propagated

$ kubectl get transitgatewayroutetable corp-tgw-spoke -o jsonpath="$ROUTES"
10.72.0.0/24	hub-subnet	propagated
```

スポーク用テーブルにはハブのSubnetしか載っていません。スポーク同士が到達しないのはこのためです。

### 6. 各VpcのRouteTableにルートを追加

VpcのメインRouteTableはVpc名と同じ名前で自動生成されます。TransitGateway経由で出したい宛先を書き足します。

```yaml
apiVersion: juneau.loutres.me/v1alpha1
kind: RouteTable
metadata:
  name: hub-vpc
spec:
  vpc: hub-vpc
  routes:
    - dst: 10.73.0.0/24
      via:
        type: transitGateway
        transitGateway: corp-tgw
    - dst: 10.74.0.0/24
      via:
        type: transitGateway
        transitGateway: corp-tgw
---
apiVersion: juneau.loutres.me/v1alpha1
kind: RouteTable
metadata:
  name: spoke-a-vpc
spec:
  vpc: spoke-a-vpc
  routes:
    - dst: 10.72.0.0/24
      via:
        type: transitGateway
        transitGateway: corp-tgw
---
apiVersion: juneau.loutres.me/v1alpha1
kind: RouteTable
metadata:
  name: spoke-b-vpc
spec:
  vpc: spoke-b-vpc
  routes:
    - dst: 10.72.0.0/24
      via:
        type: transitGateway
        transitGateway: corp-tgw
```

VpcPeeringと違い、ここでの`dst`は複数のSubnetをまとめたスーパーネットでも構いません。実際の宛先解決はTransitGatewayRouteTableの中で行われます。

戻り方向にもルートが必要なので、ハブ側にもスポーク宛のルートを書きます。

```console
$ kubectl get routetable spoke-a-vpc -o jsonpath='{.status.routes[?(@.dst=="10.72.0.0/24")]}'
{"dst":"10.72.0.0/24","transitGatewayRouteTable":"corp-tgw-spoke","via":{"type":"transitGateway","transitGateway":"corp-tgw"}}
```

`transitGatewayRouteTable`には、そのVpcのアタッチメントが`association`に指定したルートテーブルが入ります。

### 7. Podをデプロイ

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: shared
  annotations:
    juneau.loutres.me/subnet: hub-subnet
spec:
  containers:
    - name: nginx
      image: nginx:1.27
---
apiVersion: v1
kind: Pod
metadata:
  name: app-b
  annotations:
    juneau.loutres.me/subnet: spoke-b-subnet
spec:
  containers:
    - name: nginx
      image: nginx:1.27
---
apiVersion: v1
kind: Pod
metadata:
  name: app-a
  annotations:
    juneau.loutres.me/subnet: spoke-a-subnet
spec:
  containers:
    - name: curl
      image: curlimages/curl:8.7.1
      command: ["sleep", "infinity"]
```

### 8. 疎通を確認

custom VpcのPodからはCoreDNSが使えないため、宛先のPod IPを直接指定します。

```console
$ SHARED=$(kubectl get pod shared -o jsonpath='{.status.podIP}')
$ kubectl exec app-a -- curl -sS --max-time 5 http://$SHARED/
<!DOCTYPE html>
...
<h1>Welcome to nginx!</h1>
```

スポークからハブへは届きます。スポーク同士は、`spoke-a-vpc`のRouteTableに`10.74.0.0/24`のルートを足しても届きません。パケットはTransitGatewayまで届きますが、`corp-tgw-spoke`に`10.74.0.0/24`のエントリが無いため破棄されます。

## すべてのVpcを相互に接続する場合

スポーク同士も通したい場合は、ルートテーブルを分けずに、3つのアタッチメントすべての`association`と`propagations`にdefault route tableを指定します。

```yaml
spec:
  transitGateway: corp-tgw
  vpc: spoke-a-vpc
  association: corp-tgw
  propagations:
    - corp-tgw
```

この構成では、default route tableに3つのVpcのSubnetがすべて載るため、どのVpcからどのVpcへも到達できます。

## 特定の宛先だけ落とす

相互接続の構成のまま一部の宛先だけ遮断したい場合は、TransitGatewayRouteTableにblackhole routeを書きます。

```yaml
apiVersion: juneau.loutres.me/v1alpha1
kind: TransitGatewayRouteTable
metadata:
  name: corp-tgw
spec:
  transitGateway: corp-tgw
  routes:
    - dst: 10.74.0.0/24
      blackhole: true
```

static routeはpropagated routeより優先されるため、広報された`10.74.0.0/24`はこのblackholeで上書きされます。

```console
$ kubectl get transitgatewayroutetable corp-tgw -o jsonpath='{.status.routes[?(@.dst=="10.74.0.0/24")]}'
{"blackhole":true,"dst":"10.74.0.0/24","origin":"static"}
```

`blackhole`を使わないstatic routeでは`attachment`が必須で、`dst`はそのアタッチメントのVpcに存在するSubnetのCIDRと完全に一致している必要があります。

## SecurityGroupを併用する場合

SecurityGroupの`securityGroupRef`は同じVpcのSecurityGroupしか参照できません。TransitGateway経由で届く他VpcのPodからの通信を許可するには、`cidr`のルールを書いてください。

```yaml
apiVersion: juneau.loutres.me/v1alpha1
kind: SecurityGroup
metadata:
  name: shared-sg
spec:
  vpc: hub-vpc
  ingress:
    - from:
        - cidr: 10.73.0.0/24
        - cidr: 10.74.0.0/24
      protocol: tcp
      ports:
        - port: 80
```

## うまくいかないとき

1. **TransitGatewayAttachmentが作成できない**
    - `association`や`propagations`のTransitGatewayRouteTableが、`spec.transitGateway`と同じTransitGatewayに属しているか
    - 同じルートテーブルを共有する他のVpcとSubnetのCIDRが重複していないか
    - 同じVpcを同じTransitGatewayに2回アタッチしていないか
2. **TransitGatewayRouteTableに宛先が載らない**
    - 宛先のVpcのアタッチメントが、そのルートテーブルを`spec.propagations`に含んでいるか
    - `kubectl get transitgatewayattachment <name> -o jsonpath='{.status.prefixes}'`で広報対象のSubnetを確認
3. **RouteTableが`Ready=False`で`Vpc ... has no attachment to TransitGateway ...`と出る**
    - そのVpcのTransitGatewayAttachmentが存在するか
4. **RouteTableは解決済みなのにPodから届かない**
    - 送信元Vpcのアタッチメントが`association`しているルートテーブルに、宛先のエントリがあるか
    - そのエントリが`blackhole: true`になっていないか
    - 宛先PodのSecurityGroupが`cidr`のルールで送信元Subnetを許可しているか
    - ClusterIP宛なら、バックエンドPodがTransitGateway越しの他のVpcにいないか
5. **TransitGatewayRouteTableを削除できない**
    - `spec.association`または`spec.propagations`で参照しているTransitGatewayAttachmentが残っています
    - TransitGatewayと同じ名前のdefault route tableは単独では削除できません
6. **TransitGatewayを削除できない**
    - TransitGatewayAttachmentか、`via.transitGateway`で参照しているRouteTableが残っています

## 参照

- [TransitGateway](../resources/transitgateway.md)
- [TransitGatewayRouteTable](../resources/transitgatewayroutetable.md)
- [TransitGatewayAttachment](../resources/transitgatewayattachment.md)
- [RouteTable](../resources/routetable.md)
- [VpcPeering](../resources/vpcpeering.md)
- [Vpc](../resources/vpc.md)
- [Subnet](../resources/subnet.md)
