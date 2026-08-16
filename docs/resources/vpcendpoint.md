# VpcEndpoint

VpcEndpointを作成すると、Serviceルーティングを有効にしていないVpcからでも、そのVpcに属するアドレスでKubernetes Serviceひとつに到達することができます。

Vpcの `spec.service` を設定すると、そのVpcのRouteTableにService CIDR向けの経路が入り、Vpc内のPodはクラスタ内のClusterIPを引けるようになります。VpcEndpointはこれより狭い許可です。Vpc全体のServiceルーティングは無効のまま、名指しした1つのServiceだけをそのVpcのアドレスの後ろに置きます。

VpcEndpointはクラスタスコープのリソースです。

## 最小構成

VIPの払い出し元になるプールをVpc側に宣言してから、VpcEndpointを作ります。

```yaml
apiVersion: juneau.loutres.me/v1alpha1
kind: Vpc
metadata:
  name: guest-vpc
spec:
  endpointPool:
    cidrs:
      - 10.80.255.0/28
---
apiVersion: juneau.loutres.me/v1alpha1
kind: Subnet
metadata:
  name: guest-subnet
spec:
  vpc: guest-vpc
  cidr: 10.80.0.0/24
```

`guest-vpc` には `spec.service` がありません。この状態のまま、default Vpcにある普通のServiceをVpcEndpointで前に出せます。

```yaml
apiVersion: juneau.loutres.me/v1alpha1
kind: VpcEndpoint
metadata:
  name: nginx
spec:
  vpc: guest-vpc
  service:
    namespace: default
    name: nginx
```

```console
$ kubectl get vpcendpoint
NAME    VPC         ADDRESS       READY
nginx   guest-vpc   10.80.255.2   True
```

`guest-subnet` に置いたPodから、払い出されたアドレスでbackendに届きます。待ち受けるポートはServiceの `spec.ports` に書いたものがそのまま使われます。

```console
$ kubectl exec curl -- curl -sS http://10.80.255.2/
<!DOCTYPE html>
...
```

同じPodからbackendのClusterIPを直接叩いても届きません。`guest-vpc` はServiceルーティングを有効にしていないので、開いているのはVpcEndpointのアドレスだけです。

## アドレスの払い出し元

VIPはVpcの `spec.endpointPool.cidrs` から取られます。どのCIDRを使うかはユーザーが決めます。CIDRは複数書けるので、払い出し済みのアドレスを動かさないままプールを後から足すことができます。

プールは、そのVpcのどのSubnetとも重ならない範囲に置いてください。Subnetの外に置くと、次の3つが同時に成り立ちます。

- VIPがSubnetのアドレスを消費しません。VpcEndpointをいくつ作ってもPodのアドレス在庫は減りません
- RouteTableに入る経路が、VpcEndpointごとの `/32` ではなくプールのCIDRごとに1本で済みます
- データプレーンがVIPのARPエントリを持たずに済みます。Podが持つ経路はgateway向けの `0.0.0.0/0` だけなので、Subnetの外のアドレスは何もしなくてもgatewayに向かいます

プールの経路は `via.type: vpcEndpoint` として、そのVpcのRouteTableに自動で入ります。ユーザーが `spec.routes` にこの型を書いても無視されます。

```console
$ kubectl get routetable guest-vpc -o yaml
...
status:
  routes:
    - dst: 10.80.0.0/24
      subnet: guest-subnet
      via:
        type: connected
    - dst: 10.80.255.0/28
      via:
        type: vpcEndpoint
```

この経路はVpcEndpointが1つも無くても残ります。プールの中でVpcEndpointが乗っていないアドレス宛のパケットは、ClusterIPとして解決されずにその場で落ちます。

## status

`status.address` が払い出されたVIP、`status.allocationClaim` がそれを押さえているAllocationClaimの名前です。

conditionは3つあります。

| type | Trueになる条件 | Falseのときのreason |
|---|---|---|
| `AddressAllocated` | プールからVIPを1つ確保できた | `VpcUnavailable` / `EndpointPoolNotConfigured` / `Allocating` |
| `ServiceAccepted` | backendのServiceが存在し、ClusterIPを持ち、そのServiceの持ち主のVpcがこの公開を許している | `ServiceNotFound` / `ClusterIPUnavailable` / `ServiceVpcNotFound` / `ServiceRoutingDisabled` / `NotAServiceProvider` |
| `Ready` | 上の2つがTrueで、backendにReadyなendpointが1つ以上ある | `VpcUnavailable` / `EndpointPoolNotConfigured` / `AddressPending` / `ServiceNotAccepted` / `BackendUnavailable` |

daemonがデータプレーンに書き込む基準は `ServiceAccepted` で、`Ready` ではありません。`Ready` はbackendのEndpointSliceにも連動するので、これを基準にするとPodが1つ入れ替わるたびにマップを書き直すことになります。

裏を返すと、controllerが受け入れなかったVpcEndpointは疎通しません。`status.address` が付いていても `ServiceAccepted` がFalseなら、そのアドレスは一切応答しません。アドレスがあるのに繋がらないときは、まず `ServiceAccepted` のreasonを読んでください。

## backend Serviceの受け入れ条件

VpcEndpointが指すServiceの持ち主は、Serviceの `juneau.loutres.me/vpc` annotationで決まります。annotationの無いServiceはdefault Vpcのものとして扱われます。

持ち主のVpcは、`spec.service` でServiceルーティングを有効にしている必要があります。無効なら `ServiceRoutingDisabled` で止まります。
持ち主のVpcがVpcEndpointの `spec.vpc` と違うときは、そのVpcがprovider (`spec.service.provider`) でなければなりません。providerでなければ `NotAServiceProvider` になります。

default Vpcはbootstrap時に `service.provider.natSourceSubnet: default` が入っているため、default VpcのServiceは追加設定なしで指せます。

[共有Service](../guides/shared-service.md)とは許可の出し方が違います。共有Serviceでは、Service側の `juneau.loutres.me/shared-service: "true"` と、呼び出す側のVpcの `spec.service.consume: true` の両方が要ります。VpcEndpointはどちらも要りません。VpcEndpointというリソースの存在自体が、そのVpcにそのServiceを見せるという1件の許可になっているためです。Service単位のconsumer ACLも適用されません。VpcEndpointを作れる権限は、Serviceを1つ開ける権限と同じ重さだと考えてください。

## 制限事項

### 他の経路との衝突

プールのCIDRは、同じFIBに載る他のprefixと重なってはいけません。webhookは次を拒否します。

- 同じVpcのSubnetと重なるCIDR
- VpcPeeringで接続した対向VpcのSubnetと重なるCIDR
- TransitGateway経由で届くVpcのSubnetと重なるCIDR
- クラスタのService CIDRと重なるCIDR
- `spec.endpointPool.cidrs` の中で互いに重なるCIDR

いずれも、重ねるとFIBに同じprefixの経路が2本入り、片方しか勝ちません。

### プールの書き方

CIDRはIPv4で、prefix長は `/16` から `/32` の範囲に収めてください。`/32` は、VIPを1つだけ置くプールとして通ります。`/16` より広い指定は、Vpcのアドレス空間を丸ごと飲み込むので拒否されます。

### プールの過不足

`spec.endpointPool` を持たないVpcを指すVpcEndpointは作成できません。プールが無ければアドレスを取れず、自力でReadyになることもないので、Status conditionに置くのではなくadmissionで返します。

VpcEndpointが使用中のアドレスを含まなくなるようなプールの縮小や削除も拒否されます。Vpc controllerはCIDRが消えた時点でAllocationPoolを削除するため、そのまま通すとVpcEndpointは存在しないpoolへのclaimを抱えたままになり、エラーも出ないままVIPが応答しなくなります。

作成後に `spec.vpc` を変えることもできません。VIPは変更前のVpcのプールから取ったものだからです。`spec.service` のほうは変更できます。アドレスを据え置いたまま向き先だけ差し替えるのは正当な運用なので、webhookはこちらを通します。
