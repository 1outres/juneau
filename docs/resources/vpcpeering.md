# VpcPeering

VpcPeeringは、2つのVpcを接続するリソースです。

`spec.requester.vpc`と`spec.accepter.vpc`で両端のVpcを指定します。AWSのような承認フローは無く、2つの側に機能上の違いはありません。statusの表示順を安定させるために名前を分けているだけです。

`spec.requester`と`spec.accepter`は作成後に変更することができません。

## RouteTableとの連携

VpcPeeringを作成しただけでは通信は成立しません。到達させたい宛先ごとに、VpcのRouteTableへ`via.type: vpcPeering`のルートを追加し、`via.vpcPeering`でVpcPeering名を参照します。

ルートを書いた方向にしか通りません。双方向で通信する場合は、両方のVpcのRouteTableにルートが必要です。

詳しくは[RouteTable](routetable.md)を参照してください。

## dstの制約

`via.type: vpcPeering`のルートの`dst`は、対向Vpcに存在するSubnetのCIDRと完全に一致している必要があります。

データプレーンはこのルートを1つの宛先SubnetのVNIへ転送するため、複数のSubnetにまたがるスーパーネットでは転送先が定まりません。一致するSubnetが無い場合、RouteTableは`Ready=False`になり、`no Subnet in Vpc ... has CIDR ...`というメッセージを返します。

## 推移しない接続

ピアリングは推移しません。VpcAとVpcB、VpcBとVpcCがそれぞれピアリングしていても、VpcAからVpcCへは到達できません。3つ以上のVpcをまとめて接続する場合は、すべての組み合わせにVpcPeeringを作るか、[TransitGateway](transitgateway.md)を利用してください。

## CIDRの重複

ピアリングする2つのVpcの間では、SubnetのCIDRが重複していてはいけません。重複したままVpcPeeringを作成しようとするとwebhookで拒否されます。ピアリング済みのVpcに対して、対向のSubnetと重複するCIDRのSubnetを作成しようとした場合も同様に拒否されます。

## SecurityGroupの制約

SecurityGroupのルールで対向のPodを`securityGroupRef`で指定できるのは、同じVpcのSecurityGroupだけです。所属判定はVpc単位で行われるため、対向VpcのPodは`securityGroupRef`のルールにマッチしません。対向Vpcからの通信を許可するには`cidr`のルールを書いてください。別VpcのSecurityGroupを参照するルールはwebhookで拒否されます。

NetworkACLはアドレスベースの評価なので、対向Vpcからの通信にもそのままルールが効きます。

## status

`status.conditions`の`Ready`は、両側のVpcが存在し、SubnetのCIDRが重複していないことを表します。`Ready=True`になるまでは、このVpcPeeringを参照するRouteTableのルートも有効になりません。

## 削除

このVpcPeeringを`via.vpcPeering`で参照しているRouteTableが残っている間は削除できません。先に参照元のRouteTableからルートを外してください。
