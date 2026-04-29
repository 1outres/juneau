# Subnet

Subnetは、論理的なネットワークセグメントです。任意のVpcに対して作成することができます。

Juneauでは、PodはSubnetに接続され、どのIPアドレスが割り当てられるかか、どのL2セグメントに属するかをSubnetが表します。

## Vpc との関係

各Subnetは、必ず1つのVpcに属します。
1つのVpcには、複数のSubnetを作成できます。

## default Subnet

`default` という名前のSubnetは、クラスタに最初から存在する特別なSubnetです。

`default` Subnetは必ず `default` Vpcに属します。
また、`default` Vpcを参照できるのも `default` Subnetだけです。

Pod作成時にVpcやSubnetをアノテーションにより明示しない場合、Podはこの `default` Subnetの所属します。

## CIDR

`spec.cidr` には、そのSubnetが管理するIPv4アドレス範囲を指定します。

利用できるのはIPv4 CIDRだけです。
プレフィックス長は `/16` から `/28` までに制限されます。

## RouteTable のoverride

`spec.routeTable` は省略可能で、指定した場合はそのRouteTableがこのSubnetに属するPodの経路制御に使われます。
未指定の場合は、所属Vpcのメインルートテーブルが使われます。

`spec.routeTable` で参照するRouteTableは、このSubnetと同じVpcに属している必要があります。

## status

`status.gateway` は、そのSubnetで利用するゲートウェイIPv4アドレスです。

`status.gatewayMAC` は、そのゲートウェイIPに対応するMACアドレスです。
Podから見ると、このMACアドレスを持つ相手がサブネットのデフォルトゲートウェイとして振る舞います。

