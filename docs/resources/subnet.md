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

## status

`status.vni` は、そのSubnetに割り当てられたVXLAN Network Identifierです。
Juneauはこれを使って、異なるSubnet同士のL2セグメントを識別します。

`status.gateway` は、そのSubnetで利用するゲートウェイIPv4アドレスです。

`status.gatewayMAC` は、そのゲートウェイIPに対応するMACアドレスです。
Podから見ると、このMACアドレスを持つ相手がサブネットのデフォルトゲートウェイとして振る舞います。

