# Vpc

Vpcは、論理的に分離されたプライベートネットワーク環境を表します。

Juneauでは、PodやSubnetはVpcに所属し、異なるVpc間ではネットワークを分離して扱います。
Vpcは、どのSubnet同士が同じネットワーク空間に属するかを決めるための単位です。

## VpcとSubnetの関係

1つのVpcには、複数のSubnetを所属させられます。
`default` 以外のVpcでも、複数のSubnetを持つことを前提としています。

各Subnetは1つのVpcに属し、VpcがSubnet群の論理的なまとまりを表します。

## default Vpc

`default` Vpcは、クラスタに最初から存在する特別なVpcです。

Pod作成時にVPCやSubnetを指定するannotationが存在しない場合、そのPodは `default` Vpcに属する `default` Subnetを利用します。

そのため、明示的にネットワークを分けない限り、クラスタ内のワークロードはまず `default` Vpcを利用することになります。

## ルートテーブル

すべてのVpcには、メインルートテーブルが1つ存在します。

Subnetごとに個別のルートテーブルでoverrideしない場合、そのVpcのメインルートテーブルが利用されます。
つまり、Vpcのメインルートテーブルは、そのVpcに属するSubnetに対するデフォルトの経路制御を表します。

## Serviceの有効化

`spec.enableService`を`true`にすると、そのVpcに属するPodが同じVpc内のServiceに到達できるようになります。default以外のVpcでServiceを扱うには、このフィールドを明示的に有効化する必要があります。

`spec.enableService`が有効なVpcでは、そのメインルートテーブルにService CIDR向けの経路が自動で注入されます。

具体的な構築手順は[VPCでServiceを利用する](../guides/custom-vpc-service.md)を参照してください。

## 共有Serviceとの関係

`spec.enableService=true`が設定されたVpcは、default Vpcで公開された共有ServiceにClusterIP経由で到達できます。共有Serviceの公開と利用については[Vpcで共有Serviceを利用する](../guides/shared-service.md)を参照してください。
