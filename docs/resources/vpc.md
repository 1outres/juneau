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

##ルートテーブル

すべてのVpcには、メインルートテーブルが1つ存在します。

Subnetごとに個別のルートテーブルでoverrideしない場合、そのVpcのメインルートテーブルが利用されます。
つまり、Vpcのメインルートテーブルは、そのVpcに属するSubnetに対するデフォルトの経路制御を表します。
