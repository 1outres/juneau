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

bootstrap 時の default Vpc には Service 関連の opt-in (`spec.service.consume: true` および `spec.service.provider.natSourceSubnet: default`) があらかじめ設定されています。

## ルートテーブル

すべてのVpcには、メインルートテーブルが1つ存在します。

Subnetごとに個別のルートテーブルでoverrideしない場合、そのVpcのメインルートテーブルが利用されます。
つまり、Vpcのメインルートテーブルは、そのVpcに属するSubnetに対するデフォルトの経路制御を表します。

## Service ルーティング

`spec.service` は、その Vpc が Service ルーティングにどのように関与するかを決める設定です。`spec.service` が未設定の Vpc では、その Vpc に属する Pod はいかなる ClusterIP にも到達できません (メインルートテーブルにも Service 用の経路が注入されません)。

`spec.service` の中の以下のいずれかが設定されると、その Vpc は Service ルーティング有効として扱われ、メインルートテーブルに Service CIDR 向けの経路が自動で注入されます。

| フィールド | 役割 |
|---|---|
| `spec.service.consume` | 自 Vpc の Pod が他 Vpc の共有Service に到達することを許可します |
| `spec.service.provider.natSourceSubnet` | 自 Vpc の Service を共有Service として公開するときに、SNAT のソースアドレスを払い出す Subnet を指定します |

両方を同時に設定することもできます。

具体的な構築手順は次を参照してください。

- [Vpc で Service を利用する](../guides/custom-vpc-service.md)
- [Vpc 間で共有Service を利用する](../guides/shared-service.md)

### Provider Subnet の制約

`spec.service.provider.natSourceSubnet` には、同じ Vpc に属する既存の Subnet の名前を指定する必要があります (webhook で検証されます)。指定した Subnet からは、Node ごとに 1 つの SNAT アドレスが払い出されます。Pod 用の払い出しと同じ Subnet を共有することもできますが、運用上は Service NAT 専用の Subnet を分けると衝突を避けられます。

### Consumer の ACL

`spec.service.consume: true` を設定すると、その Vpc の Pod は他 Vpc の共有Service にデフォルトで到達できます。Service 側で `juneau.loutres.me/shared-service-allowed-consumer-vpcs` annotation を指定すると、Service 単位で許可する caller Vpc を whitelist で絞り込めます。
