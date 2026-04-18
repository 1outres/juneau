# Vpc

`Vpc` は、論理的に分離されたプライベートネットワーク環境を表します。

Juneau では、Pod や Subnet は `Vpc` に所属し、異なる `Vpc` 間ではネットワークを分離して扱います。
`Vpc` は、どの Subnet 同士が同じネットワーク空間に属するかを決めるための単位です。

## Vpc と Subnet の関係

1 つの `Vpc` には、複数の `Subnet` を所属させられます。
`default` 以外の `Vpc` でも、複数の `Subnet` を持つことを前提としています。

各 `Subnet` は 1 つの `Vpc` に属し、`Vpc` が Subnet 群の論理的なまとまりを表します。

## default Vpc

`default` Vpc は、クラスタに最初から存在する特別な Vpc です。

Pod 作成時に VPC や Subnet を指定する annotation が存在しない場合、その Pod は `default` Vpc に属する `default` Subnet を利用します。

そのため、明示的にネットワークを分けない限り、クラスタ内のワークロードはまず `default` Vpc を利用することになります。

##ルートテーブル

すべての `Vpc` には、メインルートテーブルが 1 つ存在します。

Subnet ごとに個別のルートテーブルで override しない場合、その `Vpc` のメインルートテーブルが利用されます。
つまり、Vpc のメインルートテーブルは、その Vpc に属する Subnet に対するデフォルトの経路制御を表します。
