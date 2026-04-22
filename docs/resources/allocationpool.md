# AllocationPool

AllocationPoolは、番号やアドレスなどのリソース属性を排他的に払い出すための汎用プールを表すリソースです。
SubnetのVNIやRouteTableのIDなど、クラスター内で一意であることが求められる値の割り当てにAllocationClaimから利用されます。

`spec.type`はこのAllocationPoolが扱う割当対象の種類を指定します。

- `number`:数値を払い出すプール

現状サポートされているのは`number`のみです。`ip`は予約されており、将来的にアドレス払い出しへ拡張される想定です。

`spec.strategy`は割当アルゴリズムを指定します。

- `firstFit`:プール範囲の下限から順に、未使用の値を最初に見つけたものから割り当てる

`spec.number`は`spec.type=number`の場合に必須で、払い出す数値の範囲を指定します。

- `spec.number.min`:払い出す数値の下限
- `spec.number.max`:払い出す数値の上限

`spec.number.min`は`spec.number.max`以下である必要があります。

`spec.type`、`spec.strategy`、`spec.number.min`、`spec.number.max`は作成後に変更できません。

`status.conditions`の`Ready`は、AllocationPoolが正常に利用可能かを表します。
`status.allocationVersion`は割り当てが更新されるたびに増加するカウンタで、`status.lastAllocatedNumber`は最後に割り当てられた数値です。

AllocationPoolがAllocationClaimから参照されている間は削除できません。
削除するには先に参照しているAllocationClaimを削除してください。

クラスター初期化時に、Subnet用のVNIプール`subnet-vni`とRouteTable用のIDプール`route-table-id`がブートストラップにより自動生成されます。
