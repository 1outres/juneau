# AllocationClaim

AllocationClaimは、AllocationPoolから1つの値を排他的に予約するための要求を表すリソースです。
SubnetのVNIやRouteTableのIDなど、AllocationPool管理下の値を払い出す側のリソースから作成されます。

`spec.poolRef.name`は、どのAllocationPoolから値を割り当てるかを指定します。

`spec.resourceRef`は、この割り当てが紐づく対象のリソースを表します。

- `spec.resourceRef.apiVersion`:対象リソースのAPIバージョン
- `spec.resourceRef.kind`:対象リソースのKind
- `spec.resourceRef.name`:対象リソースの名前

参照するリソースが存在しない間はAllocationClaimの割り当ては行われません。

`spec.attribute`は、割当値を対象リソースのどのフィールドに使うかを識別する文字列です。
例えばSubnetのVNI割当では`status.vni`、RouteTableのID割当では`status.tableID`のような値が使われます。

`spec.requestedNumber`は任意で、特定の数値を要求したい場合に指定します。
指定する値はAllocationPoolの`spec.number.min`と`spec.number.max`の範囲内で、かつ他のAllocationClaimが既に取得していない必要があります。
既に他のAllocationClaimが取得している値を要求した場合や範囲外の値を要求した場合は、割り当てに失敗し`Ready=False`となります。

`spec`全体は作成後に変更できません。

`status.phase`は割り当ての進行状況を表します。

- `Pending`:対象リソースやプールの解決待ち、または割り当てに失敗している状態
- `Allocated`:値が割り当て済みの状態

`status.value.number`には割り当てられた数値が格納されます。
`status.conditions`の`Ready`は、割り当てが完了し対象リソースから利用可能な状態であるかを表します。

AllocationClaimの`ownerReferences`は呼び出し側のリソースが設定する運用を想定しており、所有リソースが削除された際にはAllocationClaimもカスケードで削除されます。
