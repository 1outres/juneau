# ServiceNATAttachment

ServiceNATAttachmentは、共有Service の SNAT ソースアドレスを (Node, Provider Vpc) の組ごとに表すリソースです。

通常はユーザーが直接作成するリソースではなく、`spec.service.provider.natSourceSubnet` が設定された Vpc を起点として、その Vpc × クラスタ内の各 Node の組み合わせごとに 1 つずつ自動的に作成されます。クラスター管理者は、組ごとに割り当てられたソースNAT アドレスを確認するためにこのリソースを参照します。

## 利用される場面

ある Vpc の Pod が別 Vpc の共有Service に到達するとき、その Pod が配置されている Node 上で、共有Service の owner Vpc に紐付いた ServiceNATAttachment のアドレスがソース IP として書き換え (SNAT) に利用されます。SNAT のソースは Provider Vpc 側の Subnet から払い出されるため、Provider Vpc 内のファブリックを通って backend からの応答を呼び出し元の Node に戻すことができます。

詳しくは[Vpc 間で共有Service を利用する](../guides/shared-service.md)を参照してください。

## metadata.name

ServiceNATAttachment の `metadata.name` は `<nodeName>.<vpc>` という形に固定されています (webhook で検証されます)。`spec.nodeName` と `spec.vpc` を結合したものと一致している必要があり、作成後に変更することはできません。

## spec

`spec.nodeName` は対象の Node の名前です。
`spec.vpc` はこの ServiceNATAttachment が紐付く Provider Vpc の名前です。Provider Vpc は `spec.service.provider.natSourceSubnet` を設定済みである必要があります。

両方とも、作成後に変更することはできません。

## status

`status.assignedIP` は、この (Node × Provider Vpc) に対して払い出されたソース NAT アドレスです。Provider Vpc の `spec.service.provider.natSourceSubnet` で指定された Subnet のアドレス範囲から自動的に選ばれます。

`status.assignedMAC` は、`status.assignedIP` に対応する内部 MAC アドレスです。Provider Vpc 側のファブリックでこのソース NAT アドレス向けの応答パケットを正しく該当 Node へ届けるために利用されます。

`status.subnet` は、`status.assignedIP` を払い出した Subnet の名前です。Provider Vpc の `spec.service.provider.natSourceSubnet` の現在値を反映します。

`status.conditions` の `Ready` は、ソース NAT アドレスの払い出しが完了し、このアタッチメントが利用可能な状態かを表します。
