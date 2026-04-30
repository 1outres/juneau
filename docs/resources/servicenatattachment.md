# ServiceNATAttachment

ServiceNATAttachmentは、Nodeごとの共有Service用ソースNATアドレスの割り当てを表すリソースです。

通常はユーザーが直接作成するリソースではなく、クラスタ内の各Nodeに対して1つずつ自動的に作成されます。クラスター管理者は、Nodeごとに割り当てられたソースNATアドレスを確認するためにこのリソースを参照します。

## 利用される場面

`spec.enableService=true`が設定されたVpcのPodから`shared-service`の対象として公開されたServiceに到達する際、Pod が配置されているNodeに対応するアドレスがソースIPとして利用されます。

詳しくは[Vpcで共有Serviceを利用する](../guides/shared-service.md)を参照してください。

## spec

`spec.nodeName`は対象のNodeの名前です。`metadata.name`と一致している必要があり、作成後に変更することはできません。

## status

`status.assignedIP`は、このNodeに対して払い出されたソースNATアドレスです。default Subnetのアドレス範囲から自動的に選ばれます。

`status.assignedMAC`は、`status.assignedIP`に対応する内部MACアドレスです。default Subnet内でこのソースNATアドレス向けの応答パケットを正しく該当Nodeへ届けるために利用されます。

`status.conditions`の`Ready`は、ソースNATアドレスの払い出しが完了し、このアタッチメントが利用可能な状態かを表します。
