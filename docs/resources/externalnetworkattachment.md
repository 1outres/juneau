# ExternalNetworkAttachment

ExternalNetworkAttachmentは、ExternalNetworkに対するNodeごとのNAPTソースIPアドレスの割り当てを表すリソースです。
NATGatewayがNodeごとに動作するために必要となる、(ExternalNetwork, Node) の関連付けを保持します。

通常はユーザーが直接作成するリソースではなく、NATGatewayが参照するExternalNetworkに対して、クラスタ内のNodeごとに1つずつ自動的に作成されます。
クラスター管理者は、Nodeごとに割り当てられたNAPTソースIPアドレスを確認するためにこのリソースを参照します。

`spec.externalNetwork`は対象のExternalNetworkの名前です。
`spec.nodeName`は対象のNodeの名前です。

`spec.externalNetwork`と`spec.nodeName`は作成後に変更できません。

## status

`status.assignedIP`は、このExternalNetworkAttachmentに対して払い出されたNAPTソースIPアドレスです。
このNode上のPodがNATGateway経由でVpc外へ出る際、このアドレスがソースIPとして使われます。

`status.conditions`の`Ready`は、NAPTソースIPアドレスの払い出しが完了し、このAttachmentが利用可能な状態かを表します。

## 広報

払い出したNAPTソースIPアドレスに戻り通信を届けるため、controllerは`ena-<ExternalNetworkAttachment名>`という名前のadvertisementを1つ作成します。
どちらの種類になるかは参照先ExternalNetworkの`spec.type`で決まります。

- `bgp`の場合、`spec.prefix`が`<assignedIP>/32`、`spec.nodeName`がこのAttachmentのNodeであるBGPAdvertisement
- `arp`の場合、`spec.address`が`assignedIP`、`spec.nodeName`がこのAttachmentのNodeである[ARPAdvertisement](arpadvertisement.md)

どちらもExternalNetworkAttachmentがOwnerになっているため、ExternalNetworkAttachmentを削除するとGarbage Collectorが回収します。

ExternalNetworkAttachment名は`<ExternalNetwork名>--<Node名>`です。
