# ElasticIPAttachment

ElasticIPAttachmentは、ElasticIPをNetworkInterfaceへ関連付けるリソースです。

1つのElasticIPに対して有効なElasticIPAttachmentは最大1つです。
1つのNetworkInterfaceに対して有効なElasticIPAttachmentも最大1つです。

## 前提

- 対象のNetworkInterfaceは**default以外のSubnet**に属している必要があります。default SubnetのPodはElasticIPの対象にできません
- 対象Podが属するVpcのRouteTableに`type: internetGateway`のルートが必要です。無いと外部疎通が成立しません

セットアップ手順の全体像は[BGPを使ってExternalNetworkを構築する](../guides/external-network-bgp.md)を参照してください。

`status.elasticIP`は関連付け対象として解決されたElasticIPのアドレスです。
`status.podIP`は関連付け先NetworkInterfaceのPod側IPアドレスです。
`status.nodeName`は関連付け先NetworkInterfaceが存在するノード名です。

`Ready`は、この関連付けを安全に扱える状態かを表します。
`Ready=True`ならElasticIPとNetworkInterfaceが解決され、対応するNetworkEndpointも一意に定まり、関連付け済みです。
`Ready=False`なら依存リソース待ち、または不整合があります。

## Phase

- Pending:依存リソースの割り当てや対応するNetworkEndpointの作成待ち
- Attached:ElasticIPが1つのNetworkInterfaceへ正常に関連付けられている状態
- Error:参照先不整合や複数NetworkEndpoint一致などで正常に扱えない状態
