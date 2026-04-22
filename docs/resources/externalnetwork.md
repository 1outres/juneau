# ExternalNetwork

ExternalNetworkは、クラスター外部とつなぐネットワーク接続点を表すリソースです。
外部へ広報する複数のAddressPoolを1つの論理的なネットワークとしてまとめ、ElasticIPなどのリソースがここから外部到達可能なアドレスを払い出します。

`spec.type`はこのExternalNetworkがどの方式で外部へ経路を広報するかを指定します。

- `bgp`:BGPで経路広報される外部ネットワーク
- `arp`:ARPで到達性が広報される外部ネットワーク

`spec.type`は作成時に必須で、変更はできません。

`spec.addressPools`はこのExternalNetworkが利用するAddressPoolの名前の集合です。
重複は許されず、少なくとも1つの要素が必要です。

`spec.addressPools`に含まれる各AddressPoolは、`spec.advertiseMode`が`spec.type`と一致している必要があります。
`spec.type=bgp`ならAddressPoolは`spec.advertiseMode=bgp`、`spec.type=arp`ならAddressPoolは`spec.advertiseMode=arp`でなければなりません。

