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

## type: arp

`spec.type=arp`の場合、上流へ経路を広報するのではなく、払い出したアドレス宛のARP Requestに対してNodeが直接ARP Replyを返します。
ElasticIP、ServiceLoadBalancer、NATGatewayの各controllerが、払い出したアドレスと応答するNodeの組を[ARPAdvertisement](arpadvertisement.md)として作成し、そのNode上のdaemonがeBPFでARP Replyを組み立てます。BGPPeerもBGPAdvertisementも必要ありません。

1つのアドレスに応答するNodeは常に1つだけです。同じアドレスを持つARPAdvertisementが2つ以上作られることは、ARPAdvertisementのwebhookが拒否します。
上流から見ると宛先MACが1つしか無いため、BGPのECMPに相当する分散はできず、1アドレスあたりの帯域はNode1台分になります。

払い出すアドレスは、NodeのNICと同じL2サブネット内でなければなりません。上流のルータやホストがARPでそのアドレスを解決できることが前提です。
daemonがARP Replyを返すNICは`--node-ingress-iface`で指定したもので、未指定の場合はNodeのInternalIPを持つNICになります。

構築手順は[ARPを使ってExternalNetworkを構築する](../guides/external-network-arp.md)を参照してください。
