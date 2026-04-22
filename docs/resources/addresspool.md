# AddressPool

AddressPoolは、外部広報に利用できる外部アドレス範囲をまとめるリソースです。
ExternalNetworkやBGPAdvertisementから参照され、それらのリソースが払い出し可能なアドレスの源になります。

`spec.advertiseMode`はこのAddressPoolがどの方式で外部へ広報されるかを指定します。

- `bgp`:BGPで経路広報されるAddressPool
- `arp`:ARPで到達性が広報されるAddressPool

`spec.advertiseMode`は作成時に必須で、変更はできません。

`spec.addresses`はこのAddressPoolが保持するアドレス範囲の集合です。
重複は許されず、少なくとも1つの要素が必要で、要素を後から削除することはできません（追加のみ許容）。

`spec.addresses`の各要素の形式は`spec.advertiseMode`によって異なります。

- `spec.advertiseMode=bgp`の場合、各要素はIPv4 CIDR（プレフィックス長は/8から/32の範囲）で指定します。
- `spec.advertiseMode=arp`の場合、各要素は`start-end`形式のIPv4アドレス範囲で指定します。

AddressPoolがExternalNetworkまたはBGPAdvertisementから参照されている間は削除できません。
削除するには先に参照側のリソースから外すか、参照側のリソースを削除してください。
