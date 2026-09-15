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

`start-end`は開始アドレスと終了アドレスをハイフンでつないだ形式で、`10.225.32.240-10.225.32.250`のように書きます。
両端を含みます。開始アドレスが終了アドレスより後になっている場合や、CIDRを書いた場合は拒否されます。

1つのアドレスを持てるAddressPoolは1つだけです。
`spec.addresses`のどれかが他のAddressPoolのアドレスと1つでも重なると、作成も更新もwebhookに拒否されます。
`spec.advertiseMode`が違うAddressPoolどうしも比べるので、`bgp`のCIDRと`arp`の`start-end`が重なった場合も拒否されます。
エラーには、重なった相手のAddressPool名とその要素、重なったアドレスの範囲が出ます。

重なりを確認するのはwebhookだけで、controllerは確認しません。
この検証が入る前のバージョンで作られた重なりは、そのまま残ります。重なっているAddressPoolを次に更新しようとしたときに、はじめて拒否されます。
`spec.addresses`の要素は削除できないので、重なりをなくすにはどちらかのAddressPoolを作り直してください。

AddressPoolがExternalNetworkまたはBGPAdvertisementから参照されている間は削除できません。
削除するには先に参照側のリソースから外すか、参照側のリソースを削除してください。

## 払い出しの実体

AddressPoolを作成すると、controllerが`addr-<AddressPool名>`という名前のAllocationPoolを自動的に作成します。
ElasticIPやServiceLoadBalancerが実際にアドレスを確保するのはこのAllocationPoolに対してで、AddressPool自体には使用中のアドレスは記録されません。

`spec.advertiseMode`によって、AllocationPoolに書き込まれるフィールドが変わります。

- `bgp`の場合、`spec.addresses`のCIDRがそのまま`spec.ip.cidrs`に入ります。各CIDRのネットワークアドレスとブロードキャストアドレスは払い出しの対象外です。
- `arp`の場合、`start-end`を分解した`{start, end}`が`spec.ip.ranges`に入ります。範囲内のアドレスはすべて払い出しの対象です。

`advertiseMode=arp`のAddressPoolの範囲に、NodeのInternalIPを含めないでください。
そのアドレスがElasticIPなどに払い出されると、[ARPAdvertisement](arpadvertisement.md)の作成がwebhookに拒否され、そのリソースは利用可能になりません。
