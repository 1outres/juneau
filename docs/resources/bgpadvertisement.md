# BGPAdvertisement

BGPAdvertisementは、AddressPoolが保持するアドレス範囲をBGPで外部へ経路広報するためのリソースです。
ピアリング先との接続情報はBGPPeerで別途定義し、BGPAdvertisementは「どのAddressPoolを広報するか」のみを宣言します。

`spec.addressPools`はBGPで広報するAddressPoolの名前の集合です。
重複は許されず、少なくとも1つの要素が必要です。
作成後も自由に要素を追加・削除できます。

`spec.addressPools`に含まれる各AddressPoolは、`spec.advertiseMode=bgp`である必要があります。
`spec.advertiseMode=arp`のAddressPoolは参照できません。
