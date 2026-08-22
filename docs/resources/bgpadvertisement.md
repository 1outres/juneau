# BGPAdvertisement

BGPAdvertisementは、AddressPoolが保持するアドレス範囲をBGPで外部へ経路広報するためのリソースです。
ピアリング先との接続情報はBGPPeerで別途定義し、BGPAdvertisementは「どのAddressPoolを広報するか」のみを宣言します。

`spec.addressPools`はBGPで広報するAddressPoolの名前の集合です。
重複は許されず、少なくとも1つの要素が必要です。
作成後も自由に要素を追加・削除できます。

`spec.addressPools`に含まれる各AddressPoolは、`spec.advertiseMode=bgp`である必要があります。
`spec.advertiseMode=arp`のAddressPoolは参照できません。
arp modeの広報には[ARPAdvertisement](arpadvertisement.md)を使いますが、こちらはcontrollerが自動的に作成するもので、ユーザーが作る必要はありません。

## 広報範囲の絞り込み

`spec.nodeName`は省略可能で、指定した場合はそのNode上のbgp-speakerだけがこのBGPAdvertisementを広報します。
未指定の場合は、すべてのNodeのbgp-speakerが広報します。
特定のNodeをingress入口にしたい場合に利用します。

`spec.prefix`は省略可能で、指定した場合はそのCIDR1件のみを広報します。
指定するCIDRは、`spec.addressPools`で参照しているAddressPoolが保持するCIDRのいずれかに含まれている必要があります。
AddressPoolが持つCIDR全体ではなく、そのうちの一部だけを広報したい場合に利用します。

## 広報状況の確認

BGPAdvertisementを作成すると、各Node上のbgp-speakerが参照先AddressPoolのCIDRをピアに広報します。bgp-speakerが**広報しようとしている**CIDR集合は、[BGPNodeState](bgpnodestate.md)の`status.advertisements[].prefixes`で確認できます。これはbgp-speakerの意図値（intent）で、reconcile成功時にAddressPool定義から計算されたものです。

**意図と実送信は必ずしも一致しません**。BGPNodeStateからは「Juneauが広報しようとしているCIDR」までしか判定できないため、実際にピアが受信しているかを確認したい場合は上流ルータ側で受信ルートを確認してください。

`BGPNodeState.status.conditions.Ready=True`かつ`status.advertisements`に期待CIDRが乗っていれば、通常は広報も成功しています。乗っていない場合は`status.errors[]`にspec不整合（参照先AddressPool欠落、`advertiseMode`不一致など）が記録されていないかも併せて確認してください。
