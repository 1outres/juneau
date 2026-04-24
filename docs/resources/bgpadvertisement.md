# BGPAdvertisement

BGPAdvertisementは、AddressPoolが保持するアドレス範囲をBGPで外部へ経路広報するためのリソースです。
ピアリング先との接続情報はBGPPeerで別途定義し、BGPAdvertisementは「どのAddressPoolを広報するか」のみを宣言します。

`spec.addressPools`はBGPで広報するAddressPoolの名前の集合です。
重複は許されず、少なくとも1つの要素が必要です。
作成後も自由に要素を追加・削除できます。

`spec.addressPools`に含まれる各AddressPoolは、`spec.advertiseMode=bgp`である必要があります。
`spec.advertiseMode=arp`のAddressPoolは参照できません。

## 広報状況の確認

BGPAdvertisementを作成すると、各Node上のbgp-speakerが参照先AddressPoolのCIDRをピアに広報します。bgp-speakerが**広報しようとしている**CIDR集合は、[BGPNodeState](bgpnodestate.md)の`status.advertisements[].prefixes`で確認できます。これはbgp-speakerの意図値（intent）で、reconcile成功時にAddressPool定義から計算されたものです。

**意図と実送信は必ずしも一致しません**。bgp-speakerが使うBGPデーモン(BIRD)のBMP実装はadj-RIB-out（実際にピアに送信したRIB）を公開していないため、BGPNodeStateだけでは「実際にピアが受信しているか」までは判定できません。実送信の確認が必要な場合は、bgp-speaker Pod内で`birdc show route export <protocol>`を叩くか、ピア側のBGPルータ上で受信ルートを確認してください。

`BGPNodeState.status.conditions.Ready=True`かつ`status.advertisements`に期待CIDRが乗っていれば、通常は広報も成功しています。乗っていない場合は`status.errors[]`にspec不整合（参照先AddressPool欠落、`advertiseMode`不一致など）が記録されていないかも併せて確認してください。
