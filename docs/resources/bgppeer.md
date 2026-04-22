# BGPPeer

BGPPeerは、BGPピアリング対象の外部ルーターを宣言するリソースです。
BGPAdvertisementによって広報されるAddressPoolの経路は、ここで定義されたピアに対して送出されます。

`spec.myASN`はこのクラスター側のAS番号です。
`spec.peerASN`はピアリング対象のAS番号です。
いずれも必須で、指定できる値の範囲は1から4294967294までです。
2-byte ASN（1-65535）および4-byte ASNの両方を扱えます。

`spec.peerAddress`はピアリング対象のIPv4アドレスです。必須で、IPv6アドレスは指定できません。

`spec.peerPort`はピアリング対象のTCPポートです。optionalで、未指定の場合はBGPのwell-known portである`179`が使用されます。
