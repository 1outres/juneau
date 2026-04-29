# BGPPeer

BGPPeerは、BGPピアリング対象の外部ルーターを宣言するリソースです。
BGPAdvertisementによって広報されるAddressPoolの経路は、ここで定義されたピアに対して送出されます。

`spec.myASN`はこのクラスター側のAS番号です。
`spec.peerASN`はピアリング対象のAS番号です。
いずれも必須で、指定できる値の範囲は1から4294967294までです。
2-byte ASN（1-65535）および4-byte ASNの両方を扱えます。

`spec.peerAddress`はピアリング対象のIPv4アドレスです。必須で、IPv6アドレスは指定できません。

`spec.peerPort`はピアリング対象のTCPポートです。optionalで、未指定の場合はBGPのwell-known portである`179`が使用されます。

## セッション状態の確認

BGPPeerを作成すると、各Node上のbgp-speakerがこのピアに対してBGPセッションを張ります。セッションの状態（Up/Down）、最終Established時刻、直近のPeerDown理由などは[BGPNodeState](bgpnodestate.md)の`status.bgpSessions[]`で観測できます。`BGPNodeState`の`peerAddress`が`BGPPeer.spec.peerAddress`と一致するエントリを参照してください。

`kubectl get bgpnodestate`の`Ready`列が`True`になっていれば、そのNode上のbgp-speakerが正常に動作し、直近のreconcileも成功している状態で、設定されたBGPPeerとのセッションも期待どおりに確立しています。
