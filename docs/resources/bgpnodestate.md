# BGPNodeState

BGPNodeStateは、クラスター内の各NodeにおけるBGP観測状態を表すリソースです。
ユーザーが直接作成・編集するリソースではなく、JuneauがNodeごとに自動的に生成し、各Nodeで動作するbgp-speakerが`status`フィールドを書き込みます。
クラスター管理者はBGPピアリングの状態を`kubectl get bgpnodestate`などで確認するためにこのリソースを参照します。


`status.bgpSessions`は各BGPセッションの状態の一覧です。各エントリは以下を含みます。

- `peerAddress`: bgp-speakerが観測したBGPピアのIPアドレス。常に埋まります。
- `peerName`: 対応するBGPPeerリソースのname。bgp-speakerが`peerAddress`から解決できた場合のみ埋まります。BGPPeerリソースが削除済みで古いセッションだけ残っている、設定の反映がまだ走っていない、などの状態では空になります（フォールバック値は入れません）。
- `state`: `Up` / `Down` / `Unknown`。
- `upSince`: セッションが最後にEstablishedになった時刻。
- `lastError`: 直近のPeerDown理由（BGP NOTIFICATIONコード/サブコードを含む）。

`status.advertisements`はこのNodeから広報しようとしているAddressPool（= BGPAdvertisementから参照される`advertiseMode=bgp`のpool）の**意図値**です。`prefixes`はbgp-speakerがピアに広報しようとしているユニークCIDRの集合（ソート済み文字列配列）、`lastSyncedAt`は設定の反映に成功した時刻です。**ここに載っているCIDRが実際にピアへ送信されているかは、このフィールドからは判定できません**。実送信の確認は上流ルータ側で受信ルートを確認してください。

`status.conditions`はKubernetes標準の`metav1.Condition`による状態表現で、Nodeレベルでの総合的な稼働状態を示します。以下の3つのtypeを定義します。

- `BirdRunning`: bgp-speakerでBGPセッション処理が起動しているか。
- `BMPConnected`: bgp-speakerのBGPセッション状態の監視経路が確立しているか。切断中は`status.bgpSessions`は空になります。
- `Ready`: 上記すべてが`True`かつ最近のreconcileが成功している場合のみ`True`。

`status.errors`はreconcile中に検出したspec不整合（参照先AddressPool欠落、BGPPeerのASN=0など）の記録です。対象リソースの種別・名前、メッセージ、直近の発生時刻を含み、同一`(kind,name)`で最新値のみを保持します。

`status.heartbeat`はbgp-speakerが最後にこのstatusを更新した時刻です。
