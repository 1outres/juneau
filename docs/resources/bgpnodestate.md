# BGPNodeState

BGPNodeStateは、クラスター内の各NodeにおけるBGP観測状態を表すリソースです。
ユーザーが直接作成・編集するリソースではなく、juneauのNodeReconcilerがNodeごとに自動的に生成し、各Nodeで動作するbgp-speakerデーモンが`status`フィールドを書き込みます。
クラスター管理者はBGPピアリングの状態を`kubectl get bgpnodestate`などで確認するためにこのリソースを参照します。


`status.bgpSessions`は各BGPセッションの状態の一覧です。各エントリは以下を含みます。

- `peerAddress`: BMPで観測したBGPピアのIPアドレス。常に埋まります。
- `peerName`: 対応するBGPPeerリソースのname。bgp-speakerがconfig組立時に作る`peerAddress → name`マップで解決できた場合のみ埋まります。BGPPeerリソースが削除されたが古いセッションがまだ生きている、bird.conf reloadがまだ走っていない、などの状態では空になります（フォールバック値は入れません）。
- `state`: `Up` / `Down` / `Unknown`。
- `upSince`: セッションが最後にEstablishedになった時刻。
- `lastError`: 直近のPeerDown理由（BGP NOTIFICATIONコード/サブコードを含む）。

`status.advertisements`はこのNodeから広報しようとしているAddressPool（= BGPAdvertisementから参照される`advertiseMode=bgp`のpool）の**意図値**です。`prefixes`はbgp-speakerがピアに広報しようとしているユニークCIDRの集合（ソート済み文字列配列）、`lastSyncedAt`はbirdへのreload成功時刻です。**bird3のBMPはadj-RIB-outを公開しないため、ここに載っているCIDRが実際にピアへ送信できているかはこのフィールドからは読めません**。実送信の確認はbirdcで行ってください。

`status.conditions`はKubernetes標準の`metav1.Condition`による状態表現で、Nodeレベルでの総合的な稼働状態を示します。以下の3つのtypeを定義します。

- `BirdRunning`: bird (BGPデーモン) プロセスが走っているか。
- `BMPConnected`: bgp-speaker内のBMP stationにbirdがTCP接続しているか。切断中はstatus.bgpSessionsは空になります。
- `Ready`: 上記すべてが`True`かつ最近のreconcileが成功している場合のみ`True`。

`status.errors`はreconcile中に検出したspec不整合（参照先AddressPool欠落、BGPPeerのASN=0など）の記録です。対象リソースの種別・名前、メッセージ、直近の発生時刻を含み、同一`(kind,name)`で最新値のみを保持します。

`status.heartbeat`はbgp-speakerが最後にこのstatusを更新した時刻です。デフォルト15秒間隔で更新されます。
