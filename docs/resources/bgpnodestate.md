# BGPNodeState

BGPNodeStateは、クラスター内の各NodeにおけるBGP観測状態を表すリソースです。
ユーザーが直接作成・編集するリソースではなく、juneauのNodeReconcilerがNodeごとに自動的に生成し、各Nodeで動作するbgp-speakerデーモンが`status`フィールドを書き込みます。
クラスター管理者はBGPピアリングの状態を`kubectl get bgpnodestate`などで確認するためにこのリソースを参照します。

`status.heartbeat`はbgp-speakerが最後にstatusを更新した時刻です。長時間更新されていない場合、該当Node上のbgp-speakerが停止している可能性があります。

`status.bgpSessions`は各BGPPeerに対するセッションの状態の一覧です。ピアごとの状態、セッション確立時刻、直近のエラー情報などを含みます。

`status.advertisements`は現在このNodeから広報しているAddressPoolと、その広報内容（プレフィックス数や最終同期時刻など）の一覧です。

`status.conditions`はKubernetes標準の`metav1.Condition`による状態表現で、Nodeレベルでの総合的な稼働状態を示します。

`status.errors`はreconcile中に発生した不整合やエラーの記録です。対象リソースの種別・名前、メッセージ、直近の発生時刻を含みます。
