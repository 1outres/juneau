- VXLANに入るパケットを見る
- ドロップすると書かれている場合、TC_ACT_SHOTを返す。

# Functions

## tc_vxlan_ingress

1. L2ヘッダーのパースを行う
2. tunnel keyを取得し、そこからsubnet_idを復元する
3. subnet_idが1の場合、host_iface mapを引く。宛先MACアドレスをmacで書き換えて、ifindexに転送する
4. subnet_idが1以外、IPv4の場合、apply_reverse_snatを呼び出す
   - subnet_mapからvpc_idを取得し、ct_mapを5-tupleで引く
   - CT_ACTION_SNATがヒットしたら、src IP+portをClusterIPの値に書き換える
   - CT missや別actionなら何もしない
5. fdb mapを引く(macは宛先macaddr)
6. fdb mapになかったらドロップ
7. ifindexが0じゃなかったら、そのifindexにbpf_redirect
8. ifindexが0だったらドロップ

## apply_reverse_snat

別ノードのpod_egressでforward DNATされたService flowに対する応答パケットに、ローカルct_mapに登録されているreverse SNATエントリを適用する。

forward DNATとforward CT登録は呼び出し元podの存在するノードで行われる。応答パケットはVXLAN経由でそのノードに戻ってくるため、そのノードのvxlan_ingressでct_map lookupすればhitする(SNAT entryがある)。これがないとresponseはbackendのpod IPをsrcに持ったまま呼び出し元に届き、TCPセッションが破綻する。

