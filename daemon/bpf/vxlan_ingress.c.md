- VXLANに入るパケットを見る
- ドロップすると書かれている場合、TC_ACT_SHOTを返す。

# Functions

## tc_vxlan_ingress

1. L2ヘッダーのパースを行う
2. tunnel keyを取得し、そこからsubnet_idを復元する
3. subnet_idが1の場合、host_iface mapを引く。宛先MACアドレスをmacで書き換えて、ifindexに転送する
4. subnet_idが1以外の場合、fdb mapを引く(macは宛先macaddr)
5. fdb mapになかったらドロップ
6. ifindexが0じゃなかったら、そのifindexにbpf_redirect
7. ifindexが0だったらドロップ

Service の reverse SNAT は、vxlan_ingress が bpf_redirect で送り出した先の Pod veth egress に attach されている pod_ingress で行われる。vxlan_ingress 自体は decap + L2 forward のみを担当する。

