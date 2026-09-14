- VXLANに入るパケットを見る
- ドロップすると書かれている場合、TC_ACT_SHOTを返す。

# Functions

## tc_vxlan_ingress

1. L2ヘッダーのパースを行う
2. tunnel keyを取得し、そこからsubnet_idを復元する
   - l2_network_mapにあればL2Networkの分岐に進む
   - subnet_mapに無ければ、handle_external_overlayに渡してその返り値を返す
3. fdb mapを引く(macは宛先macaddr)
4. fdb mapになかったらドロップ
5. ifindexが0じゃなかったら、そのifindexにbpf_redirect
6. ifindexが0だったらドロップ

Service の reverse SNAT は、vxlan_ingress が bpf_redirect で送り出した先の Pod veth egress に attach されている pod_ingress で行われる。vxlan_ingress 自体は decap + L2 forward のみを担当する。

default Subnet (VNI=1) も他の Subnet と同様に扱われる。default Subnet の gw_mac は cluster-wide な LAA で、Pod は通常の fdb 経路で到達できる。

## handle_external_overlay

別のNodeのnode_ingressが、ElasticIPを直接持つNIC宛にVXLANで送ってきたフレームを扱う。VNIはExternalNetworkのnetworkIDで、L2NetworkにもSubnetにも当たらない。

1. fdb mapを(VNI, 宛先MAC)で引く。無いか、ifindexが0(別のNode)ならドロップ
2. ifindex_external_network mapをそのifindexで引く。無いか、network_idがVNIと違えばドロップ
3. そのifindexにbpf_redirectする

送り元のNodeがNICの場所を解決済みなので、別のNodeへは中継しない。2の確認で、同じ番号がfdbで別の種類のvethを指していても届かない。

traceイベントは出さない。traceのtupleはVpcのスコープで引くが、このNICにはVpcが無い。

