- VXLANに入るパケットを見る
- ドロップすると書かれている場合、TC_ACT_SHOTを返す。

# Functions

## tc_vxlan_ingress

1. L2ヘッダーのパースを行う
2. tunnel keyを取得し、そこからsubnet_idを復元する
3. fdb mapを引く(macは宛先macaddr)
4. fdb mapになかったらドロップ
5. ifindexが0じゃなかったら、そのifindexにbpf_redirect
6. ifindexが0だったらドロップ

Service の reverse SNAT は、vxlan_ingress が bpf_redirect で送り出した先の Pod veth egress に attach されている pod_ingress で行われる。vxlan_ingress 自体は decap + L2 forward のみを担当する。

default Subnet も他の Subnet と同様に扱われる (default を含むすべての Subnet は subnet-vni AllocationPool から VNI を払い出される)。default Subnet の gw_mac は cluster-wide な LAA で、Pod は通常の fdb 経路で到達できる。

VNI=1 は `VNI_UNDERLAY` (`daemon/bpf/maps.h`) として予約されており、cross-Node の underlay 等価パケット (LB owner redirection 等) を運ぶ用途に使われる。real Subnet には allocator が払い出さない (subnet-vni AllocationPool の Min=2)。

