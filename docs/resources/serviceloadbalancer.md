# ServiceLoadBalancer

ServiceLoadBalancer は、Juneau が管理する Kubernetes Service (type: LoadBalancer) から派生するリソースです。

Juneau の controller は、`spec.loadBalancerClass: juneau.loutres.me/load-balancer` が設定された LoadBalancer Service を発見すると、同じ namespace に同名の ServiceLoadBalancer を自動的に生成します。利用者がこのリソースを直接作成・編集することは想定されていません。

VIP の払い出し条件は次の通りです。

- 親 Service の annotation `juneau.loutres.me/load-balancer-external-network` で指定された ExternalNetwork が存在する
- ExternalNetwork が参照する AddressPool のうち少なくとも 1 つの `advertiseMode` が ExternalNetwork の `spec.type` と一致している
- 任意で `juneau.loutres.me/load-balancer-requested-ip` を指定した場合、その IP が AddressPool の範囲内に含まれている

## Phase

- Pending: VIP の払い出しを待っている状態
- Allocated: VIP は払い出されたが、まだ広告できる Local backend が居ない状態
- Ready: VIP が払い出され、少なくとも 1 つのノードで広告されている状態
- Degraded: VIP は払い出されたが、現在広告しているノードが 1 つも無い状態
- Error: ExternalNetwork や AddressPool の不整合で VIP を払い出せない状態

## status のフィールド

- `status.vip` — 払い出された外部 IP
- `status.addressPool` — VIP の払い出し元 AddressPool
- `status.ports` — Service の port をデータプレーン用に正規化した一覧 (named targetPort も整数に解決済み)
- `status.advertisingNodes` — 現在 VIP を広告できるノード名の一覧。各ノードに少なくとも 1 つの Ready/Serving/non-terminating な Local endpoint が存在する場合に限り含まれる。type=bgp ではこの全ノードが VIP を広告し、type=arp ではこの中から 1 つが選ばれる
- `status.arpAnnouncingNode` — type=arp のとき、ARP に応答しているノード名。type=bgp のときと、応答できるノードが 1 つも無いときは空になる
- `status.backendSummary.totalReady` — Service 全体で Ready な endpoint 数
- `status.backendSummary.localReadyNodes` — `advertisingNodes` の数
- `status.conditions[type=Allocated]` — VIP 割り当ての成否
- `status.conditions[type=Available]` — 広告可能な状態かどうか (False のとき reason=NoReadyBackends)

## type=arp の ExternalNetwork を使う場合

VIP を広告するのは 1 ノードだけです。controller は `status.advertisingNodes` から 1 つを選び、`slb-<namespace>-<ServiceLoadBalancer 名>` という名前の [ARPAdvertisement](arpadvertisement.md) を作ります。選ばれたノード名は `status.arpAnnouncingNode` にも書かれます。

選出は、現在のノードが `status.advertisingNodes` に残っている限りそのノードを維持します。残っていない場合だけ、VIP とノード名から計算する rendezvous hashing で選び直します。VIP が複数あれば、それぞれ別のノードに散ります。

`status.advertisingNodes` が空になると ARPAdvertisement は削除され、Phase は Degraded になります。この間 VIP には誰も応答しません。

応答ノードが移ったとき、Juneau は gratuitous ARP を送りません。上流の neighbor キャッシュが古い MAC を保持している間は、backend が Ready でも VIP に到達できません。詳しくは [ARPAdvertisement](arpadvertisement.md) を参照してください。

## 制限事項

- IPv4 / TCP・UDP のみ
- externalTrafficPolicy: Local のみ
- backend は Juneau-managed の Pod のみ
