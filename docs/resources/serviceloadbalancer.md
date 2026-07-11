# ServiceLoadBalancer

ServiceLoadBalancer は、Juneau が管理する Kubernetes Service (type: LoadBalancer) から派生するリソースです。

Juneau の controller は、`spec.loadBalancerClass: juneau.loutres.me/load-balancer` が設定された LoadBalancer Service を発見すると、同じ namespace に同名の ServiceLoadBalancer を自動的に生成します。利用者がこのリソースを直接作成・編集することは想定されていません。

VIP の払い出し条件は次の通りです。

- 親 Service の annotation `juneau.loutres.me/load-balancer-external-network` で指定された ExternalNetwork が存在する
- ExternalNetwork が参照する AddressPool のうち少なくとも 1 つが `advertiseMode=bgp` である
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
- `status.advertisingNodes` — 現在 VIP を BGP 広告しているノード名の一覧。各ノードに少なくとも 1 つの Ready/Serving/non-terminating な Local endpoint が存在する場合に限り含まれる
- `status.backendSummary.totalReady` — Service 全体で Ready な endpoint 数
- `status.backendSummary.localReadyNodes` — `advertisingNodes` の数
- `status.conditions[type=Allocated]` — VIP 割り当ての成否
- `status.conditions[type=Available]` — 広告可能な状態かどうか (False のとき reason=NoReadyBackends)

## 制限事項

- IPv4 / TCP・UDP のみ
- externalTrafficPolicy: Local のみ
- backend は Juneau-managed の Pod のみ
