# RouteTable

RouteTableは、Vpc内の経路制御を表すリソースです。

Vpcに属するSubnetの接続経路は自動的にconnected routeとして生成されます。
`spec.routes`は、それに追加する経路を表します。

## メインRouteTable

すべてのVpcにはメインのRouteTableが1つ存在します。Vpcを作成すると、controllerがVpcと同じ名前のRouteTableを作り、その名前をVpcの`status.mainRouteTable`に書きます。

このRouteTableはユーザーが作るものではありません。Vpcと同じ名前のRouteTableをマニフェストに書いたときは、controllerが作ったオブジェクトに経路を足すことになります。

controllerがこのRouteTableに書き込むのは`spec.vpc`とownerReferenceだけです。`spec.routes`には触らないため、ユーザーが書いた経路がcontrollerに消されることはありません。

### VpcとメインRouteTableを一度に適用する

VpcとメインRouteTableを1つのマニフェストにまとめて適用するときは、server-side applyを使ってください。

```console
$ kubectl apply --server-side -f vpc.yaml
```

`kubectl apply -f`によるクライアント側のapplyは、対象をGETして、無ければPOSTするという2回のリクエストで動きます。Vpcを作った直後はcontrollerも同じ名前のRouteTableを作りに来るため、この2回の隙間にcontrollerのCreateが着地すると、POSTが`Error from server (AlreadyExists)`で失敗します。GitOpsでディレクトリを一括同期する構成では、タイミング次第でこの失敗を踏みます。

server-side applyはcreate-or-mergeを1回のリクエストで行うので、controllerとユーザーのどちらが先でも失敗しません。ユーザーが先に作った場合は、controllerが後からownerReferenceを付けて自分の管理下に入れますが、`spec.routes`はそのまま残ります。`spec.vpc`は双方が同じ値を書くため、フィールドの所有者が2つになるだけで、コンフリクトにはなりません。

## `spec.routes[].via.type`

- `connected`: 同じVpc内のSubnetへ直接届くLayer 2通信。自動生成されるため通常ユーザーが手動指定することはありません
- `endpoint`: 特定のNetworkEndpointを経由する通信。`via.endpointName`で指定します
- `internetGateway`: Vpc外への通信。ElasticIPを付けたPodから外部へ出て行く経路はこのタイプを必要とします。デフォルトでは生成されないため、外部疎通が必要な場合は`spec.routes`に明示的に追加してください (例: [BGP ExternalNetworkガイド](../guides/external-network-bgp.md))
- `service`: 同じVpc内のServiceへ向かう通信。所属Vpcの `spec.service` でService ルーティングが有効になっている場合、Service CIDR向けの経路がこのタイプで自動注入されます。ユーザが手動で指定する必要はありません
- `natGateway`: NATGateway経由でVpc外へ出る通信。`via.natGateway`で対象NATGatewayの名前を指定します。N:1のNAPTで外部へ出る経路を作るときに利用します
- `vpcPeering`: VpcPeeringで接続した対向VpcのSubnetへ向かう通信。`via.vpcPeering`で対象VpcPeeringの名前を指定します。`dst`は対向Vpcに存在するSubnetのCIDRと完全に一致させてください (例: [VpcPeeringガイド](../guides/vpc-peering.md))
- `transitGateway`: TransitGateway経由で他のVpcへ向かう通信。`via.transitGateway`で対象TransitGatewayの名前を指定します。宛先の解決はTransitGatewayRouteTableで行われるため、`dst`はスーパーネットでも構いません (例: [TransitGatewayガイド](../guides/transit-gateway.md))
- `vpcEndpoint`: VpcEndpointのVIP宛の通信。所属Vpcの `spec.endpointPool.cidrs` からコントローラが1つずつ自動注入します。`spec.routes`に手で書いても無視されるため、ユーザが指定することはできません (例: [VpcEndpoint](vpcendpoint.md))

