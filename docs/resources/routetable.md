# RouteTable

RouteTableは、Vpc内の経路制御を表すリソースです。

すべてのVpcにはメインのRouteTableが1つ存在します。

Vpcに属するSubnetの接続経路は自動的にconnected routeとして生成されます。
`spec.routes`は、それに追加する経路を表します。

## `spec.routes[].via.type`

- `connected`: 同じVpc内のSubnetへ直接届くLayer 2通信。自動生成されるため通常ユーザーが手動指定することはありません
- `endpoint`: 特定のNetworkEndpointを経由する通信。`via.endpointName`で指定します
- `internetGateway`: Vpc外への通信。ElasticIPを付けたPodから外部へ出て行く経路はこのタイプを必要とします。デフォルトでは生成されないため、外部疎通が必要な場合は`spec.routes`に明示的に追加してください (例: [BGP ExternalNetworkガイド](../guides/external-network-bgp.md))
- `service`: 同じVpc内のServiceへ向かう通信。所属Vpcの `spec.service` でService ルーティングが有効になっている場合、Service CIDR向けの経路がこのタイプで自動注入されます。ユーザが手動で指定する必要はありません
- `natGateway`: NATGateway経由でVpc外へ出る通信。`via.natGateway`で対象NATGatewayの名前を指定します。N:1のNAPTで外部へ出る経路を作るときに利用します

