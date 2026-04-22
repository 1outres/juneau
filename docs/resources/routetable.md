# RouteTable

RouteTableは、Vpc内の経路制御を表すリソースです。

すべてのVpcにはメインのRouteTableが1つ存在します。

Vpcに属するSubnetの接続経路は自動的にconnected routeとして生成されます。
`spec.routes`は、それに追加する経路を表します。

