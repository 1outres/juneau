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
- `endpoint`: ワークロードのNICを経由する通信。`via.endpoint`で、namespace、allocation identity、NICの名前を指定します。詳しくは「[endpoint経由の経路](#endpoint経由の経路)」を見てください
- `internetGateway`: Vpc外への通信。ElasticIPを付けたPodから外部へ出て行く経路はこのタイプを必要とします。デフォルトでは生成されないため、外部疎通が必要な場合は`spec.routes`に明示的に追加してください (例: [BGP ExternalNetworkガイド](../guides/external-network-bgp.md))
- `service`: 同じVpc内のServiceへ向かう通信。所属Vpcの `spec.service` でService ルーティングが有効になっている場合、Service CIDR向けの経路がこのタイプで自動注入されます。ユーザが手動で指定する必要はありません
- `natGateway`: NATGateway経由でVpc外へ出る通信。`via.natGateway`で対象NATGatewayの名前を指定します。N:1のNAPTで外部へ出る経路を作るときに利用します
- `vpcPeering`: VpcPeeringで接続した対向VpcのSubnetへ向かう通信。`via.vpcPeering`で対象VpcPeeringの名前を指定します。`dst`は対向Vpcに存在するSubnetのCIDRと完全に一致させてください (例: [VpcPeeringガイド](../guides/vpc-peering.md))
- `transitGateway`: TransitGateway経由で他のVpcへ向かう通信。`via.transitGateway`で対象TransitGatewayの名前を指定します。宛先の解決はTransitGatewayRouteTableで行われるため、`dst`はスーパーネットでも構いません (例: [TransitGatewayガイド](../guides/transit-gateway.md))
- `vpcEndpoint`: VpcEndpointのVIP宛の通信。所属Vpcの `spec.endpointPool.cidrs` からコントローラが1つずつ自動注入します。`spec.routes`に手で書いても無視されるため、ユーザが指定することはできません (例: [VpcEndpoint](vpcendpoint.md))

- `blackhole`: `dst`宛ての通信を捨てます。ほかの`via`のフィールドは指定できません

## endpoint経由の経路

`endpoint`は、ルーターやファイアウォールとして動くPodやVMに通信を通すための経路です。経由先は1つのPodではなく、ワークロードのNICとして指定します。

```yaml
spec:
  routes:
    - dst: 10.50.0.0/16
      via:
        type: endpoint
        endpoint:
          namespace: net
          allocationIdentity: router
          interface: eth0
```

`allocationIdentity`は、NetworkInterfaceの`spec.allocationIdentity`です。Podでは`juneau.loutres.me/allocation-identity`アノテーションで指定します（[NetworkInterface](networkinterface.md)を見てください）。

controllerは、このidentityのアドレス（AllocationLease）をいま持っているNetworkInterfaceを探し、そのNetworkEndpointを経由先にします。Podが作り直されると、新しいPodのNetworkEndpointに付け替えます。KubeVirtのlive migrationのように同じidentityのNICが2つあるときは、アドレスを持っている移行元のNICが経由先のままです。

経由先を決められないときは、その経路だけをblackholeにして通信を捨てます。ほかの経路はそのまま動きます。次のときがこれに当たります。

- identityのアドレスを持っているNetworkInterfaceがない
- そのNetworkInterfaceのNetworkEndpointがまだない（Podが動いていない）
- NetworkEndpointがRouteTableと同じVpcのSubnetにない

経由先のPodの中でIP転送を有効にする必要があります。Juneauはパケットを経由先のNICへ渡すだけです。

## `status.routes`

`status.routes`は、data planeに入る経路の一覧です。controllerが自動で足した経路と、`spec.routes`の参照を解決した経路が並びます。

| フィールド | 意味 |
|---|---|
| `dst` | 宛先のCIDR |
| `via` | `spec.routes`の`via`をそのまま写したもの |
| `subnet` | パケットを送り込むSubnet。endpoint経由の経路では、経由先のNetworkEndpointがあるSubnetです |
| `networkEndpoint` | endpoint経由の経路が解決したNetworkEndpointの`namespace`と`name`。`state`が`Active`のときだけ入ります |
| `state` | `Active`なら転送し、`Blackhole`なら捨てます。`via.type: blackhole`の経路は常に`Blackhole`です |
| `message` | `spec.routes`で転送を指定した経路をcontrollerがblackholeにしている理由 |

endpoint経由の経路がblackholeになっていても、RouteTableの`Ready`条件は`True`のままです。経由先のPodが入れ替わる間にblackholeになるのは想定内の状態で、RouteTableの失敗ではないためです。どの経路がなぜblackholeになっているかは、`status.routes[].state`と`message`で確認してください。
