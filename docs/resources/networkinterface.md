# NetworkInterface

NetworkInterfaceは、Podに紐づく論理NICを表すリソースです。

通常はユーザーが直接作成するのではなく、PodControllerがPodのネットワーク要求に応じて自動作成します。名前は`<Pod名>.<interface>`です。

```console
$ kubectl get networkinterface
NAME       NODE       SUBNET       L2NETWORK   ELASTICIP   ADDRESS          PHASE
app.eth0   worker-1   app-subnet                           10.90.0.5/24     Ready
gw.eth0    worker-2   default                              10.16.0.9/16     Ready
gw.eth1    worker-2                            gw-eip      10.225.51.6/32   Ready
```

## spec

`spec.subnet`、`spec.l2Network`、`spec.elasticIP`は、NICの接続先です。3つのうちちょうど1つを指定します。

`spec.subnet`には、このNetworkInterfaceが接続されるSubnetを指定します。

`spec.l2Network`には、このNetworkInterfaceが接続される[L2Network](l2network.md)を指定します。

`spec.elasticIP`には、同じnamespaceにある[ElasticIP](elasticip.md)の名前を指定します。このNICはElasticIPのアドレスをそのまま持ち、NATを通しません。どのVpcにも属しません。作成後は変更できません。

`spec.address`は省略可能で、指定した場合はそのIPv4アドレスを要求します。
未指定の場合は、Juneauが`spec.subnet`の範囲から空いているアドレスを自動割り当てします。

`spec.securityGroups`は、このNICに適用するSecurityGroupです。

`spec.elasticIP`を指定したNICでは、`spec.address`と`spec.securityGroups`は空でなければなりません。アドレスはElasticIPが持っていて、NIC側で別のアドレスを選ぶことはできません。Vpcに属さないので、SecurityGroupも付けられません。アドレスの予約(AllocationClaim)もNIC側では作りません。

`spec.podRef`は、この論理NICがどのPodのどのインターフェースを表しているかを示します。

`spec.allocationIdentity`は、名前が毎回変わるPod(KubeVirtのvirt-launcher Podなど)でも同じワークロードだと分かるようにする値です。SubnetのNICでは、同じ値を持つNIC同士がアドレスの予約を共有します。`spec.elasticIP`のNICは何も予約しないので、ここでの意味は1つだけです。同じ値を持つ古いNICがElasticIPを持っている間でも、新しいNICがそのElasticIPを参照して作られることを許します。新しいNICは古いNICが消えるまで`Pending`で待ちます。

## status

`status.address`は、実際に割り当てられたIPv4アドレスとプレフィックス長です。
`spec.elasticIP`のNICでは`<ElasticIPのアドレス>/32`になります。ElasticIPを別のNICが持っている間は空です。

`status.routes`は、CNIがPodのnetwork namespaceに入れる経路です。

| フィールド | 意味 |
|---|---|
| `dst` | 宛先のCIDR |
| `gw` | ネクストホップ |
| `onLink` | `true`なら、NICのアドレスの範囲外にある`gw`をリンク上にあるものとして扱います。`ip route`の`onlink`です |
| `table` | 経路を入れるルートテーブルの番号。0か省略ならmainテーブルです |

`status.rules`は、CNIがPodのnetwork namespaceに入れるpolicy routingのルールです。

| フィールド | 意味 |
|---|---|
| `from` | 送信元のCIDR |
| `table` | 一致したパケットが引くルートテーブルの番号 |
| `priority` | ルールの優先度。小さいほど先に評価されます |

NICの種類ごとに、入るものは次のとおりです。

| NIC | `status.routes` | `status.rules` |
|---|---|---|
| eth0 / Subnet | `0.0.0.0/0` via Subnetのゲートウェイ | なし |
| eth0 / L2Network | `0.0.0.0/0` via L2Networkの`status.gateway` | なし |
| eth0 / ElasticIP | `0.0.0.0/0` via `169.254.0.1`、`onLink: true` | なし |
| 追加NIC / SubnetかL2Network | なし | なし |
| 追加NIC / ElasticIP | `0.0.0.0/0` via `169.254.0.1`、`onLink: true`、`table: <番号>` | `from: <ElasticIP>/32`、`table: <番号>`、`priority: 100` |

mainテーブルに入るデフォルトルートは、eth0の1本だけです。追加NICのSubnetやL2Networkに経路を入れないのは、Podのデフォルトルートを1本に保つためです。

ElasticIPの追加NICだけは、専用のテーブルにデフォルトルートを入れ、そのアドレスを送信元とするパケットをそのテーブルへ向けるルールを足します。外から追加NICのElasticIPに届いた通信の応答は送信元がElasticIPなので、ルールに一致して追加NICから出ていきます。ルールが無いと、応答がeth0から別のアドレスの経路に乗ってしまいます。

`169.254.0.1`は、ElasticIPを持つNICのゲートウェイです。NICは/32しか持たないので、ゲートウェイはどのアドレスの範囲にも入りません。そのため`onLink`を付けます。このアドレス宛のARPには、Node側のvethでeBPFが応答します。

```yaml
status:
  address: 10.225.51.6/32
  routes:
    - dst: 0.0.0.0/0
      gw: 169.254.0.1
      onLink: true
      table: 182530822
  rules:
    - from: 10.225.51.6/32
      table: 182530822
      priority: 100
```

## ルートテーブルの番号

ElasticIPの追加NICが使うテーブルの番号は、ElasticIPのIPv4アドレスを32ビットの整数として読んだ値です。上位のオクテットから並べるので、`10.225.51.6`は`10×2^24 + 225×2^16 + 51×2^8 + 6`で`182530822`になります。

番号をNIC自身のアドレスだけから決めているので、何度reconcileしても、どのNodeでも、同じElasticIPでPodを作り直しても、番号は変わりません。1つのPodの2枚のNICが同じElasticIPを持つことはwebhookが拒否するので、Podの中で番号がぶつかることもありません。

`0.0.0.0`から`0.0.0.255`までのアドレスは、Linuxが予約している0から255のテーブル番号に当たるので、このNICには使えません。

ルールの優先度は100で固定です。mainテーブルを引くルール(32766)より先に評価させるためです。1つのPodに複数のElasticIPの追加NICがあっても、ルールごとに送信元が違うので、同じ優先度で並んでいて構いません。

## Phase

- Pending:まだ割り当て待ち、または必要な依存リソース待ち
- Allocated:IPは確保済みだが、まだNetworkEndpoint待ち
- Ready:NetworkEndpointもそろい利用可能
- Failed:割り当てや整合性確認に失敗

`spec.elasticIP`のNICでは、次の場合に`Pending`になります。

| reason | 状態 |
|---|---|
| `WaitingForElasticIP` | ElasticIPを別のNetworkInterfaceが持っている、ElasticIPAttachmentが使っている、またはElasticIPがまだどのNICにも渡していない |
| `NetworkNotReady` | ElasticIPにアドレスが無い、またはExternalNetworkの`status.networkID`がまだ0 |

どちらも`Allocated`と`Ready`のconditionに同じreasonが入り、messageに待っている相手の名前が出ます。

ElasticIPが存在しない、アドレスが無い、ExternalNetworkに`status.networkID`が無い、のいずれかに当てはまる間は、PodControllerがNetworkInterface自体を作りません。`kubectl get networkinterface`にNICが出てこないときは、controllerのログの`waiting for the network of a Pod NIC`を見てください。

ElasticIPのアドレスを解釈できない場合は、reason `InvalidElasticIPAddress`で`Failed`になります。
