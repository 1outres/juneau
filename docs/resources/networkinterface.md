# NetworkInterface

NetworkInterfaceは、Podに紐づく論理NICを表すリソースです。

通常はユーザーが直接作成するのではなく、PodControllerがPodのネットワーク要求に応じて自動作成します。

## spec

`spec.subnet`には、このNetworkInterfaceが接続されるSubnetを指定します。

`spec.address`は省略可能で、指定した場合はそのIPv4アドレスを要求します。
未指定の場合は、Juneauが`spec.subnet`の範囲から空いているアドレスを自動割り当てします。

`spec.podRef`は、この論理NICがどのPodのどのインターフェースを表しているかを示します。

## status

`status.ipLease`は、このNetworkInterfaceに対して確保されたIPLeaseの名前です。

`status.address`は、実際に割り当てられたIPv4アドレスとプレフィックス長です。

`status.routes`は、Pod側に設定すべき経路情報です。
通常はSubnetのゲートウェイに向かうデフォルトルートが入ります。

## AllocatedとReadyの違い

Allocatedは、IPアドレスが確保されたことを表します。
つまりIPLeaseが作成され、`status.ipLease`と`status.address`が確定した段階です。

Readyは、割り当て済みであることに加えて、対応するNetworkEndpointが存在し、Pod側の接続準備まで進んだことを表します。

そのため、Allocated=TrueでもReady=Falseの状態はありえます。

## phase

`phase`は、conditionsを要約した見やすい状態表示です。

大まかには次のように読みます。

- Pending:まだ割り当て待ち、または必要な依存リソース待ち
- Allocated:IPは確保済みだが、まだNetworkEndpoint待ち
- Ready:NetworkEndpointもそろい利用可能
- Failed:割り当てや整合性確認に失敗
