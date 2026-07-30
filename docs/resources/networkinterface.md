# NetworkInterface

NetworkInterfaceは、ワークロードのライフサイクルにわたって維持される論理NICです。
IPアドレスとSecurityGroupはこのリソースに紐づき、Podが再作成されても
NetworkInterfaceが削除されない限り維持されます。

VMやコンテナなどの上位コントローラーは、ワークロードごとに
NetworkInterfaceを作成し、Pod templateへ
`juneau.loutres.me/network-interface` annotationを設定します。
annotationがない通常のPodには、PodControllerがPod所有の
NetworkInterfaceを自動作成します。

## spec

`spec.subnet`には、このNetworkInterfaceが接続されるSubnetを指定します。

`spec.address`は省略可能で、指定した場合はそのIPv4アドレスを要求します。
未指定の場合は、Juneauが`spec.subnet`の範囲から空いているアドレスを自動割り当てします。

`spec.attachmentRef`は、現在このNICを実体化する
NetworkInterfaceAttachmentの名前とUIDです。Pod再作成時は、旧Endpointの削除後に
新しいAttachmentへ更新します。

## status

`status.address`は、実際に割り当てられたIPv4アドレスとプレフィックス長です。

`status.routes`は、Pod側に設定すべき経路情報です。
通常はSubnetのゲートウェイに向かうデフォルトルートが入ります。

## Phase

- Pending:まだ割り当て待ち、または必要な依存リソース待ち
- Allocated:IPは確保済みだが、まだNetworkEndpoint待ち
- Ready:NetworkEndpointもそろい利用可能
- Failed:割り当てや整合性確認に失敗
