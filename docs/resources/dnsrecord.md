# DNSRecord

DNSRecordを作成すると、DNSZone内の1つの所有者名にIPv4アドレスの集合を登録することができます。アドレスは直接指定するほか、NetworkInterface、VpcEndpoint、PodSelectorから取得できます。4種類のsourceは1つのレコード内で混在できます。

DNSRecordはクラスタスコープのリソースです。

```yaml
apiVersion: juneau.loutres.me/v1alpha1
kind: DNSRecord
metadata:
  name: app-backends
spec:
  zone: apps-internal
  name: backends
  type: A
  ttl: 30
  sources:
    - podSelector:
        namespace: app
        interface: eth0
        selector:
          matchLabels:
            app: backend
```

この例のFQDNは`backends.<DNSZoneのspec.domain>.`です。

## spec

| フィールド | 内容 |
|---|---|
| `spec.zone` | 参照する既存のDNSZone名 |
| `spec.name` | Zoneからの相対名。Zone apexには`@`を指定します |
| `spec.type` | `A`のみ |
| `spec.ttl` | 応答に付けるTTL（秒）。省略時は30 |
| `spec.sources` | アドレスの取得元。1件以上100件以下 |

`spec.zone`、`spec.name`、`spec.type`は作成後に変更できません。`spec.ttl`と`spec.sources`は変更できます。TTLの範囲は1から86400秒です。

`spec.name`には小文字のDNS-1123相対名か`@`を指定し、末尾の`.`は付けません。ワイルドカードは使えません。Zoneのドメインと連結したFQDNも253文字以内でなければなりません。同じZoneと相対名を持つDNSRecordは1つだけ作れます。

## source

`spec.sources`の各要素には、次の4種類のうち1つだけを書きます。異なる種類を同じ配列に並べることはできます。

```yaml
sources:
  - ip: 192.0.2.10
  - networkInterface:
      namespace: app
      name: backend-0.eth0
  - vpcEndpoint:
      name: database
  - podSelector:
      namespace: app
      interface: eth0
      selector:
        matchLabels:
          app: backend
        matchExpressions:
          - key: track
            operator: In
            values: [stable, canary]
```

`namespace`とリソース名には有効なKubernetes名を使います。`podSelector.interface`は空にできず、`selector`には`matchLabels`か`matchExpressions`を1つ以上指定します。sourceの参照先が存在するか、どのVpcに属するかはcontrollerが評価し、結果をstatusへ書き込みます。

### ip

`ip`にはCIDRではなくIPv4アドレスを1つ指定します。Vpc内で到達可能かどうかは確認されません。公開用アドレスや別ネットワークのアドレスも値としては受け付けられるため、経路は別途用意してください。

### networkInterface

`networkInterface`はnamespaceと名前で1つのNetworkInterfaceを指定します。NetworkInterfaceが削除中ではなく、現在の世代で`Ready=True`になったときだけ`status.address`のIPv4アドレスを使います。

接続先のSubnetまたはL2NetworkがZoneと同じVpcに属している必要があります。名前で指定したNetworkInterfaceが存在しない、接続先を判定できない、または別Vpcに属する場合はレコード全体のエラーです。ほかのsourceが正常でも`Ready=False`となり、部分的な応答は返しません。条件を満たしたNetworkInterfaceの`status.address`が不正な場合も同じです。正しいVpcに属するNetworkInterfaceが削除中またはまだReadyでない場合はエラーにせず、そのsourceからアドレスを返しません。

### vpcEndpoint

`vpcEndpoint`はクラスタスコープのVpcEndpointを名前で指定します。削除中ではなく、Zoneと同じVpcに属するVpcEndpointが、現在の世代で`AddressAllocated=True`かつ`ServiceAccepted=True`になったときに`status.address`を使います。backendの有無を表すVpcEndpointの`Ready`は判定に使いません。

名前で指定したVpcEndpointが存在しない場合と別Vpcに属する場合は、レコード全体が`Ready=False`になります。ほかのsourceから得たアドレスも応答には使いません。条件を満たしたVpcEndpointの`status.address`が不正な場合も同じです。同じVpcに属していても、削除中、アドレスの確保待ち、Serviceの受理待ちならエラーにせず、そのsourceからアドレスを返しません。

### podSelector

`podSelector.selector`には空でない標準のKubernetes LabelSelectorを指定します。`namespace`内でlabelが一致するPodのうち、削除中ではなく`Ready=True`のPodが対象です。

各Podについて、Podの正確なUIDと`interface`に一致するNetworkInterfaceを探します。そのNetworkInterfaceが削除中ではなく、現在の世代で`Ready=True`になり、接続先のSubnetかL2NetworkがZoneと同じVpcに属している場合だけアドレスを採用します。

PodSelectorでは、削除中やReadyでないPod、UIDとinterfaceが一致するNetworkInterfaceを持たないPod、ReadyでないNetworkInterface、接続先を判定できないNetworkInterface、別VpcのNetworkInterfaceを候補から外します。個々の候補を読み飛ばして評価を続けるため、選択結果が0件でも`Ready=True`の空レコードになります。ただし、selector自体が不正な場合と、採用対象のNetworkInterfaceが不正なIPv4 CIDRをstatusに持つ場合は`Ready=False`になります。

## status

`status.addresses`には、すべてのsourceから得たIPv4アドレスを重複除去して格納します。最大100件です。`status.observedGeneration`と`Ready` conditionが現在の世代を指していれば、その内容をDNS応答に使います。

| `Ready` | reason | 内容 |
|---|---|---|
| `True` | `Ready` | sourceを正常に評価できた。アドレスが0件でもTrue |
| `False` | `ZoneNotFound` / `ZoneNotReady` | DNSZoneが存在しない、または現在の世代でReadyではない |
| `False` | `DuplicateRecord` | 同じZoneと相対名のDNSRecordが複数ある |
| `False` | `InvalidSource` | sourceの種類や参照先ネットワークを判定できない |
| `False` | `SourceNotFound` | 指定したNetworkInterfaceまたはVpcEndpointが存在しない |
| `False` | `SourceVpcMismatch` | 名前で指定したsourceがZoneとは別のVpcに属する |
| `False` | `InvalidAddress` | sourceのstatusに有効なIPv4アドレスがない |
| `False` | `TooManyAddresses` | 重複除去後のアドレスが100件を超えた |

1つでもエラーになるsourceがあれば、正常なsourceのアドレスも含めて応答には使いません。`Ready=False`になったレコードへの問い合わせはSERVFAILです。

## DNS応答

| 状態 | 応答 |
|---|---|
| Readyなレコードにアドレスがある | `NOERROR`とAレコード |
| Readyなレコードのアドレスが0件 | `NOERROR`、answerなし（NODATA） |
| 存在する所有者名へAAAAやCNAMEなど未対応のtypeで問い合わせた | `NOERROR`、answerなし（NODATA） |
| ReadyなZone内に所有者名がない | `NXDOMAIN` |
| Zoneか該当レコードがReadyでない、競合している、またはstatusが不正 | `SERVFAIL` |

AレコードのTTLには`spec.ttl`を使います。Juneauは問い合わせごとにアドレスの順番をランダム化します。偶然、前回と同じ順番になることもあるため、応答順には依存しないでください。

### 応答サイズ

UDP応答の上限は、クライアントがEDNS(0)で通知したバッファーサイズです。EDNS(0)がない問い合わせでは512バイト、512バイト未満の値は512バイトとして扱います。RRset全体が上限を超えると、Juneauはanswerを空にして`TC=1`を返します。部分的なRRsetは返しません。

通常のDNSクライアントは`TC=1`を受けるとTCPで問い合わせ直します。JuneauはTCP問い合わせにも対応し、最大100アドレスのRRset全体を返します。動作確認では`dig +tcp backends.apps.internal. A`を使えます。

Juneauは独自ZoneのドメインをPodの検索ドメインへ追加しません。`backends`のような短い名前ではこのレコードを指定できないので、`backends.apps.internal.`のような完全修飾名で問い合わせます。

現在作成できるのはAレコードだけです。AAAA、CNAME、PTR、SRVなどのレコード作成には未対応です。

## ライフサイクル

DeploymentをPodSelectorで参照すると、replica数の変更やrolling updateに合わせて`status.addresses`が更新されます。DNSRecord自体を書き換える必要はありません。クライアントが古い応答をTTLまでキャッシュする点には注意してください。

DNSRecordが残っているDNSZoneは削除できません。DNSRecordを先に削除してください。
