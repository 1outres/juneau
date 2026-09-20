# DNSZone

DNSZoneを作成すると、指定したVpcだけで使えるDNSサフィックスを登録することができます。たとえば`apps.internal`のZoneに`api`というDNSRecordを作ると、そのVpc内でJuneauのSubnet DNSをネームサーバーに使うPodは`api.apps.internal.`を引けます。

DNSZoneはクラスタスコープのリソースです。

```yaml
apiVersion: juneau.loutres.me/v1alpha1
kind: DNSZone
metadata:
  name: apps-internal
spec:
  vpc: app-vpc
  domain: apps.internal
```

## spec

| フィールド | 内容 |
|---|---|
| `spec.vpc` | Zoneを利用する既存のVpc名 |
| `spec.domain` | ZoneのDNSサフィックス。小文字のDNS-1123サブドメインで、末尾の`.`は付けません |

`spec.vpc`と`spec.domain`は作成後に変更できません。別のVpcやドメインへ移す場合は、DNSRecordを削除してからZoneを作り直します。

`spec.domain`は253文字以内です。`cluster.local`自身とその配下、たとえば`apps.cluster.local`はKubernetesの名前解決用に予約されているため使えません。DNSRecordとの組み合わせでFQDNが`cluster.local`自身またはその配下になる指定も拒否されます。

## Zoneの選択

同じVpcに同一ドメインのDNSZoneを2つ作ることはできません。Vpcが異なれば同じドメインを使えます。`apps.internal`を複数のVpcに登録しても、問い合わせ元Podが属するVpcのZoneとレコードだけが応答に使われます。

親子のZoneは同じVpcにも作成できます。`example.com`と`dev.example.com`の両方が問い合わせ名に一致すると、より長い`dev.example.com`が選ばれます。子Zoneのレコードと親Zoneのレコードは合成されません。子Zoneに該当する所有者名がなければNXDOMAINです。子Zoneが現在の世代でReadyでない場合はSERVFAILとなり、親Zoneへ戻って検索しません。

## PodのDNS設定

JuneauのSubnet DNSを自動で使うのは、次の条件を満たして作成されたPodです。

- primary network（`eth0`）がdefault以外のVpcに属するSubnetへ接続されている
- `hostNetwork`を使うPodでもmirror Podでもない
- `juneau.loutres.me/dns-inject-skip: "true"`を指定していない
- `dnsPolicy`が未指定、`ClusterFirst`、`ClusterFirstWithHostNet`のいずれかである
- Pod作成時にSubnetの`status.dns`へDNS VIPが入っている

admission webhookは条件を満たすPodの`dnsPolicy`を`None`に変え、SubnetのDNS VIPを`dnsConfig.nameservers`の先頭へ入れます。default VpcのPod、primary networkがL2NetworkかElasticIPのPod、`dnsPolicy: Default`や`dnsPolicy: None`を明示したPodには、この設定を入れません。

この処理はPodのCREATE時にだけ行います。DNS VIPがあとから入っても既存Podは変わらないので、Subnetの`status.dns`を確認してからPodを作成してください。先に作ったPodで利用するには、そのPodを作り直します。

## status

`status.observedGeneration`にはcontrollerが確認した世代が入ります。`status.conditions`の`Ready`は次の状態を表します。

| status | reason | 内容 |
|---|---|---|
| `True` | `Ready` | Vpcが存在し、同じVpc内に同一ドメインの競合がない |
| `False` | `VpcNotFound` | 参照先Vpcが存在しない |
| `False` | `DuplicateZone` | 同じVpcとドメインを持つDNSZoneが複数ある |

通常はadmission webhookが存在しないVpcや重複Zoneの作成を拒否します。競合や古いリソースが残った場合もcontrollerが`Ready=False`にします。

DNS応答に使うZoneは、削除中ではなく、`status.observedGeneration`が`metadata.generation`と一致し、現在の世代を指す`Ready=True` conditionを1つだけ持つ必要があります。どれか1つでも満たさなければ、そのZoneへの問い合わせはSERVFAILです。親ZoneがReadyでも、選ばれた子Zoneから親へ切り替えません。

## ライフサイクル

DNSZoneを参照するDNSRecordが残っている間は、そのZoneを削除できません。また、DNSZoneが残っているVpcも削除できません。削除はDNSRecord、DNSZone、Vpcの順で行います。

レコードの書き方とDNS応答の扱いは[DNSRecord](dnsrecord.md)を参照してください。構築例は[VpcプライベートDNSを使う](../guides/vpc-private-dns.md)にあります。
