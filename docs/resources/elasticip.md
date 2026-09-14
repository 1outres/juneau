# ElasticIP

ElasticIPは、外部から到達可能なIPアドレスを1つ予約するリソースです。

`spec.externalNetwork`で参照したExternalNetworkに紐づくAddressPoolから1つのアドレスが選ばれます。
ElasticIPで利用されるAddressPoolは、`spec.advertiseMode`がExternalNetworkの`spec.type`と一致している必要があります。

`spec.requestedIP`は省略可能で、指定した場合はそのIPv4アドレスをElasticIPとして要求します。
指定するアドレスは、`spec.externalNetwork`で参照したExternalNetworkに紐づくAddressPoolのいずれかに含まれている必要があります。
省略した場合は、利用可能なアドレスから1つが自動的に選ばれます。

## 2つの使い方

予約したアドレスの使い方は2通りあります。

| 使い方 | 設定するもの | Podの中から見えるアドレス |
|---|---|---|
| NAT | [ElasticIPAttachment](elasticipattachment.md)でNetworkInterfaceに関連付ける | Vpc内のアドレス。NodeがElasticIPとの間を1:1 NATで変換します |
| 直接 | PodのNICが`juneau.loutres.me/elastic-ip`アノテーションか、`juneau.loutres.me/networks`の`elasticIP`でElasticIPを参照する | ElasticIPのアドレスそのもの |

1つのElasticIPを2つの使い方で同時に使うことはできません。ElasticIPAttachmentが使っているElasticIPをPodのNICから参照するとPodの作成が拒否され、NICが直接使っているElasticIPを参照するElasticIPAttachmentも拒否されます。

直接使う手順は[PodのNICにElasticIPを直接持たせる](../guides/elastic-ip-direct.md)にあります。

ElasticIPによる1:1 NATは、ICMPエラーメッセージが内包する元パケットのヘッダも書き換えます。Path MTU Discoveryや`traceroute`がどう成立するかは[ElasticIPAttachment](elasticipattachment.md)のICMPの扱いを参照してください。直接使う場合はNATを通らないので、書き換えも起きません。

## status.attachment

`status.attachment`は、いまこのアドレスを使っているものです。`kind`と`name`の組で、指す先はElasticIPと同じnamespaceにあります。

- `kind: ElasticIPAttachment`:NATで使われています。`name`はElasticIPAttachmentの名前です
- `kind: NetworkInterface`:直接使われています。`name`はアドレスを持っているNetworkInterfaceの名前です

何にも使われていない間は空です。

```console
$ kubectl get elasticip
NAME        EXTERNALNETWORK   ADDRESS       ATTACHMENTKIND        ATTACHMENT         PHASE      ALLOCATED   ATTACHED
nginx-eip   ext-net           10.225.51.5   ElasticIPAttachment   nginx-eip-attach   Attached   True        True
web-eip     ext-net           10.225.51.8   NetworkInterface      web.eth0           Attached   True        True
```

## Phase

- Pending:参照先ExternalNetworkとAddressPoolは解決できたが、利用可能なアドレスがまだ選ばれていない状態
- Available:アドレスは選ばれているが、何にも使われていない状態
- Attached:アドレスが選ばれ、1つのElasticIPAttachmentか、1つのNetworkInterfaceに使われている状態
- Error:依存リソースの不整合や、複数のElasticIPAttachmentからの参照などで正常に扱えない状態

ElasticIPAttachmentとNetworkInterfaceの両方から参照されたときも`Error`になります。reasonは`Conflict`で、messageに両方の名前が出ます。webhookが拒否するので普通は起きませんが、2つを同時に作るとすり抜けることがあります。どちらかを消してください。

## 直接使うNetworkInterfaceの選び方

同じElasticIPを参照するNetworkInterfaceが、同時に2つ以上存在することがあります。終了中のPodと入れ替わりの新しいPodが並んだときや、KubeVirtのvirt-launcher Podが作り直されたときです。アドレスを持てるのはそのうち1つだけで、controllerは次の順に決めます。

1. `status.attachment`に書かれているNetworkInterfaceは、残っている限りアドレスを持ち続けます。削除中でも手放しません
2. 1に当てはまらず、参照しているNetworkInterfaceのどれかが削除中なら、どれにも渡しません。消えるまで待ちます
3. どちらでもなければ、一番古いNetworkInterfaceが持ちます。作成時刻が同じなら名前の順です

2で待つのは、ElasticIPが一度`Error`を通ると`status.attachment`が消えるからです。そのあとでは、削除中のNetworkInterfaceがまだアドレスを持っているかどうかをcontrollerが確かめられません。

待っている間は`PHASE: Available`のままで、`Attached`conditionが`False`、reasonが`WaitingForHandover`になります。messageには、消えるのを待っているNetworkInterfaceの名前が出ます。

アドレスを持てなかったNetworkInterfaceは`Pending`で止まり、そのPodは起動しません。詳しくは[NetworkInterface](networkinterface.md)を参照してください。

## 削除

NATで使っている場合の削除は、これまでと変わりません。

直接使っているNetworkInterfaceが1つでも残っている間は、ElasticIPの削除が完了しません。finalizerがNetworkInterfaceが無くなるのを待ち、その間はアドレスの予約(AllocationClaim)もARPAdvertisementも外しません。先に予約を外すと、動いているPodのNICがまだ持っているアドレスを、別のElasticIPが取れてしまうからです。

待っている間は`Allocated`conditionのreasonが`WaitingForNetworkInterfaces`になり、messageに残っているNetworkInterfaceの名前が並びます。そのNetworkInterfaceを持つPodを消せば、削除が進みます。

削除中のElasticIPは、新しく作られたNetworkInterfaceにアドレスを渡しません。

## type=arpのExternalNetworkを使う場合

外部からの到達性は、経路広報ではなく、ElasticIPを使っているPodが動いているNodeがARP Replyを返すことで成立します。
controllerは`eip-<namespace>-<ElasticIP名>`という名前の[ARPAdvertisement](arpadvertisement.md)を作り、`spec.nodeName`に次のNodeを書きます。

- NATで使っている場合:ElasticIPAttachmentの`status.nodeName`
- 直接使っている場合:アドレスを持っているNetworkInterfaceの`spec.nodeName`

Podが別のNodeへ再スケジュールされると、このNodeが変わり、ARPAdvertisementもそれに追従します。

何にも使われていない間はARPAdvertisementが削除され、そのアドレスにはどのNodeも応答しません。
`PHASE: Available`のままでも外部からは到達できない、という状態になります。

応答するNodeが移ったときにgratuitous ARPを送らないため、上流のneighborキャッシュが更新されるまで通信は戻りません。詳しくは[ARPAdvertisement](arpadvertisement.md)を参照してください。
