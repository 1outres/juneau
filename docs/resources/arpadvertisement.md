# ARPAdvertisement

ARPAdvertisementは、`type=arp`のExternalNetworkが持つ外部アドレスについて、どのNodeがARP Requestに応答するかを表すリソースです。
BGPにおけるBGPAdvertisementに相当しますが、こちらはユーザーが直接作成するリソースではなく、ElasticIP、ServiceLoadBalancer、ExternalNetworkAttachmentの各controllerが自動的に作成します。

`spec.externalNetwork`は対象のExternalNetworkの名前です。`type=arp`である必要があります。
`spec.address`は応答するIPv4アドレスで、`spec.externalNetwork`が参照するAddressPoolのいずれかの範囲に含まれている必要があります。
`spec.nodeName`はARP Requestに応答するNodeの名前です。

`spec.externalNetwork`と`spec.address`は作成後に変更できません。
`spec.nodeName`だけが変更でき、アドレスを別のNodeへ移すときはここが書き換わります。

## 1アドレスにつき1つ

同じ`spec.address`を持つARPAdvertisementが2つ以上存在することはできません。
すでに他のARPAdvertisementが使っているアドレスで作成しようとすると、webhookがForbiddenで拒否します。
2つのNodeが同じアドレスに応答すると、上流がどちらのARP Replyをキャッシュしたかで通信先が決まってしまいます。作成の時点で止めます。

`spec.address`がいずれかのNodeのInternalIPと一致する場合も拒否します。
そのアドレスに応答してしまうと、Node自身がクラスター外から見えなくなります。

## 生成元

| 生成元 | 名前 | 応答するNode |
|---|---|---|
| ExternalNetworkAttachment | `ena-<ExternalNetworkAttachment名>` | そのExternalNetworkAttachmentの`spec.nodeName` |
| ElasticIP | `eip-<namespace>-<ElasticIP名>` | ElasticIPAttachmentの`status.nodeName` |
| ServiceLoadBalancer | `slb-<namespace>-<ServiceLoadBalancer名>` | `status.advertisingNodes`から選ばれた1つ |

ExternalNetworkAttachmentが作るものはOwnerReferenceでひもづいており、ExternalNetworkAttachmentを削除するとGarbage Collectorが回収します。
ElasticIPとServiceLoadBalancerはnamespaceを持つリソースなので、cluster-scopedなARPAdvertisementにOwnerReferenceを張れません。かわりに、それぞれのfinalizerが削除時にARPAdvertisementを消します。

応答できるNodeが無くなった場合は、ARPAdvertisement自体が削除されます。
ElasticIPAttachmentが外れたとき、ServiceLoadBalancerのLocal backendが全滅したときがこれにあたります。
古いNodeが応答し続けるより、誰も応答しない状態のほうが原因を追いやすいためです。

## 応答するNodeが変わったとき

Juneauはgratuitous ARPを送りません。
`spec.nodeName`が書き換わっても、上流のneighborキャッシュが古いMACを保持している間は通信が戻りません。Linuxのルータで概ね数十秒、機器によってはさらに長くかかります。

この待ち時間を避けるため、ServiceLoadBalancerの応答Nodeの選出は、現在のNodeが`status.advertisingNodes`に残っている限りそのNodeを維持します。
残っていない場合だけ、VIPとNode名から計算するrendezvous hashingで選び直します。同じ入力からは常に同じNodeが選ばれるので、controllerのリーダーが交代しても結論は変わりません。

## 確認

```console
$ kubectl get arpadvertisement
NAME                  EXTERNALNETWORK   ADDRESS          NODE       AGE
eip-default-web-eip   ext-net-arp       10.225.32.241    worker-1   3m
slb-default-web       ext-net-arp       10.225.32.242    worker-2   3m
```

Nodeのdaemonがこの内容をeBPFのmapに落とし込みます。実際にmapへ入った内容は`kubectl juneau bpf dump external_arp_table`で確認できます。
