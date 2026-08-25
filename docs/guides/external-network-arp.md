# ARPを使ってExternalNetworkを構築する

`type: arp`のExternalNetworkでは、外部アドレス宛のARP RequestにNodeが直接ARP Replyを返します。上流とBGPセッションを張れない環境でも、NodeのNICと同じL2セグメントからアドレスを切り出せば、Podに外部到達可能なIPアドレスを割り当てられます。このガイドはその一連のリソースをゼロから組み立てる手順を示します。

BGPで経路を広報する場合は[BGPを使ってExternalNetworkを構築する](external-network-bgp.md)を参照してください。

## このガイドで構築するもの

- NodeのNICと同じL2サブネットから切り出したアドレス範囲 `10.225.32.240-10.225.32.250` を持つAddressPool
- `type: arp` のExternalNetwork。BGPPeerもBGPAdvertisementも作りません
- EIP対象Pod用の専用Vpc/Subnet (`10.60.0.0/24`) とInternetGateway経路
- ElasticIPをnginx Podに割り当て、同じL2上のホストから `curl http://<elasticIP>/` で到達確認

## 前提条件

- Juneauのcontroller/daemonが動作しているクラスター
- NodeのNICが接続しているL2サブネット（本ガイドでは `10.225.32.0/24`）
- そのサブネットのうち、DHCPや他のホストに使われていないアドレス範囲（本ガイドでは `10.225.32.240` から `10.225.32.250`）
- daemonの `--node-ingress-iface` が外部L2に面したNICを指していること。未指定の場合はNodeのInternalIPを持つNICが使われます

## 制約

arp modeには、BGPを使う場合には無い制約があります。構築を始める前に確認してください。

**外部アドレスはNodeのNICと同じL2サブネット内であること。**
ARPはブロードキャストドメインの中でしか届きません。ルータを1つ挟んだ別サブネットのアドレスを払い出しても、そのアドレスへのARP RequestはNodeまで来ないので、誰も応答しません。

**`--node-ingress-iface`が外部L2に面したNICであること。**
daemonのeBPFプログラムはこのNICのingressでARP Requestを受け取り、同じNICへReplyを折り返します。overlay用のNICや管理用のNICを指していると、外部からのARP Requestがそもそもプログラムに届きません。

**1つのアドレスには1つのNodeしか応答しません。**
上流から見た宛先MACは1つだけなので、BGPのECMPのようにNode間でトラフィックを分散させることはできません。1アドレスあたりの帯域はNode1台分です。ServiceLoadBalancerのbackendが複数Nodeに散っていても、外から入る経路は1本になります。

**応答Nodeが移ってもgratuitous ARPを送りません。**
arp modeで一番影響が大きい制約です。ElasticIPを付けたPodが別のNodeへ再スケジュールされたとき、あるいはServiceLoadBalancerの応答Nodeが切り替わったとき、Juneauは新しいMACを上流に通知しません。上流のneighborエントリがaging outするまで通信は戻らず、Linuxのルータで概ね数十秒、L2スイッチや商用ルータではさらに長くかかることがあります。

急ぐなら、上流側で`ip neigh flush <アドレス>`を実行してキャッシュを捨ててください。
Juneau側からGARPを送る余地はあります。virtserviceがすでにAF_PACKETでフレームを送出する仕組みを持っているので、同じものをnode ingressのNICに向ければeBPFを変えずに実装できます。現時点では入っていません。

**ARP Replyに載せるMACは物理NICのMACです。**
アドレスごとの仮想MACは使いません。応答Nodeが変わるとMACも変わるので、上流のキャッシュが更新されるまで待つことになります。

**AddressPoolの範囲にNodeのInternalIPを含めないでください。**
含めたAddressPool自体は作成できてしまいますが、そのアドレスがElasticIPなどに払い出された時点で、ARPAdvertisementの作成がwebhookに拒否されます。仮に応答してしまうと、Node自身がクラスター外から見えなくなります。

## 手順

### 1. AddressPoolを作成

外部に出すアドレス範囲を`start-end`形式で定義します。

```yaml
apiVersion: juneau.loutres.me/v1alpha1
kind: AddressPool
metadata:
  name: ext-pool-arp
spec:
  advertiseMode: arp
  addresses:
    - 10.225.32.240-10.225.32.250
```

`advertiseMode: arp`ではCIDRを書けません。`advertiseMode`は変更不可です。詳細は[AddressPool](../resources/addresspool.md)を参照してください。

controllerが`addr-ext-pool-arp`という名前のAllocationPoolを作ります。範囲が正しく渡っているか確認します。

```console
$ kubectl get allocationpool addr-ext-pool-arp -o yaml
...
spec:
  type: ip
  strategy: firstFit
  ip:
    ranges:
      - start: 10.225.32.240
        end: 10.225.32.250
```

### 2. ExternalNetworkを作成

AddressPoolを1つの論理的な外部ネットワークとしてまとめます。

```yaml
apiVersion: juneau.loutres.me/v1alpha1
kind: ExternalNetwork
metadata:
  name: ext-net-arp
spec:
  type: arp
  addressPools:
    - ext-pool-arp
```

`type: arp`の場合、参照するAddressPoolは`advertiseMode: arp`である必要があります。詳細は[ExternalNetwork](../resources/externalnetwork.md)を参照してください。

BGPを使う場合と違い、ここでBGPPeerやBGPAdvertisementを作る手順はありません。

### 3. EIP対象Pod用のVpc/Subnetを作成

ElasticIPを付与するPodは、**default以外のSubnetに配置する必要があります**。専用Vpcとそこに属するSubnetを用意します。

```yaml
apiVersion: juneau.loutres.me/v1alpha1
kind: Vpc
metadata:
  name: ext-vpc
---
apiVersion: juneau.loutres.me/v1alpha1
kind: Subnet
metadata:
  name: ext-subnet
spec:
  vpc: ext-vpc
  cidr: 10.60.0.0/24
```

詳細は[Vpc](../resources/vpc.md) / [Subnet](../resources/subnet.md)を参照してください。

### 4. RouteTableにInternetGatewayルートを追加

VpcのメインRouteTableは自動生成されますが、EIP egress (Pod → 外部) に必要な**InternetGateway向けデフォルトルートはデフォルトでは含まれません**。手動で追記します。

```yaml
apiVersion: juneau.loutres.me/v1alpha1
kind: RouteTable
metadata:
  name: ext-vpc
spec:
  vpc: ext-vpc
  routes:
    - dst: 0.0.0.0/0
      via:
        type: internetGateway
```

RouteTableのメタ名はVpc名と同じです。Vpcと同じマニフェストにまとめて適用するなら、`kubectl apply --server-side`を使ってください。詳細は[RouteTable](../resources/routetable.md)を参照してください。

### 5. ElasticIPを作成

ExternalNetworkから1つのアドレスを払い出します。

```yaml
apiVersion: juneau.loutres.me/v1alpha1
kind: ElasticIP
metadata:
  name: nginx-eip
spec:
  externalNetwork: ext-net-arp
```

```console
$ kubectl get elasticip nginx-eip
NAME        EXTERNALNETWORK   ADDRESS         ATTACHMENT   PHASE       ALLOCATED   ATTACHED
nginx-eip   ext-net-arp       10.225.32.240                Available   True        False
```

`PHASE: Available`で`ADDRESS`が埋まればアドレス確保完了です。この時点ではまだどのNodeも応答しません。応答するNodeはElasticIPAttachmentで決まるためです。

### 6. Podをデプロイ

対象のPodを、手順3で作ったSubnetに配置します。`juneau.loutres.me/subnet` annotationで明示します。

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx
  labels:
    app: nginx
  annotations:
    juneau.loutres.me/subnet: ext-subnet
spec:
  containers:
    - name: nginx
      image: nginx:1.27
```

NetworkInterface名はデフォルトで `<Pod名>.eth0` です。

### 7. ElasticIPAttachmentでひもづけ

ElasticIPをPodのNetworkInterfaceに関連付けます。

```yaml
apiVersion: juneau.loutres.me/v1alpha1
kind: ElasticIPAttachment
metadata:
  name: nginx-eip-attach
spec:
  elasticIPRef:
    name: nginx-eip
  targetRef:
    networkInterfaceName: nginx.eth0
```

```console
$ kubectl get elasticipattachment
NAME               ELASTICIP   NETWORKINTERFACE   EIP              PODIP        NODE       PHASE      READY
nginx-eip-attach   nginx-eip   nginx.eth0         10.225.32.240    10.60.0.12   worker-1   Attached   True
```

`PHASE: Attached`かつ`READY: True`になれば、該当NodeでElasticIPがPodに関連付けられた状態です。詳細は[ElasticIPAttachment](../resources/elasticipattachment.md)を参照してください。

### 8. ARPAdvertisementを確認

ElasticIP controllerが、応答するNodeを指定したARPAdvertisementを作ります。

```console
$ kubectl get arpadvertisement
NAME                    EXTERNALNETWORK   ADDRESS          NODE       AGE
eip-default-nginx-eip   ext-net-arp       10.225.32.240    worker-1   10s
```

`NODE`が手順7の`NODE`と一致していることを確認します。ここがElasticIPAttachmentの`status.nodeName`をそのまま反映します。

Node上のdaemonがこの内容をeBPFのmapに落とします。実際に入った内容は次のコマンドで見られます。

```console
$ kubectl juneau bpf dump external_arp_table
```

詳細は[ARPAdvertisement](../resources/arpadvertisement.md)を参照してください。

### 9. 外部からの疎通を確認

同じL2サブネット上の任意のホストから、まずARPで解決できるかを見ます。

```console
$ arping -c 3 -I eth0 10.225.32.240
ARPING 10.225.32.240 from 10.225.32.5 eth0
Unicast reply from 10.225.32.240 [02:42:0a:e1:20:03] 0.712ms
```

返ってきたMACは、応答Node (`worker-1`) の外部NICのMACです。他のNodeのMACが返る場合や、複数のMACが返る場合は設定を疑ってください。

続いてHTTPで到達を確認します。

```console
$ curl -sS http://10.225.32.240/
<!DOCTYPE html>
...
<h1>Welcome to nginx!</h1>
```

レスポンスが返れば、ARP解決 → NodeへのL2転送 → ElasticIPのDNAT → Pod、の経路が通っています。

## NATGatewayとServiceLoadBalancerで使う

同じExternalNetworkを[NATGateway](../resources/natgateway.md)と[ServiceLoadBalancer](../resources/serviceloadbalancer.md)からも参照できます。ARPAdvertisementの作られ方だけが異なります。

NATGatewayを作ると、NodeごとにExternalNetworkAttachmentが1つずつ作られ、それぞれが別のアドレスを1つ消費します。各ExternalNetworkAttachmentが自分のNodeを指すARPAdvertisementを作るので、Node数だけアドレスが必要です。

ServiceLoadBalancerでは、`status.advertisingNodes`のうち1つだけがVIPに応答します。選ばれたNodeは`status.arpAnnouncingNode`で確認できます。

```console
$ kubectl get slb
NAME   SERVICE   EXTERNALNETWORK   VIP              PHASE   ADVERTISINGNODES   ARPNODE    ALLOCATED   AVAILABLE
web    web       ext-net-arp       10.225.32.241    Ready   2                  worker-2   True        True
```

`ADVERTISINGNODES`が2でも`ARPNODE`は1つです。上流から見た入口はこの1Nodeだけになります。

## うまくいかないとき

1. **ElasticIPの`ADDRESS`が埋まらない**
    - `PHASE: Error`なら、AddressPoolの`advertiseMode`とExternalNetworkの`type`が食い違っています。どちらも`arp`に揃えてください
    - `PHASE: Pending`のままなら、AddressPoolの範囲を使い切っている可能性があります。`kubectl get allocationlease`で払い出し済みのアドレスを確認できます
2. **`kubectl get arpadvertisement`にエントリが無い**
    - ElasticIPの場合、ElasticIPAttachmentが`PHASE: Attached`になっているか。外れている間は意図的に削除されます
    - ServiceLoadBalancerの場合、`status.advertisingNodes`が空でないか。Local backendが1つも無ければ応答するNodeも決まりません
3. **arpingが返ってこない**
    - クライアントがNodeと同じL2サブネットにいるか。ルータを挟んでいると届きません
    - 応答するはずのNodeで`kubectl juneau bpf dump external_arp_table`を実行し、期待するアドレスが入っているか
    - daemonの`--node-ingress-iface`が外部L2に面したNICを指しているか。入っていないなら`ip link`でNIC名を確認して指定し直します
    - そのアドレスを他のホストが使っていないか。`arping`に複数のMACが返る場合はIPアドレスの重複です
4. **arpingは返るのにcurlが通らない**
    - 対象Podが**default以外のSubnet**に属しているか。default SubnetのPodはElasticIPの対象にできません
    - Podが属するVpcのRouteTableに`type: internetGateway`のルートがあるか。無いと外部疎通が成立しません
    - `elasticipattachment.status.conditions[?(@.type=="Ready")].status`が`True`か
5. **Podを別のNodeへ移したあと通信が戻らない**
    - `kubectl get arpadvertisement`の`NODE`が新しいNodeに変わっているか。変わっていればJuneau側の処理は終わっています
    - 変わっているのに戻らないなら、上流のneighborキャッシュが古いMACを保持しています。`ip neigh show 10.225.32.240`で確認し、`ip neigh flush 10.225.32.240`で捨ててください。放置してもaging outすれば戻りますが、待ち時間は上流機器によります

## 参照

- [AddressPool](../resources/addresspool.md)
- [ExternalNetwork](../resources/externalnetwork.md)
- [ARPAdvertisement](../resources/arpadvertisement.md)
- [ElasticIP](../resources/elasticip.md)
- [ElasticIPAttachment](../resources/elasticipattachment.md)
- [ExternalNetworkAttachment](../resources/externalnetworkattachment.md)
- [NATGateway](../resources/natgateway.md)
- [ServiceLoadBalancer](../resources/serviceloadbalancer.md)
