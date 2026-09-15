# PodのNICにElasticIPを直接持たせる

ElasticIPAttachmentを使うと、Vpc内にいるPodのアドレスとElasticIPの間を、Nodeが1:1 NATで変換します。Podの中から見えるのはVpc内のアドレスです。

PodのNICにElasticIPのアドレスそのものを持たせることもできます。Podの中で`ip addr`を実行すると外部アドレスが見え、パケットはNATを通りません。ペイロードに自分のアドレスを書くプロトコルを動かすときや、ゲストOSに自分の外部アドレスを見せたいVMで使います。

このガイドでは、eth0にElasticIPを持たせたPodと、追加NICにElasticIPを持たせたPodを作り、外部から到達することを確認します。

## このガイドで構築するもの

- ElasticIP `web-eip` をeth0に持つPod `web`
- default Subnetのeth0と、ElasticIP `gw-eip` を持つeth1のPod `gw`
- クラスター外から両方のElasticIPへ `curl` で到達確認

## 前提条件

- ExternalNetworkが構築済みであること。本ガイドでは[BGPを使ってExternalNetworkを構築する](external-network-bgp.md)の手順1から5で作った `ext-net` (`10.225.51.0/24`) を使います。ARPの場合は[ARPを使ってExternalNetworkを構築する](external-network-arp.md)の手順1と2で作った `ext-net-arp` に読み替えてください
- `kubectl juneau` プラグイン(確認とトラブルシュートに使います)

VpcやSubnet、RouteTableの`internetGateway`ルートは要りません。ElasticIPを直接持つNICはどのVpcにも属さないからです。

## NATとの違い

| | ElasticIPAttachment (NAT) | NICに直接持たせる |
|---|---|---|
| Podの中のアドレス | Vpc内のアドレス | ElasticIP (/32) |
| 置けるNIC | default以外のSubnetのNIC | eth0でも追加NICでも |
| RouteTableの`internetGateway`ルート | 必要 | 不要 |
| SecurityGroupとNetworkACL | 効く | 効かない |
| ClusterIP Service | Vpcの設定しだいで届く | 届かない |
| Serviceのバックエンド | なれる | eth0が直接持つPodはなれない |
| `kubectl juneau trace` | 使える | 使えない |

1つのElasticIPを両方で同時に使うことはできません。

## 手順

### 1. ExternalNetworkのnetworkIDを確認

ElasticIPを直接持つNICは、ExternalNetworkの`status.networkID`をVNIとするセグメントにいるものとして扱われます。0の間は、PodControllerがNICを作らずに待ちます。

```console
$ kubectl get externalnetwork ext-net -o jsonpath='{.status.networkID}'
4097
```

詳細は[ExternalNetwork](../resources/externalnetwork.md)を参照してください。

### 2. ElasticIPを作成

```yaml
apiVersion: juneau.loutres.me/v1alpha1
kind: ElasticIP
metadata:
  name: web-eip
spec:
  externalNetwork: ext-net
---
apiVersion: juneau.loutres.me/v1alpha1
kind: ElasticIP
metadata:
  name: gw-eip
spec:
  externalNetwork: ext-net
```

```console
$ kubectl get elasticip
NAME      EXTERNALNETWORK   ADDRESS       ATTACHMENTKIND   ATTACHMENT   PHASE       ALLOCATED   ATTACHED
gw-eip    ext-net           10.225.51.6                                 Available   True        False
web-eip   ext-net           10.225.51.8                                 Available   True        False
```

ElasticIPはPodと同じnamespaceに作ってください。別のnamespaceのElasticIPは参照できません。

### 3. eth0にElasticIPを持たせる

`juneau.loutres.me/elastic-ip` アノテーションにElasticIPの名前を書きます。

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: web
  annotations:
    juneau.loutres.me/elastic-ip: web-eip
spec:
  containers:
    - name: nginx
      image: nginx:1.27
      readinessProbe:
        httpGet:
          path: /
          port: 80
    - name: tools
      image: nicolaka/netshoot:v0.16
      command: ["sleep", "infinity"]
```

`juneau.loutres.me/networks` に `interface: eth0` のエントリを書いても同じです。

```yaml
  annotations:
    juneau.loutres.me/networks: |
      [
        {"interface": "eth0", "elasticIP": "web-eip"}
      ]
```

どちらの書き方でも、eth0はdefault Subnetに入りません。`juneau.loutres.me/subnet`、`juneau.loutres.me/address`、`juneau.loutres.me/security-groups` と一緒に書くとwebhookが拒否します。`networks`でeth0を書いた場合は、`juneau.loutres.me/elastic-ip`も一緒に書けません。ElasticIPのエントリには`address`と`securityGroups`も書けません。

Podが起動したら、NetworkInterfaceとElasticIPを確認します。

```console
$ kubectl get networkinterface web.eth0
NAME       NODE       SUBNET   L2NETWORK   ELASTICIP   ADDRESS          PHASE
web.eth0   worker-1                        web-eip     10.225.51.8/32   Ready

$ kubectl get elasticip web-eip
NAME      EXTERNALNETWORK   ADDRESS       ATTACHMENTKIND     ATTACHMENT   PHASE      ALLOCATED   ATTACHED
web-eip   ext-net           10.225.51.8   NetworkInterface   web.eth0     Attached   True        True
```

`kubectl get pod web -o wide` の`IP`もElasticIPのアドレスになります。

Podの中では、/32のアドレスと、`169.254.0.1`へ向かうデフォルトルートが見えます。

```console
$ kubectl exec web -c tools -- ip -4 addr show eth0
2: eth0@if23: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000 link-netnsid 0
    inet 10.225.51.8/32 scope global eth0
       valid_lft forever preferred_lft forever

$ kubectl exec web -c tools -- ip route
default via 169.254.0.1 dev eth0 onlink
```

`169.254.0.1`はどのホストのアドレスでもありません。このアドレス宛のARPに、Node側のvethでeBPFがvethのMACを返します。Podから出たパケットはNodeが受け取り、宛先に応じて転送します。

### 4. 外部からの疎通を確認

上流ルータ側、または上流ルータから到達可能なホストから確認します。

```console
$ curl -sS http://10.225.51.8/
<!DOCTYPE html>
...
<h1>Welcome to nginx!</h1>
```

Podから外へ出るパケットの送信元も、ElasticIPのままです。

```console
$ kubectl exec web -c tools -- curl -sS https://1.1.1.1/cdn-cgi/trace | grep ip=
ip=10.225.51.8
```

### 5. 追加NICにElasticIPを持たせる

eth0はこれまで通りSubnetに置いて、外部アドレスだけを追加NICで持たせることもできます。eth0がSubnetにあるので、クラスターDNSやServiceはeth0から使えます。

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: gw
  annotations:
    juneau.loutres.me/networks: |
      [
        {"interface": "eth1", "elasticIP": "gw-eip"}
      ]
spec:
  containers:
    - name: nginx
      image: nginx:1.27
    - name: tools
      image: nicolaka/netshoot:v0.16
      command: ["sleep", "infinity"]
```

```console
$ kubectl get networkinterface gw.eth0 gw.eth1
NAME      NODE       SUBNET    L2NETWORK   ELASTICIP   ADDRESS          PHASE
gw.eth0   worker-2   default                           10.16.0.9/16     Ready
gw.eth1   worker-2                         gw-eip      10.225.51.6/32   Ready
```

追加NICのデフォルトルートは、mainテーブルではなく専用のテーブルに入ります。送信元がElasticIPのパケットだけが、ルールでそのテーブルへ向かいます。

```console
$ kubectl exec gw -c tools -- ip rule
0:	from all lookup local
100:	from 10.225.51.6 lookup 182530822
32766:	from all lookup main
32767:	from all lookup default

$ kubectl exec gw -c tools -- ip route show table 182530822
default via 169.254.0.1 dev eth1 onlink
```

テーブルの番号は、ElasticIPのアドレスを32ビットの整数として読んだ値です。決め方は[NetworkInterface](../resources/networkinterface.md)のルートテーブルの番号を参照してください。

外から`10.225.51.6`に届いた通信への応答は、送信元が`10.225.51.6`なのでeth1から出ます。

```console
$ curl -sS http://10.225.51.6/
<!DOCTYPE html>
...
```

Podの中から新しく張る通信は、何も指定しなければmainテーブルのデフォルトルートでeth0から出ます。ElasticIPから出したいときは、送信元のアドレスを指定してください。

```console
$ kubectl exec gw -c tools -- curl -sS --interface 10.225.51.6 https://1.1.1.1/cdn-cgi/trace | grep ip=
ip=10.225.51.6
```

## type: arpのExternalNetworkで使う

ElasticIP controllerが`eip-<namespace>-<ElasticIP名>`のARPAdvertisementを作り、アドレスを持っているNetworkInterfaceの`spec.nodeName`をNodeに書きます。PodのいるNodeがARPに応答します。

```console
$ kubectl get arpadvertisement eip-default-web-eip
NAME                  EXTERNALNETWORK   ADDRESS         NODE       AGE
eip-default-web-eip   ext-net-arp       10.225.32.240   worker-1   30s
```

`NODE`は`kubectl get networkinterface web.eth0`の`NODE`と一致します。PodのNodeが変わるとARPAdvertisementも追従しますが、gratuitous ARPは送りません。上流のneighborキャッシュが更新されるまで、外からの通信は古いNodeに届きます。詳しくは[ARPを使ってExternalNetworkを構築する](external-network-arp.md)の制約を参照してください。

## type: bgpのExternalNetworkで使う

ElasticIPごとの経路は広報しません。BGPAdvertisementで広報しているAddressPoolの経路がそのまま使われます。上流ルータがECMPでどのNodeに送っても、そのNodeがPodのNodeへVXLANで運びます。VNIはExternalNetworkの`status.networkID`です。

AddressPoolがBGPAdvertisementで広報されていないと、外からは届きません。

## Podから出ていくパケット

ElasticIPを持つNICから出たパケットは、SNATもVpcのRouteTableも通りません。宛先によって次のように扱われます。

| 宛先 | 扱い |
|---|---|
| Nodeの`external_address_pools`に`EXTERNAL_ADDRESS_DELIVERED_HERE`で入っているアドレス | Nodeの中で折り返し、外からNodeに届いたパケットと同じ処理に回します |
| PodがいるNodeのアドレス | Nodeのカーネルに渡します |
| それ以外 | PodがいるNodeのルーティングテーブルに従って、NodeのNICから出します |

`EXTERNAL_ADDRESS_DELIVERED_HERE`に入るのは、そのNodeが外から受け取るアドレスです。他のPodが直接持つElasticIPは、PodがどのNodeにいても全Nodeに入るので、Pod同士はNodeの中で折り返して届きます。ServiceLoadBalancerのVIPやNATGatewayのアドレスが入るかどうかは、そのNodeが広報やARPの応答を受け持っているかで決まります。入っていなければNodeのNICから出て、外側のネットワークを通って受け持つNodeに届きます。

`spec.nodeName`で別のNodeに絞ったBGPAdvertisementの範囲は`EXTERNAL_ADDRESS_DELIVERED_ELSEWHERE`になり、全Nodeが広報するAddressPoolに含まれていても折り返しません。NATGatewayがNodeごとに広報するアドレスがこれにあたります。

VpcのPodが持つVpc内のアドレスには届きません。ClusterIP Serviceにも届きません。

送信元がElasticIPでないパケットと、IPv4以外のパケットは捨てます。ARPは`169.254.0.1`宛のリクエストと、自分のElasticIPについての応答だけを通します。

## 注意点

### DNS

eth0がElasticIPを持つPodは、dnsPolicyが`Default`に書き換わります。ClusterFirstが指すCoreDNSのClusterIPに、ElasticIPのNICからは届かないからです。

| 作成時のdnsPolicy | 結果 |
|---|---|
| 未指定、`ClusterFirst`、`ClusterFirstWithHostNet` | `Default` |
| `Default` | そのまま |
| `None` | そのまま |

`Default`のPodは、Nodeの`resolv.conf`(kubeletの`--resolv-conf`)にあるDNSサーバを使います。問い合わせの送信元はElasticIPなので、そのDNSサーバがElasticIPからの問い合わせに答え、応答を返せる必要があります。`*.svc.cluster.local`のようなクラスター内の名前は引けません。

`juneau.loutres.me/dns-inject-skip: "true"`を付けたPodは、dnsPolicyを書き換えません。dnsPolicyを書いていなければClusterFirstのままになり、名前解決ができません。

eth0がSubnetで、追加NICだけがElasticIPを持つPodは、これまで通りSubnetのDNSが注入されます。

### kubeletのプローブ

eth0がElasticIPを持つPodには、CNIがNodeに`<ElasticIP>/32 dev <Podのvethのホスト側>`の経路を入れます。kubeletのhttpGetやtcpSocketのプローブはこの経路でPodに届き、応答はPodからNodeのカーネルに戻ります。controllerの`--enable-probe-rewrite`は、このPodのプローブを書き換えません。

経路はPodのsandboxと一緒に消えます。追加NICのElasticIPには経路を入れません。kubeletがプローブするのはeth0のアドレスだからです。

### Service

eth0がElasticIPを持つPodは、ServiceとServiceLoadBalancerのバックエンドになれません。selectorに一致しても、daemonはバックエンドに入れません。外に公開するならElasticIPのアドレスへ直接つないでください。

ElasticIPのNICからClusterIP Serviceにも届きません。Serviceを使いたいPodは、eth0をSubnetに置いて、ElasticIPは追加NICに持たせてください。

### SecurityGroupとNetworkACL

ElasticIPを持つNICには、SecurityGroupもNetworkACLも効きません。どのVpcにも属さないからです。そのアドレスに届いたパケットは、ポートを問わずすべてPodに入ります。

守りたいポートがあるなら、Podの中でファイアウォールを設定してください。

### ElasticIPを削除するとき

PodのNICがElasticIPを参照している間、ElasticIPの削除は完了しません。アドレスの予約を外すと、動いているPodのアドレスを別のElasticIPが取れてしまうからです。先にPodを消してください。

```console
$ kubectl delete elasticip web-eip --wait=false
$ kubectl get elasticip web-eip -o jsonpath='{.status.conditions[?(@.type=="Allocated")].reason}'
WaitingForNetworkInterfaces
```

### Podを作り直すとき

1つのElasticIPを持てるNICは1つだけです。持っているPodが動いている間に、同じElasticIPを参照する別のPodを作ると、webhookが拒否します。

次の場合は受け付けて、新しいPodのNICは古いNICが消えるまで`Pending`で待ちます。その間、新しいPodは`ContainerCreating`のままです。

- 持っているPodが終了中
- 持っているNICと新しいNICの`spec.allocationIdentity`が同じ。KubeVirtのvirt-launcher Podは`vmi.<VirtualMachine名>`が入るので、VMを再起動しても同じElasticIPを持ち続けます

webhookはPodを作るときにNetworkInterfaceを見て判断するので、同じElasticIPを参照するPodを2つ同時に作ると、両方とも受け付けられることがあります。この場合も両方のNICが作られ、ElasticIPを持てなかった方は`Pending`で待ちます。reasonは`WaitingForElasticIP`で、messageにアドレスを持っているNICの名前が出ます。持っているPodを消すと、待っていたNICがすぐにアドレスを引き継ぎます。

Deploymentでは、ローリングアップデートが古いPodを残したまま新しいPodを作ろうとするので、webhookが新しいPodを拒否して更新が進みません。1つのElasticIPを使うDeploymentは`replicas: 1`にして、`strategy.type: Recreate`か`maxSurge: 0`を指定してください。古いPodが終了中になってから新しいPodが作られます。

## 制限

- `kubectl juneau trace`は、ElasticIPを持つNICを送信元にも宛先にも指定できません。`tracing such a NIC is not supported yet`というエラーになります。このNICを通るパケットはtraceイベントを出しません
- IPv4だけです
- MTUはSubnetのNICと同じくカーネルの既定値で、VXLANのオーバーヘッドを引いていません。BGPでPodのいないNodeに着いたパケットはVXLANで運ぶので、underlayのMTUに50バイトの余裕が無いと、大きなパケットが届きません
- KubeVirtのライブマイグレーションには対応していません。移行先のvirt-launcher PodのNICは移行元のNICが消えるまで`Pending`で待つので、移行先のPodが起動しません。また、VMのゲストOSは`169.254.0.1`のMACとして古いvethのMACを覚えています。Podが変わったあと、ゲストのARPキャッシュが更新されるまでは、Nodeのカーネル宛の通信(プローブの応答など)が届きません
- ElasticIPAttachmentとPodを同時に作ってwebhookをすり抜けると、ElasticIPは`Error`になり、NICは`Pending`になります。すでに動いていたPodのデータプレーンの設定は外れず、ElasticIPのアドレスで通信を続けます。ElasticIPAttachmentを消し、Podを作り直してください
- Nodeが落ちてNetworkEndpointが残ったまま、同じElasticIPを持つPodが別のNodeで起動すると、2つのNetworkEndpointが同じアドレスを持ちます。`arp_table`と`fdb`は後から書いた方が勝つので、古いNetworkEndpointが消えるまで外からの通信が落ちたNodeに向かうことがあります
- NodeのアドレスがAddressPoolの範囲に入っていると、PodからそのNodeへの応答がNodeのカーネルに渡らず、kubeletにプローブの応答が届きません。AddressPoolにNodeのアドレスを含めないでください
- Podのアノテーションの組み合わせを確認するwebhookは、Podの作成時にしか動きません。作成後に書き換えたアノテーションは確認されないので、NICを変えるときはPodを作り直してください

## うまくいかないとき

1. **`kubectl get networkinterface`にNICが出てこない**
    - PodControllerは、ElasticIPが無い、ElasticIPの`ADDRESS`が空、ExternalNetworkの`status.networkID`が0、のどれかの間はNetworkInterfaceを作りません。controllerのログに`waiting for the network of a Pod NIC`と理由が出ます
    - ElasticIPがPodと同じnamespaceにあるか確認してください
2. **NetworkInterfaceが`Pending`のまま**
    - `kubectl get networkinterface web.eth0 -o jsonpath='{.status.conditions[?(@.type=="Allocated")]}'`でreasonとmessageを見ます
    - reasonが`WaitingForElasticIP`なら、messageに書かれたNetworkInterfaceかElasticIPAttachmentがElasticIPを使っています。古いPodが残っていないか、ElasticIPAttachmentを消し忘れていないか確認してください
    - ElasticIPのreasonが`WaitingForHandover`なら、削除中のNetworkInterfaceが消えるのを待っています。messageに名前が出ます。finalizerで止まっていないか確認してください
3. **NetworkInterfaceは`Allocated`なのに、Podが`ContainerCreating`のまま**
    - `kubectl describe pod web`のイベントを見ます。`Failed to read the ElasticIP of a NIC`が`forbidden`で出ている場合、daemonのServiceAccountがElasticIPを読めません。ClusterRoleBinding `cni-daemon-elasticip-viewer-binding`を含むdaemonのマニフェストを適用し直してください
4. **外から届かない**
    - まず`kubectl juneau describe pod web`で、NICの行が`ElasticIP  web-eip  (direct, ..., carried by this NIC)`になっているか見ます。`carried by NetworkInterface ...`なら別のNICが持っています
    - 全Nodeの`elastic_ip_direct`にアドレスが入っているか確認します。`NETWORK_ID`はExternalNetworkの`status.networkID`と同じはずです。入っていないNodeに届いたパケットは捨てられます

        ```console
        $ kubectl juneau bpf dump elastic_ip_direct --filter addr=10.225.51.8
        NODE      ADDR          NETWORK_ID
        worker-1  10.225.51.8   4097
        worker-2  10.225.51.8   4097
        ```

    - 同じく全Nodeの`external_address_pools`に、そのアドレスの/32が`EXTERNAL_ADDRESS_DELIVERED_HERE`で入っているか確認します。ここに無いアドレス宛のパケットは、NodeのNICに着いた時点で捨てられます

        ```console
        $ kubectl juneau bpf dump external_address_pools --filter addr=10.225.51.8
        NODE      PREFIXLEN  ADDR          DELIVERY
        worker-1  32         10.225.51.8   EXTERNAL_ADDRESS_DELIVERED_HERE
        worker-2  32         10.225.51.8   EXTERNAL_ADDRESS_DELIVERED_HERE
        ```

    - 全Nodeの`arp_table`で、`SUBNET_ID`がnetworkID、`IPADDR`がElasticIPのエントリのMACが、Podのeth0のMACになっているか確認します。PodのMACは`kubectl get networkendpoint web.eth0 -o jsonpath='{.spec.macAddress}'`で分かります

        ```console
        $ kubectl juneau bpf dump arp_table --filter subnet_id=4097 --filter ipaddr=10.225.51.8
        ```

    - `fdb`を`--filter subnet_id=4097`で見ます。PodのいるNodeでは`IFINDEX`にvethのifindexが、それ以外のNodeでは`IFINDEX`が0で`VTEP_IP`にPodのNodeのアドレスが入っているはずです
    - PodのいるNodeの`ifindex_external_network`に、vethのifindexとElasticIPが入っているか確認します。無いと、そのNICから出るパケットはすべて捨てられます

        ```console
        $ kubectl juneau bpf dump ifindex_external_network --node worker-1
        IFINDEX  NETWORK_ID  IPV4
        23       4097        10.225.51.8
        ```

    - `type: arp`なら、`kubectl get arpadvertisement eip-default-web-eip`の`NODE`がPodのNodeか、そのNodeの`kubectl juneau bpf dump external_arp_table`にアドレスがあるかを見ます
    - `type: bgp`なら、AddressPoolがBGPAdvertisementで広報されているか、`kubectl get bgpnodestate`がReadyかを見ます
5. **Podから外に出られない**
    - Podの中で`ip neigh show 169.254.0.1`を実行し、MACが`kubectl juneau bpf dump ifindex_host_mac --node worker-1 --filter ifindex=23`の値と同じか確認します。ARPが解決できていなければ、`ifindex_external_network`か`ifindex_host_mac`にvethが入っていません
    - Podの中で別のアドレスを振っていたり、VMのゲストOSでNATしていたりすると、送信元がElasticIPでないパケットになり、捨てられます
    - 追加NICの場合、送信元をElasticIPにしないとeth0から出ます。`kubectl exec gw -c tools -- ip route get 1.1.1.1 from 10.225.51.6`で`dev eth1`になるか見てください
6. **readinessProbeが失敗する**
    - PodのいるNodeで`ip route get 10.225.51.8`を実行し、`dev eth0+`で始まるvethが返るか見ます。返らなければNodeの経路が入っていません。Podを作り直してください
    - NodeのアドレスがAddressPoolの範囲に入っていないか確認してください。入っていると、Podからの応答がNodeのカーネルではなく外部アドレスの処理に回ります
7. **他のPodのElasticIPやServiceLoadBalancerのVIPに届かない**
    - 送信元PodのNodeで`kubectl juneau bpf dump external_address_pools --node <Node名>`を見ます。宛先が`EXTERNAL_ADDRESS_DELIVERED_HERE`の範囲に入っていればNodeの中で折り返します。`EXTERNAL_ADDRESS_DELIVERED_ELSEWHERE`なら、別のNodeが広報しているアドレスとして上流ルータへ出します。どちらにも無ければ、NodeのNICから外へ出します

## 参照

- [ElasticIP](../resources/elasticip.md)
- [ElasticIPAttachment](../resources/elasticipattachment.md)
- [NetworkInterface](../resources/networkinterface.md)
- [NetworkEndpoint](../resources/networkendpoint.md)
- [ExternalNetwork](../resources/externalnetwork.md)
- [ARPAdvertisement](../resources/arpadvertisement.md)
- [PodにNICを追加する](multi-nic-pod.md)
