# L2Networkで自由なセグメントを作る

SubnetはIPv4を前提にしていて、SecurityGroupもNetworkACLもServiceもIPの上に載っています。IP以外のプロトコルを流したい、Podの中でbridgeを組みたい、DHCPサーバを自分で立てたい、という場合はSubnetでは足りません。

L2Networkは宛先MACアドレスだけで転送するセグメントです。JuneauはL3を一切解釈しないので、任意のEtherTypeと任意のIPプロトコルが通ります。
このガイドでは、CIDRを持たないL2Networkを2つのPodの追加NICに繋いで、自分で決めたアドレスで通信させます。

## このガイドで構築するもの

- 専用Vpc (`lab-vpc`) とSubnet 1つ
    - `lab-subnet` (`10.91.0.0/24`): Podのeth0を置くSubnet
- CIDRを持たないL2Network (`lab-net`)
- eth0が`lab-subnet`、eth1が`lab-net`のPod 2つ
- eth1に手で付けたアドレス同士でのpingと、非IPのフレームの通過

## 前提条件

- Juneauのcontroller/daemonが動作しているクラスター
- kubectlが利用可能なこと

## 手順

### 1. VpcとSubnetとL2Networkを作成

L2Networkは`spec.vpc`が必須です。`default` Vpcは使えないので、専用のVpcを作ります。

```yaml
apiVersion: juneau.loutres.me/v1alpha1
kind: Vpc
metadata:
  name: lab-vpc
---
apiVersion: juneau.loutres.me/v1alpha1
kind: Subnet
metadata:
  name: lab-subnet
spec:
  vpc: lab-vpc
  cidr: 10.91.0.0/24
---
apiVersion: juneau.loutres.me/v1alpha1
kind: L2Network
metadata:
  name: lab-net
spec:
  vpc: lab-vpc
```

`spec.cidr`を書かなければJuneauはアドレスを配りません。VNIとMTUだけがstatusに入ります。

```console
$ kubectl get l2network
NAME      VPC       CIDR   MTU    READY
lab-net   lab-vpc          1450   True
```

### 2. L2Networkに繋がるPodを2つ作成

eth0は今まで通り`juneau.loutres.me/subnet`で、追加NICは`juneau.loutres.me/networks`で指定します。エントリに`subnet`ではなく`l2Network`を書きます。

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: lab-a
  annotations:
    juneau.loutres.me/subnet: lab-subnet
    juneau.loutres.me/networks: |
      [
        {"interface": "eth1", "l2Network": "lab-net"}
      ]
spec:
  containers:
    - name: shell
      image: nicolaka/netshoot:v0.16
      command: ["sleep", "3600"]
      securityContext:
        capabilities:
          add: ["NET_ADMIN"]
---
apiVersion: v1
kind: Pod
metadata:
  name: lab-b
  annotations:
    juneau.loutres.me/subnet: lab-subnet
    juneau.loutres.me/networks: |
      [
        {"interface": "eth1", "l2Network": "lab-net"}
      ]
spec:
  containers:
    - name: shell
      image: nicolaka/netshoot:v0.16
      command: ["sleep", "3600"]
      securityContext:
        capabilities:
          add: ["NET_ADMIN"]
```

自分でアドレスを振るために`NET_ADMIN`を付けています。DHCPサーバをセグメントに置く場合や、Podの中でbridgeを組む場合も同じです。

Podが起動したら、eth1にアドレスが付いていないことを確認します。

```console
$ kubectl exec lab-a -- ip -4 addr show eth1
3: eth1@if42: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1450 ...
```

MTUの1450はL2Networkの`status.mtu`です。eth0の方は今まで通り1500のままで、L2NetworkのNICだけがセグメントのMTUを受け取ります。

### 3. 自分でアドレスを振って通信

```console
$ kubectl exec lab-a -- ip addr add 192.168.50.1/24 dev eth1
$ kubectl exec lab-b -- ip addr add 192.168.50.2/24 dev eth1
$ kubectl exec lab-a -- ping -c 3 192.168.50.2
PING 192.168.50.2 (192.168.50.2) 56(84) bytes of data.
64 bytes from 192.168.50.2: icmp_seq=1 ttl=64 time=0.412 ms
```

Juneauは192.168.50.0/24を知りません。最初のARPリクエストはセグメントの全ポートに複製され、返ってきたARPリプライで両側のMACが学習されます。それ以降のフレームは学習したポートへ直接送られます。

Nodeを跨いでいても同じです。ARPリクエストは参加している全Nodeへ複製され、返事が来たNodeのVTEPが学習されます。

### 4. 学習の様子を確認

`kubectl juneau bpf dump`でセグメントの転送テーブルを読めます。VNIは`kubectl get l2network lab-net -o jsonpath='{.status.vni}'`で確認できます。

```console
$ kubectl juneau bpf dump l2_fdb --all-nodes --inner-key vni=4242
NODE      VNI   MAC                IFINDEX  VTEP_IP     LAST_SEEN_NS
worker-1  4242  1a:2b:3c:00:00:01  42       0.0.0.0     913842771203
worker-1  4242  1a:2b:3c:00:00:02  0        10.0.0.12   913844015886
```

`ifindex`が入っているのがこのNodeのvethに居るMAC、`vtep_ip`が入っているのが別Nodeに居るMACです。300秒フレームを見なかったエントリは掃除されます。

フレームがどのhookを通ったかは`kubectl juneau trace`で追えます。どのNICの話なのかと、自分で振ったアドレスの両方を渡してください。

```console
$ kubectl juneau trace --from-pod default/lab-a --interface eth1 --from-ip 192.168.50.1 \
    --to-pod default/lab-b --to-interface eth1 --to-ip 192.168.50.2 --proto icmp
```

### 5. IP以外のフレームが通ることを確認

3で通ったpingは、その前のARPが届いていたということです。ARPのEtherTypeは0x0806で、IPv4ではありません。tcpdumpで実際に流れているところを見ることができます。

```console
$ kubectl exec lab-b -- ip neigh flush dev eth1
$ kubectl exec lab-b -- timeout 10 tcpdump -i eth1 -e -n arp
```

別のターミナルからpingを打つと、リクエストがブロードキャストで、リプライがユニキャストで返っているのが見えます。

```console
$ kubectl exec lab-a -- ping -c 1 192.168.50.2
```

Subnetでは事情が違います。policyの付いたPodの非IPv4フレームは`POLICY_ETHERTYPE_DROP`で落ち、ARPだけがデータプレーンの都合で例外として通ります。L2Networkにはpolicyの評価そのものがありません。IPv6もSTPも独自のEtherTypeも同じように通ります。

## 注意点

### eth0には使えません

CIDRを持たないL2NetworkのNICにはアドレスが載りません。コンテナランタイムはCNIの結果のeth0にアドレスが1つも無いとsandboxの作成を失敗させるので、L2Networkは追加NIC専用です。`juneau.loutres.me/subnet`もSubnet名しか受け付けません。

`spec.cidr`を書いたL2NetworkならJuneauがアドレスを配るので、この制限はかかりません。

### セグメントの中にpolicyは効きません

SecurityGroupもNetworkACLも、L2Network上のNIC同士の通信には一切効きません。データプレーンがpolicyを読まないからです。`spec.networkACL`を書けるのはgatewayを持つL2Networkだけで、そのACLもgatewayを跨ぐ通信にしか適用されません。

同じL2Networkに繋いだPod同士は、互いに何でもできます。テナント境界は`spec.vpc`で引いてください。

### MACの詐称を止めません

誰がどのMACを名乗るかを制限していません。NICの後ろでbridgeを組んだりnested VMを動かしたりすると、NIC自身のものではないMACが必ず出てくるので、制限するとL2Networkの使い道が消えます。

### ブロードキャストは全ポートに複製されます

ブロードキャストも、マルチキャストも、まだ学習していない宛先へのユニキャストも、セグメントの全ポートに複製されます。参加しているNodeが多いほどNodeを跨ぐ複製が増えるので、ブロードキャストの多いワークロードを大きなセグメントに置くときは気をつけてください。

### MTUを合わせてください

L2Networkの既定MTUは1450です。1500バイトのunderlayからVXLANの50バイトを引いた値で、underlayがこれと違う場合は`spec.mtu`で合わせてください。

非IPプロトコルはフラグメントできないので、MTUが大きすぎるとフレームが黙って消えます。IPv4ならPMTUDが救ってくれることもありますが、L2Networkで流すものはそうとは限りません。
