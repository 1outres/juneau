# BGPでLoadBalancer Serviceを公開する

JuneauではServiceを `type: LoadBalancer` で作ると、ExternalNetworkから払い出された外部到達可能なIP (LoadBalancer Ingress) を取得し、その経路をBGPで上流ルータに広報できます。Service backendは複数Nodeにまたがって配置できて、外部クライアントから単一のVIPで到達できます。

このガイドはBGP公開用のLoadBalancer Serviceをゼロから組み立てる手順を示します。

## このガイドで構築するもの

- 外部公開用CIDR `10.225.52.0/24` を持つAddressPool
- 上流ルータとのBGPピアリングと広報
- LoadBalancer Service用のExternalNetwork
- 複数Nodeに散ったnginx PodをbackendとするService.type=LoadBalancer
- 上流ルータ側から `curl http://<LoadBalancerIP>/` で到達確認

## 前提条件

- Juneauのcontroller / daemon / bgp-speakerが動作しているクラスター (Worker Node 2台以上推奨)
- クラスターのAS番号 (本ガイドでは **65001**)
- 上流BGPルータ側でJuneauクラスターを受け入れる設定 (AS **65002**、Juneau Node各IPとのピアリング)
- 広報に使うCIDRが上流ネットワークで未使用であること (本ガイドでは `10.225.52.0/24`)
- Service backend Podが属するVpcは `spec.service.consume: true` になっていること (default Vpcは初期状態で有効)

## 手順

### 1. AddressPoolを作成

LoadBalancer IPの払い出し範囲です。

```yaml
apiVersion: juneau.loutres.me/v1alpha1
kind: AddressPool
metadata:
  name: lb-pool
spec:
  advertiseMode: bgp
  addresses:
    - 10.225.52.0/24
```

### 2. BGPPeerとBGPAdvertisementを作成

ExternalNetworkで使うBGPの広報先と広報内容を宣言します。BGPピアの確立 / 広報の確認方法は[ExternalNetworkをBGPで公開するガイド](external-network-bgp.md)を参照してください。

```yaml
apiVersion: juneau.loutres.me/v1alpha1
kind: BGPPeer
metadata:
  name: upstream
spec:
  myASN: 65001
  peerASN: 65002
  peerAddress: 10.225.32.1
---
apiVersion: juneau.loutres.me/v1alpha1
kind: BGPAdvertisement
metadata:
  name: lb-adv
spec:
  addressPools:
    - lb-pool
```

### 3. ExternalNetworkを作成

LoadBalancer ServiceがどのAddressPoolから外部IPを取るかを束ねます。

```yaml
apiVersion: juneau.loutres.me/v1alpha1
kind: ExternalNetwork
metadata:
  name: lb-extnet
spec:
  type: bgp
  addressPools:
    - lb-pool
```

### 4. backend Pod用のVpc / Subnetを用意

backendを置くSubnetはdefaultでも構いませんが、ガイドでは隔離のために専用のVpc / Subnetを用意します。

```yaml
apiVersion: juneau.loutres.me/v1alpha1
kind: Vpc
metadata:
  name: lb-vpc
spec:
  service:
    consume: true
---
apiVersion: juneau.loutres.me/v1alpha1
kind: Subnet
metadata:
  name: lb-subnet
spec:
  vpc: lb-vpc
  cidr: 10.220.0.0/24
```

`spec.service.consume: true` はService配信の参加スイッチです。defaultはVpcの`service`欄を持つので有効ですが、自前で作ったVpcはこの設定を入れないとServiceの転送が成立しません。

### 5. backend Podをデプロイ

複数Nodeに散らすため、Pod1つ目はWorker A、2つ目はWorker Bに配置します。`juneau.loutres.me/subnet` annotationで配置先Subnetを指定します。

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-a
  labels:
    app: lb-nginx
  annotations:
    juneau.loutres.me/subnet: lb-subnet
spec:
  nodeName: worker-a
  containers:
    - name: nginx
      image: nginx:1.27
---
apiVersion: v1
kind: Pod
metadata:
  name: nginx-b
  labels:
    app: lb-nginx
  annotations:
    juneau.loutres.me/subnet: lb-subnet
spec:
  nodeName: worker-b
  containers:
    - name: nginx
      image: nginx:1.27
```

### 6. Service.type=LoadBalancerを作成

JuneauのloadBalancerClass (`juneau.loutres.me/lb`) と、外部IPを払い出すExternalNetworkをannotationで指定します。

```yaml
apiVersion: v1
kind: Service
metadata:
  name: nginx
  annotations:
    juneau.loutres.me/external-network: lb-extnet
    juneau.loutres.me/vpc: lb-vpc
spec:
  type: LoadBalancer
  loadBalancerClass: juneau.loutres.me/lb
  selector:
    app: lb-nginx
  ports:
    - port: 80
      targetPort: 80
      protocol: TCP
```

annotation:

| Key | 値 | 役割 |
|---|---|---|
| `juneau.loutres.me/external-network` | ExternalNetwork名 | LoadBalancer IPを払い出すExternalNetwork |
| `juneau.loutres.me/vpc` | Vpc名 | Service backendがどのVpcに属するかを明示 |
| `juneau.loutres.me/loadbalancer-ip` | IPアドレス (任意) | 特定のIPを要求したいときに指定 |

`spec.allocateLoadBalancerNodePorts` はadmissionで自動的に `false` に設定されるので、明示的に書く必要はありません。

### 7. LoadBalancer IPの払い出しを確認

```console
$ kubectl get service nginx
NAME    TYPE           CLUSTER-IP       EXTERNAL-IP    PORT(S)        AGE
nginx   LoadBalancer   10.96.123.45     10.225.52.5    80:0/TCP       30s
```

`EXTERNAL-IP` が払い出され、上流ルータに `10.225.52.5/32` のhost routeがJuneau全Worker Node経由のECMPで広報されます。

### 8. 外部からの疎通を確認

上流ルータ側、または上流ルータから到達可能な任意のホストから:

```console
$ curl -sS http://10.225.52.5/
<!DOCTYPE html>
...
<h1>Welcome to nginx!</h1>
```

backendは複数Nodeに散らばっていますが、外部から見える応答は単一のIPからの応答に集約されます。連続して何度叩いても、LoadBalancerはコネクション単位でどちらかのbackendへ振り分けます。

```console
$ for i in $(seq 1 10); do curl -sS http://10.225.52.5/; done | sort -u
<!DOCTYPE html>
... (worker-aのnginxの応答)
<!DOCTYPE html>
... (worker-bのnginxの応答)
```

## うまくいかないとき

1. **`EXTERNAL-IP` が `<pending>` のまま**
    - `juneau.loutres.me/external-network` annotationが正しいExternalNetworkを指しているか
    - ExternalNetworkの`spec.type: bgp` か、参照するAddressPoolが`advertiseMode: bgp`か
    - AddressPool / ExternalNetworkのstatus.errorsを確認
2. **`EXTERNAL-IP` が出ているのに外部からcurlが通らない**
    - 上流ルータで該当host routeがECMPで複数next-hopを持って学習されているか (`show ip route 10.225.52.5/32`)
    - backend Podが `READY` か (`kubectl get pods -l app=lb-nginx`)
    - backend Podが属するVpcが `spec.service.consume: true` か (defaultでない自前のVpcを使うときに見落としやすい)
    - 上流ルータが**L4 hash policy** (5-tuple基準) でECMPする設定でも、Juneauは同じTCPコネクションのパケットが別Nodeに散らばる状況を内部で吸収して同じbackendに導きます。L3 hash policy / L4 hash policyのどちらでも疎通します
3. **`juneau.loutres.me/loadbalancer-ip` で要求したIPが採用されない**
    - 要求IPがExternalNetworkの参照するAddressPoolのCIDRに含まれているか
    - 要求IPが他のElasticIP / LoadBalancer Serviceに既に払い出されていないか
    - 要求IPの形式が正しいか (`10.225.52.5` のような単一IPv4)

## 参照

- [AddressPool](../resources/addresspool.md)
- [BGPAdvertisement](../resources/bgpadvertisement.md)
- [BGPPeer](../resources/bgppeer.md)
- [ExternalNetwork](../resources/externalnetwork.md)
- [Vpc](../resources/vpc.md) / [Subnet](../resources/subnet.md)
- [BGPでExternalNetworkを構築する](external-network-bgp.md)
- [VPCでServiceを利用する](custom-vpc-service.md)
