# Service LoadBalancer を公開する

Juneau の Service LoadBalancer 機能は、Kubernetes の `Service type: LoadBalancer` に対して外部 VIP を払い出し、その VIP 宛のトラフィックを Pod の backend に届けます。Juneau の LoadBalancer は **送信元 IP を保持** する設計になっており、外部クライアントが backend Pod に到達した時点で、Pod は元のクライアント IP をそのまま観測できます。

このガイドでは、

1. ExternalNetwork と AddressPool を準備する
2. Juneau-managed の LoadBalancer Service を作成する
3. VIP の払い出しと広告状態を確認する
4. backend Pod から見た送信元 IP を確認する

の流れを示します。

## 前提条件

- Juneau の controller / daemon / bgp-speaker が動作しているクラスター
- 上流ルータと BGP セッションが確立しており、Juneau が広告した経路を受け取れること
- kubectl が利用可能なこと
- VIP として割り当てる IP 範囲を払い出せる ExternalNetwork と AddressPool

Service LoadBalancer の初期リリースが対応する範囲は次の通りです。

- IPv4 のみ
- TCP / UDP のみ
- externalTrafficPolicy: Local のみ
- Juneau が管理する Pod backend のみ (host-network Pod は対応していません)

## 1. ExternalNetwork と AddressPool を準備する

VIP は、ExternalNetwork が参照する AddressPool から払い出されます。BGP で広告するため AddressPool の advertiseMode は bgp である必要があります。

```yaml
apiVersion: juneau.loutres.me/v1alpha1
kind: AddressPool
metadata:
  name: public-v4
spec:
  advertiseMode: bgp
  addresses:
    - 203.0.113.0/24
---
apiVersion: juneau.loutres.me/v1alpha1
kind: ExternalNetwork
metadata:
  name: public
spec:
  type: bgp
  addressPools:
    - public-v4
```

AddressPool が広告対象として有効になるよう、対応する BGPAdvertisement と BGPPeer を別途設定しておきます。詳細は「BGPを使ってExternalNetworkを構築する」のガイドを参照してください。

## 2. Juneau-managed の LoadBalancer Service を作成する

LoadBalancer Service が Juneau の管理対象になる条件は次の 2 点です。

- spec.type が LoadBalancer
- spec.loadBalancerClass が `juneau.loutres.me/load-balancer`

加えて、Juneau が VIP を払い出すために以下の annotation が必須です。

| annotation | 役割 |
|---|---|
| `juneau.loutres.me/load-balancer-external-network` | 必須。VIP を払い出す ExternalNetwork の名前 |
| `juneau.loutres.me/load-balancer-requested-ip` | 任意。割り当ててほしい VIP を IPv4 でピン留めする |

externalTrafficPolicy は Local に固定する必要があります。

### backend Deployment と Service

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx
spec:
  replicas: 3
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
        - name: nginx
          image: nginx:1.27
          ports:
            - containerPort: 80
              name: http
---
apiVersion: v1
kind: Service
metadata:
  name: nginx
  annotations:
    juneau.loutres.me/load-balancer-external-network: public
spec:
  type: LoadBalancer
  loadBalancerClass: juneau.loutres.me/load-balancer
  externalTrafficPolicy: Local
  selector:
    app: nginx
  ports:
    - name: http
      protocol: TCP
      port: 80
      targetPort: http
```

特定の VIP を要求したい場合は次のように `requested-ip` annotation を付与します。要求した IP は ExternalNetwork が参照する AddressPool の範囲内である必要があります。

```yaml
metadata:
  annotations:
    juneau.loutres.me/load-balancer-external-network: public
    juneau.loutres.me/load-balancer-requested-ip: 203.0.113.10
```

## 3. VIP の払い出しと広告状態を確認する

Juneau の controller は、Service ごとに ServiceLoadBalancer リソースを自動生成します。VIP の払い出し状況、広告ノード、backend サマリは ServiceLoadBalancer の status から確認できます。

```sh
kubectl get serviceloadbalancer nginx -o yaml
```

代表的なフィールド:

- `status.vip` — 割り当てられた外部 IP
- `status.addressPool` — VIP の払い出し元 AddressPool
- `status.advertisingNodes` — VIP を BGP 広告しているノード一覧 (Local backend を持つノードに限定される)
- `status.backendSummary.totalReady` — Service 全体で Ready な endpoint 数
- `status.backendSummary.localReadyNodes` — `advertisingNodes` の数

Service の `.status.loadBalancer.ingress[0].ip` にも同じ VIP が反映されるため、`kubectl get svc nginx -w` で payload を確認できます。

`kubectl-juneau` プラグインを使うと、これらの情報をまとめて参照できます。

```sh
kubectl juneau describe loadbalancer nginx
```

出力例:

```text
ServiceLoadBalancer  default/nginx  (vip: 203.0.113.10, phase: Ready)
├── parent Service  default/nginx  (type=LoadBalancer, externalTrafficPolicy=Local)
├── ExternalNetwork  public  type=bgp  pools=public-v4
├── AllocatedFrom  AddressPool/public-v4
├── Ports
│   └── TCP/80  ->  80
├── AdvertisingNodes  (2)
│   ├── node-a
│   └── node-c
└── Backends  totalReady=3  localReadyNodes=2
```

`AdvertisingNodes` に並ぶノードのみが /32 ルートを上流ルータへ広告し、上流ルータは ECMP で受信トラフィックを分散します。Local backend が居なくなったノードは即座に広告から外れます。

## 4. backend Pod から見た送信元 IP を確認する

Juneau の LoadBalancer は SNAT を行わないため、backend Pod は元のクライアント IP をそのまま観測します。`X-Forwarded-For` ヘッダなしでも実 IP を取得できます。

クライアント側 (例えば外部のテストルータ) で:

```sh
curl http://203.0.113.10/
```

backend Pod のログには元のクライアント IP がそのまま記録されます。

```sh
kubectl logs deploy/nginx
```

```text
198.51.100.42 - - [...] "GET / HTTP/1.1" 200 615 "-" "curl/8.8.0"
```

レスポンスは Juneau の dataplane が逆 NAT を行い、クライアントから見ると VIP を送信元とする応答に見えます。

## 制限事項

初期リリースでは以下の機能はサポートしません。

- externalTrafficPolicy: Cluster — Local 専用です
- IPv6 / SCTP
- host-network Pod を backend とする LoadBalancer
- loadBalancerSourceRanges による発信元フィルタ
- healthCheckNodePort

これらは将来のリリースで個別に検討されます。
