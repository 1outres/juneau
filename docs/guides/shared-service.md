# Vpc 間で共有Serviceを利用する

Juneauの共有Service機能を使うと、ある Vpc に置いた Service を他の Vpc から到達できるように公開できます。デフォルトでは Vpc は互いに隔離されているため、ClusterIP 経由の通信もそのままでは Vpc 境界を越えません。共有Service はこの境界を、許可した呼び出し側のみに開ける仕組みです。

共有Service は次の 3 つの独立した opt-in を組み合わせて成立します。

| 役割 | 設定先 | 内容 |
|---|---|---|
| Provider | Vpc.spec.service.provider.natSourceSubnet | 自 Vpc が共有Service を「公開」する。発信元書き換え用の SNAT アドレスをこの Subnet から払い出す |
| Service マーカ | Service annotation `juneau.loutres.me/shared-service: "true"` | この Service を共有公開する |
| Consumer | Vpc.spec.service.consume | 自 Vpc の Pod が他 Vpc の共有Service を呼べる |

加えて、Service ごとに到達可能な Consumer Vpc を絞り込む whitelist annotation `juneau.loutres.me/shared-service-allowed-consumer-vpcs` も設定できます。

呼び出す側の Vpc に `spec.service.consume: true` を立てたくない場合は、[VpcEndpoint](../resources/vpcendpoint.md)で Service 1 つ分だけ穴を開けることもできます。Service 側の `shared-service` annotation も不要になる代わりに、到達できる先は VpcEndpoint に書いた Service だけになります。

このガイドでは、

1. default Vpc の共有Service に 別の Vpc からアクセス
2. 別 Vpc が公開する共有Service に default Vpc からアクセス
3. Consumer の whitelist で絞り込み

の 3 パターンを順に示します。

## 前提条件

- Juneau の controller / daemon が動作しているクラスター
- kubectl が利用可能なこと
- クラスターで Service の仮想IP (ClusterIP) 用の CIDR が設定されていること
- Provider となる Vpc の `service.provider.natSourceSubnet` に、Node 数分の予備アドレスが残っていること (Node ごとに 1 つずつ共有Service 用の SNAT アドレスが払い出されます)

## 1. default Vpc の共有Service に別 Vpc からアクセス

bootstrap 時に default Vpc は `service.provider.natSourceSubnet: default`、`service.consume: true` の状態で作成されます。Provider の設定がすでに揃っているので、共有Service にしたい Service へ annotation を付与するだけで公開できます。

### backend Deployment と共有Service

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx
spec:
  replicas: 2
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
---
apiVersion: v1
kind: Service
metadata:
  name: nginx
  annotations:
    juneau.loutres.me/shared-service: "true"
spec:
  selector:
    app: nginx
  ports:
    - port: 80
      targetPort: 80
```

Service の owner Vpc を省略するか `juneau.loutres.me/vpc: default` を明示すれば default Vpc 所属になります。

### caller 側 Vpc / Subnet

呼び出し側の Vpc には `spec.service.consume: true` が必須です。

```yaml
apiVersion: juneau.loutres.me/v1alpha1
kind: Vpc
metadata:
  name: app-vpc
spec:
  service:
    consume: true
---
apiVersion: juneau.loutres.me/v1alpha1
kind: Subnet
metadata:
  name: app-subnet
spec:
  vpc: app-vpc
  cidr: 10.80.0.0/24
```

### ServiceNATAttachment の確認

各 Node には Provider Vpc 単位で SNAT アドレスが払い出されます。リソース名は `<node>.<provider-vpc>` です。

```console
$ kubectl get servicenatattachment
NAME              NODE       VPC       ASSIGNEDIP    SUBNET    READY
worker-1.default  worker-1   default   10.16.0.200   default   True
worker-2.default  worker-2   default   10.16.0.201   default   True
```

すべての Node が `READY: True` で `ASSIGNEDIP` が埋まっていれば公開準備完了です。

### 別 Vpc から疎通

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: curl
  annotations:
    juneau.loutres.me/subnet: app-subnet
spec:
  containers:
    - name: curl
      image: curlimages/curl:8.7.1
      command: ["sleep", "infinity"]
```

```console
$ kubectl exec curl -- curl -sS http://nginx.default.svc/
<!DOCTYPE html>
...
<h1>Welcome to nginx!</h1>
```

## 2. 別 Vpc の共有Service に default Vpc からアクセス

Provider 役を default 以外の Vpc に持たせる構成です。`service.provider.natSourceSubnet` に同 Vpc 内の Subnet を指定すると、その Vpc の Service を共有公開できるようになります。

### Provider Vpc / Subnet

```yaml
apiVersion: juneau.loutres.me/v1alpha1
kind: Vpc
metadata:
  name: tenant-vpc
spec:
  service:
    consume: true
    provider:
      natSourceSubnet: tenant-subnet
---
apiVersion: juneau.loutres.me/v1alpha1
kind: Subnet
metadata:
  name: tenant-subnet
spec:
  vpc: tenant-vpc
  cidr: 10.90.0.0/24
```

### backend Pod と共有Service

backend を `tenant-subnet` に置き、Service の owner Vpc を `tenant-vpc` に指定します。

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx
  annotations:
    juneau.loutres.me/subnet: tenant-subnet
  labels:
    app: nginx
spec:
  containers:
    - name: nginx
      image: nginx:1.27
---
apiVersion: v1
kind: Service
metadata:
  name: nginx
  annotations:
    juneau.loutres.me/vpc: tenant-vpc
    juneau.loutres.me/shared-service: "true"
spec:
  selector:
    app: nginx
  ports:
    - port: 80
      targetPort: 80
```

### default Vpc の Pod から疎通

default Vpc は bootstrap で `service.consume: true` が立っているので追加設定は不要です。

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: curl-default
spec:
  containers:
    - name: curl
      image: curlimages/curl:8.7.1
      command: ["sleep", "infinity"]
```

```console
$ kubectl exec curl-default -- curl -sS http://nginx.default.svc/
<!DOCTYPE html>
...
```

ServiceNATAttachment は Provider Vpc ごとに別系統で払い出されます。default Vpc から `tenant-vpc` の共有Service を呼ぶ場合、`<node>.tenant-vpc` の attachment が用意され、そこに記録された SNAT アドレスがソースとして使われます。

```console
$ kubectl get servicenatattachment
NAME                  NODE       VPC          ASSIGNEDIP     SUBNET           READY
worker-1.default      worker-1   default      10.16.0.200    default          True
worker-1.tenant-vpc   worker-1   tenant-vpc   10.90.0.200    tenant-subnet    True
worker-2.default      worker-2   default      10.16.0.201    default          True
worker-2.tenant-vpc   worker-2   tenant-vpc   10.90.0.201    tenant-subnet    True
```

## 3. Consumer Vpc を whitelist で絞り込む

`juneau.loutres.me/shared-service-allowed-consumer-vpcs` annotation をカンマ区切りで指定すると、リストにある Vpc からの呼び出しだけを許可できます。annotation を省略した場合は `service.consume: true` の全 Vpc から到達可能です。

例: `tenant-vpc` の共有Service を default Vpc からのみ受け付ける。

```yaml
apiVersion: v1
kind: Service
metadata:
  name: nginx
  annotations:
    juneau.loutres.me/vpc: tenant-vpc
    juneau.loutres.me/shared-service: "true"
    juneau.loutres.me/shared-service-allowed-consumer-vpcs: "default"
spec:
  selector:
    app: nginx
  ports:
    - port: 80
      targetPort: 80
```

annotation 内の各 Vpc は実在し、かつ `spec.service.consume: true` が必要です (webhook で検証されます)。

同一 Vpc 内 (Service の owner Vpc と caller が同じ Vpc) の通信には ACL は適用されず、所有者は常に到達可能です。

## うまくいかないとき

1. **Service の apply が拒否される (`Vpc ... is not configured as a Service provider`)**
    - 共有Service の owner Vpc に `spec.service.provider.natSourceSubnet` が設定されているかを確認します。
2. **`shared-service-allowed-consumer-vpcs` が拒否される**
    - 列挙した Vpc がすべて存在し、`spec.service.consume: true` になっているかを確認します。
    - `shared-service: "true"` が同時に付いていないと拒否されます (ACL 単独では効果がないため)。
3. **caller Pod から ClusterIP に到達しない**
    - caller Pod の Vpc に `spec.service.consume: true` が設定されているか
    - 対象 Service に `juneau.loutres.me/shared-service: "true"` が付いているか
    - ACL を設定している場合、caller の Vpc 名が `shared-service-allowed-consumer-vpcs` に含まれているか
    - `kubectl get servicenatattachment` で `<node>.<provider-vpc>` が `READY: True` になっているか
    - `kubectl get endpointslice -l kubernetes.io/service-name=<svc>` で backend の Pod IP が登録されているか
4. **`kubectl get servicenatattachment` の `ASSIGNEDIP` が空のままの行がある**
    - Provider Vpc の `natSourceSubnet` の Subnet に Node 数分の在庫が残っているか
    - `READY: False` の場合は `status.conditions[?(@.type=="Ready")].message` を確認

## 参照

- [Vpc](../resources/vpc.md)
- [Subnet](../resources/subnet.md)
- [ServiceNATAttachment](../resources/servicenatattachment.md)
- [Vpc で Service を利用する](custom-vpc-service.md)
