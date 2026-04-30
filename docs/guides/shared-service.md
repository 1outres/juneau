# Vpcで共有Serviceを利用する

Juneauでは、default Vpcに置いたServiceに`juneau.loutres.me/shared-service: "true"` annotationを付与すると、別のVpcから到達できる「共有Service」として公開できます。共有Serviceは`spec.enableService=true`が設定されたVpcから到達でき、クラスタ全体で同じClusterIPを通じて利用されます。

クラスタの`kubernetes` Service (`default` namespace) は、annotationの有無にかかわらず暗黙的に共有Serviceとして扱われます。これにより、別Vpcに属するPodもapiserverに到達できます。

このガイドでは、default Vpc上のnginx Serviceを共有Serviceとして公開し、別Vpcに居るPodからClusterIP経由で到達するまでの手順を一通り示します。

## このガイドで構築するもの

- nginxによるbackend Deployment (replicas: 2) とそれに対応する共有Service (default Vpc所属)
- Service機能を有効化したVpc (`app-vpc`)
- `app-vpc`に属するSubnet (`app-subnet`, `10.80.0.0/24`)
- 別Vpcに置いたclient Podから、共有nginx Serviceに到達

## 前提条件

- Juneauのcontroller/daemonが動作しているクラスター
- kubectlが利用可能なこと
- クラスターでServiceの仮想IP (ClusterIP) 用のCIDRが設定されていること
- default Vpcのdefault Subnetに、Node数分の予備アドレスが残っていること (Nodeごとに1つずつ共有Service用のソースNATアドレスが払い出されます)

## 手順

### 1. backend Deploymentをdefault Vpcに作成

backendのnginxを2レプリカで`default` Subnetに配置します (annotation不要、default Vpcに所属)。

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
```

### 2. 共有Serviceを作成

ServiceにはVpcのannotation (省略するとdefault Vpc所属)と、共有Serviceとして公開することを示す`juneau.loutres.me/shared-service: "true"` annotationを付けます。共有Service annotationを付けられるのは、default Vpcに属するServiceだけです。

```yaml
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

```console
$ kubectl get service nginx
NAME    TYPE        CLUSTER-IP      EXTERNAL-IP   PORT(S)   AGE
nginx   ClusterIP   10.96.123.45    <none>        80/TCP    5s
```

`shared-service` annotationを付けずに作成したdefault Vpc所属のServiceは、これまで通りdefault Vpc内のPodからのみ到達できます。

### 3. caller側のVpc/Subnetを作成

共有Serviceを利用するVpcには`spec.enableService: true`が必須です。

```yaml
apiVersion: juneau.loutres.me/v1alpha1
kind: Vpc
metadata:
  name: app-vpc
spec:
  enableService: true
---
apiVersion: juneau.loutres.me/v1alpha1
kind: Subnet
metadata:
  name: app-subnet
spec:
  vpc: app-vpc
  cidr: 10.80.0.0/24
```

詳細は[Vpc](../resources/vpc.md) / [Subnet](../resources/subnet.md)を参照してください。

### 4. 各NodeにServiceNATAttachmentが払い出されたことを確認

クラスタ内の各Nodeに対して、共有Serviceのソースとして使うアドレスが自動的に1つずつ払い出されます。Pod が共有ServiceのClusterIPに通信するとき、そのPodが配置されているNodeに対応するアドレスがソースIPとして利用されます。

```console
$ kubectl get servicenatattachment
NAME       NODE       ASSIGNEDIP    ASSIGNEDMAC          READY
worker-1   worker-1   10.16.0.200   02:00:0a:10:00:c8    True
worker-2   worker-2   10.16.0.201   02:00:0a:10:00:c9    True
```

すべてのNodeに対して`READY: True`、`ASSIGNEDIP`が埋まっていれば、共有Serviceのソースアドレスの払い出しは完了です。詳細は[ServiceNATAttachment](../resources/servicenatattachment.md)を参照してください。

### 5. 別Vpcにclient Podをデプロイ

`app-subnet`にcurl用のPodを配置します。

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

### 6. ClusterIPへの疎通を確認

別Vpcに居るclient PodからnginxのClusterIPに到達できることを確認します。

```console
$ kubectl exec curl -- curl -sS http://nginx.default.svc/
<!DOCTYPE html>
...
<h1>Welcome to nginx!</h1>
```

`app-vpc`のPodからdefault Vpcに置いたnginx Serviceに、共有Service経由で到達できています。

## うまくいかないとき

1. **Serviceのapplyが拒否される (`shared-service annotation is only valid on...`)**
    - `juneau.loutres.me/shared-service: "true"`が付いているServiceは、必ずdefault Vpcに所属している必要があります (`juneau.loutres.me/vpc` annotationを省略するか、`default`を指定)
2. **client PodからClusterIPに到達しない**
    - client Podを配置しているVpcの`spec.enableService`が`true`になっているか
    - 対象ServiceにAnnotation `juneau.loutres.me/shared-service: "true"`が付いているか、もしくはdefault namespaceの`kubernetes` Serviceか
    - `kubectl get servicenatattachment`で、各Nodeが`READY: True`になっているか
    - `kubectl get endpointslice -l kubernetes.io/service-name=nginx`でbackendのPod IPが登録されているか
3. **`kubectl get servicenatattachment`の`ASSIGNEDIP`が空のままのNodeがある**
    - default Subnetの`AddressPool`にIP在庫が残っているか (Node数より多くのIPが必要)
    - `READY: False`の場合は`status.conditions[?(@.type=="Ready")].message`を確認

## 参照

- [Vpc](../resources/vpc.md)
- [Subnet](../resources/subnet.md)
- [ServiceNATAttachment](../resources/servicenatattachment.md)
- [VPCでServiceを利用する](custom-vpc-service.md)
