# VpcプライベートDNSを使う

`app-dns-vpc`にnginxのPodを3つ作り、`backends.apps.internal.`で3つのPod IPを返します。DNSRecordはPodとNetworkInterfaceの現在の状態を追うため、Deploymentのscaleやrolling updateのあとも同じ名前を使えます。

Vpcの`spec.service`は設定しません。独自DNSZoneの名前解決はServiceルーティングの有効、無効にかかわらず利用できます。この構成ではServiceもClusterIPも使わず、返されたPod IPへ直接接続します。

## 前提条件

- Juneauのcontrollerとdaemonが動作しているクラスター
- `kubectl`を利用できること
- `10.80.0.0/24`をほかのSubnetで使っていないこと

## ネットワークとDNS

まず、Namespace、Vpc、Subnet、DNSZone、DNSRecordを作ります。次の内容を`vpc-private-dns-base.yaml`として保存してください。DNSZoneとDNSRecordはクラスタスコープです。それぞれの`metadata.name`は、同じkind内でクラスター全体を通して一意にします。

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: dns-demo
---
apiVersion: juneau.loutres.me/v1alpha1
kind: Vpc
metadata:
  name: app-dns-vpc
spec: {}
---
apiVersion: juneau.loutres.me/v1alpha1
kind: Subnet
metadata:
  name: app-dns-subnet
spec:
  vpc: app-dns-vpc
  cidr: 10.80.0.0/24
---
apiVersion: juneau.loutres.me/v1alpha1
kind: DNSZone
metadata:
  name: app-dns-zone
spec:
  vpc: app-dns-vpc
  domain: apps.internal
---
apiVersion: juneau.loutres.me/v1alpha1
kind: DNSRecord
metadata:
  name: app-dns-backends
spec:
  zone: app-dns-zone
  name: backends
  type: A
  ttl: 30
  sources:
    - podSelector:
        namespace: dns-demo
        interface: eth0
        selector:
          matchLabels:
            app: dns-backend
```

適用したら、SubnetがReadyになり、`status.dns`にDNS VIPが入るまで待ちます。

```console
$ kubectl apply -f vpc-private-dns-base.yaml
$ kubectl wait --for=condition=Ready subnet/app-dns-subnet --timeout=60s
$ kubectl wait --for=jsonpath='{.status.dns}' subnet/app-dns-subnet --timeout=60s
$ kubectl get subnet app-dns-subnet -o jsonpath='{.status.dns}{"\n"}'
10.80.0.2
$ kubectl wait --for=condition=Ready dnszone/app-dns-zone --timeout=60s
$ kubectl wait --for=condition=Ready dnsrecord/app-dns-backends --timeout=60s
```

この時点ではPodがないため、DNSRecordは`Ready=True`、`status.addresses`は空です。

JuneauはPodを作成するときだけ`dnsPolicy`と`dnsConfig`を書き換えます。`status.dns`が空のうちにPodを作ると、あとからDNS VIPが入っても既存Podの設定は変わりません。その場合はPodを作り直してください。

## ワークロード

DNS VIPを確認してからDeploymentとclient Podを作ります。次の内容を`vpc-private-dns-workloads.yaml`として保存してください。

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  namespace: dns-demo
  name: dns-backend
spec:
  replicas: 3
  selector:
    matchLabels:
      app: dns-backend
  template:
    metadata:
      labels:
        app: dns-backend
      annotations:
        juneau.loutres.me/subnet: app-dns-subnet
    spec:
      containers:
        - name: nginx
          image: nginx:1.27
          ports:
            - containerPort: 80
---
apiVersion: v1
kind: Pod
metadata:
  namespace: dns-demo
  name: dns-client
  annotations:
    juneau.loutres.me/subnet: app-dns-subnet
spec:
  containers:
    - name: client
      image: nicolaka/netshoot:v0.16
      command: ["sleep", "3600"]
```

```console
$ kubectl apply -f vpc-private-dns-workloads.yaml
$ kubectl rollout status deployment/dns-backend -n dns-demo
$ kubectl wait --for=condition=Ready pod/dns-client -n dns-demo --timeout=60s
$ until [ "$(kubectl get dnsrecord app-dns-backends \
    -o go-template='{{len .status.addresses}}')" = "3" ]; do sleep 1; done
```

## RRsetの確認

DNSRecordの`status.addresses`には、条件を満たした3つのPodのIPが入ります。

```console
$ kubectl get dnsrecord app-dns-backends \
    -o jsonpath='{range .status.addresses[*]}{.}{"\n"}{end}'
10.80.0.4
10.80.0.5
10.80.0.6
```

アドレスは出力例です。実際の値はPodへの割り当てによって変わります。

PodSelectorはlabelに加えてPodとNICの状態も確認します。選択されたPodが`Ready=True`かつ削除中でない場合、そのPodのUIDと`eth0`に一致する現在のNetworkInterfaceからアドレスを取ります。NetworkInterfaceも`Ready=True`で、`app-dns-vpc`に属していなければなりません。

`dns-client`からFQDNを問い合わせます。末尾の`.`まで付けると、検索ドメインの影響を受けません。

```console
$ kubectl exec -n dns-demo dns-client -- \
    dig +noall +answer backends.apps.internal. A
backends.apps.internal. 30 IN A 10.80.0.5
backends.apps.internal. 30 IN A 10.80.0.4
backends.apps.internal. 30 IN A 10.80.0.6
```

Juneauは応答を返すたびに3件をランダムに並べます。偶然、前回と同じ順番になることもあります。DNSの応答順を接続先の優先順位には使えません。

Juneauは`apps.internal`をPodの検索ドメインへ追加しないため、`backends`だけではこのDNSRecordを引けません。アプリケーションにも`backends.apps.internal.`という完全修飾名を設定します。

## scaleとrolling update

Deploymentのreplica数を2に減らすと、削除中のPodは対象から外れます。controllerの反映後、`status.addresses`とDNS応答は2件になります。次の`kubectl get`を繰り返し、アドレスが2件になったことを確認します。

```console
$ kubectl scale deployment/dns-backend -n dns-demo --replicas=2
$ kubectl rollout status deployment/dns-backend -n dns-demo
$ kubectl get dnsrecord app-dns-backends \
    -o jsonpath='{range .status.addresses[*]}{.}{"\n"}{end}'
10.80.0.4
10.80.0.5
```

replica数を3に戻す場合もDNSRecordは変更しません。`status.addresses`が3件に戻ってから問い合わせます。

```console
$ kubectl scale deployment/dns-backend -n dns-demo --replicas=3
$ kubectl rollout status deployment/dns-backend -n dns-demo
$ kubectl get dnsrecord app-dns-backends
$ kubectl exec -n dns-demo dns-client -- \
    dig +short backends.apps.internal. A
10.80.0.7
10.80.0.4
10.80.0.5
```

`kubectl rollout restart deployment/dns-backend -n dns-demo`でPodを入れ替えた場合も同じです。新しいPodはPodとNetworkInterfaceの両方がReadyになってから加わり、削除中のPodは外れます。rolling update中の件数はDeploymentの`maxSurge`や`maxUnavailable`によって増減しますが、完了後は現在の3つのPodへ収束します。DNSクライアントは古い応答を最大30秒キャッシュすることがあります。

## Vpcごとの応答

`app-dns-zone`を利用できるのは`app-dns-vpc`のPodだけです。別VpcのPodから同じFQDNを問い合わせても、このZoneや3つのPod IPは使われません。

同じ`apps.internal`というドメインを別VpcのDNSZoneにも設定できます。その場合は問い合わせ元のVpcに属するZoneが選ばれるため、Vpcごとに異なる`backends.apps.internal.`を返せます。

## エラーの見分け方

名前が引けないときは、まずDNSRecordの`Ready`とreasonを確認します。

```console
$ kubectl get dnsrecord app-dns-backends
$ kubectl describe dnsrecord app-dns-backends
```

PodSelectorは、対応するNetworkInterfaceが存在しない候補、PodまたはNetworkInterfaceがReadyでない候補、Zoneと異なるVpcの候補を除外します。結果が0件でもDNSRecordは`Ready=True`のままで、問い合わせにはNODATAを返します。存在しない所有者名、たとえば`missing.apps.internal.`にはNXDOMAINを返します。一方、名前を直接指定したNetworkInterfaceまたはVpcEndpointが存在しないか別Vpcに属する場合や、アドレスが100件を超えた場合は、レコード全体が`Ready=False`となり、問い合わせはSERVFAILです。詳しいreasonは[DNSRecord](../resources/dnsrecord.md)を参照してください。

## 削除

DNSRecordがDNSZoneの削除を止め、DNSZoneがVpcの削除を止めます。この順番で片付けます。

```console
$ kubectl delete dnsrecord app-dns-backends
$ kubectl delete dnszone app-dns-zone
$ kubectl delete namespace dns-demo
$ kubectl delete subnet app-dns-subnet
$ kubectl delete vpc app-dns-vpc
```
