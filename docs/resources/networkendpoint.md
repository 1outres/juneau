# NetworkEndpoint

NetworkEndpointは、daemonやCNIがPod側の接続事実を書き込むためのリソースです。

通常はユーザーが直接作成するものではありません。

## NetworkInterfaceとの関係

NetworkInterfaceは、Podに必要な論理NICの要求と割り当て状態を表します。

それに対してNetworkEndpointは、実際にノード上で接続が作られた際に作成され、MACアドレスなどの接続情報を表します。

そのため、NetworkInterfaceがReadyになるには、対応するNetworkEndpointが作成されている必要があります。

## 接続先

`spec.subnet`、`spec.l2Network`、`spec.externalNetwork`は、そのエンドポイントがどのセグメントにいるかを表します。3つのうちちょうど1つが入ります。

| NetworkInterfaceの接続先 | NetworkEndpointに入るもの |
|---|---|
| `spec.subnet` | 同じ名前の`spec.subnet` |
| `spec.l2Network` | 同じ名前の`spec.l2Network` |
| `spec.elasticIP` | そのElasticIPの`spec.externalNetwork`を`spec.externalNetwork`に |

`spec.externalNetwork`は、ElasticIPを直接持つPodのNICのためのフィールドです。`spec.kind`が`Pod`のときだけ書くことができ、作成後は変更できません。`spec.address`には`<ElasticIPのアドレス>/32`が入ります。

データプレーンは、このエンドポイントをExternalNetworkの`status.networkID`をVNIとするセグメントの一員として扱います。Podと別のNodeにパケットが届いたときは、そのVNIでVXLANに載せてPodのNodeへ運びます。

CNIはElasticIPをdaemonのキャッシュから読んで`spec.externalNetwork`を決めます。まだキャッシュに無いときはエラーを返し、kubeletがCNI ADDをやり直します。

```console
$ kubectl get networkendpoint
NAME      KIND   NODE       SUBNET    L2NETWORK   EXTERNALNETWORK   ADDRESS
gw.eth0   Pod    worker-2   default                                 10.16.0.9/16
gw.eth1   Pod    worker-2                         ext-net           10.225.51.6/32
```
