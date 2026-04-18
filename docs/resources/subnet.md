# Subnet

`Subnet` は、`Vpc` の中に作るアドレス範囲であり、同時に論理的なネットワークセグメントでもあります。

Juneau では、Pod や NetworkInterface は `Subnet` に接続され、どの IPv4 アドレス帯を使うか、どの L2 セグメントに属するかを `Subnet` が表します。

## Vpc との関係

各 `Subnet` は、必ず 1 つの `Vpc` に属します。

1 つの `Vpc` には、複数の `Subnet` を作成できます。
つまり `Vpc` が大きな論理ネットワーク、`Subnet` がその中を分割した個別のアドレス範囲という関係です。

## default Subnet

`default` という名前の `Subnet` は、クラスタに最初から存在する特別な `Subnet` です。

`default` Subnet は必ず `default` Vpc に属します。
逆に、`default` Vpc を参照できるのも `default` Subnet だけです。

Pod 作成時に Vpc や Subnet を明示しない場合、Juneau はこの `default` Subnet を基準に通信先のネットワークを決めます。

## CIDR

`spec.cidr` には、その `Subnet` が管理する IPv4 アドレス範囲を指定します。

利用できるのは IPv4 CIDR だけです。
プレフィックス長は `/16` から `/28` までに制限されます。

## status の意味

`status.vni` は、その `Subnet` に割り当てられた VXLAN Network Identifier です。
Juneau はこれを使って、異なる `Subnet` 同士の L2 セグメントを識別します。

`status.gateway` は、その `Subnet` で利用するゲートウェイ IPv4 アドレスです。

`status.gatewayMAC` は、そのゲートウェイ IP に対応する MAC アドレスです。
Pod や NetworkInterface から見ると、この MAC アドレスを持つ相手がサブネットのデフォルトゲートウェイとして振る舞います。

## Ready

`Ready=True` は、その `Subnet` を Juneau が解釈でき、参照先の `Vpc` も利用可能で、必要な状態値（`vni` や `gateway` など）が揃っていることを意味します。

`Ready=False` のときは、削除中であるか、参照先 `Vpc` が存在しない、まだ Ready ではない、または `Subnet` 自身の計算に失敗している状態です。
