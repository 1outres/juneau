# Getting Started

## Requirements

- Kubernetes 1.32以降
- eBPF (TC / XDP) をサポートするLinuxカーネル、およびcgroup v2
- クラスターにCNIが無効化されていること

## Preparation

### kubeadm

```console
$ sudo kubeadm init --pod-network-cidr=10.16.0.0/16
```

### k3s

```console
$ curl -sfL https://get.k3s.io | sh -s - \
    --flannel-backend=none \
    --disable-network-policy \
    --disable=servicelb \
    --cluster-cidr=10.16.0.0/16
```

## Installation

```console
$ curl -LO https://github.com/1outres/juneau/releases/download/latest/install.yaml
```

Pod CIDRに`10.16.0.0/16`以外を使う場合は、controller Deploymentのargsに `--default-subnet-cidr` を追加します。

```yaml
    spec:
      containers:
        - name: manager
          args:
            - --leader-elect
            - --health-probe-bind-address=:8081
            - --default-subnet-cidr=10.24.0.0/16
```

```console
$ kubectl apply -f install.yaml
```

