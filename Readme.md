# RawSocket发包

## 使用方法
```shell
#./raw_tcp 
# Usage:
# ./raw_tcp <IF> <smac> <sip> <sport> <dmac> <dip> <dport>
# ./raw_tcp <IF> <smac> <sip> <sport> <dmac> <dip> <dport> <vlan>
```
### 示例
```shell
 ./raw tcp enp2s0f1 aa:bb:cc:dd:ee:ff 192.168.1.1 123456 ff:ee:dd:cc:bb:aa 192.168.1.2 80 4001
```