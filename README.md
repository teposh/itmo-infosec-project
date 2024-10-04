# itmo-infosec-project

This is an example of using ebpf for effective dns ddos mitigation.

The main idea from [Fair-share Rate limiting in BPF](https://lpc.events/event/7/contributions/677/attachments/570/1006/LPC_2020__Fair-share_Rate_Limiting_in_BPF.pdf "Fair-share Rate limiting in BPF") (Cloudflare).

## Install dependencies

For Fedora 40:

```
sudo dnf install clang-18.1.8-1.fc40 libbpf-devel-2:1.2.3-1.fc40
```

## Testing

```
cd itmo-infosec-project
make
./bootstrap interfaces
# at this point you can make any amount of queries
./bootstrap query
./bootstrap on
# and now you can make only 10 req/min
./bootstrap q
```

## Schema

![alt](https://github.com/teposh/itmo-infosec-project/blob/assets/images/schema.png?raw=true)

## References

* https://habr.com/p/683566
* https://habr.com/p/529316
* https://habr.com/p/473286
