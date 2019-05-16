dns_attackers
===


## Table of Contents

[TOC]

## Requirements



Usage
---

### DNS Amplification Attack 
```
python3 ...
```


### DNS Cache Poisoning
```
python3
```

User flows
---
```sequence
DNS server->Attacker: Hello Bob, how are you?
Note right of Attacker: Bob thinks
Attacker-->DNS server: I am good thanks!
Note left of DNS server: Alice responds
DNS server->Attacker: Where have you been?
DNS server->Victim: Where have you been?
```