# intercept

## Name

*intercept* - Query interception plugin.

## Description

The intercept plugin intercepts queries and returns predefined
responses for specific clients

## Syntax

~~~
intercept [ZONE...] {
    record TTL CLASS RR-TYPE ANSWER... [net NETWORK...]
}
~~~

- **ZONE** zones it should be authoritative for. If empty, the zones from the configuration block are used.
- **TTL** sets the DNS TTL of the answers generated
- **CLASS** the query class (usually IN or ANY).
- **RR-TYPE** the query type (A, PTR, ... can be ANY to match all types). "*" stands for all record types.
- **ANSWER** the answers to return, multiple answers allowed
- **NETWORK** is the source IP address to match for the requests to be intercepted. Typical CIDR notation and single IP address are supported. "*" stands for all possible source IP addresses.

## Examples

~~~ corefile
. {
    intercept a.example.org {
        record 3600 IN * 127.0.0.2 net 192.168.1.0/24
    }
}
~~~
