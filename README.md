# IPIP Direct (Not Supported)

## Description
An [XDP](https://en.wikipedia.org/wiki/Express_Data_Path) program I made in C that is supposed to attach to the main interface of a machine and capture outgoing IPIP packets from an IPIP tunnel. The program removes the outer IP header and changes the main IP header's source address to the forwarding server's IP (outer IP header's destination address). This would result in packets being sent back to the client directly instead of going back through the forwarding server. Unfortunately, after making the program, I learned that XDP doesn't support the TX path/outgoing packets. However, I wanted to release this code anyways in case support does get implemented.

**Warning** - As I said above, this program doesn't work at the moment. I am releasing the code in case XDP supports the TX path in the future. I am probably going to have to learn [DPDK](https://www.dpdk.org/) to achieve what I initially wanted with fast packet processing.

## Usage
Here's its current usage:

```
./IPIPDirect_loader <Interface>
```

Example:

```
./IPIPDirect_loader ens18
```

## Credits
* [Christian Deacon](https://www.linkedin.com/in/christian-deacon-902042186/) - Creator
* [Dreae](https://github.com/dreae) - Checksum file.