# nftables-unmatched-logger

Log unmatched nftables packets

## Installation

1. Clone this repository:

   ```shell
   git clone 'https://github.com/fussel178/nftables-unmatched-logger.git'
   cd nftables-unmatched-logger
   ```

2. Build and install the package:

   ```shell
   makepkg -si
   ```

3. Install ulogd:

   ```shell
   sudo pacman -S ulogd
   ```

4. Enable plugins and configure logging stack in `/etc/ulogd.conf`:

   ```ini
   [global]
   logfile="/var/log/ulogd.log"
   loglevel=5
   rmem=131071
   bufsize=150000

   ##
   ## plugins
   ##

   # inputs
   plugin="/usr/lib/ulogd/ulogd_inppkt_NFLOG.so"
   plugin="/usr/lib/ulogd/ulogd_raw2packet_BASE.so"

   # filters
   plugin="/usr/lib/ulogd/ulogd_filter_IP2STR.so"
   plugin="/usr/lib/ulogd/ulogd_filter_HWHDR.so"
   plugin="/usr/lib/ulogd/ulogd_filter_IFINDEX.so"

   # outputs
   plugin="/usr/lib/ulogd/ulogd_output_JSON.so"

   # JSON to python stack
   #
   stack=log1:NFLOG,base1:BASE,ifi1:IFINDEX,ip2str1:IP2STR,mac2str1:HWHDR,json1:JSON

   ##
   ## part configurations
   ##

   [log1]
   group=1

   [json1]
   sync=1
   mode="unix"
   file="/run/nftables-unmatched-logger/ulog.sock"
   ```

5. Configure the log group in nftables:

   ```shell
   # after all commands in input chain
   nft add rule inet filter input log prefix "nft_in_unmtch" group 1 limit rate 3/second

6. Enable and start both systemd services:

   ```shell
   sudo systemctl enable --now nftables-unmatched-logger.service
   sudo systemctl enable --now ulogd.service
   ```

7. Finished!

## Query data

To query data via console, you can use the `sqlite3` command line interface:

```shell
sudo sqlite3 -column -header /var/lib/nftables-unmatched-logger/main.sqlite "
  SELECT ip_address,addresses.first_seen,addresses.last_seen,proto,port,name,count FROM calls 
    INNER JOIN addresses ON addresses.id = calls.address_id 
    INNER JOIN services ON services.id = calls.service_id 
    ORDER BY ip_address;
"
```
