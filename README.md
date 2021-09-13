# dnspod-client
Dnspod client with c++, dynamically update domain name records when your public IP changes by get the current IP periodically. For example, I deploy it at my own Raspberry Pi 4.

### build

```
git clone https://github.com/maywine/dnspod-client.git

cd dnspod-client

git submodule init

git submodule update

mkdir build

cd build

cmake ../

make && make install
```

### usage

dnspod-client read config from json file:

```bash
dnspod  /your/config/path/config.json
```

run in the background:

```bash
setsid dnspod /your/config/path/config.json >> ~/log/dns_pod.log 2>&1 &
```

or use systemctl for management by create the **/etc/systemd/system/dnspod.service** file and enter the following:

```bash
[Unit]
Description=dnspod-client
After=network.target network-online.target nss-lookup.target

[Service]
Type=simple
StandardError=journal
User=nobody
ExecStart=/usr/local/bin/dnspod /usr/local/etc/dnspod-client/config.json
Restart=on-failure
RestartSec=15s

[Install]
WantedBy=multi-user.target
```

then start dnspod:

```bash
sudo systemctl enable dnspod.service
sudo systemctl start dnspod.service
```

### config format

a example config:

```json
{
    // you can get this at https://console.dnspod.cn/account/token
    "token": "123456,aaaaabbbbbcccccc", // dnspod api id and token

    // the domain info
    // you need add the domain record to dnspod firstly
    "domain_list":[
        {
            "domain": "domain.com", // domain name
            "sub_domain": "@" // http:://domain.com is @
                              // http:://www.domain.com is wwww
                              // http:://abc.domain.com is abc
        }
    ]
}
```
the default url to check what your public IP is is https://ifconfig.me/ip, equivalent to call with curl:

```bash
curl --http1.1 -X GET -L https://ifconfig.me/ip
```

you can set up the query url:

```json
{
    // you can get this at https://console.dnspod.cn/account/token
    "token": "123456,aaaaabbbbbcccccc", // dnspod api id and token: "$api_id,$api_token"

    // the domain info
    // you need add the domain record to dnspod firstly
    "domain_list":[
        {
            "domain": "domain.com", // domain name
            "sub_domain": "@" // http:://domain.com is @
                              // http:://www.domain.com is wwww
                              // http:://abc.domain.com is abc
        }
    ],

    // the query url info
    "query_ip_host": {
        "method": "GET", // http method
        "host": "ifconfig.me", // the host
        "port": 443, // port
        "path": "/ip" // url
    }
}
```

equivalent to call with curl:

```bash
curl --http1.1 -X GET -L https://ifconfig.me:443/ip
```

you can also use the traceroute command to get the public IP :
```json
{
    // you can get this at https://console.dnspod.cn/account/token
    "token": "123456,aaaaabbbbbcccccc", // dnspod api id and token: "$api_id,$api_token"

    // the domain info
    // you need add the domain record to dnspod firstly
    "domain_list":[
        {
            "domain": "domain.com", // domain name
            "sub_domain": "@" // http:://domain.com is @
                              // http:://www.domain.com is wwww
                              // http:://abc.domain.com is abc
        }
    ],

    // traceroute command
    "traceroute": {
        // you need to test this command at your host
        // You need to adjust the number '2' according to the actual situation 
        "cmd": "traceroute -m 2 www.baidu.com | awk '{if (NR>2){print $2}}'|cut -d ':' -f 2",
    }
}
```

Tip: may need to install the traceroute command firstly. 