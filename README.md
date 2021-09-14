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
    "dnspod_token": "123456,aaaaabbbbbcccccc", // dnspod api id and token: "$api_id,$api_token"

    // the domain info
    // you need add the domain record to dnspod firstly
    "domain_list":[
        {
            "domain": "domain.com", // domain name
            "sub_domain": "@", // http:://domain.com is @
                               // http:://www.domain.com is wwww
                               // http:://abc.domain.com is abc
            "ttl": 600 // option
        }
    ],

    // the query url info
    "query_self_request": {
        "method": "GET", // http method
        "host": "ifconfig.me", // the host
        "port": 443, // port
        "path": "/ip", // url
        "body": "" // optional body
    },

    // query interval, default 10 second
    "query_self_interval": 10
}
```

equivalent to call with curl:

```bash
curl --http1.1 -X GET -L https://ifconfig.me:443/ip
```

you can also use command to get the public IP :
```json
{
    // you can get this at https://console.dnspod.cn/account/token
    "dnspod_token": "123456,aaaaabbbbbcccccc", // dnspod api id and token: "$api_id,$api_token"

    // the domain info
    // you need add the domain record to dnspod firstly
    "domain_list":[
        {
            "domain": "domain.com", // domain name
            "sub_domain": "@", // http:://domain.com is @
                               // http:://www.domain.com is wwww
                               // http:://abc.domain.com is abc
            "ttl": 600 // optional ttl
        }
    ],

    // command
    "query_self_cmd": "curl -s -X GET -L https://1.1.1.1/cdn-cgi/trace | awk -F '=' '{if (NR==3){print $2}}'",

    // query interval, default 10 second
    "query_self_interval": 10
}
```