To build and run a demo

```
cd src
./make-cert-rsa
make
./demo google.com
```

Demo output with SSLTRACE disabled

```
hostname google.com
host ip 216.58.193.206
ssl ready (client side)
GET / HTTP/1.0
Host: google.com

HTTP/1.0 301 Moved Permanently
Location: https://www.google.com/
Content-Type: text/html; charset=UTF-8
Date: Thu, 26 Sep 2019 04:25:53 GMT
Expires: Sat, 26 Oct 2019 04:25:53 GMT
Cache-Control: public, max-age=2592000
Server: gws
Content-Length: 220
X-XSS-Protection: 0
X-Frame-Options: SAMEORIGIN
Alt-Svc: quic=":443"; ma=2592000; v="46,43",h3-Q046=":443"; ma=2592000,h3-Q043=":443"; ma=2592000

<HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">
<TITLE>301 Moved</TITLE></HEAD><BODY>
<H1>301 Moved</H1>
The document has moved
<A HREF="https://www.google.com/">here</A>.
</BODY></HTML>
POLLHUP
$ 
```
