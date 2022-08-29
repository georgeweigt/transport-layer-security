The following demo program uses bespoke https to get a web page.

To build and run

```
cd src
make
./demo google.com
```

Demo output

```
hostname google.com
host ip 142.250.72.174
ssl ready (client side)
GET / HTTP/1.0
Host: google.com

HTTP/1.0 301 Moved Permanently
Location: https://www.google.com/
Content-Type: text/html; charset=UTF-8
Date: Sun, 28 Aug 2022 20:14:44 GMT
Expires: Tue, 27 Sep 2022 20:14:44 GMT
Cache-Control: public, max-age=2592000
Server: gws
Content-Length: 220
X-XSS-Protection: 0
X-Frame-Options: SAMEORIGIN
Alt-Svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000,h3-Q050=":443"; ma=2592000,h3-Q046=":443"; ma=2592000,h3-Q043=":443"; ma=2592000,quic=":443"; ma=2592000; v="46,43"

<HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">
<TITLE>301 Moved</TITLE></HEAD><BODY>
<H1>301 Moved</H1>
The document has moved
<A HREF="https://www.google.com/">here</A>.
</BODY></HTML>
POLLHUP
ssl_disconnect (half_close) from line 26
ssl_malloc_count 0
```

To run a self test

```
./demo selftest
```
