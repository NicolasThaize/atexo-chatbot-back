To start 
```docker compose up -d```

To disable SSL (for development only), inside the keyclaok container 

1. ```cd /opt/keycloak/bin```
2. ```./kcadm.sh config credentials --server http://localhost:7080 --realm master --user admin```
3. ```./kcadm.sh update realms/master -s sslRequired=NONE```
