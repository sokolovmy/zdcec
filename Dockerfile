FROM alpine:latest

COPY requirements.txt  /requirements.txt

RUN apk --no-cache --clean-protected add mc vim zabbix-agent libressl-dev musl-dev libffi-dev py3-openssl && \
    sed -i 's/^Server=.*/Server=zabbix-server/' /etc/zabbix/zabbix_agentd.conf && \
    echo 'Include=/etc/zabbix/zabbix_agentd.d/*.conf' >> /etc/zabbix/zabbix_agentd.conf && \
    apk add python3 && apk add py3-pip && \
     mkdir /etc/zabbix/scripts && \
     mkdir /etc/zabbix/zabbix_agentd.d && \
     pip install pip --upgrade && \
     pip install -r /requirements.txt 

COPY etc/zabbix/scripts /etc/zabbix/scripts
COPY etc/zabbix/zabbix_agent.d /etc/zabbix/zabbix_agentd.d
#COPY tmp /tmp

CMD ["/usr/sbin/zabbix_agentd", "--foreground", "-c", "/etc/zabbix/zabbix_agentd.conf"]
# CMD ['/bin/sh']

