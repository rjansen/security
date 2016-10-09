FROM centos:centos7
MAINTAINER Raphael Jansen <raphael.jansen@gmail.com>

RUN mkdir -p /opt/security
#RUN mkdir -p /etc/security

ADD security /opt/security/security
ADD security.yaml /opt/security/security.yaml
EXPOSE 7080

ENTRYPOINT tail -f /dev/null
#ENTRYPOINT /opt/security/security -conf /opt/security/security.yaml > /opt/security/security.log 2>&1

#CMD ["/etc/security/security -conf /etc/security/security.yaml > /opt/security/security.log 2>&1"]
#CMD ["tail -f /dev/null"]