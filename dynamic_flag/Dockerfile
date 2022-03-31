FROM debian:11
RUN apt update && apt -y upgrade && \
    apt install -y python3-openssl docker.io wget && \
    cd /tmp && \
    wget -q 'https://github.com/yangzhaofeng/openssh-acceptall/releases/download/1%258.4p1-5%2Ball11u1/openssh-server_8.4p1-5+all11u1_amd64.deb' && \
    wget -q 'https://github.com/yangzhaofeng/openssh-acceptall/releases/download/1%258.4p1-5%2Ball11u1/openssh-sftp-server_8.4p1-5+all11u1_amd64.deb' && \
    wget -q 'https://github.com/yangzhaofeng/openssh-acceptall/releases/download/1%258.4p1-5%2Ball11u1/openssh-client_8.4p1-5+all11u1_amd64.deb' && \
    apt install -y ./openssh-server_8.4p1-5+all11u1_amd64.deb ./openssh-sftp-server_8.4p1-5+all11u1_amd64.deb ./openssh-client_8.4p1-5+all11u1_amd64.deb && \
    apt remove --purge -y wget && \
    apt autoremove --purge -y && \
    rm -rf openssh-server_8.4p1-5+all11u1_amd64.deb openssh-sftp-server_8.4p1-5+all11u1_amd64.deb openssh-client_8.4p1-5+all11u1_amd64.deb && \
    rm -rf /var/lib/apt/lists/* && \
    passwd -d root
COPY front.py /
COPY cert.pem /
CMD ["/usr/sbin/sshd", "-D", "-p", "2333", "-o", "environment=port=${port} conn_interval=${conn_interval} token_timeout=${token_timeout} challenge_timeout=${challenge_timeout} pids_limit=${pids_limit} cpus_limit=${cpus_limit} mem_limit=${mem_limit} challenge_docker_name=${challenge_docker_name}"]
