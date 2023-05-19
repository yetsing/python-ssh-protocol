FROM ubuntu:20.04
ENV TZ=Asia/Shanghai

RUN apt-get update && \
    apt-get -o Dpkg::Options::='--force-confnew' -y dist-upgrade && \
    DEBIAN_FRONTEND=noninteractive apt-get -y install openssh-server && \
    apt-get clean

RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone
RUN dpkg-reconfigure --frontend noninteractive tzdata

RUN useradd -rm -s /bin/bash -g root -G sudo -u 1000 test

RUN  echo 'test:test' | chpasswd

RUN service ssh start

CMD ["/usr/sbin/sshd","-D"]