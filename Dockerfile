FROM kevinwmatthews/docker-cmake:3.5.1-latest

RUN apt purge -y \
    libssl-dev \
    libssl1.0.0 \
    openssl

WORKDIR /tmp
#TODO why did this suddenly start failing? Source is no longer trusted.
# https://www.openssl.org/source/openssl-1.0.2h.tar.gz
RUN wget https://www.openssl.org/source/old/1.0.2/openssl-1.0.2h.tar.gz --no-check-certificate \
    && tar -xf openssl-1.0.2h.tar.gz

WORKDIR /tmp/openssl-1.0.2h
# --prefix      location of library objects, header files, and executables
# --openssldir  location of certs, keys, config files, and man files
# shared        build shared libraries, not just static
# threads       ?
RUN ./config --prefix=/usr --openssldir=/etc/ssl shared threads \
    && make -s depend \
    && make -s \
    && make test \
    && make install

WORKDIR /
RUN rm -r /tmp/openssl-1.0.2h

CMD ["bash"]
