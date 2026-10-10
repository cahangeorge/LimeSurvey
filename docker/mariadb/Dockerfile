# Only gosu is replaced; the official MariaDB runtime contract is inherited.
FROM golang:1.27.2-alpine3.24@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS gosu
ENV GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=linux GOARCH=arm64
WORKDIR /src
RUN wget -q -O /tmp/gosu.tar.gz https://codeload.github.com/tianon/gosu/tar.gz/6456aaa0f3c854d199d0f037f068eb97515b7513 \
 && echo '33d7537d588ea49458b9509bcf4554bdf5ceacc66da71e5caa1058ea3b689c3b  /tmp/gosu.tar.gz' | sha256sum -c - \
 && tar -xzf /tmp/gosu.tar.gz --strip-components=1 -C /src \
 && printf '%s\n' 'module github.com/tianon/gosu' 'go 1.26.0' 'require (' 'github.com/moby/sys/user v0.4.1' 'golang.org/x/sys v0.49.0' ')' > go.mod \
 && printf '%s\n' \
 'github.com/moby/sys/user v0.4.1 h1:RgjRlaDKi/Xmyrz4t8lyzXT6v2ooFeO/7xtchmhVWE0=' \
 'github.com/moby/sys/user v0.4.1/go.mod h1:E9QsW5WRe1kUAf7kW8hXKwu1uhsZEAdPLYHYSDudF4Y=' \
 'golang.org/x/sys v0.49.0 h1:XbzkgYJHdqh/8m2Uu0W/dQv8nktxx4BFHp1M0gROTXA=' \
 'golang.org/x/sys v0.49.0/go.mod h1:hNLxWAXmnKAxqDtdwIYC4bM9oQPEecfsnNMuSxOs3og=' > go.sum \
 && go mod download \
 && go build -trimpath -ldflags '-d -w' -buildvcs=false -mod=readonly -o /gosu .
FROM mariadb:11.4.13-noble@sha256:0130d92c05fbf2d82adc2b86de742eaede65b2596c65d91786f8e03cd19e6a39
COPY --from=gosu --chmod=0755 /gosu /usr/local/bin/gosu
