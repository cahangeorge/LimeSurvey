# Keep the official Nginx runtime and entrypoint; patch only affected APKs.
FROM nginx:1.30.6-alpine3.24@sha256:47928bf67eb62a1863cb08d9ecb52d3e704304ba614eaee17884204677702951

RUN apk add --no-cache --upgrade \
        libexpat=2.9.0-r0 \
        libpng=1.6.59-r0 \
        libx11=1.8.14-r0 \
        musl-utils=1.2.6-r3 \
        pcre2=10.49-r0 \
        tiff=4.7.2-r0
