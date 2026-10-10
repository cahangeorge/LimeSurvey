# Keep the official Nginx runtime and entrypoint; patch only affected APKs.
FROM nginx:1.30.5-alpine3.24@sha256:0985e772fb9f729e6fa0980da05fca5d9c468e870eed43071545afa9d2e27d94

RUN apk add --no-cache --upgrade \
        libexpat=2.8.5-r0 \
        libpng=1.6.59-r0 \
        pcre2=10.49-r0 \
        tiff=4.7.2-r0
