FROM wordpress:4.9.8-apache
ENV WORDPRESS_DB_PASSWORD=weakpassword

FROM ghcr.io/zaproxy/zaproxy:stable
