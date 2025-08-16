FROM nginx:stable-alpine

RUN rm /etc/nginx/conf.d/default.conf

COPY ./myapp.conf /etc/nginx/conf.d/default.conf 

COPY ./frontend /var/www/nginxapp/frontend

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]

