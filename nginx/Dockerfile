FROM nginx:alpine

RUN rm /etc/nginx/conf.d/default.conf

COPY ./nginx/myapp.conf /etc/nginx/conf.d/default.conf 

COPY ./nginx/frontend /var/www/nginxapp/frontend

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]

