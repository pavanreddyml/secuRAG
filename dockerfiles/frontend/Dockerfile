FROM node:20

WORKDIR /usr/src/app

COPY react react
RUN mv react/securagfrontend securagfrontend && rm -rf react

WORKDIR /usr/src/app/securagfrontend

RUN npm ci
RUN npm run build

EXPOSE 3000
CMD ["npm", "start"]
