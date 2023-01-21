Dockerfile - executing shell script file on Entrypoint

While creating auto deployment process, sometime it is needed that you will have to run bash shell script on Entrypoint or at starting point of container. Like you may need to execute multiple commands at start point of container which is not easy to do that. But fortunetly , you can add shell script file in Entrypoint and it will get executed.

Here is the example how you can run shell script from file on Entrypoint in dockerfile.

init.sh file
```

#!/bin/bash
npm install
npx prisma generate
npx start

```
Dockerfile

##########
```

FROM node:16-alpine3.11

ADD init.sh /usr/src/app/init.sh
USER root
RUN chmod +x /usr/src/app/init.sh
ENV PORT 5000
EXPOSE $PORT
ENTRYPOINT ["sh","/usr/src/app/init.sh"]

 ```
##
##
##
