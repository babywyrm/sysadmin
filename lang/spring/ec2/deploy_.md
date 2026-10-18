### name: AWS EC2 Deployment
### 
 
# Trigger deployment only on push to main branch
on:
  push:
    branches:
      - main
 
env:
  JAR_FILE: web-service-0.0.1-SNAPSHOT.jar
 
jobs:
  build:
    name: Build and Upload
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Set up JDK 17
        uses: actions/setup-java@v3
        with:
          java-version: '17'
          distribution: 'temurin'
 
      - name: Build with Maven
        run: mvn clean package
 
      - name: Upload to remote with SCP
        uses: appleboy/scp-action@master
        with:
          USERNAME: ${{ secrets.USERNAME }}
          HOST: ${{ secrets.HOST_DNS }}
          KEY: ${{ secrets.EC2_SSH_KEY }}
          source: './target/web-service-0.0.1-SNAPSHOT.jar'
          target: '~/'
          overwrite: true
 
  clean:
    name: Terminate Web Service on EC2
    continue-on-error: true
    runs-on: ubuntu-latest
    needs: build
 
    steps:
      - name: Checkout code
        uses: actions/checkout@v2
 
      - name: Install SSH
        run: sudo apt-get update && sudo apt-get install openssh-client -y
 
      - name: Copy SSH key
        uses: webfactory/ssh-agent@v0.5.0
        with:
          ssh-private-key: ${{ secrets.EC2_SSH_KEY }}
 
      - name: SSH into EC2 instance and kill the web service app
        run: |
          ssh -o StrictHostKeyChecking=no -f -i ~/.ssh/id_rsa ec2-user@${{ secrets.HOST_DNS }} "nohup killall java &"
 
  deploy:
    name: Start the Web Service on EC2
    runs-on: ubuntu-latest
    needs: [ build, clean ]
 
    steps:
      - name: Checkout code
        uses: actions/checkout@v2
 
      - name: Install SSH
        run: sudo apt-get update && sudo apt-get install openssh-client -y
 
      - name: Copy SSH key
        uses: webfactory/ssh-agent@v0.5.0
        with:
          ssh-private-key: ${{ secrets.EC2_SSH_KEY }}
 
      - name: SSH into EC2 instance and start Spring Boot app
        run: |
          ssh -o StrictHostKeyChecking=no -f -i ~/.ssh/id_rsa ec2-user@${{ secrets.HOST_DNS }} "nohup java -jar target/$JAR_FILE &"
