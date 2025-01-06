# Sonarqube Setup

1. Install Prerequisites
Ensure you have Java (11 or later), Git, and a database like PostgreSQL installed:

```bash
sudo apt update
sudo apt install -y openjdk-17-jdk wget unzip git postgresql postgresql-contrib
```

2. Update JAVA_HOME: Set the JAVA_HOME environment variable to point to Java 17. Add the following lines to the .bashrc file for the sonar user:
```bash
Copy code
export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
export PATH=$JAVA_HOME/bin:$PATH
```
3. Apply the changes:
```bash
source ~/.bashrc
```

4. In my fresh installation I came across the following error *vm.max_map_count [65530] is too low, increase to at least [262144]* so go ahead and set the following in `/etc/sysctl.conf`:
```bash
vm.max_map_count=262144
```
Additional Notes:
The vm.max_map_count setting controls the maximum number of memory map areas a process can have, which is critical for Elasticsearch.
If you're running SonarQube in a containerized environment (e.g., Docker), you may need to apply the setting on the host system.

5. Reload System Configuration: Apply the change permanently without rebooting:
```bash
```bash
sudo sysctl -p
```

6. Set Up PostgreSQL (Database for SonarQube)
Create a SonarQube database and user:

```bash
sudo -u postgres psql
```

7. Run the following SQL commands:
```sql
Copy code
CREATE DATABASE sonarqube;
CREATE USER sonar WITH ENCRYPTED PASSWORD 'sonarpassword';
GRANT ALL PRIVILEGES ON DATABASE sonarqube TO sonar;
\q
```

8. Download SonarQube:
```bash
wget https://binaries.sonarsource.com/Distribution/sonarqube/sonarqube-<version>.zip
```

9. Replace <version> with the latest version from SonarQube Downloads.

10. Extract and move the files:
```bash
unzip sonarqube-<version>.zip
sudo mv sonarqube-<version> /opt/sonarqube
```

11. Set up permissions:
```bash
sudo groupadd sonar
sudo useradd -d /opt/sonarqube -g sonar sonar
sudo chown -R sonar:sonar /opt/sonarqube
```

12. Edit /opt/sonarqube/conf/sonar.properties and configure the PostgreSQL settings:
```properties
sonar.jdbc.username=sonar
sonar.jdbc.password=sonarpassword
sonar.jdbc.url=jdbc:postgresql://localhost:5432/sonarqube
```

13. Start the SonarQube service:
```bash
sudo su sonar
/opt/sonarqube/bin/linux-x86-64/sonar.sh start
Access SonarQube at http://localhost:9000 in your browser. Default credentials are admin / admin.
```

14. Download SonarScanner:
```bash
wget https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-<version>-linux.zip
```

15. Extract and move:
```bash
unzip sonar-scanner-cli-<version>-linux.zip
sudo mv sonar-scanner-<version>-linux /opt/sonar-scanner
```

16. Update the PATH:
```bash
Copy code
echo "export PATH=/opt/sonar-scanner/bin:\$PATH" >> ~/.bashrc
source ~/.bashrc
```

17. Create a sonar-project.properties file in your project directory:
```properties
sonar.projectKey=your-project-key
sonar.projectName=Your Project Name
sonar.projectVersion=1.0
sonar.sources=.
sonar.host.url=http://localhost:9000
sonar.login=your-sonarqube-token
```

18. Generate a token from SonarQube under Administration > Security > Tokens.
```bash
sonar-scanner
```

19. View Results
Log in to the SonarQube UI (http://localhost:9000) to view the scan results.
Export results in desired formats using plugins like SonarQube PDF Plugin or via APIs.

20. Automate Reports (Optional)
You can use SonarQube's API to extract results in JSON format:
```bash
curl -u your-sonarqube-token: "http://localhost:9000/api/issues/search?componentKeys=your-project-key"
```