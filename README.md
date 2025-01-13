# Master's Capstone

## Title: Development of a Secure Code Analysis Framework Leveraging Radeon Open Compute (ROCm) and Advanced Machine Learning Models

## Abstract

This project presents the design and implementation of a secure code analysis framework optimized for a ROCm (Radeon Open Compute) system utilizing an AMD 7900XTX GPU. The framework integrates static analysis tools—Bandit, Dodgy and Semgrep—with machine learning models, including CodeBERT and Llama, to detect and mitigate vulnerabilities in Python codebases. I detail the system architecture, implementation specifics and the integration of notable dependencies such as PyTorch and Transformers. My evaluation demonstrates the framework's effectiveness in identifying security flaws, thereby enhancing code security in high-performance computing environments.

## Table of Contents

1. [Introduction](#1-introduction)
2. [Background and Related Work](#2-background-and-related-work)
   - 2.1 [Static Code Analysis Tools](#21-static-code-analysis-tools)
   - 2.2 [Machine Learning Models for Code Analysis](#22-machine-learning-models-for-code-analysis)
   - 2.3 [ROCm and GPU-Accelerated Computing](#23-rocm-and-gpu-accelerated-computing)
3. [System Architecture](#3-system-architecture)
   - 3.1 [Hardware and Software Environment](#31-hardware-and-software-environment)
   - 3.2 [Integration of Static Analysis Tools](#32-integration-of-static-analysis-tools)
   - 3.3 [Machine Learning Model Deployment](#33-machine-learning-model-deployment)
4. [Implementation Details](#4-implementation-details)
   - 4.1 [Code Analysis Workflow](#41-code-analysis-workflow)
   - 4.2 [GPU Offloading Strategies](#42-gpu-offloading-strategies)
   - 4.3 [Dependency Management](#43-dependency-management)
5. [Evaluation and Results](#5-evaluation-and-results)
   - 5.1 [Performance Metrics](#51-performance-metrics)
   - 5.2 [Security Vulnerability Detection](#52-security-vulnerability-detection)
   - 5.3 [Case Studies](#53-case-studies)
6. [Conclusion and Future Work](#6-conclusion-and-future-work)
7. [References](#references)

## 1. Introduction

In the realm of software development, ensuring code security is paramount. With the increasing complexity of codebases, traditional manual code reviews are becoming insufficient. This dissertation introduces a framework that combines static code analysis tools with machine learning models to automate and enhance the detection of security vulnerabilities in Python projects. Leveraging the computational capabilities of a ROCm system equipped with an AMD 7900XTX GPU, the framework aims to provide efficient and accurate code analysis.

## 2. Background and Related Work

### 2.1 Static Code Analysis Tools

Static code analysis is a method of evaluating source code without executing it, aiming to identify potential vulnerabilities and ensure code quality. Tools such as Bandit, Dodgy and Semgrep are instrumental in this process, each offering unique capabilities that, when combined, provide a comprehensive security assessment.

- `Bandit`:
Bandit is a security linter designed specifically for Python. It examines Abstract Syntax Trees (ASTs) to detect common security issues, such as the use of insecure functions or modules. By scanning Python codebases, Bandit identifies vulnerabilities like hardcoded passwords, weak cryptographic practices and improper exception handling. Its integration into continuous integration pipelines facilitates automated security checks, promoting the development of secure Python applications.[Github Bandit](https://github.com/PyCQA/bandit)

- `Dodgy`
Dodgy is a straightforward tool that searches codebases for "dodgy" values using simple regular expressions. It focuses on detecting potentially dangerous functions, hardcoded secrets and weak cryptographic practices. By identifying these risky elements, Dodgy helps developers eliminate insecure coding patterns that could lead to vulnerabilities.[Github Dodgy](https://github.com/prospector-dev/dodgy)

- `Semgrep`
Semgrep is a versatile static analysis tool that supports multiple programming languages. It allows developers to write custom rules to detect code patterns, enabling the identification of complex security vulnerabilities and enforcement of coding standards. Semgrep's pattern-matching capabilities make it effective in finding issues that may be overlooked by other tools and its support for various languages makes it suitable for diverse codebases.[URL](https://github.com/semgrep/semgrep)
  - `p/default`: This is Semgrep's standard ruleset, encompassing a broad range of general-purpose rules designed to identify common security issues and code quality concerns across various programming languages.[Application Security Guide](https://appsec.guide/docs/static-analysis/semgrep/in-your-organization)
  - `p/owasp-top-ten`: This ruleset focuses on detecting vulnerabilities outlined in the OWASP Top Ten, which represents the most critical security risks to web applications. It includes rules to identify issues such as SQL injection, cross-site scripting (XSS) and insecure deserialization.[Semgrep OWASP Top Ten](https://semgrep.dev/solutions/owasp-top-ten)
  - `p/python`: Tailored specifically for Python codebases, this ruleset includes rules that detect security vulnerabilities, code quality issues and adherence to Pythonic conventions. It helps in identifying problems like the use of insecure functions, improper exception handling and other Python-specific concerns.[Semgrep Python Rules](https://github.com/semgrep/semgrep-rules/tree/develop/python)
  - `p/django`: When the codebase uses the Django framework, this ruleset is included to detect security issues and enforce best practices specific to Django applications. It identifies problems such as improper use of Django's ORM, security misconfigurations and other framework-specific concerns.[Semgrep Python Django Rules](https://github.com/semgrep/semgrep-rules/tree/develop/python/django)
  - `p/flask`: Similarly, for projects utilizing the Flask framework, this ruleset is added to detect vulnerabilities and enforce best practices pertinent to Flask applications. It focuses on issues like unsafe route definitions, improper input handling and other Flask-specific security concerns.[Semgrep Python Flask](https://github.com/semgrep/semgrep-rules/tree/develop/python/flask) 

Complementary Use of Bandit, Dodgy and Semgrep

While each tool independently enhances code security, their combined use offers a more robust analysis:

- Comprehensive Coverage: Bandit specializes in Python security issues, Dodgy focuses on detecting dangerous functions and hardcoded secrets and Semgrep provides flexible pattern-based scanning across multiple languages. Together, they cover a broader spectrum of potential vulnerabilities.

- Layered Analysis: Employing multiple tools ensures that different types of vulnerabilities are detected. For instance, while Bandit might identify insecure function usage, Dodgy can detect hardcoded secrets and Semgrep can enforce coding standards and detect complex patterns.

- Reduced False Positives: Cross-verifying findings from multiple tools can help in distinguishing true vulnerabilities from false positives, leading to more accurate and reliable results.

Incorporating Bandit, Dodgy and Semgrep into the development workflow enables developers to identify and address security concerns early, ensuring the delivery of secure and robust software applications.

### 2.2 Machine Learning Models for Code Analysis

Recent advancements in machine learning have led to models capable of understanding and analyzing code semantics:

- **CodeBERT**: A transformer-based model pre-trained on large code corpora, fine-tuned for tasks like vulnerability detection.

- **Llama**: A language model designed for efficient inference, suitable for generating code completions and detecting anomalies.

### 2.3 ROCm and GPU-Accelerated Computing

ROCm is an open-source platform for GPU-accelerated computing, providing tools and libraries for high-performance applications. The AMD 7900XTX GPU, with its substantial computational resources, facilitates the efficient execution of machine learning models and parallelizable tasks within the framework.

## 3. System Architecture

### 3.1 Hardware and Software Environment

The framework operates on a system configured with:

- **Hardware**: 
- Full System Specification [here](https://github.com/vampireLibrarianMonk/amd-gpu-hello) 

- **Software**:
  - ROCm 6.3.1
  - Python 3.10.6
  - PyTorch 2.4.0 with ROCm support
  - Torchvision 0.19.0 with ROCm support
  - Transformers 4.47.1
  - llama-cpp-python 0.3.1

### 3.2 Integration of Static Analysis Tools

The framework incorporates Bandit, Dodgy and Semgrep to perform comprehensive static analysis. Each tool scans the codebase, generating reports that highlight potential security issues. These reports are then aggregated for further processing.

### 3.3 Machine Learning Model Deployment

Machine learning models are employed to analyze code snippets for vulnerabilities:

- **CodeBERT**: Utilized for sequence classification to detect insecure code patterns.

- **Llama**: Deployed for code generation tasks, aiding in suggesting secure code implementations.

Both models are optimized to leverage GPU acceleration provided by the ROCm platform, ensuring efficient inference.

## 4. Implementation Details

### 4.1 Code Analysis Workflow

The workflow involves:

1. **Static Analysis**: Executing Bandit, Dodgy and Semgrep on the target codebase to identify potential vulnerabilities.

2. **Machine Learning Evaluation**: Analyzing code snippets using CodeBERT to classify them as secure or insecure.

3. **Report Generation**: Compiling findings into comprehensive reports, highlighting areas that require attention.

### 4.2 GPU Offloading Strategies

To maximize performance, the framework determines the optimal number of transformer layers to offload to the GPU. This is achieved by assessing the available GPU memory and the model's characteristics, ensuring efficient utilization of resources. Techniques such as interleaved offloading and overlapping computations with data transfers are employed to enhance training efficiency. [link](https://arxiv.org/html/2410.21316)

In the context of ROCm systems utilizing GPUs like the 7900XTX, it's crucial to consider the specific hardware capabilities and software dependencies. For instance, using optimized libraries and frameworks compatible with ROCm can significantly impact performance. Additionally, understanding the memory hierarchy and bandwidth limitations of the GPU can inform decisions on layer offloading strategies. Implementing efficient memory management techniques, such as those discussed in recent studies, can further enhance performance. [link](https://arxiv.org/abs/2406.10728)

By integrating these strategies, the framework ensures that the GPU's computational power is effectively harnessed, leading to improved performance and resource utilization during model training and inference.

### 4.3 Dependency Management
1. We’ll use the Mamba package manager to create the Python environment. You can learn more about it in my getting started tutorial.

The following bash commands will download the latest release, install it and relaunch the current bash shell to apply the relevant changes:
```bash
# Download the latest Miniforge3 installer for the current OS and architecture
wget "https://github.com/conda-forge/miniforge/releases/latest/download/Miniforge3-$(uname)-$(uname -m).sh"

# Run the Miniforge3 installer silently (-b flag for batch mode)
bash Miniforge3-$(uname)-$(uname -m).sh -b

# Initialize mamba for shell usage
~/miniforge3/bin/mamba init

# Restart the shell to apply changes
bash
```

2. Create a Python Environment in mamba

```bash
mamba env create -f environment.yml -y
mamba activate pytorch-rocm-capstone
```

### 5. Evaluation and Results

### 5.1 Performance Metrics

To assess mitigation capability, employ datasets with known vulnerabilities, such as the ones in section [5.2](#52-security-vulnerability-detection). Implement a script that mitigates identified vulnerabilities and dynamically generates test cases to manually validate the functionality of the original code. This approach ensures that the mitigated code maintains the intended behavior. If preserving the original functionality is not feasible due to security concerns, the script should provide comments explaining why the initial implementation was insecure and suggest alternative solutions. These alternatives may produce different outputs but will enhance the overall security posture of the codebase.

Monitoring the performance metrics of your Python scripts is essential for optimizing efficiency and resource management, especially when performing Large Language Model (LLM) inference using the llama_cpp library on AMD GPUs with the ROCm platform. Here's how you can measure CPU usage, RAM consumption and GPU memory utilization, of which [here](https://github.com/vampireLibrarianMonk/gpu-grafana-dashboard) is the repository to use to monitor these metrics for the AMD GPU Machine:

   - CPU Usage: Utilize the psutil library to monitor CPU utilization. The psutil.cpu_percent(interval=1) function returns the CPU usage percentage over a specified interval. By calling this function at regular intervals, you can track CPU usage throughout your script's execution.

   - RAM Consumption: The psutil library also provides capabilities to assess memory usage. The psutil.virtual_memory() function returns a named tuple containing information about system memory usage, including the percentage of RAM used. This allows you to monitor your script's memory footprint in real-time.

   - GPU Memory Utilization: For tracking GPU memory usage on AMD GPUs with ROCm, the pyrsmi library can be employed. This Python package provides bindings to the ROCm System Management Interface (SMI), allowing you to query various GPU metrics directly within your Python scripts. By integrating pyrsmi into your monitoring workflow, you can effectively track GPU resource consumption.

#### 5.1.1 Integrating LLM Inference with `llama_cpp` for specifically testing gpu metrics.

This [script](test_llm_w_metrics.py) demonstrates how to log CPU, RAM and GPU memory usage before and after performing LLM inference using the llama_cpp library, providing insights into resource consumption during the process.

### 5.2 Security Vulnerability Detection
Dataset Utilization: Review and piecemeal glean the following datasets containing Python files labeled with respective vulnerabilities:

   - [Intentionally Vulnerable Python Application](https://github.com/mukxl/Intentionally-Vulnerable-Python-Application):
   - [Vulnerability Detection](https://github.com/LauraWartschinski/VulnerabilityDetection): A collection of Python code snippets labeled for various vulnerabilities. 
   - [Python_Vulnerable_Code](https://github.com/Vulnerable-Code-Samples/Python_Vulnerable_Code): A small collection of vulnerable Python code snippets categorized by vulnerability type. 
   - [AEGIS](https://github.com/Abdechakour-Mc/AEGIS): A transformer-based Python vulnerability detection model accompanied by a curated dataset from real-world code and synthetic examples.
   - [Function-level-Vulnerability-Dataset](https://github.com/Seahymn2019/Function-level-Vulnerability-Dataset): Labeled vulnerable functions for statistical analysis and neural network training.

### 5.3 Case Studies
Real-World Application: Apply your detection and mitigation scripts to real-world Python projects. Document specific instances where vulnerabilities were successfully identified and mitigated, demonstrating practical effectiveness.

Before-and-After Analysis: Present code snippets showcasing vulnerabilities before and after mitigation by your scripts. Highlight the improvements and discuss any challenges encountered during the process.

This structured evaluation will provide a comprehensive understanding of your system's performance, reliability and practical applicability in detecting and mitigating security vulnerabilities in Python codebases.

# Scanner Setup

## Bandit, Dodgy and Semgrep
Note this are already setup for you via the envrionment.yml.

## Sonarqube Setup

1. Install Prerequisites
Ensure you have Java (11 or later), Git and a database like PostgreSQL installed:

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

8. Download [SonarQube](https://binaries.sonarsource.com/?prefix=Distribution/sonarqube/):

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

14. Download [SonarScanner](https://binaries.sonarsource.com/?prefix=Distribution/sonar-scanner-cli/):

15. Extract and move:
```bash
unzip sonar-scanner-cli-<version>-linux.zip
sudo mv sonar-scanner-<version>-linux /opt/sonar-scanner
```

16. Update the PATH:
```bash
echo "export PATH=/opt/sonar-scanner/bin:\$PATH" >> ~/.bashrc
source ~/.bashrc
```

17. Create a `sonar-project.properties` file in your project directory:
```properties
sonar.projectKey=your-project-key
sonar.projectName=Your Project Name
sonar.projectVersion=1.0
sonar.sources=.
sonar.host.url=http://localhost:9000
sonar.login=your-sonarqube-token
```

18. Generate a token from SonarQube under Administration > Security > Tokens.

19. Run Sonar Scanner
```bash
sonar-scanner
```

20. View Results
Log in to the SonarQube UI (http://localhost:9000) to view the scan results.
Export results in desired formats using plugins like SonarQube PDF Plugin or via APIs.

21. Automate Reports (Optional)
You can use SonarQube's API to extract results in JSON format:
```bash
curl -u your-sonarqube-token: "http://localhost:9000/api/issues/search?componentKeys=your-project-key"
```