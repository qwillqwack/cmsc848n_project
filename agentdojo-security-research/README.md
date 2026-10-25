# agentdojo-security-research

## Overview
This project focuses on enhancing the security of AI agents against indirect prompt injection attacks. It is structured into three main workstreams: measurement, defense, and attack. Each workstream operates independently but contributes to the overall goal of improving agent security.

## Project Structure
The project is organized into the following directories and files:

- **harness/**: Contains the core logic for running experiments and tracking provenance data.
  - `__init__.py`: Initializes the harness module.
  - `runner.py`: Main logic for executing tasks.
  - `provenance.py`: Handles provenance data tracking.

- **defense/**: Implements various defense mechanisms against attacks.
  - `__init__.py`: Initializes the defense module.
  - `rules.py`: Implements rule-based defenses.
  - `classifier.py`: Contains the intent classifier implementation.
  - `hybrid.py`: Combines rule-based and classifier approaches.

- **attacks/**: Implements different attack strategies against the defenses.
  - `__init__.py`: Initializes the attacks module.
  - `adaptive_search.py`: Implements adaptive search attacks.
  - `binding_steering.py`: Contains logic for binding-steering attacks.

- **tests/**: Contains unit tests for each module to ensure functionality.
  - `test_harness.py`: Tests for the harness module.
  - `test_defense.py`: Tests for the defense module.
  - `test_attacks.py`: Tests for the attacks module.

- **results/**: Directory for storing results of experiments (tracked by Git with `.gitkeep`).

- **Dockerfile**: Contains instructions for building the Docker image for the project.

- **requirements.txt**: Lists the Python dependencies required for the project.

- **.gitignore**: Specifies files and directories to be ignored by Git.

## Setup Instructions
1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd agentdojo-security-research
   ```

2. **Build the Docker image**:
   ```bash
   docker build -t agentdojo-security-research .
   ```

3. **Run the Docker container**:
   ```bash
   docker run -it agentdojo-security-research
   ```

## Usage
After running the Docker container, the main application can be executed using the following command:
```bash
python3 harness/runner.py
```

## Contribution
Contributions to this project are welcome. Please fork the repository and submit a pull request for any changes or improvements.

## License
This project is licensed under the MIT License. See the LICENSE file for more details.