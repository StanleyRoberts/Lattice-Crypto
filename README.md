# README

This is the code for the project 'Implementing Lattice Based Cryptography' by Stanley Roberts


# Installation/Configuration

SageMath and Python3 needs to be installed on your machine. Please see
[ Sage Installation Guide v9.4](https://doc.sagemath.org/html/en/installation/) for details on installing SageMath.
Notebook files (.ipynb) can be opened using [Jupyter Notebook](https://jupyter.org/install) and Sage files (.sage)
can be run in the sage shell with `sage filename` and Python files (.py) can be run in the sage shell with `python filename`


## Files

 - [ ] **CLI**:
 Provides a basic interface for LWE encryption, note that not all parameters are customisable in this mode
 - [ ] **Benchmark**:
 Compares execution times of functions in standard (amortised) LWE and Ring-LWE. We compare public key generation,
 encryption and decryption
 - [ ] **LWE_PKE**:
 Implements a Public Key Encryption system using Regev's design and an alternative amortised system based on this.
 - [ ] **FHE_RLWE**:
 Implements a Fully Homomorphic Encryption system based on Ring-LWE.
 - [ ] **test.py**:
A test.py file is included in every package and contains UnitTests for the appropriate package. You can run these in the Sage shell if desired
 - [ ] **demo_lwe**:
 This notebook contains a very simple possible implementation of the LWE_PKE module
 - [ ] **demo_fhe**:
 This notebook contains a very simple possible implementation of the FHE_RLWE module
## Usage
The simplest way to use this project is running the notebook files, these provide a highly annotated description of the functionality and purpose of each module and program. You can also run the high level programs like CLI and Benchmark in the Notebook or Sage shell.

This project is supposed to function as a mini-library however, so the best way to use the project is create your own Notebook or Sage file, import some modules and start encrypting and decrypting data. The CLI and Demo files can give you an idea of how to use the modules.
All files are documented using Python DocStrings and notebook files are additionally annoted with Markdown cells to facilitate ease of use. 

Note that in order to use the top-level notebook files (CLI and Benchmark) you must install the module import-ipynb.
This can be done for your Sage's python using the command 'sage -pip install import-ipynb'