This tool automates the process of analyzing cryptographic ciphers using the Meet-in-the-Middle (MITM) attack. It supports various block ciphers, including CRAFT, Midori64, Midori128, WARP, PRESENT80, and ARADI.

Key features:

✅ Supports regular key and equivalent key attacks.

✅ Generates round keys and defines bit relations for supported ciphers

✅ Allows customization of attack parameters (rounds, printing options, etc.)

✅ Exports results to a file for detailed analysis

✅ Implements guess-and-determine (only for PRESENT80)


📜 Installation

Ensure you have Python 3.x installed. You can check your Python version using:

    python3 --version
    
 
 Install Dependencies

    pip install -r requirements.txt
    
🚀 Usage

Run the tool using the following command:
    
    python3 main.py --cipher <CIPHER> --attack_type <ATTACK_TYPE> [OPTIONS]
    
🔹 Required Arguments:


| Argument       | Description |
|---------------|-------------|
| `--cipher`    | Specifies the cipher to analyze. Choose from: `CRAFT`, `Midori64`, `Midori128`, `WARP`, `PRESENT80`, `ARADI`. |
| `--attack_type` | Defines the attack type: `regular_key` or `equivalent_key`. |


🔹 Optional Arguments:

| Argument                 | Description |
|-------------------------|-------------|
| `--rounds <N>`             | Overrides the default number of rounds (e.g., `--rounds 5`). |
| `--guess_and_determine`    | Enables guess-and-determine (only for `PRESENT80`). |
| `--output <FILENAME>`      | Specifies the output file (default: `output.txt`). |
| `--print_key`              | Prints the generated forward & backward keys. |
| `--print_block`            | Prints forward & backward blocks. |
| `--print_block_car`        | Prints block cardinality. |
| `--print_bit_addr_info`    | Prints bit address information. |
| `--evaluate_key_diffusion` | Evaluate key bit diffusion (requires a key bit, e.g., 'k_13') |
| `--navigate_bit_position`  | Navigate bit position progress (requires a bit position, e.g., 3) |


📌 Example Commands


Running an attack on Midori64 (Regular Key Attack)

    python3 main.py --cipher Midori64 --attack_type regular_key --rounds 5 --print_key --output midori_results.txt    
This command analyzes Midori64 using a regular key attack with 5 rounds, prints the key, and saves results in midori_results.txt.

Running an Equivalent Key Attack on CRAFT

    python3 main.py --cipher CRAFT --attack_type equivalent_key --print_block --print_block_car
Runs an equivalent key attack on CRAFT, printing the block structure and cardinality.

Running Guess-and-Determine on PRESENT80

    python3 main.py --cipher PRESENT80 --attack_type regular_key --guess_and_determine --print_bit_addr_info
Performs guess-and-determine analysis on PRESENT80, printing bit address information.

⚠️ Notes & Limitations

The guess-and-determine technique is only applicable to PRESENT80.

The cipher names are case-insensitive, but must match their official names (Midori64, not MIDORI64).

Equivalent key attacks are not supported for WARP and PRESENT80.


## How to Describe a Cipher to the Tool

To describe a cipher, you need to determine the positions of the bit addresses. As an example, consider the **regular key attack on CRAFT**:

![Diagram Description](craft_regular_key.png)

### 1. Generating Round Keys
First, the round keys must be generated based on the cipher’s key schedule. Refer to `generate_round_key.py`, where round keys are generated for other ciphers.

### 2. Describing Cipher Components in Bit-Level Representation
All cipher components—such as permutations and mix columns—must be described at the **bit level**. The Sage Jupyter file `sage_support_material.ipynb` is useful for understanding and visualizing the bit-level representation of different ciphers.

For determining **bit dependencies in S-boxes**, the component functions should be computed using **SageMath**. See the Sage file `sage_support_material.ipynb` for guidance.

To describe dependencies for the S-box, two dependency lists should be written:
- **`lin_dependent_ind`** → Stores the indices of linearly dependent bits.
- **`non_lin_dependent_ind`** → Stores the indices of non-linearly dependent bits.

⚠️ **Important:** A bit position **must not** appear in both `lin_dependent_ind` and `non_lin_dependent_ind`.  
For example, in **CRAFT**:

```python
lin_dependent_ind = [[], [], [], []]
non_lin_dependent_ind = [[0, 1, 2, 3], [0, 1, 2, 3], [0, 1, 3], [0, 1, 2, 3]]







