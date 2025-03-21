
from config import check_dependencies
check_dependencies()
import argparse
import logging
from find_good_bit_address import FindGoodBitAddress
from generate_round_key import GenerateRoundKey
from typing import List, Union


# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


def main():
    """Main function to select and execute the correct cipher analysis."""
    parser = argparse.ArgumentParser(description="Automated Tool for Meet in the Middle Attack")
    parser.add_argument("--cipher", type=str, choices=["CRAFT", "Midori64", "Midori128", "WARP",
                                    "PRESENT80", "ARADI"], required=True, help="Cipher name (e.g., CRAFT, Midori64)")
    parser.add_argument("--rounds", type=int, help="Override the number of rounds (optional)")
    parser.add_argument("--attack_type", type=str, choices=["regular_key", "equivalent_key"], required=True,
                        help="Type of attack to perform")
    parser.add_argument("--guess_and_determine", action="store_true", help="Perform guess-and-determine")

    parser.add_argument("--print_key", action="store_true", help="Print forward & backward keys")
    parser.add_argument("--print_block", action="store_true", help="Print forward & backward blocks")
    parser.add_argument("--print_block_car", action="store_true", help="Print blocks cardinality")
    parser.add_argument("--print_bit_addr_info", action="store_true", help="Print bit address info")
    parser.add_argument("--output", type=str, default="output.txt",
                        help="Specify output file for results (default: output.txt)")

    parser.add_argument("--evaluate_key_diffusion", type=str, metavar="KEY_BIT",
                        help="Evaluate key bit diffusion (requires a key bit, e.g., 'k_13')")
    parser.add_argument("--navigate_bit_position", type=int, metavar="BIT_POSITION",
                        help="Navigate bit position progress (requires a bit position, e.g., 3)")

    args = parser.parse_args()

    # cipher_name = args.cipher.upper()  # Normalize case
    cipher_name = args.cipher
    n_rounds = args.rounds  # User-defined rounds or default per cipher
    attack_type = args.attack_type
    output_file = args.output

    guess_and_determine = args.guess_and_determine

    print_key = args.print_key
    print_block = args.print_block
    print_block_car = args.print_block_car
    print_bit_addr_info = args.print_bit_addr_info

    key_bit = args.evaluate_key_diffusion
    bit_position = args.navigate_bit_position

    directions = []

    if guess_and_determine and cipher_name != "PRESENT80":
        logger.error("❌ The --guess_and_determine option is not available for this cipher")
        return

    # ============================== CRAFT ===============================
    if cipher_name == "CRAFT":
        logger.info("Initializing CRAFT analysis...")

        if not n_rounds:
            n_rounds = 14  # Default value

        block_size, key_size, t = 64, 128, 2

        perm_nib = [15, 12, 13, 14, 10, 9, 8, 11, 6, 5, 4, 7, 1, 2, 3, 0]
        perm_bit = [perm_nib[i] * 4 + j for i in range(16) for j in range(4)]

        mix_list = [
            [0, 8, 12], [1, 9, 13], [2, 10, 14], [3, 11, 15],
            [4, 12], [5, 13], [6, 14], [7, 15],
            [8], [9], [10], [11], [12], [13], [14], [15]
        ]

        mix_perm_nib = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]
        # the mixing should be applied on the columns of the state
        mix_perm_bit = [mix_perm_nib[i] * 4 + j for i in range(16) for j in range(4)]


        lin_dependent_ind = [[], [], [], []]
        non_lin_dependent_ind = [[0, 1, 2, 3], [0, 1, 2, 3], [0, 1, 3], [0, 1, 2, 3]]
        s_box_list = [lin_dependent_ind, non_lin_dependent_ind]

        key = GenerateRoundKey(n_rounds, block_size, 'CRAFT', attack_type, perm_bit=mix_perm_bit,
                               mixing_list=mix_list)
        round_keys, relations = key.roundKey, key.relations

        if attack_type == "regular_key":
            directions = [
                ['fwd',
                 [n_rounds - 1, ['a', 'mixing', mix_list, mix_perm_bit], ['*', 'key_addition'], ['*', 'perm', perm_bit],
                  ['b', 's_box', s_box_list]],
                 [1, ['a', 'mixing', mix_list, mix_perm_bit], ['*', 'key_addition']]
                 ],
                ['bwd',
                 [1, ['*', '-'], ['a', 'key_addition']],
                 [n_rounds - 1, ['b', 'mixing', mix_list, mix_perm_bit], ['*', 's_box', s_box_list],
                  ['*', 'perm_inv', perm_bit], ['a', 'key_addition']]
                 ]
            ]
        else:  # Equivalent Key Attack
            directions = [
                ['fwd',
                 [n_rounds - 1, ['*', 'mixing', mix_list, mix_perm_bit], ['a', 'key_addition'], ['b', 'perm', perm_bit],
                  ['c', 's_box', s_box_list]],
                 [1, ['*', 'mixing', mix_list, mix_perm_bit], ['a', 'key_addition']]
                 ],
                ['bwd', [1, ['a', '-']],
                 [n_rounds - 1, ['c', 'key_addition'], ['b', 's_box', s_box_list], ['a', 'perm_inv', perm_bit],
                  ['*', 'mixing', mix_list, mix_perm_bit]]
                ]
            ]

    # ============================== Midori64 ===============================
    elif cipher_name == "Midori64":
        logger.info("Initializing Midori64 cipher analysis...")
        if not n_rounds:
            n_rounds = 5

        block_size, key_size, t = 64, 128, 2

        perm_nib = [0, 10, 5, 15, 14, 4, 11, 1, 9, 3, 12, 6, 7, 13, 2, 8]
        perm_bit = [perm_nib[i] * 4 + j for i in range(16) for j in range(4)]

        mix_list = [
            [4, 8, 12], [5, 9, 13], [6, 10, 14], [7, 11, 15],
            [0, 8, 12], [1, 9, 13], [2, 10, 14], [3, 11, 15],
            [0, 4, 12], [1, 5, 13], [2, 6, 14], [3, 7, 15],
            [0, 4, 8], [1, 5, 9], [2, 6, 10], [3, 7, 11]
        ]

        lin_dependent_ind = [[], [], [], []]
        non_lin_dependent_ind = [[0, 1, 2, 3], [0, 1, 2, 3], [0, 1, 3], [0, 1, 2, 3]]
        s_box_list = [lin_dependent_ind, non_lin_dependent_ind]

        key = GenerateRoundKey(n_rounds, block_size, "Midori64", attack_type, mixing_list=mix_list)
        round_keys, relations = key.roundKey, key.relations

        if attack_type == "regular_key":
            directions = [
                ['fwd',
                 [['*', 'key_addition']], [n_rounds - 1, ['a', 's_box', s_box_list], ['b', 'perm', perm_bit],
                    ['c', 'mixing', mix_list], ['d', 'key_addition']], [1, ['a', 's_box', s_box_list],
                                                                        ['b', 'key_addition']]
                 ],
                ['bwd',
                 [1, ['b', '-'], ['a', 'key_addition']], [n_rounds - 1, ['d', 's_box', s_box_list],
                    ['c', 'key_addition'], ['b', 'mixing', mix_list], ['a', 'perm_inv', perm_bit], ]
                 ]
            ]
        else:  # Equivalent Key Attack
            directions = [
                ['fwd',
                 [n_rounds-1, ['a', 'key_addition'], ['b', 's_box', s_box_list], ['c', 'perm', perm_bit],
                  ['*', 'mixing', mix_list]], [1, ['a', 'key_addition'], ['b', 's_box', s_box_list]]
                ],
                ['bwd',
                 [1, ['b', 'key_addition'], ['a', 's_box', s_box_list]], [n_rounds - 1, ['*', 'mixing', mix_list],
                    ['c', 'key_addition'], ['b', 'perm_inv', perm_bit], ['a', 's_box', s_box_list]]
                 ]
            ]


    # ============================== Midori128 ===============================
    elif cipher_name == "Midori128":
        logger.info("Initializing Midori128 cipher analysis...")
        if not n_rounds:
            n_rounds = 7

        block_size, key_size, t = 128, 128, 1

        perm_nib = [0, 10, 5, 15, 14, 4, 11, 1, 9, 3, 12, 6, 7, 13, 2, 8]
        perm_bit = [perm_nib[i] * 8 + j for i in range(16) for j in range(8)]

        mix_list = [
            [8, 16, 24], [9, 17, 25], [10, 18, 26], [11, 19, 27],
            [12, 20, 28], [13, 21, 29], [14, 22, 30], [15, 23, 31],
            [0, 16, 24], [1, 17, 25], [2, 18, 26], [3, 19, 27],
            [4, 20, 28], [5, 21, 29], [6, 22, 30], [7, 23, 31],
            [0, 8, 24], [1, 9, 25], [2, 10, 26], [3, 11, 27],
            [4, 12, 28], [5, 13, 29], [6, 14, 30], [7, 15, 31],
            [0, 8, 16], [1, 9, 17], [2, 10, 18], [3, 11, 19],
            [4, 12, 20], [5, 13, 21], [6, 14, 22], [7, 15, 23]
        ]

        # ============permute bits for the s-boxes=================================================
        y0 = [4, 1, 6, 3, 0, 5, 2, 7]
        y1 = [1, 6, 7, 0, 5, 2, 3, 4]
        y2 = [2, 3, 4, 1, 6, 7, 0, 5]
        y3 = [7, 4, 1, 2, 3, 0, 5, 6]
        bytes_order = [y0, y1, y2, y3]
        y32 = [8 * i + j for i in range(4) for j in bytes_order[i]]
        perms_box = [32 * i + j for i in range(4) for j in y32]
        # ============end of permute bits for the s-boxes==========================================

        s_box_list = [[], [], [], []]

        key = GenerateRoundKey(n_rounds, block_size, 'Midori128', attack_type, mixing_list=mix_list)
        round_keys, relations = key.roundKey, key.relations

        if attack_type == "regular_key": # for the usual key attack
            directions = [
                ['fwd',
                 [['*', 'key_addition']], [n_rounds - 1, ['a', 's_box', s_box_list, perms_box], ['b', 'perm', perm_bit],
                    ['c', 'mixing', mix_list], ['d', 'key_addition']], [1, ['a', 's_box', s_box_list, perms_box],
                  ['b', 'key_addition']]
                 ],
                ['bwd',
                 [1, ['b', '-'], ['a', 'key_addition']], [n_rounds - 1, ['d', 's_box', s_box_list, perms_box],
                    ['c', 'key_addition'], ['b', 'mixing', mix_list], ['a', 'perm_inv', perm_bit], ]
                 ]
            ]
        else: # for the equivalent key attack
            directions = [
                ['fwd',
                 [n_rounds - 1, ['a', 'key_addition'], ['b', 's_box', s_box_list, perms_box], ['c', 'perm', perm_bit],
                  ['*', 'mixing', mix_list]], [1, ['a', 'key_addition'], ['b', 's_box', s_box_list, perms_box]]
                 ],
                ['bwd',
                 [1, ['b', 'key_addition'], ['a', 's_box', s_box_list, perms_box]],
                 [n_rounds - 1, ['*', 'mixing', mix_list],
                  ['c', 'key_addition'], ['b', 'perm_inv', perm_bit], ['a', 's_box', s_box_list, perms_box]]
                 ]
            ]

    # ============================== WARP ===============================
    elif cipher_name == "WARP":
        logger.info("Initializing WARP cipher analysis...")
        if not n_rounds:
            n_rounds = 18

        block_size, key_size, t = 128, 128, 1

        perm_nib = [31, 6, 29, 14, 1, 12, 21, 8, 27, 2, 3, 0, 25, 4, 23, 10,
                   15, 22, 13, 30, 17, 28, 5, 24, 11, 18, 19, 16, 9, 20, 7, 26]
        perm_bit = [perm_nib[i] * 4 + j for i in range(32) for j in range(4)]

        input_nib = [0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30]
        output_nib = [1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 27, 29, 31]
        input_bit = [input_nib[i] * 4 + j for i in range(16) for j in range(4)]
        output_bit = [output_nib[i] * 4 + j for i in range(16) for j in range(4)]
        pattern = [input_bit, output_bit]

        lin_dependent_ind = [[], [], [], []]
        non_lin_dependent_ind = [[0, 1, 2, 3], [0, 1, 2, 3], [0, 2, 3], [0, 1, 2, 3]]
        s_box_list = [lin_dependent_ind, non_lin_dependent_ind]

        if attack_type == "regular_key":
            block_id1 = ['*1', 'b']  # the block identifier for xor in the forward directions
            block_id2 = ['*2', '*1']  # the block identifier for xor in the backward directions
            directions = [
                ['fwd',
                 [n_rounds - 1, [pattern, 'a', 's_box', s_box_list], [pattern[1], '*1', 'key_addition'],
                  [pattern[1], '*2', 'xor', block_id1], ['b', 'perm', perm_bit]], [1, [pattern, 'a', 's_box', s_box_list],
                        [pattern[1], '*1', 'key_addition'], [pattern[1], 'b', 'xor', block_id1]]
                 ],
                ['bwd',
                 [1, ['b', '-'], [pattern, 'a', 's_box', s_box_list], [pattern[1], '*1', 'key_addition']],
                 [n_rounds - 1, [pattern[1], 'b', 'xor', block_id2], ['*1', 'perm_inv', perm_bit],
                  [pattern, 'a', 's_box', s_box_list], [pattern[1], '*2', 'key_addition']]
                 ]
            ]
        elif attack_type == "equivalent_key":  # Equivalent Key Attack
            logger.info("Equivalent key technique is not applicable for the WARP cipher ...")
            return

        key = GenerateRoundKey(n_rounds, block_size, "WARP", attack_type)
        round_keys, relations = key.roundKey, []


    # ============================== PRESENT80 ===============================
    elif cipher_name == "PRESENT80":
        logger.info("Initializing PRESENT80 cipher analysis...")
        if not n_rounds:
            n_rounds = 6

        block_size, key_size, t = 64, 80, 2

        perm_bits = [
            0, 16, 32, 48, 1, 17, 33, 49, 2, 18, 34, 50, 3, 19, 35, 51, 4, 20, 36,
            52, 5, 21, 37, 53, 6, 22, 38, 54, 7, 23, 39, 55, 8, 24, 40, 56, 9, 25,
            41, 57, 10, 26, 42, 58, 11, 27, 43, 59, 12, 28, 44, 60, 13, 29, 45, 61,
            14, 30, 46, 62, 15, 31, 47, 63
        ]
        s_box_list = [[], [], [], [0, 3]]
        s_box_inv_list = [[], [], [], [0, 2]]

        key = GenerateRoundKey(n_rounds, block_size, "PRESENT80", perm_bit=perm_bits)
        round_keys, relations = key.roundKey, key.relations

        if attack_type == "regular_key":
            directions = [
                ['fwd',
                 [n_rounds, ['*1', 'key_addition'], ['a', 's_box', s_box_list], ['*2', 'perm', perm_bits]]],
                ['bwd',
                 [n_rounds, ['*2', 'key_addition'], ['a', 'perm_inv', perm_bits], ['*1', 's_box', s_box_inv_list]]]
            ]
            
        else:  # Equivalent Key Attack
            logger.info("Equivalent key technique is not applicable for the PRESENT80 cipher ...")
            return


    # ============================== ARADI ===============================
    elif cipher_name == "ARADI":
        logger.info("Initializing ARADI cipher analysis...")
        if not n_rounds:
            n_rounds = 5

        block_size, key_size, t = 128, 256, 2

        lin_dependent_ind = [[], [2], [], [0]]
        non_lin_dependent_ind = [[0, 1, 2, 3], [1, 3], [0, 1, 2, 3], [1, 2, 3]]
        lin_dependent_ind_inv = [[3], [], [1], []]
        non_lin_dependent_ind_inv = [[0, 2], [0, 1, 2, 3], [0, 2, 3], [0, 1, 2, 3]]
        s_box_list = [lin_dependent_ind, non_lin_dependent_ind]
        s_box_inv_list = [lin_dependent_ind_inv, non_lin_dependent_ind_inv]

        perm_for_s_box = [0] * 128
        for i in range(32):
            perm_for_s_box[i] = i * 4
            perm_for_s_box[i + 32] = i * 4 + 1
            perm_for_s_box[i + 64] = i * 4 + 2
            perm_for_s_box[i + 96] = i * 4 + 3

        def _helper_form_linear_layer(j, word_indices):
            a = [11, 10, 9, 8]
            b = [8, 9, 4, 9]
            c = [14, 11, 14, 7]

            ind_left = word_indices[0:16]
            ind_right = word_indices[16:32]

            s_a_ind_left = ind_left[a[j]:] + ind_left[:a[j]]
            s_c_ind_right = ind_right[c[j]:] + ind_right[:c[j]]

            s_a_ind_right = ind_right[a[j]:] + ind_right[:a[j]]
            s_b_ind_left = ind_left[b[j]:] + ind_left[:b[j]]

            fin_indices = [[] for _ in range(32)]
            for ind in range(16):
                fin_indices[ind].append(ind_left[ind])
                fin_indices[ind].append(s_a_ind_left[ind])
                fin_indices[ind].append(s_c_ind_right[ind])

                fin_indices[ind + 16].append(ind_right[ind])
                fin_indices[ind + 16].append(s_a_ind_right[ind])
                fin_indices[ind + 16].append(s_b_ind_left[ind])

            return fin_indices

        word_ind = [ind for ind in range(32)]
        lin_layers = []
        for j_mod in range(4):
            lin_layers.append(_helper_form_linear_layer(j_mod, word_ind))

        key = GenerateRoundKey(n_rounds, block_size, "ARADI")
        round_keys = key.roundKey
        relations = None

        operation = List[Union[int, List[Union[str, List[Union[str, List]]]]]]
        directions_type = List[List[Union[str, operation]]]

        if attack_type == "regular_key":
            directions: directions_type = [['fwd'], ['bwd']]
            for i in range(n_rounds):
                fwd_dir = [1, ['a', 'key_addition'], ['b', 's_box', s_box_list, perm_for_s_box],
                           ['c', 'mixing', lin_layers[i % 4]]]
                bwd_dir = [1, ['c', 'key_addition'], ['b', 'mixing', lin_layers[(n_rounds - i) % 4]],
                           ['a', 's_box', s_box_inv_list, perm_for_s_box]]
                directions[0].append(fwd_dir)
                directions[1].append(bwd_dir)
        else:
            logger.info("Equivalent key technique is not applicable for the ARADI cipher ...")
            return

    else:
        logger.error(f"Cipher '{cipher_name}' is not supported.")
        return

    #============================== Execute Analysis ===============================

    logger.info(f"Selected Cipher: {cipher_name}")
    logger.info(f"Attack Type: {attack_type}")

    if n_rounds:
        logger.info(f"Overriding rounds: {n_rounds}")

    # 🔹 Execute Analysis
    f = FindGoodBitAddress(n_rounds, block_size, key_size, t, round_keys, directions, attack_type, cipher_name,
                           relations, guess_and_determine)
    if any([print_key, print_block, print_block_car, print_bit_addr_info]):
        f.print_details(output_file, print_key, print_block, print_block_car, print_bit_addr_info)
    else:
        logger.info("No output flags selected, skipping output file generation.")

    if key_bit:
        logger.info(f"Evaluating key bit diffusion for: {key_bit}")
        f.evaluate_key_bit_diffusion(key_bit)

    if bit_position is not None:
        logger.info(f"Navigating bit position progress for position: {bit_position}")
        f.navigate_bit_position_progress(bit_position)


if __name__ == "__main__":
    
    main()


