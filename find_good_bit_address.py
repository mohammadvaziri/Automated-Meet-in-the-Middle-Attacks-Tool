from sympy import symbols, log, S
import numpy as np
from collections import defaultdict
import re
import pandas as pd


from utils import (
    return_required_lists_for_operation,
    return_bwd_matrix,
    compute_cardinality_with_guess_and_determine,
    compute_non_lin_keys_for_present80,
    compute_key_com_key_union_between_fwd_bwd_keys,
    compute_key_com_key_union_for_present80,
    apply_operation_for_evaluate_key_bit_diffusion,
    apply_operations_for_navigate_bit_position_progress,
    write_line
)
from generate_round_key import *


class FindGoodBitAddress:

    def __init__(self, n_rounds, block_size, key_size, t, round_keys, directions, attack_type, cipher_name,
                 relations=None,  guess_and_determine=False):

        self.n_rounds = n_rounds
        self.block_size = block_size
        self.key_size = key_size  # the length of the master key
        self.t = t # number of plaintext/ciphertext required to check the correctness of the guessed key
        self.fwd_key = round_keys[0]  # key bits in the forward direction
        self.bwd_key = round_keys[1]  # key bits in the backward direction
        self.directions = directions  # the list of fwd and bwd directions
        self.attack_type = attack_type  # the round keys are generated based on the type of the attack :
        # 'equivalent_key'or 'regular_key' for some ciphers 'equivalent_key' can't be implemented
        self.relations = relations  # linear relations between the forward and backward keys
        self.cipher_name = cipher_name
        self.guess_and_determine = guess_and_determine # if guess_and_determine tool is used to determine the
        # cardinality of the set of key bits

        self.fwd_blocks = []  # the block of bit addresses for the forward direction
        self.bwd_blocks = []  # the block of bit addresses for the backward direction
        self.fwd_bit_addr_info = []  # records the name of the bit address along with its index in the self.fwd_blocks
        self.bwd_bit_addr_info = []  # records the name of the bit address along with its index in the self.bwd_blocks
        self.fwd_blocks_car = []  # the cardinality of bit addresses for the forward direction
        self.bwd_blocks_car = []  # the cardinality of bit addresses for the backward direction
        self.fwd_blocks.append(self.gen_block(0))  # the first block of forward bit addresses
        self.bwd_blocks.append(self.gen_block(self.n_rounds - 1))  # the first block of backward bit addresses
        self.bit_addr_info = []  # the list of bit addresses including
        # [name, non_lin_fwd_car, non_lin_bwd_car, time_complexity, [fwd_ind, bwd_ind]]


        """
        print("n_rounds: ", n_rounds)
        print("block_size: ", block_size)
        print("key_size: ", key_size)
        print("t: ", t)
        print("round_keys", round_keys)
        print("directions: ", directions)
        print("attack_type: ", attack_type)
        print("relations: ", relations)
        print("cipher_name: ", cipher_name)
        print("guess_and_determine: ", guess_and_determine)
        """

        self.find_good_bit_addr()


    def gen_block(self, rond, name=''):
        block = []
        if name:
            for b in range(self.block_size):
                block.append([name + '_' + str(rond) + '_' + str(b), [], []])  # [bit_addr, [lin], [non_lin]]
        else:
            for b in range(self.block_size):
                block.append(['', [], []])  # [bit_addr, [lin], [non_lin]]
        return block

    def classify_bit_addresses(self, rond, direction, name, operation, rond_key_index=0, s_box_list=None,
                               mixing_list=None, perm_bit=None, blocks_id=None, pattern=None):
        """
        :param rond: round number
        :param direction: forward or backward direction
        :param name: the name of the block
        :param operation: the operation of the block: key_addition, s_box, perm, mixing, perm_inv, xor,  -
        :param rond_key_index: the indices of the key bits that are added to the block (if operation == 'key_addition')
        :param s_box_list: linearly and non_linearly dependent indices of each bit output of the s_box relative to
        the input bits, if len(s_box_list)==1 : [[lin1], [lin2],...],
        if len(s_box_list)==2:[ [[lin1], [lin2],...], [[non_lin1], [non_lin2],...] ]
        :param mixing_list: the mixing list (if operation == 'mixing')
        :param perm_bit: the permutation bits
        :param blocks_id: the block identifier for xor operation
        :param pattern: the pattern of applying operations on the bit position on a state if needed(the order should be
            based on bits) [[input], [output]] --> for s_box and mixing
        """

        if direction == 'fwd':
            name = name + '_f'
            blocks = self.fwd_blocks
            keys = self.fwd_key
        else:
            name = name + '_b'
            blocks = self.bwd_blocks
            keys = self.bwd_key
        last_block = blocks[-1]
        block = self.gen_block(rond, name)

        if operation == 'key_addition':
            subkey = keys[rond_key_index]  # the subkey of the round
            block = self.classify_after_key_addition(last_block, block, subkey, pattern=pattern)
        if operation == 's_box':
            block = self.classify_after_s_box(last_block, block, s_box_list, perm_bit=perm_bit, pattern=pattern)
        if operation == 'mixing':
            block = self.classify_after_mixing(last_block, block, mixing_list, perm_bit=perm_bit, pattern=pattern)
        if operation == 'perm':
            block = self.classify_after_perm(last_block, block, perm_bit)
        if operation == 'perm_inv':
            block = self.classify_after_perm_inv(last_block, block, perm_bit)
        if operation == 'xor':
            block = self.classify_after_xor(blocks, block, blocks_id=blocks_id, pattern=pattern)
        if operation == '-':
            block = self.classify_after_no_action(last_block, block)

        if blocks[0][0][0] == '':
            blocks[0] = block
        else:
            blocks.append(block)

    def classify_after_key_addition(self, last_block, block, subkey, pattern=None):
        pattern = pattern if pattern else [p for p in range(self.block_size)]

        for b in range(self.block_size):
            lin = list(last_block[b][1])
            non_lin = list(last_block[b][2])
            if b in pattern:
                index = pattern.index(b)
                if type(subkey[index]) == list:
                    lin.extend(set(subkey[index]))
                else:
                    lin.append(subkey[index])
                lin = list(set(lin) - set(non_lin))
            block[b][1] = list(lin)
            block[b][2] = list(non_lin)
        return block

    def classify_after_s_box(self, last_block, block, s_box_list, perm_bit=None, pattern=None):
        """
        linDependentInd: [[lin1], [lin2],...]   each list contains the indices of the input bits of the s_box
            that are linearly dependent on the output bit
        pattern: # is used for the structures like Fiestel
        """

        lin_dependent_ind = s_box_list[0] if len(s_box_list) == 2 else s_box_list
        non_lin_dependent_ind = s_box_list[1] if len(s_box_list) == 2 else None

        input_indices = pattern[0] if pattern else [p for p in range(self.block_size)]
        output_indices = pattern[1] if pattern else [p for p in range(self.block_size)]
        last_block_copy = []  # for the case of perm_bit

        if perm_bit:  # if a permutation needs to be applied prior to apply s-box
            last_block_copy = copy.deepcopy(last_block)
            for b in range(self.block_size):
                last_block[perm_bit[b]][1] = list(last_block_copy[b][1])
                last_block[perm_bit[b]][2] = list(last_block_copy[b][2])

        s_box_size = len(lin_dependent_ind)
        if len(input_indices) % s_box_size != 0:
            raise Exception("the number of dependencies are not equal to the size of the s_box")
        if len(input_indices) != len(output_indices):
            raise Exception("the number of input and output indices are not equal")
        if non_lin_dependent_ind:
            assert s_box_size == len(non_lin_dependent_ind), ("the number of dependencies is not equal to the size of"
                                                               "the s_box")
            for s in range(s_box_size):
                if lin_dependent_ind[s] != [] and non_lin_dependent_ind[s] != []:
                    for l in lin_dependent_ind[s]:
                        if l in non_lin_dependent_ind[s]:
                            raise Exception(
                            "the s_box is linearly and non_linearly dependent on the bit " + l + "th at the same time")

        iterate = self.block_size // s_box_size  # the number of s_boxes
        for it in range(iterate):
            for s in range(s_box_size):

                if s_box_size * it + s in output_indices:
                    lin, non_lin = [], []
                    if non_lin_dependent_ind:
                        lin_bits = lin_dependent_ind[s]
                        non_lin_bits = non_lin_dependent_ind[s]
                    else:
                        lin_bits = lin_dependent_ind[s]
                        non_lin_bits = list(set(range(s_box_size)) - set(lin_bits))
                    for k in non_lin_bits:
                        index = output_indices.index(s_box_size * it + k)
                        non_lin.extend(last_block[input_indices[index]][1])
                        non_lin.extend(last_block[input_indices[index]][2])
                    for k in lin_bits:
                        index = output_indices.index(s_box_size * it + k)
                        lin.extend(last_block[input_indices[index]][1])
                        non_lin.extend(last_block[input_indices[index]][2])
                    block[s_box_size * it + s][1] = list(set(lin) - set(non_lin))
                    block[s_box_size * it + s][2] = list(set(non_lin))

                else:
                    block[s_box_size * it + s][1] = list(last_block[s_box_size * it + s][1])
                    block[s_box_size * it + s][2] = list(last_block[s_box_size * it + s][2])

        if perm_bit:  # inverse of permutation should be applied after mixing to return it to the original order
            block_copy = copy.deepcopy(block)
            for b in range(self.block_size):
                block[b][1] = list(block_copy[perm_bit[b]][1])
                block[b][2] = list(block_copy[perm_bit[b]][2])
                last_block[b][1] = list(last_block_copy[b][1])
                last_block[b][2] = list(last_block_copy[b][2])

        return block

    def classify_after_mixing(self, last_block, block, mixing_list, perm_bit=None, pattern=None):
        input_indices = pattern[0] if pattern else [b for b in range(self.block_size)]
        output_indices = pattern[1] if pattern else [b for b in range(self.block_size)]
        last_block_copy = [] # for the case of perm_bit
        if perm_bit:  # if a permutation needs to be applied prior to apply mixing
            last_block_copy = copy.deepcopy(last_block)
            for b in range(self.block_size):
                last_block[b][1] = list(last_block_copy[perm_bit[b]][1])
                last_block[b][2] = list(last_block_copy[perm_bit[b]][2])

        if len(input_indices) % len(mixing_list) != 0:
            raise Exception("the length of block is not divisible by the length of mixingList")

        mixing_size = len(mixing_list)
        iterate = len(input_indices) // mixing_size  # the number of iterations
        for it in range(iterate):
            for m in range(mixing_size):  # for each mixing,  the bit location is mixingSize*i+j

                if mixing_size * it + m in output_indices:
                    lin, non_lin = [], []
                    for k in mixing_list[m]:
                        index = output_indices.index(mixing_size * it + k)
                        lin.extend(last_block[input_indices[index]][1])
                        non_lin.extend(last_block[input_indices[index]][2])
                        lin = list(set(lin))
                        non_lin = list(set(non_lin))
                    lin = list(set(lin) - set(non_lin))
                    block[mixing_size * it + m][1] = list(lin)
                    block[mixing_size * it + m][2] = list(non_lin)
                else:
                    block[mixing_size * it + m][1] = list(last_block[mixing_size * it + m][1])
                    block[mixing_size * it + m][2] = list(last_block[mixing_size * it + m][2])

        if perm_bit:  # inverse of permutation should be applied after mixing to return it to the original order
            block_copy = copy.deepcopy(block)
            for b in range(self.block_size):
                block[perm_bit[b]][1] = list(block_copy[b][1])
                block[perm_bit[b]][2] = list(block_copy[b][2])
                last_block[b][1] = list(last_block_copy[b][1])
                last_block[b][2] = list(last_block_copy[b][2])
        return block

    def classify_after_perm(self, last_block, block, perm_bit):
        for b in range(self.block_size):
            block[perm_bit[b]][1] = list(last_block[b][1])
            block[perm_bit[b]][2] = list(last_block[b][2])
        return block

    def classify_after_perm_inv(self, last_block, block, perm_bit):
        for b in range(self.block_size):
            block[b][1] = list(last_block[perm_bit[b]][1])
            block[b][2] = list(last_block[perm_bit[b]][2])
        return block

    def classify_after_xor(self, blocks, block, blocks_id, pattern=None):
        """
        the function looks for the blocks_id before the block of the xor and as soon as it finds block with the same
        ids, it applies the xor operation, so the order of putting the xor in directions is important
        the order of the ids in the blocks_id does not matter
        """
        pattern = pattern if pattern else [b for b in range(self.block_size)]

        b_ids = [None] * 2
        for ind, b_id in enumerate(blocks_id):
            for bl in blocks[::-1]:
                if b_id in bl[0][0]:
                    b_ids[ind] = blocks.index(bl)
                    break

        if b_ids[0] is None and b_ids[1] is None:
            raise Exception("the block ids: " + str(blocks_id) + " for the xor operation are not found ")

        if b_ids[0] is not None and b_ids[1] is not None:
            block1 = blocks[b_ids[0]]
            block2 = blocks[b_ids[1]]
            for b in range(self.block_size):
                if b in pattern:
                    intersection = list(set(block1[b][1]) & set(block2[b][1]))
                    lin = list(set(block1[b][1] + block2[b][1]))
                    non_lin = list(set(block1[b][2] + block2[b][2]))
                    lin = list(set(lin) - set(non_lin) - set(intersection))
                    block[b][1] = list(lin)
                    block[b][2] = list(non_lin)
                else:
                    block[b][1] = list(block2[b][1])
                    block[b][2] = list(block2[b][2])

        else:
            index = b_ids[0] if b_ids[0] is not None else b_ids[1]
            for b in range(self.block_size):
                block[b][1] = list(blocks[index][b][1])
                block[b][2] = list(blocks[index][b][2])

        return block

    def classify_after_no_action(self, last_block, block):
        for b in range(self.block_size):
            block[b][1] = list(last_block[b][1])
            block[b][2] = list(last_block[b][2])
        return block

    def apply_operations_for_create_fwd_bwd_directions(self, operations, direction, round_offset, rond_key_ind,
                                                       block_ind, bit_addr_info):
        # if the operations are included in the round:
        for r in range(operations[0] if type(operations[0]) == int else 1):
            # function else the repetition is 1
            rd = round_offset + r if direction == 'fwd' and type(
                operations[0]) == int else round_offset - r if direction == 'bwd' and type(operations[0]) == int else 0
            for op in (operations[1:] if type(operations[0]) == int else operations):

                pattern = op[0] if isinstance(op[0], list) else None
                name = op[1] if isinstance(op[0], list) else op[0]
                operation = op[2] if isinstance(op[0], list) else op[1]

                perm_bit = op[2] if operation in {'perm', 'perm_inv'} else None

                if operation == 's_box':
                    s_box_list, perm_bit = return_required_lists_for_operation(op)
                else:
                    s_box_list = None

                if operation == 'mixing':
                    mixing_list, perm_bit = return_required_lists_for_operation(op)

                else:
                    mixing_list = None

                if operation == 'xor':
                    blocks_id = op[3] if isinstance(op[0], list) else op[2]
                else:
                    blocks_id = None

                self.classify_bit_addresses(rd, direction, name, operation, rond_key_index=rond_key_ind,
                                            s_box_list=s_box_list, mixing_list=mixing_list, perm_bit=perm_bit,
                                            blocks_id=blocks_id,
                                            pattern=pattern)

                if '*' not in name:
                    bit_addr_info.append([name, block_ind])
                block_ind += 1
                if operation == 'key_addition':
                    rond_key_ind += 1 if direction == 'fwd' else -1

        return rond_key_ind, block_ind

    def create_fwd_bwd_directions(self):
        """
        directions structure: [ ['fwd', [r,[],[],...], [[],[]...],... ], ['bwd', [r,[],[]...], [[],[],...],... ] ]
        """
        if len(self.directions) != 2 or self.directions[0][0] != 'fwd' or self.directions[1][0] != 'bwd':
            raise Exception("the direction list is not well defined")

        rond = 0
        rond_key_index = 0
        block_index = 0
        for ops in self.directions[0][1:]:
            rond_key_index, block_index = self.apply_operations_for_create_fwd_bwd_directions(ops, 'fwd', rond,
                                                                rond_key_index, block_index, self.fwd_bit_addr_info)
            if type(ops[0]) is int:
                rond += ops[0]

        rond -= 1
        rond_key_index = len(self.bwd_key) - 1
        block_index = 0
        for ops in self.directions[1][1:]:
            rond_key_index, block_index = self.apply_operations_for_create_fwd_bwd_directions(ops, 'bwd', rond,
                                                                rond_key_index, block_index, self.bwd_bit_addr_info)
            if type(ops[0]) is int:
                rond -= ops[0]

        fwd_names = [item[0] for item in self.fwd_bit_addr_info]
        bwd_names = [item[0] for item in self.bwd_bit_addr_info]
        if fwd_names != bwd_names[::-1]:
            print('fwd_names:        ', fwd_names)
            print('reverse bwd_names:', bwd_names[::-1])
            raise Exception("the names of the forward and backward operations are not matched")

    def compute_fwd_bwd_cardinality(self):
        """
        compute the cardinality of the nonlinear key bits in each bit address in the forward and backward directions
        """
        fwd_size = len(self.fwd_blocks)
        bwd_size = len(self.bwd_blocks)
        for fwd in range(fwd_size):
            block = []
            for b in range(self.block_size):
                if self.cipher_name == 'PRESENT80':
                    if self.guess_and_determine:
                        non_lin_fwd_car = compute_cardinality_with_guess_and_determine(self.fwd_blocks[fwd][b][2],
                                                                                       self.relations)
                    else:
                        non_lin_fwd_car = compute_non_lin_keys_for_present80(self.fwd_blocks[fwd][b][2], self.relations)
                else:
                        non_lin_fwd_car = len(self.fwd_blocks[fwd][b][2])
                block.append([self.fwd_blocks[fwd][b][0], non_lin_fwd_car])  # [name, non_lin_fwd_car]
            self.fwd_blocks_car.append(block)

        for bwd in range(bwd_size):
            block = []
            for b in range(self.block_size):
                if self.attack_type == 'equivalent_key':
                    if not self.bwd_blocks[bwd][b][2]:
                        non_lin_bwd_car = 0
                    else:
                        key_involved = set()
                        bwd_matrix, _ = return_bwd_matrix(self.bwd_blocks[bwd][b][2], self.relations, key_involved)
                        rank = np.linalg.matrix_rank(bwd_matrix)
                        non_lin_bwd_car = int(rank)

                elif self.cipher_name == 'PRESENT80':
                    if self.guess_and_determine:
                        non_lin_bwd_car = compute_cardinality_with_guess_and_determine(self.bwd_blocks[bwd][b][2],
                                                                                       self.relations)
                    else:
                        non_lin_bwd_car = compute_non_lin_keys_for_present80(self.bwd_blocks[bwd][b][2], self.relations)
                else:
                    non_lin_bwd_car = len(self.bwd_blocks[bwd][b][2])
                block.append([self.bwd_blocks[bwd][b][0], non_lin_bwd_car])  # [name, non_lin_bwd_car]
            self.bwd_blocks_car.append(block)

    def compute_max_fwd_bwd_cardinalities(self):

        fwd_ind = [item[1] for item in self.fwd_bit_addr_info]
        bwd_ind = [item[1] for item in self.bwd_bit_addr_info[::-1]]
        size = len(fwd_ind)
        for ind in range(size):
            block = []
            for b in range(self.block_size):
                #bit_addr: [name, non_lin_fwd_car, non_lin_bwd_car, k_com, [K_com: fwd-bwd-non_lin-intersection]]
                bit_addr: list = []
                name = self.fwd_blocks[fwd_ind[ind]][b][0]
                name = name.replace('_f', '', 1)
                bit_addr.append(name)
                bit_addr.append(self.fwd_blocks_car[fwd_ind[ind]][b][1])  # non_lin_fwd_car
                bit_addr.append(self.bwd_blocks_car[bwd_ind[ind]][b][1])  # non_lin_bwd_car
                block.append(bit_addr)

                # computing the maximum cardinality of the bit address
                max_car = max(bit_addr[1], bit_addr[2])
                bit_addr.append(max_car)
                bit_addr.append([fwd_ind[ind], b])  # the location of the bit address in the forward direction
                bit_addr.append([bwd_ind[ind], b])  # the location of the bit address in the backward direction
            self.bit_addr_info.append(block)

    def compute_print_min_time_memory_data_complexity(self):
        """
        printing the good bit address(es) (candidates) as the matching point with the minimum time, memory and data
        complexity
        """

        #=========finding the bit addresses with the minimum cardinality along with their memory============
        car_list = [bit_addr[3] for bit_addr_inf in self.bit_addr_info for bit_addr in
                             bit_addr_inf]  # the list of the maximum cardinalities
        min_car_val = min(car_list)  # the minimum value of the maximum cardinalities

        if min_car_val == self.key_size:
            print('\n\nthe time complexity of the attack is equal to exhaustive search')

        else:
            min_car_list = [] # the list of the bit addresses with the minimum cardinality
            for bit_addresses in self.bit_addr_info:  # find the bit addresses with the minimum cardinality
                for bit_addr in bit_addresses:
                    if bit_addr[3] == min_car_val:
                        min_car_list.append(bit_addr)

            mem_min_car_list = []  # the list of memory of the minimum cardinalities
            # [name, car_fwd, car_bwd, memory, k_union, k_com, fwd_ind, bwd_ind]
            for bit_addr in min_car_list:
                fwd_keys = list(self.fwd_blocks[bit_addr[4][0]][bit_addr[4][1]][2])
                bwd_keys = list(self.bwd_blocks[bit_addr[5][0]][bit_addr[5][1]][2])
                if self.attack_type == 'equivalent_key':
                    k_union, k_com = compute_key_com_key_union_between_fwd_bwd_keys(fwd_keys, bwd_keys, self.relations)
                elif self.cipher_name == 'PRESENT80':
                    k_union, k_com = compute_key_com_key_union_for_present80(fwd_keys, bwd_keys, self.relations)
                else:
                    k_union = len(list(set(fwd_keys) | set(bwd_keys)))
                    k_com = len(list(set(fwd_keys) & set(bwd_keys)))

                memory = min(bit_addr[1], bit_addr[2]) - k_com
                mem_min_car_list.append([bit_addr[0], bit_addr[1], bit_addr[2], memory, k_union, k_com, bit_addr[4],
                                         bit_addr[5]])

            # =========finding the bit addresses with the minimum cardinality and minimum memory complexity============
            mem_list = [bit_addr[3] for bit_addr in mem_min_car_list]  # the list of memory complexities
            min_mem_val = min(mem_list)  # the minimum value of the memory complexities
            min_car_min_mem_list = [] # the list of the bit addresses with the minimum cardinality and memory complexity
            for bit_addr in mem_min_car_list:  # finding the bit addresses with the minimum memory complexity
                if bit_addr[3] == min_mem_val:
                    min_car_min_mem_list.append(bit_addr)

            # =========================finding the matching points======================================================
            # dictionaries to store the sets and their corresponding indices for the forward and backward directions
            # the bit addresses that share the same set in the forward and backward directions are considered
            fwd_sets_indices = {}  # Dictionary to store sets and their corresponding indices for fwd
            bwd_sets_indices = {}  # Dictionary to store sets and their corresponding indices for bwd
            for idx, sublist in enumerate(min_car_min_mem_list):
                # Convert the set to a frozenset to use it as a dictionary key
                fwd_frozen_set = frozenset(set(self.fwd_blocks[sublist[6][0]][sublist[6][1]][2]))
                bwd_frozen_set = frozenset(set(self.bwd_blocks[sublist[7][0]][sublist[7][1]][2]))
                if fwd_frozen_set not in fwd_sets_indices:
                    fwd_sets_indices[fwd_frozen_set] = []
                if bwd_frozen_set not in bwd_sets_indices:
                    bwd_sets_indices[bwd_frozen_set] = []
                fwd_sets_indices[fwd_frozen_set].append(idx)
                bwd_sets_indices[bwd_frozen_set].append(idx)

            # the indices of the bit addresses in tim_min_mem_min that have same keys in the forward and backward
            # directions are stored in equal_sets_indices
            equal_sets_indices = []
            for indices in fwd_sets_indices.items():
                fwd_ind_list = indices[1]
                for bwd_indices in bwd_sets_indices.items():
                    bwd_ind_list = bwd_indices[1]
                    equal_indices = list(set(fwd_ind_list) & set(bwd_ind_list))
                    if equal_indices:
                        equal_sets_indices.append(equal_indices)
                        break

            # finding the indices in equal_sets_indices in a same layer (same name and round) of the round function
            pattern = re.compile(r'^[a-zA-Z*_]+_[0-9]+_[0-9]+$')  # Regex to match the format of the names of bit_addr
            max_groups = []
            for indices in equal_sets_indices:
                groups = defaultdict(list)  # Dictionary to hold groups
                for idx in indices:
                    name = min_car_min_mem_list[idx][0]  # Get the name of the bit address
                    if pattern.match(name):
                        parts = name.split('_')
                        key_group = (parts[0], parts[1])  # Group by the first two parts of the name
                        groups[key_group].append([name, idx])
                max_group = max(groups.items(), key=lambda x: len(x[1]))
                max_groups.append([max_group])
            overall_max_group = max(max_groups, key=lambda x: len(x[0][1]))

            #===========================computing the time and data complexity of the attack============================
            # min_car_min_mem_list: [name, car_fwd, car_bwd, memory, k_union, k_com, fwd_ind, bwd_ind]
            car_fwd = min_car_min_mem_list[overall_max_group[0][1][0][1]][1]
            car_bwd = min_car_min_mem_list[overall_max_group[0][1][0][1]][2]
            k_union = min_car_min_mem_list[overall_max_group[0][1][0][1]][4]
            k_com = min_car_min_mem_list[overall_max_group[0][1][0][1]][5]
            k_remaining = self.key_size - k_union
            matching_point_num = len(overall_max_group[0][1])
            matching_points = [min_car_min_mem_list[bit_addr[1]][0] for bit_addr in overall_max_group[0][1]]

            #==========form the function tau=====
            d = symbols('d') # data complexity
            t = S(self.t)
            kf = S(car_fwd)
            kb = S(car_bwd)
            kr = S(k_remaining)
            kc = S(k_com)
            m = S(matching_point_num)

            # Define the function F
            tau = d * 2 ** kf + d * 2 ** kb + t * 2 ** (kf + kb + kr - kc - (d - 1) * m)
            min_d = None # Initialize variables to track the minimum values
            min_tau_val = None
            for d_val in range(1, 1024): # Search for minimum F value for integer values of d from 0 to 1024
                tau_val = tau.subs(d, d_val)
                if min_tau_val is None or tau_val < min_tau_val:
                    min_d = d_val
                    min_tau_val = tau_val
            log_min_tau_val = float(log(min_tau_val, 2)) # Calculate log base 2 of the minimum F value
            min_time = log_min_tau_val
            min_data = min_d + 1  # Add 1 to the minimum data complexity to account for the initial difference pair
            min_memory = min_car_min_mem_list[overall_max_group[0][1][0][1]][3]

            if min_time >= self.key_size:
                print('\n\nthe time complexity of the attack is equal to exhaustive search')
                print(' The nummer of the non-linear dependent key bits in the forward direction at the matching'
                      'point(s): ', car_fwd)
                print(' The nummer of the non-linear dependent key bits in the backward direction at the matching'
                      'point(s): ', car_bwd)
                print(' The number of the union of the non-linear dependent key bits in the forward and backward'
                      'directions at the matching point(s): ', k_union)
                print(' The number of the common non-linear dependent key bits in the forward and backward directions'
                      'at the matching point(s): ', k_com)
                print(' The number of the remaining non-linear dependent key bits in the forward and backward '
                      'directions at the matching point(s): ', k_remaining)
                print(' The number of the matching point(s): ', matching_point_num)
            else:
                print('\nThe result of the Meet in the Middle attack for ', self.n_rounds, ' rounds is as follows:')
                print('\nThe time complexity of the attack to recover all the key bits involved in the forward and '
                      'backward direction is: 2^{', min_time, '}')
                print('The data complexity (number of the differences pairs of plain_txt/cipher_txt) of the attack to '
                      'recover all the key bits involved in the forward and backward direction is: ', min_data)
                print('The memory complexity of the attack to recover all the key bits involved in the forward and '
                      'backward direction is: 2^{', min_memory, '}')

                print('\nThe matching point(s) are as follows:')
                for ind, point in enumerate(matching_points):
                    print(ind, ': ', point)
                print(' The nummer of the non-linear dependent key bits in the forward direction at the matching'
                        'point(s): ', car_fwd)
                print(' The nummer of the non-linear dependent key bits in the backward direction at the matching'
                        'point(s): ', car_bwd)
                print(' The number of the union of the non-linear dependent key bits in the forward and backward'
                        'directions at the matching point(s): ', k_union)
                print(' The number of the common non-linear dependent key bits in the forward and backward directions'
                        'at the matching point(s): ', k_com)
                print(' The number of the remaining non-linear dependent key bits in the forward and backward '
                        'directions at the matching point(s): ', k_remaining)
                print(' The number of the matching point(s): ', matching_point_num)

    def find_good_bit_addr(self):
        self.create_fwd_bwd_directions()
        self.compute_fwd_bwd_cardinality()
        self.compute_max_fwd_bwd_cardinalities()
        self.compute_print_min_time_memory_data_complexity()
        print('\n\n\nDone!-------------------\n\n')

    def print_details(self, output_file="output.txt", print_key=False, print_block=False, print_block_car=False,
                      print_bit_addr_info=False):
        """
        Print details of the analysis and save them to a file.
        """
        if not (print_key or print_block or print_block_car or print_bit_addr_info):
            return

        with open(output_file, "w", encoding="utf-8") as file:

            if print_key:
                write_line(file, "=== Printing Forward and Backward Keys, each key is a list of bit names ===")
                write_line(file, "Forward Keys:")
                for round_key in self.fwd_key:
                    write_line(file, str(round_key))
                write_line(file, "\nBackward Keys:")
                for round_key in self.bwd_key:
                    write_line(file, str(round_key))
                write_line(file, "-------------------\n")

            if print_block:
                write_line(file, "=== Printing Forward and Backward Blocks, each block is a list of bit addresses, "
                                 "each bit address is a list of [name, lin, non_lin]: ===")
                write_line(file, "Forward Blocks:")
                df_fwd = pd.DataFrame(self.fwd_blocks)
                write_line(file, df_fwd.to_string(index=True))
                write_line(file, "\nBackward Blocks:")
                df_bwd = pd.DataFrame(self.bwd_blocks)
                write_line(file, df_bwd.to_string(index=True))
                write_line(file, "-------------------\n")

            if print_block_car:
                write_line(file, "=== Printing Forward and Backward Blocks Cardinality, each block is a list of "
                                 "bit addresses, each bit address is a list of [name, non_lin]:===")
                write_line(file, "Forward Blocks Cardinality:")
                df_fwd_car = pd.DataFrame(self.fwd_blocks_car)
                write_line(file, df_fwd_car.to_string(index=True))
                write_line(file, "\nBackward Blocks Cardinality:")
                df_bwd_car = pd.DataFrame(self.bwd_blocks_car)
                write_line(file, df_bwd_car.to_string(index=True))
                write_line(file, "-------------------\n")

            if print_bit_addr_info:
                write_line(file, "=== Printing Bit Address Information, each bit address is a list of [name, "
                                 "non_lin_fwd_car, non_lin_bwd_car, time complexity]:===")
                bit_addr_info = []
                for layer in self.bit_addr_info:
                    bit_addr_info.append([bit[:4] for bit in layer])
                df_bit_addr = pd.DataFrame(bit_addr_info)
                write_line(file, df_bit_addr.to_string(index=True))
                write_line(file, "-------------------\n")

        print(f"✅ Output saved to {output_file}")


    def evaluate_key_bit_diffusion(self, key_bit):
        """
        this function is used to find the key_bit positions in the forward and backward directions
        the result is saved in a file
        """

        filename = 'evaluate_key_bit_' + key_bit + '_diffusion.txt'
        open(filename, 'w').close()  # erasing the previous data in the file
        file = open(filename, 'a')
        for ind in range(2):
            directions = ['fwd', 'bwd']
            file.write('\n\n\n' + directions[ind] + ' direction:\n')
            block_ind = 0
            for ops in self.directions[ind][1:]:
                if type(ops[0]) == int:
                    for r in range(ops[0]):
                        for op in ops[1:]:
                            state_rond = apply_operation_for_evaluate_key_bit_diffusion(op, self.fwd_blocks,
                                                self.bwd_blocks, self.block_size, key_bit, block_ind, directions[ind])
                            file.write('\n' + state_rond[0] + ', ' + state_rond[2] + '\n')
                            file.write(str(state_rond[1])[1:-1])
                            block_ind += 1
                else:
                    for op in ops:
                        state_rond = apply_operation_for_evaluate_key_bit_diffusion(op, self.fwd_blocks,
                                                self.bwd_blocks, self.block_size, key_bit, block_ind, directions[ind])
                        file.write('\n\n' + state_rond[0] + ', ' + state_rond[2] + '\n')
                        file.write(str(state_rond[1]))
                        block_ind += 1
        file.close()
        print('the diffusion of the key bit ' + key_bit + ' is saved in the file: ' + filename)

    def navigate_bit_position_progress(self, bit_position):
        """
        this function is used to navigate the progress of the bit position to check the correctness of the progress
        """
        assert bit_position < self.block_size, "the bit position is out of the block size"

        print('\n\n\nnavigating the progress of the bit position ' + str(bit_position) + ':\n')


        directions = ['fwd', 'bwd']
        for ind in range(2):  # for each direction
            cipher_blocks = self.fwd_blocks if directions[ind] == 'fwd' else self.bwd_blocks
            round_key = self.fwd_key if directions[ind] == 'fwd' else self.bwd_key
            print('\nchecking the Forward direction:\n\n') if ind == 0 else print(
                '\nchecking the Backward direction:\n\n')
            block_index = 0
            rond_key_index = 0 if ind == 0 else len(self.bwd_key) - 1
            for ops in self.directions[ind][1:]:
                if type(ops[0]) == int:
                    for r in range(ops[0]):
                        for op in ops[1:]:
                            rond_key_index = apply_operations_for_navigate_bit_position_progress(cipher_blocks,
                             round_key, self.block_size, op, bit_position, block_index, rond_key_index, directions[ind])
                            block_index += 1
                else:
                    for op in ops:
                        rond_key_index = apply_operations_for_navigate_bit_position_progress(cipher_blocks, round_key,
                            self.block_size, op, bit_position, block_index, rond_key_index, directions[ind])
                        block_index += 1

