

import numpy as np
import subprocess
import os




def return_required_lists_for_operation(operation):
    """
    returns s_box list, and perm_bit, if the operation is s_box and
    returns mixing_list and perm_bit if the operation is mixing
    """
    list1 = operation[3] if isinstance(operation[0], list) else operation[2]
    list2 = operation[4] if isinstance(operation[0], list) and len(operation) == 5 else (
        operation[3] if isinstance(operation[0], str) and len(operation) == 4 else None)
    return list1, list2


def return_bwd_matrix(bwd_round_key, relations, key_involved):
    """
    returns the bwd_matrix and also key_involved
    """
    for bwd_key in bwd_round_key:
        for keys in relations:
            if bwd_key == keys[0]:
                key_involved.update(keys[1])
                break
    key_involved = list(key_involved)

    # fill each row with linear relations according to the linear relations
    bwd_matrix = np.zeros((len(bwd_round_key), len(key_involved)))
    for ind1, bwd_key in enumerate(bwd_round_key):
        for rels in relations:
            if bwd_key == rels[0]:
                for k_f in rels[1]:
                    for ind2, k_i in enumerate(key_involved):
                        if k_f == k_i:
                            bwd_matrix[ind1][ind2] = 1
                break

    return bwd_matrix, key_involved



def compute_cardinality_with_guess_and_determine(non_lin_keys, relations):
    """
    this function computes the cardinality of the set of key bits with the guess and determine tool
    :param non_lin_keys:
    :param relations:
    :return:
    """
    print('non_lin_keys:', non_lin_keys)
    print('len non_lin_keys', len(non_lin_keys))
    model = 'connection relations\n'
    if non_lin_keys:
        keys_involved = []
        for relation in relations:
            rel_in_keys = []  # relation in that can be extracted in non_lin_keys
            for k in relation:
                if k in non_lin_keys:
                    rel_in_keys.append(k)
            print('rel_in_keys:', rel_in_keys)
            if len(rel_in_keys) > 4:
                for i1 in range(2):
                    for i2 in range(4):
                        for k in range(4):
                            model += relation[i1 * 4 + k] + ', '
                        model = model[:-2] + ' => ' + relation[((i1 + 1) * 4 + i2) % 8] + '\n'
                keys_involved += [k for k in rel_in_keys]
        if model != 'connection relations\n':

            model += 'target\n'
            for k in keys_involved:
                model += k + '\n'
            model += 'end\n'
            print('model:\n', model)
            print('len keys_involved', len(keys_involved))

            input_filename = 'tmp.txt'
            with open(input_filename, 'w') as file:
                file.write(model)
            # Run autoguess.py with the temporary file using subprocess.run
            command = f'python3 autoguess.py --inputfile {input_filename} --solver groebner'
            result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    text=True)

            os.remove(input_filename)  # Clean up the temporary file
            guessed_number = int(result.stdout.strip())  # Convert the output to an integer

            print('guessed_number', guessed_number)
            car = len(non_lin_keys) - len(keys_involved) + guessed_number
            print('car:', car, '\n')
            return car
        else:
            car = len(non_lin_keys)
            print('car:', car, '\n')
            return car
    else:
        car = 0
        print('car:', car, '\n')
        return car

def compute_non_lin_keys_for_present80(non_lin_keys, relations):
    """
    for each s-box that is applied on the round key schedule of the PRESENT80, we guess 4 of them amd the rest
    can be deduced from the guessed ones
    until round 17 there is no dependencies between the inputs and outputs of the s-boxes
    """
    if non_lin_keys:
        for relation in relations:
            rel_in_keys = []  # relation in that can be extracted in non_lin_keys
            for k in relation:
                if k in non_lin_keys:
                    rel_in_keys.append(k)
            if len(rel_in_keys) > 4:
                non_lin_keys = list(set(non_lin_keys) - set(rel_in_keys[4:]))
    length = len(non_lin_keys)
    return length

def compute_key_com_key_union_between_fwd_bwd_keys(fwd_key, bwd_key, relations):
    """
    this function computes the cardinality of comon key bits and also key union bits sets between the forward
    and backward round key
    """
    key_involved = set(fwd_key)  # key_involved contains all the key bits in the forward and backward direction
    bwd_matrix, key_involved = return_bwd_matrix(bwd_key, relations, key_involved)
    fwd_matrix = np.zeros((len(fwd_key), len(key_involved)))
    for ind1, fk in enumerate(fwd_key):
        for ind2, inv_key in enumerate(key_involved):  # each column represents just one key_bit in key_involved
            if fk == inv_key:
                fwd_matrix[ind1][ind2] = 1
                break

    union_matrix = np.vstack((fwd_matrix, bwd_matrix))
    k_union_car = np.linalg.matrix_rank(union_matrix)
    k_com_car = len(fwd_key) + len(bwd_key) - k_union_car
    return int(k_union_car), int(k_com_car)


def compute_key_com_key_union_for_present80(fwd_key, bwd_key, relations):

    key_union = list(set(fwd_key) | set(bwd_key))
    fwd_key_car = compute_non_lin_keys_for_present80(fwd_key, relations)
    bwd_key_car = compute_non_lin_keys_for_present80(bwd_key, relations)
    key_union_car = compute_non_lin_keys_for_present80(key_union, relations)
    k_com_car = fwd_key_car + bwd_key_car - key_union_car
    return key_union_car, k_com_car


def apply_operation_for_evaluate_key_bit_diffusion(opr, fwd_blocks, bwd_blocks, block_size, key_b, block_index,
                                                    direction):

    blocks = fwd_blocks if direction == 'fwd' else bwd_blocks
    state = ['-,-'] * block_size

    for index in range(block_size):
        if key_b in blocks[block_index][index][1]:
            state[index] = 'x,-'  # the key-bit is in linear set
        if key_b in blocks[block_index][index][2]:
            state[index] = '-,x'  # the key-bit is in nonlinear set

    bit_sym = blocks[block_index][0][0].split('_')[:3]  # Split the string and take the first three parts
    bit = '_'.join(bit_sym)  # Join the parts using underscore

    operation = opr[2] if isinstance(opr[0], list) else opr[1]
    if operation == 'key_addition':
        state = ['key_addition', state, bit]
    elif operation == 's_box':
        state = ['s_box', state, bit]
    elif operation == 'perm':
        state = ['perm', state, bit]
    elif operation == 'perm_inv':
        state = ['perm_inv', state, bit]
    elif operation == 'mixing':
        state = ['mixing', state, bit]
    elif operation == 'xor':
        state = ['xor', state, bit]
    elif operation == '-':
        state = ['-', state, bit]
    return state

def apply_operations_for_navigate_bit_position_progress(blocks, rond_key, block_size, opr, bit_pos, block_ind,
                                                         rond_key_ind, direction):
    per_block_ind = block_ind if block_ind == 0 else block_ind - 1  # the index of the previous block
    operation = opr[2] if isinstance(opr[0], list) else opr[1]

    if operation == 'key_addition':
        print('\nchecking the bit address ' + blocks[block_ind][bit_pos][
            0] + ' after applying key_addition:')
        pattern = opr[0] if isinstance(opr[0], list) else [index for index in range(block_size)]
        if bit_pos in pattern:
            index = pattern.index(bit_pos)
            rond_key = rond_key[rond_key_ind][index] if isinstance(rond_key[rond_key_ind][index], list) else [
                rond_key[rond_key_ind][index]]
            rond_key_ind += 1 if direction == 'fwd' else -1
            bit = blocks[block_ind][bit_pos]
            print('the key bit(s) are: ', rond_key)
            print('the bit address after key addition is: ', bit)
            for k in rond_key:
                if k in bit[1] or k in bit[2]:
                    print('the key bit ' + k + ' is correctly added')
                if k in bit[1] and k in bit[2]:
                    print(bit, '\n')
                    raise Exception("the key bit " + k + " is added in both linear and nonlinear sets")
                if k not in bit[1] and k not in bit[2]:
                    print(bit, '\n')
                    raise Exception("the key bit " + k + " is not added")
        else:
            print('The bit address', blocks[block_ind][bit_pos][0],
                  'is not affected by the key_addition\n')
            print(bit_pos, blocks[per_block_ind][bit_pos])
            print(bit_pos, blocks[block_ind][bit_pos])

    elif operation == 's_box':
        print('\nchecking the bit address', blocks[block_ind][bit_pos][0], 'after applying s_box:')
        pattern = opr[0] if isinstance(opr[0], list) else None
        input_indices = pattern[0] if pattern else [index for index in range(block_size)]
        output_indices = pattern[1] if pattern else [index for index in range(block_size)]
        s_box_list, perm_bit = return_required_lists_for_operation(opr)

        lin_dependent_indices = s_box_list[0] if len(s_box_list) == 2 else s_box_list
        non_lin_dependent_indices = s_box_list[1] if len(s_box_list) == 2 else None
        print('the indices of liner input bits for each output bit of the s_box is:', lin_dependent_indices)
        if non_lin_dependent_indices:
            print('the indices of non_liner input bits for each output bit of the s_box is:',
                  non_lin_dependent_indices)

        if perm_bit: print('the permutation should be applied before applying s_box')


        bit_perm = perm_bit[bit_pos] if perm_bit else bit_pos
        if bit_perm in output_indices:  # if the bit_pos is affected by the s_box
            s_box_size = len(lin_dependent_indices)
            box_ord = output_indices.index(
                bit_perm) // s_box_size  # the order of the s_box that are supposed to be applied on the block
            indices = [] # the indices of the inputs of the s_box
            for ind in range(s_box_size):
                index = perm_bit.index(box_ord * s_box_size + ind) if perm_bit else box_ord * s_box_size + ind
                indices.append(index)
            box_indices = [input_indices[index] for index in indices]  # the indices of the input bits of s_box

            lin_status = lin_dependent_indices[bit_perm % s_box_size]
            non_lin_status = non_lin_dependent_indices[bit_perm % s_box_size] if non_lin_dependent_indices else []

            for ind, in_bit in enumerate(box_indices):
                in_status = ind % s_box_size
                other_keys = []
                indices = list(set(box_indices) - {in_bit})
                for index2 in indices:
                    other_keys.extend(blocks[per_block_ind][index2][1])
                    other_keys.extend(blocks[per_block_ind][index2][2])
                other_keys = set(other_keys)

                if in_status in lin_status:
                    for key_bit in blocks[per_block_ind][in_bit][2]:
                        if key_bit not in blocks[block_ind][bit_pos][2]:
                            raise Exception("the key bit", key_bit, "is not added to the nonlinear set")
                    for key_bit in blocks[per_block_ind][in_bit][1]:
                        if key_bit not in other_keys and key_bit not in blocks[block_ind][bit_pos][1]:
                            raise Exception("the key bit", key_bit, "is not added to the linear set")

                elif in_status in non_lin_status:
                    for key_bit in list(set(blocks[per_block_ind][in_bit][1]) |
                                        set(blocks[per_block_ind][in_bit][2])):
                        if key_bit not in blocks[block_ind][bit_pos][2]:
                            raise Exception("the key bit", key_bit, "is not added to the nonlinear set")

            print('the output bit address of the s_box is:')
            print(bit_pos, blocks[block_ind][bit_pos])
            print('all the key bits are correctly added\n')

        else:
            print('The bit address', blocks[block_ind][bit_pos][0], 'is not affected by the s_box\n')
            print(bit_pos, blocks[per_block_ind][bit_pos])
            print(bit_pos, blocks[block_ind][bit_pos])

    elif operation == 'mixing':
        print('\nchecking the bit position', bit_pos, 'after applying Mix column:')
        mixing_list, perm_bit = return_required_lists_for_operation(opr)


        if perm_bit: print('the permutation should be applied before applying mixing')
        mix_size = len(mixing_list)
        # the index of the mixing that should be applied on the bit position
        mix_index = perm_bit[
                        bit_pos] % mix_size if perm_bit else bit_pos % mix_size
        # the order of the column that the bit position is located
        column_ord = perm_bit[
                         bit_pos] // mix_size if perm_bit else bit_pos // mix_size
        print('the mixing that should be applied on the bit position', bit_pos, 'is:',
              mixing_list[mix_index])
        print('the bit addresses that are supposed to be mixed are:')
        lin_keys = []
        non_lin_keys = []
        for index in mixing_list[mix_index]:
            mix_ind = mix_size * column_ord + index
            checking_bit = blocks[per_block_ind][perm_bit[mix_ind]] if perm_bit else blocks[per_block_ind][mix_ind]
            print(mix_ind, checking_bit)
            for key_bit in checking_bit[1]:
                lin_keys.append(key_bit)
            for key_bit in checking_bit[2]:
                non_lin_keys.append(key_bit)
                if key_bit not in blocks[block_ind][bit_pos][2]:
                    raise Exception(f"the key bit {key_bit} is not added to the linear set")

        lin_keys = list(set(lin_keys) - set(non_lin_keys))
        for key_bit in lin_keys:
            if key_bit not in blocks[block_ind][bit_pos][1]:
                print('the output: ', bit_pos, blocks[block_ind][bit_pos])
                print(key_bit)
                raise Exception(f"the key bit {key_bit} is not added to the linear set")

        lin_remaining = set(blocks[block_ind][bit_pos][1]) - set(lin_keys)
        non_lin_remaining = set(blocks[block_ind][bit_pos][2]) - set(non_lin_keys)
        if lin_remaining: raise Exception("the linear set contains extra key bits:", lin_remaining)
        if non_lin_remaining: raise Exception("the nonlinear set contains extra key bits:", non_lin_remaining)
        print('the bit addresses at the position', bit_pos, 'after applying Mix column:')
        print(bit_pos, blocks[block_ind][bit_pos])
        print('all the key bits are correctly added\n')

    elif operation == 'perm':
        perm_bit = opr[2]
        print('\nchecking the bit address ' + blocks[per_block_ind][bit_pos][
            0] + ' after applying permutation:')
        print('permutation(' + str(perm_bit.index(bit_pos)) + ') = ' + str(bit_pos))

        print('the content of the bit address ' + blocks[per_block_ind][perm_bit.index(bit_pos)][
            0] + ' in the position ' + str(
            perm_bit.index(bit_pos)) + ' should be permuted to the position ' + str(bit_pos))
        print('the content of the bit address in the position ' + str(
            perm_bit.index(bit_pos)) + ' before applying inverse permutation is:\n' + str(
            blocks[per_block_ind][perm_bit.index(bit_pos)]))
        print('the content of the bit address in the position ' + str(
            bit_pos) + ' after applying permutation is:\n' + str(blocks[block_ind][bit_pos]))
        if ((blocks[per_block_ind][perm_bit.index(bit_pos)][1] != blocks[block_ind][bit_pos][1]) or
                (blocks[per_block_ind][perm_bit.index(bit_pos)][2] != blocks[block_ind][bit_pos][2])):
            raise Exception("the inverse permutation is not correctly applied")
        print('the bit address is correctly permuted\n')

    elif operation == 'perm_inv':
        perm_bit = opr[2]
        print('\nchecking the bit address ' + blocks[per_block_ind][bit_pos][
            0] + ' after applying inverse permutation:')
        print('permutationInv(' + str(bit_pos) + ') = ' + str(perm_bit[bit_pos]))
        print('According to the permutation, the content of the bit address ' +
              blocks[per_block_ind][perm_bit[bit_pos]][
                  0] + ' in the position ' + str(
            perm_bit[bit_pos]) + ' should be permuted back to the position ' + str(bit_pos))
        print('the content of the bit address in the position ' + str(
            perm_bit[bit_pos]) + ' before applying permutation is:\n' + str(
            blocks[per_block_ind][perm_bit[bit_pos]]))
        print('the content of the bit address in the position ' + str(
            bit_pos) + ' after applying permutation is:\n' + str(
            blocks[block_ind][bit_pos]))
        if ((blocks[per_block_ind][perm_bit[bit_pos]][1] != blocks[block_ind][bit_pos][1]) or
                (blocks[per_block_ind][perm_bit[bit_pos]][2] != blocks[block_ind][bit_pos][2])):
            raise Exception("the permutation is not correctly applied")
        print('the bit address is correctly permuted\n')

    elif operation == 'xor':

        print('\nchecking the bit position', bit_pos, 'after applying xor:')
        pattern = opr[0] if isinstance(opr[0], list) else [index for index in range(block_size)]
        blocks_id = opr[3] if isinstance(opr[0], list) else opr[2]

        b_ids = [-1] * 2
        for index, iden in enumerate(blocks_id):
            for bl in blocks[block_ind - 1::-1]:
                if iden in bl[0][0]:
                    b_ids[index] = blocks.index(bl)
                    break

        if b_ids[0] != -1 and b_ids[1] != -1:
            input1 = blocks[b_ids[0]][bit_pos]
            input2 = blocks[b_ids[1]][bit_pos]
            output = blocks[block_ind][bit_pos]
            lin_input1 = input1[1]
            lin_input2 = input2[1]
            non_lin_input1 = input1[2]
            non_lin_input2 = input2[2]

            print('the input bit addresses of the xor are:')
            print(bit_pos, 'input1:', input1)
            print(bit_pos, 'input2:', input2)

            if bit_pos in pattern:
                print('the bit addresses that are supposed to be exclusive-or-ed are:')
                lin_union_input = list(set(lin_input1 + lin_input2))
                non_lin_union_input = list(set(non_lin_input1 + non_lin_input2))
                lin_intersection_input = list(set(lin_input1) & set(lin_input2))
                lin_in_non_lin_input = list(set(lin_union_input) & set(non_lin_union_input))
                lin_legal = list(set(lin_union_input) - set(lin_intersection_input) - set(lin_in_non_lin_input))

                for key_bit in non_lin_input1:
                    if key_bit not in output[2]:
                        raise Exception(f"the key bit {key_bit} is not added to the nonlinear set")
                for key_bit in non_lin_input2:
                    if key_bit not in output[2]:
                        raise Exception(f"the key bit {key_bit} is not added to the nonlinear set")
                for key_bit in lin_intersection_input:
                    if key_bit in output[1]:
                        raise Exception(f"the key bit {key_bit} should not be added to the linear set")
                for key_bit in lin_in_non_lin_input:
                    if key_bit in output[1]:
                        raise Exception(f"the key bit {key_bit} should not be added to the linear set")

                if set(lin_legal) != set(output[1]):
                    raise Exception("the linear set is not correctly added")

            else:
                print('The bit address', blocks[block_ind][bit_pos][0], 'is not affected by the xor\n')
                if lin_input1 != lin_input2:
                    raise Exception("the linear sets are not equal")
                if non_lin_input1 != non_lin_input2:
                    raise Exception("the nonlinear sets are not equal")

        if b_ids[0] == -1 or b_ids[1] == -1:
            index = b_ids[0] if b_ids[0] != -1 else b_ids[1]
            input_bits = blocks[index][bit_pos]
            if (set(input_bits[1]) != set(blocks[block_ind][bit_pos][1]) or
                    set(input_bits[2]) != set(blocks[block_ind][bit_pos][2])):
                raise Exception("the xor is not correctly applied")

        print('the bit addresses at the position', bit_pos, 'after applying xor:')
        print(bit_pos, blocks[block_ind][bit_pos])
        print('all the key bits are correctly added\n')

    return rond_key_ind

def write_line(file, text=""):
    """Helper function to write text to a file."""
    file.write(text + "\n")


