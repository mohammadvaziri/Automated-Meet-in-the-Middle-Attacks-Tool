
import copy

class GenerateRoundKey:

    def __init__(self, n_rounds, block_size, cipher_name, attack_type=None, perm_bit=None, mixing_list=None):

        self.n_rounds = n_rounds
        self.block_size = block_size
        self.cipherName = cipher_name
        # the round keys are generated based on the type of the attack : 'equivalent_key'or 'regular_key'
        self.attack_type = attack_type
        self.perm_bit = perm_bit if perm_bit else None  # is used for the key generation
        self.mixing_list = mixing_list if mixing_list else None  # is used for the key generation
        self.fwd_key = []  # key bits in the forward direction
        self.bwd_key = []  # key bits in the backward direction
        self.relations = []  # linear relations between forward and backward register keys
        self.gen_round_key()
        self.roundKey = [self.fwd_key, self.bwd_key]


    def compute_relation_between_fwd_bwd_round_key(self, register_key_fwd, register_key_bwd, mixing_list,
                                                   perm_bits=None):
        """
        since the round key backward is moved prior to mix-column (equivalent key bit) in backward direction,
        the inverse of permutation or mixing should be applied and then linear relations between the input and
        output of the mixing should be computed
        """
        size = len(register_key_bwd)
        relations_list = [[register_key_bwd[k]] for k in range(size)]

        if len(register_key_fwd) % len(mixing_list) != 0:
            raise Exception("the length of block is not divisible by the length of mixingList")
        block_copy = copy.deepcopy(register_key_fwd)
        rel_copy = copy.deepcopy(relations_list)
        if perm_bits:  # if a permutation needs to be applied prior to apply mixing
            for b in range(self.block_size):
                block_copy[b] = register_key_fwd[perm_bits[b]]
                rel_copy[b] = relations_list[perm_bits[b]]

        mixing_size = len(mixing_list)
        iterate = self.block_size // mixing_size  # the number of iterations
        for it in range(iterate):
            for m in range(mixing_size):  # for each mixing
                # the bit location is mixingSize*i+j
                bits = []
                for k in mixing_list[m]:
                    bits.append(block_copy[mixing_size * it + k])
                    bits = list(set(bits))

                rel_copy[mixing_size * it + m].append(list(bits))  # relations[mixing_size * it + m] = list(bits)

        if perm_bits:  # if a permutation applied, then it needs to be permuted back to its original order.
            list_copy = copy.deepcopy(rel_copy)
            for s in range(size):
                relations_list[perm_bits[s]] = list(list_copy[s])
        else:
            relations_list = list(rel_copy)

        return relations_list

    def gen_round_key(self):
        if self.cipherName in ['CRAFT', 'Midori64', 'Midori128', 'WARP']:

            # CRAFT and WARP share the same key schedule, but equivalent key can't be implemented on WARP
            register_key_fwd = register_key_bwd = []
            wk = wk_fwd = wk_bwd = [] # for the Midori64 and Midori128
            if self.attack_type == 'regular_key':
                register_key_fwd = register_key_bwd = ['k_' + str(k) for k in range(128)]

                if self.cipherName == 'Midori64':
                    wk = [[register_key_fwd[k], register_key_fwd[k + 64]] for k in range(64)]
                    self.fwd_key.append(list(wk)), self.bwd_key.append(list(wk))
                if self.cipherName == 'Midori128':
                    wk = register_key_fwd
                    self.fwd_key.append(list(wk)), self.bwd_key.append(list(wk))

            elif self.attack_type == 'equivalent_key':
                register_key_fwd = ['k_' + str(k) for k in range(128)]
                register_key_bwd = ['k\'_' + str(k) for k in range(128)]
                perm_bits = self.perm_bit if self.cipherName == 'CRAFT' else None

                # the linear relations between the forward and backward register keys
                if self.cipherName == 'Midori128':
                    self.relations.extend(
                        self.compute_relation_between_fwd_bwd_round_key(register_key_fwd, register_key_bwd,
                                                                        self.mixing_list, perm_bits=perm_bits))
                else:
                    self.relations.extend(
                        self.compute_relation_between_fwd_bwd_round_key(register_key_fwd[0:64], register_key_bwd[0:64],
                                                                        self.mixing_list, perm_bits=perm_bits))
                    self.relations.extend(
                        self.compute_relation_between_fwd_bwd_round_key(register_key_fwd[64:128],
                                                    register_key_bwd[64:128], self.mixing_list, perm_bits=perm_bits))
                if self.cipherName == 'Midori64':
                    wk_fwd = [[register_key_fwd[k], register_key_fwd[k + 64]] for k in range(64)]
                    wk_bwd = [[register_key_bwd[k], register_key_bwd[k + 64]] for k in range(64)]
                    self.fwd_key.append(list(wk_fwd)), self.bwd_key.append(list(wk_bwd))

                if self.cipherName == 'Midori128':
                    wk_fwd = register_key_fwd
                    wk_bwd = register_key_bwd
                    self.fwd_key.append(list(wk_fwd)), self.bwd_key.append(list(wk_bwd))

            rounds = self.n_rounds - 1 if self.cipherName in ('Midori64', 'Midori128') else self.n_rounds
            for r in range(rounds):
                if self.cipherName == 'Midori128':
                    self.fwd_key.append(list(register_key_fwd)), self.bwd_key.append(list(register_key_bwd))
                else:
                    if r % 2 == 0:
                        rond_key_fwd = list(register_key_fwd[0:64])
                        rond_key_bwd = list(register_key_bwd[0:64])
                    else:
                        rond_key_fwd = list(register_key_fwd[64:128])
                        rond_key_bwd = list(register_key_bwd[64:128])
                    self.fwd_key.append(rond_key_fwd)
                    self.bwd_key.append(rond_key_bwd)

            if self.cipherName in ('Midori64', 'Midori128'): # adding wk
                self.fwd_key.append(list(wk)) if self.attack_type == 'regular_key' else (
                    self.fwd_key.append(list(wk_fwd)))
                self.bwd_key.append(list(wk)) if self.attack_type == 'regular_key' else (
                    self.bwd_key.append(list(wk_bwd)))

        if self.cipherName == 'SATURNIN':

            if self.attack_type == 'regular_key':
                register_key_fwd = register_key_bwd = ['k_' + str(k) for k in range(256)]
                self.fwd_key.append(list(register_key_fwd))
                self.bwd_key.append(list(register_key_bwd))

                for r in range(1, self.n_rounds + 1):
                    if r % 2 == 0:
                        rond_key_fwd = list(register_key_fwd)
                        rond_key_bwd = list(register_key_bwd)
                    else:
                        rond_key_fwd = list(register_key_fwd[80:] + register_key_fwd[:80])
                        rond_key_bwd = list(register_key_bwd[80:] + register_key_bwd[:80])
                    self.fwd_key.append(rond_key_fwd)
                    self.bwd_key.append(rond_key_bwd)

            elif self.attack_type == 'equivalent_key':
                register_key_fwd = ['k_' + str(k) for k in range(256)]
                register_key_bwd1 = ['k\'_' + str(k) for k in range(256)]
                register_key_bwd2 = ['k\"_' + str(k) for k in range(256)]
                self.fwd_key.append(list(register_key_fwd)), self.bwd_key.append(list(register_key_fwd))

                self.relations.extend(
                    self.compute_relation_between_fwd_bwd_round_key(register_key_fwd, register_key_bwd1,
                                                                    self.mixing_list))
                self.relations.extend(
                    self.compute_relation_between_fwd_bwd_round_key(register_key_fwd[80:] + register_key_fwd[:80],
                                                                    register_key_bwd2, self.mixing_list))

                for r in range(1, self.n_rounds + 1):
                    if r % 2 == 0:
                        rond_key_fwd = list(register_key_fwd)
                        rond_key_bwd = list(register_key_bwd1)
                    else:
                        rond_key_fwd = list(register_key_fwd[80:] + register_key_fwd[:80])
                        rond_key_bwd = list(register_key_bwd2)
                    self.fwd_key.append(rond_key_fwd)
                    self.bwd_key.append(rond_key_bwd)

        if self.cipherName == 'PRESENT80':
            register_key = ['k_' + str(79 - ind) for ind in range(80)]
            index = 80
            for r in range(self.n_rounds + 1):
                if r == 0:
                    rond_key_fwd = list(register_key[0:64])
                    rond_key_bwd = list(register_key[0:64])
                else:

                    rotated_list = list(register_key[61:] + register_key[:61])  # rotate left
                    relations = rotated_list[0:4]
                    rotated_list[:4] = ['k_' + str(index + ind) for ind in
                                        range(3, -1, -1)]  # apply the S-box on the first 4 bits
                    relations += rotated_list[0:4]
                    self.relations.append(relations) #
                    index += 4
                    register_key = list(rotated_list)
                    rond_key_fwd = list(rotated_list[0:64])
                    rond_key_bwd = list(rotated_list[0:64])
                self.fwd_key.append(rond_key_fwd)
                self.bwd_key.append(rond_key_bwd)

        if self.cipherName == 'ARADI':
            def _linear_map_m(rot_i, rot_j, x, y):
                s_i_y = y[rot_i:] + y[:rot_i]
                s_j_x = x[rot_j:] + x[:rot_j]
                key_1 = [[] for _ in range(32)]
                key_2 = [[] for _ in range(32)]

                for ind in range(32):
                    for bit_list in [s_i_y[ind], s_j_x[ind], x[ind]]:
                        for key_bit in bit_list:
                            key_1[ind].remove(key_bit) if key_bit in key_1[ind] else key_1[ind].append(key_bit)
                    for bit_list in [s_i_y[ind], x[ind]]:
                        for key_bit in bit_list:
                            key_2[ind].remove(key_bit) if key_bit in key_2[ind] else key_2[ind].append(key_bit)

                return key_1, key_2


            register_key = [['k_' + str(256 - ind)] for ind in range(256)]
            k_7 = register_key[0:32]  # k_0 is the least significant 32 bits of the key word
            k_6 = register_key[32:64]
            k_5 = register_key[64:96]
            k_4 = register_key[96:128]
            k_3 = register_key[128:160]
            k_2 = register_key[160:192]
            k_1 = register_key[192:224]
            k_0 = register_key[224:256]
            key_words = [k_7, k_6, k_5, k_4, k_3, k_2, k_1, k_0]

            for r in range(self.n_rounds+1):
                mod = r % 2
                k_r_3 = key_words[4 * mod + 3]
                k_r_2 = key_words[4 * mod + 2]
                k_r_1 = key_words[4 * mod + 1]
                k_r_0 = key_words[4 * mod]
                rond_key = [*k_r_3, *k_r_2, *k_r_1, *k_r_0]
                self.fwd_key.append(rond_key)
                self.bwd_key.append(rond_key)

                # print('k_0[0]', k_0[0])
                k_1, k_0 = _linear_map_m(1, 3, k_1, k_0)
                k_3, k_2 = _linear_map_m(9, 28, k_3, k_2)
                k_5, k_4 = _linear_map_m(1, 3, k_5, k_4)
                k_7, k_6 = _linear_map_m(9, 28, k_7, k_6)

                if mod == 0:
                    k_1, k_2 = list(k_2), list(k_1)
                    k_5, k_6 = list(k_6), list(k_5)
                else:
                    k_1, k_4 = list(k_4), list(k_1)
                    k_3, k_6 = list(k_6), list(k_3)
                key_words = [k_7, k_6, k_5, k_4, k_3, k_2, k_1, k_0]




