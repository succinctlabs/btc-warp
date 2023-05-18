FACTORS = [11,10,10]
B = [1, 1, 1]
M = [100, 10, 1]

all_layer_blocks = []

for l in range(3):
    print("layer", l)
    layer_blocks = []
    for job_index in range(M[l]):
        if l == 0:
            nb_proofs = B[0]
            nb_blocks_per_proof = FACTORS[0]
            offset = job_index * nb_proofs * (nb_blocks_per_proof - 1)
            for i in range(nb_proofs):
                print("[", end="")
                start = offset + i * (nb_blocks_per_proof-1)
                end = offset + (i+1) * (nb_blocks_per_proof-1)
                print(start, end=",")
                print(end, end="")
                print("]")
                layer_blocks.append("[{start},{end}]".format(start=start, end=end))
        else:
            sub_1 = 1 if l > 1 else 1
            nb_proofs = B[l]
            child_proofs_per_proof = FACTORS[l]
            offset = job_index * nb_proofs * (child_proofs_per_proof)
            for i in range(nb_proofs):
                print("[", end="")
                start = offset + i * (child_proofs_per_proof)
                end = offset + (i+1) * (child_proofs_per_proof) - 1
                print(start, end=",")
                print(end, end="")
                print("]")
                layer_blocks.append("[{start},{end}]".format(start=start, end=end))
                print("start", all_layer_blocks[l-1][start])
                print("end", all_layer_blocks[l-1][end])
    print(len(layer_blocks))
    all_layer_blocks.append(layer_blocks)