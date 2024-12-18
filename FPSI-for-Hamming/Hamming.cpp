
#include "Hamming.h"

namespace osuCrypto
{
    namespace Hamming{
        const u64 OT_NUMS_BOUND = 128UL;
        const size_t KAPPA = 128;
        std::vector<element> run_ot_receiver(coproto::LocalAsyncSocket& channel, BitVector& choices, const u64& numOTs){
        // std::vector<element> result;
        std::vector<block> recvMsg(numOTs);

        if(numOTs <= OT_NUMS_BOUND) // using libOTe-CO15
        {
            PRNG prng(block(oc::sysRandomSeed()));
            osuCrypto::DefaultBaseOT baseOTs;
            std::vector<block> mask(numOTs);
            std::vector<block> maskMsg1(numOTs);
            std::vector<block> maskMsg0(numOTs);

            // random OT
            // std::cout << " recv: choices: " << choices << std::endl;
            auto p = baseOTs.receive(choices, mask, prng, channel);
            auto r = macoro::sync_wait(macoro::when_all_ready(std::move(p)));
            std::get<0>(r).result();

            // random OT -> OT
            coproto::sync_wait(channel.recv(maskMsg1));
            coproto::sync_wait(channel.recv(maskMsg0));
            for(u64 i = 0; i < numOTs; i++)
            {
                if(choices[i] == 1){
                    recvMsg[i] = maskMsg1[i] ^ mask[i];
                }else{
                    recvMsg[i] = maskMsg0[i] ^ mask[i];
                }
            }
        }
        else
        {   
            
            PRNG prng(block(oc::sysRandomSeed()));
            osuCrypto::DefaultBaseOT baseOTs;
            std::vector<block> mask(numOTs);
            std::vector<block> maskMsg1(numOTs);
            std::vector<block> maskMsg0(numOTs);

            std::vector<std::array<element, 2>> baseSend(KAPPA);

            prng.get((u8*)baseSend.data()->data(), sizeof(block) * 2 * baseSend.size());
            auto p = baseOTs.send(baseSend, prng, channel);
            auto r = macoro::sync_wait(macoro::when_all_ready(std::move(p)));
            std::get<0>(r).result();

            osuCrypto::IknpOtExtReceiver recv;
            recv.setBaseOts(baseSend);
            auto proto = recv.receive(choices, mask, prng, channel);
            auto result = macoro::sync_wait(macoro::when_all_ready(std::move(proto)));
            std::get<0>(result).result();

            // random OT -> OT
            coproto::sync_wait(channel.recv(maskMsg1));
            coproto::sync_wait(channel.recv(maskMsg0));
            for(u64 i = 0; i < numOTs; i++)
            {
                if(choices[i] == 1){
                    recvMsg[i] = maskMsg1[i] ^ mask[i];
                }else{
                    recvMsg[i] = maskMsg0[i] ^ mask[i];
                }
            }
        }

        // for(u64 i = 0; i < numOTs; i++)
        // {
        //     if(choices[i] == 1)
        //     {
        //         result.push_back(element(recvMsg[i]));
        //     }
        // }

        return recvMsg;
    }

        void run_ot_sender(coproto::LocalAsyncSocket& channel, std::vector<std::array<element, 2>>& sendMsg)
        {
            const u64 numOTs(sendMsg.size());

            if(numOTs <= OT_NUMS_BOUND)
            {
                osuCrypto::DefaultBaseOT baseOTs;
                PRNG prng(block(oc::sysRandomSeed()));
                std::vector<block> half_sendMsg(numOTs);
                std::vector<std::array<element, 2>> randMsg(numOTs);

                // random OT
                auto p = baseOTs.send(randMsg, prng, channel);
                auto r = macoro::sync_wait(macoro::when_all_ready(std::move(p)));
                std::get<0>(r).result();

                // random OT -> OT
                for(u64 i = 0; i < numOTs; i++)
                {
                    half_sendMsg[i] = sendMsg[i][1] ^ randMsg[i][1];
                }
                coproto::sync_wait(channel.send(half_sendMsg));
                for(u64 i = 0; i < numOTs; i++)
                {
                    half_sendMsg[i] = sendMsg[i][0] ^ randMsg[i][0];
                }
                coproto::sync_wait(channel.send(half_sendMsg));
            }
            else
            {
                osuCrypto::DefaultBaseOT baseOTs;
                PRNG prng(block(oc::sysRandomSeed()));
                std::vector<block> half_sendMsg(numOTs);
                std::vector<std::array<element, 2>> randMsg(numOTs);

                std::vector<block> baseRecv(KAPPA);
                osuCrypto::BitVector baseChoice(KAPPA);
                
                baseChoice.randomize(prng);

                // random OT (base)
                auto p = baseOTs.receive(baseChoice, baseRecv, prng, channel);
                auto r = macoro::sync_wait(macoro::when_all_ready(std::move(p)));
                std::get<0>(r).result();

                osuCrypto::IknpOtExtSender sender;
                sender.setBaseOts(baseRecv, baseChoice);
                auto proto = sender.send(randMsg, prng, channel);
                auto result = macoro::sync_wait(macoro::when_all_ready(std::move(proto)));
                std::get<0>(result).result();

                // random OT -> OT
                for(u64 i = 0; i < numOTs; i++)
                {
                    half_sendMsg[i] = sendMsg[i][1] ^ randMsg[i][1];
                }
                coproto::sync_wait(channel.send(half_sendMsg));
                
                for(u64 i = 0; i < numOTs; i++)
                {
                    half_sendMsg[i] = sendMsg[i][0] ^ randMsg[i][0];
                }
                coproto::sync_wait(channel.send(half_sendMsg));

                return;
            }
        }

        inline u64 count_trailing_zeros(const u64& a){
            if(a == 0){
                return 64;
            }

            block temp_a(a);
            u64 cnt(0);
            while((temp_a&block(1)) == block(0)){
                temp_a >>= 1;
                cnt ++;
            }
            return cnt;
        }

        inline u64 count_trailing_ones(const u64& a){
            block temp_a(a);
            u64 cnt(0);
            while((temp_a&block(1)) == block(1)){
                temp_a >>= 1;
                cnt ++;
            }
            return cnt;
        }

        void interval_to_prefix(const u64& a, const u64& b, std::vector<block>& prefixes){
            u64 start(a), end(b);
            u64 num_zeros, num_ones;
            u64 length((b - a) + 1);
            block container;
            while(start < end){
                num_zeros = count_trailing_zeros(start);
                if((num_zeros == 64)||(((1) << num_zeros) > length)){
                    break;
                }
                container = block(((start >> num_zeros)), num_zeros);
                //printf("recv pre: %d, %d\n", (start >> num_zeros), num_zeros);
                prefixes.push_back(container);
                start += ((1) << num_zeros);
                length -= ((1) << num_zeros);
            }

            while(start < end){
                num_ones = count_trailing_ones(end);
                container = block(((end >> num_ones)), num_ones);
                //printf("recv pre: %d, %d\n", end >> num_ones, num_ones);
                prefixes.push_back(container);
                if(end < ((1) << num_ones)){
                    end = 1;
                    break;
                }
                end -= ((1) << num_ones);
            }

            if(start == end){
                container = block(start, 0);
                //printf("recv pre: %d, %d\n", start, 0);
                prefixes.push_back(container);
            }

            return;
        }

        void block_to_prefix(const u64& x, const int& log_delta, std::vector<block>& prefixes){
            block container;
            for(auto i = 0; i < log_delta; i++){
                container = block((x >> i), i);
                //printf("send pre: %d, %d\n", x >> i, i);
                prefixes.push_back(container);
            }
            return;
        }

        bool run_ipmt_receiver(coproto::LocalAsyncSocket& channel, const u64& x, const int& log_delta, const DH25519_number& recv_sk){

            std::vector<DH25519_point> recv_prefix_k, send_prefix_k, recv_prefix_kk, send_prefix_kk;
            std::vector<block> recv_prefixes;
            block_to_prefix(x, log_delta, recv_prefixes);

            for(auto iterator : recv_prefixes){
                recv_prefix_k.push_back(DH25519_point(iterator) * recv_sk);
            }

            //coproto::sync_wait((channel).flush());
            coproto::sync_wait((channel).send(recv_prefix_k));
            
            coproto::sync_wait((channel).flush());
            coproto::sync_wait((channel).recvResize(send_prefix_k));

            for(auto iterator : send_prefix_k){
                send_prefix_kk.push_back(iterator * recv_sk);
            }

            coproto::sync_wait((channel).flush());
            coproto::sync_wait((channel).recvResize(recv_prefix_kk));

            bool temp = false;
            for(auto iter : send_prefix_kk){
                auto it_find = find(recv_prefix_kk.begin(), recv_prefix_kk.end(), iter);
                if(it_find != recv_prefix_kk.end()){
                    temp = true;
                }
            }

            //printf("recv = %d\n", temp);

            return temp;
        }

        void run_ipmt_sender(coproto::LocalAsyncSocket& channel, const u64& a, const u64& b, const DH25519_number& send_sk){
            std::vector<DH25519_point> recv_prefix_k, send_prefix_k, recv_prefix_kk;
            std::vector<block> send_prefixes;
            interval_to_prefix(a, b, send_prefixes);

            for(auto iterator : send_prefixes){
                send_prefix_k.push_back(DH25519_point(iterator) * send_sk);
            }
            
            coproto::sync_wait((channel).recvResize(recv_prefix_k));
            
            coproto::sync_wait((channel).flush());
            coproto::sync_wait((channel).send(send_prefix_k));

            for(auto iterator : recv_prefix_k){
                recv_prefix_kk.push_back(iterator * send_sk);
            }

            coproto::sync_wait((channel).flush());
            coproto::sync_wait((channel).send(recv_prefix_kk));

            return;
        }


        void receiver_precomp_value_hamming(const std::size_t& elements_size,
        std::stack<std::array<std::vector<block>, 2>>& pre_vals,
        const u32& dimension, const u32& delta, pubkey_t* gm_pubkey){
            mpz_t cipher_bit;
            mpz_init(cipher_bit);

            for(u64 i = 0; i < elements_size * (delta + 1) * dimension; i++){
                std::vector<block> temp_val_0(GM_CIPHER_LENGTH_BLOCKS, ZeroBlock);
                std::vector<block> temp_val_1(GM_CIPHER_LENGTH_BLOCKS, ZeroBlock);
                enc_bit(&cipher_bit, 0, gm_pubkey);
                gm_cipher_to_block_vector(&cipher_bit, &(temp_val_0[0]));

                enc_bit(&cipher_bit, 1, gm_pubkey);
                gm_cipher_to_block_vector(&cipher_bit, &(temp_val_1[0]));

                std::array<std::vector<block>, 2> temp_val_pair = {temp_val_0, temp_val_1};
                pre_vals.push(temp_val_pair);
            }

            mpz_clear(cipher_bit);
            return;
        }

        void receiver_value_hamming(const std::vector<BitVector>& elements, const std::size_t& elements_size,
        std::stack<std::array<std::vector<block>, 2>>& pre_vals,
        std::vector<std::vector<block>>& vals,
        const u32& dimension, const u32& delta){
            mpz_t cipher_bit;
            mpz_init(cipher_bit);

            for(u64 i = 0; i < elements_size; i ++){
                for(u64 j = 0; j < delta + 1; j++){
                    std::vector<block> temp_val;
                    for(u64 k =0; k < dimension;k++){

                        // std::vector<block> temp_val_bit(GM_CIPHER_LENGTH_BLOCKS, ZeroBlock);
                        // enc_bit(&cipher_bit, (elements[i][k]==1) , gm_pubkey);
                        // gm_cipher_to_block_vector(&cipher_bit, &(temp_val_bit[0]));

                        // if((i==0)&(j==0)&(k==1)){
                        //     gmp_printf("\n\nrecv The cyphertext is : %Zd\n\n", cipher_bit);
                        //     std:: cout << temp_val_bit[0] << std::endl;
                        //     std:: cout << temp_val_bit[1] << std::endl;

                        // }

                        //temp_val.insert(temp_val.end(),temp_val_bit.begin(), temp_val_bit.end());

                        temp_val.insert(temp_val.end(),pre_vals.top()[(elements[i][k]==1)].begin(), pre_vals.top()[(elements[i][k]==1)].end());
                        pre_vals.pop();
                    }
                    vals.push_back(temp_val);
                }
            }
            mpz_clear(cipher_bit);
            return;
        }

        void receiver_key_hamming(const std::vector<BitVector>& elements, const std::size_t& elements_size, const std::vector<std::vector<u64>>& unique_components,
        std::vector<block>& keys,
        const u32& dimension, const u32& delta, const u32& side_length){

            for(u64 i = 0; i < elements_size; i ++){
                for(u64 j = 0; j < delta +1; j++){
                    u64 temp = 0;
                    u64 unique_component = unique_components[i][j];
                    for(u64 k = unique_component * side_length ; k < unique_component * side_length + side_length; k++){
                        temp <<= 1;
                        temp += ((elements[i][k]==1));
                    }
                    keys.push_back(block(unique_component, temp));
                }
            }
        }

        block sender_key_hamming(const BitVector& element, const u64& index,
        const u32& dimension, const u32& side_length){

            u64 temp = 0;
            u64 unique_component = index;
            for(u64 k = unique_component * side_length ; k < unique_component * side_length + side_length; k++){
                temp <<= 1;
                temp += ((element[k]==1));
            }
            
            return block(index, temp);
        }

        void sender_precomp_mask_hamming(const std::size_t& elements_size,
        std::stack<BitVector>& masks, std::stack<std::vector<std::vector<block>>>& masks_ciphers_block,
        const u32& dimension, const u32& side_length, pubkey_t* gm_pubkey
        ){
            mpz_t cipher_bit;
            mpz_init(cipher_bit);
            BitVector mask(dimension);
            PRNG prng(oc::sysRandomSeed());

            for(u64 i = 0; i < elements_size * (dimension / side_length); i++){

                mask.randomize(prng);
                masks.push(mask);
                std::vector<std::vector<block>> masks_cipher_block(dimension, std::vector<block>(GM_CIPHER_LENGTH_BLOCKS, ZeroBlock));
                for(u64 j = 0; j < dimension; j++){
                    enc_bit(&cipher_bit, (mask[j]==1), gm_pubkey);
                    gm_cipher_to_block_vector(&cipher_bit, &(masks_cipher_block[j][0]));
                }
                masks_ciphers_block.push(masks_cipher_block);
            }

            mpz_clear(cipher_bit);
            return;
        }

        BitVector sender_add_mask_hamming(const BitVector& element, const std::vector<block>& val,
        std::vector<block>& masked_val,
        const BitVector& mask, const std::vector<std::vector<block>>& mask_ciphers_block,
        const u32& dimension, const u32& side_length, pubkey_t* gm_pubkey){
            // PRNG prng(oc::sysRandomSeed());
            // BitVector mask(dimension);
            // mask.randomize(prng);

            mpz_t cipher;
            mpz_init(cipher);
            mpz_t mask_cipher;
            mpz_init(mask_cipher);
            mpz_t masked_cipher;
            mpz_init(masked_cipher);

            for(u64 i = 0; i < dimension; i++){
                block_vector_to_gm_cipher(&(val[i * GM_CIPHER_LENGTH_BLOCKS]), &cipher);
                
                // enc_bit(&mask_cipher, (mask[i] == 1), gm_pubkey);
                block_vector_to_gm_cipher(&(mask_ciphers_block[i][0]), &mask_cipher);


                xor_on_cipher(&masked_cipher, &cipher, &mask_cipher, gm_pubkey);
                std::vector<block> temp(GM_CIPHER_LENGTH_BLOCKS, ZeroBlock);
                gm_cipher_to_block_vector(&masked_cipher, &(temp[0]));

                masked_val.insert(masked_val.end(), temp.begin(), temp.end());
            }

            mpz_clear(cipher);
            mpz_clear(mask_cipher);
            mpz_clear(masked_cipher);


            return element ^ mask;
        }

        void receiver_get_choice_hamming(const std::vector<block>& masked_val, BitVector& choices, privkey_t* gm_prikey){
            mpz_t cipher_temp;
            mpz_init(cipher_temp);
            unsigned short plain_temp;
            for(u64 i =0; i < masked_val.size() / GM_CIPHER_LENGTH_BLOCKS; i++){
                block_vector_to_gm_cipher(&(masked_val[i * GM_CIPHER_LENGTH_BLOCKS]), &cipher_temp);
                // if(i == 1){
                //     gmp_printf("\n\nrecv The masked cyphertext is : %Zd\n\n", cipher_temp);
                // }
                dec_bit(&plain_temp, &cipher_temp, gm_prikey);
                choices.pushBack((plain_temp==1));
            }
            mpz_clear(cipher_temp);
            return;
        }

        void fpsi_hamming_recv_online(coproto::LocalAsyncSocket* channel,
        std::vector<BitVector>* receiver_elements, std::vector<std::vector<osuCrypto::u64>>* unique_components,
        std::stack<std::array<std::vector<block>, 2>>* pre_vals,
        u64 dimension, u64 delta, u32 side_length,
        pubkey_t* gm_pubkey, privkey_t* gm_prikey
        ){
            std::vector<block> keys;
            std::vector<std::vector<block>> vals;

            receiver_value_hamming(*receiver_elements, (*receiver_elements).size(), *pre_vals, vals, dimension, delta);
            // receiver_value_hamming(*receiver_elements, (*receiver_elements).size(),  vals, dimension, delta, gm_pubkey);
            receiver_key_hamming(*receiver_elements, (*receiver_elements).size(), *unique_components, keys, dimension, delta, side_length);

            RBOKVS paxos;
            paxos.init(keys.size(), 0.1, lambda, seed);
            std::vector<std::vector<block>> codeWords(paxos.mSize, std::vector<block>(GM_CIPHER_LENGTH_BLOCKS * dimension));

            // std::cout << keys.size() << std::endl;
            // std::cout << vals.size() << std::endl;
            
            // std:: cout << keys[0] << std::endl;
            // std:: cout << vals[0][8] << std::endl;
            // std:: cout << vals[0][9] << std::endl;

            paxos.encode(keys, vals, GM_CIPHER_LENGTH_BLOCKS * dimension, codeWords);

            coproto::sync_wait((*channel).flush());
            coproto::sync_wait((*channel).send(paxos.mSize));

            coproto::sync_wait((*channel).flush());
            coproto::sync_wait((*channel).send(keys.size()));

            for(u64 i = 0;i < paxos.mSize; i++){
                coproto::sync_wait((*channel).flush());
                coproto::sync_wait((*channel).send(codeWords[i]));
            }

            
            std::vector<block> masked_val;
            coproto::sync_wait((*channel).flush());
            coproto::sync_wait((*channel).recvResize(masked_val));

            u64 send_set_size;
            coproto::sync_wait((*channel).flush());
            coproto::sync_wait((*channel).recvResize(send_set_size));

            BitVector choices;
            
            receiver_get_choice_hamming(masked_val, choices, gm_prikey);

            // printf("recv:\n");
            // for(u64 i = 0; i < dimension; i++){
            //     printf("%d ", (choices[i] == 1));
            // }
            // printf("\n");

            //printf("recv OT num = %d\n", send_set_size * (dimension / side_length) * dimension);
            auto ot_results = run_ot_receiver(*channel, choices, send_set_size * (dimension / side_length) * dimension);

            // for(u64 i = 0; i < 2;i++){
            //     printf("recv bit: %d *****", (choices[i]==1));
            //     std::cout <<ot_results[i] << std::endl;
            // }
            u64 sum, send_pad_num;

            std::vector<u64> pads;

            send_pad_num = send_set_size * (dimension / side_length);

            for(u64 i = 0; i < send_pad_num; i++){
                sum = 0;
                for(u64 j = 0; j < dimension ; j++){
                    // if((i==0)&(j<2)){
                    //     printf("ij : %llu ", ot_results[i * dimension + j].get<u64>(0));
                    //     std:: cout << ot_results[i * dimension + j] << std::endl;
                    // }
                    sum += ot_results[i * dimension + j].get<u64>(0);
                }
                pads.push_back(sum);
            }

            // printf("recv:\n");
            // for(u64 i = 0; i < delta + 1; i++){
            //     printf("%llu ", pads[i]);
            // }
            // printf("\n");

            bool check;
            PRNG prng(oc::sysRandomSeed());
            DH25519_number recv_sk(prng);
            BitVector result;

            for(u64 i =0; i < send_set_size; i ++){
                check = false;
                for(u64 j = 0 ; j < (dimension / side_length) ; j++){
                    auto temp = run_ipmt_receiver(*channel, pads[i * (dimension / side_length) + j ], log2ceil(delta + 1), recv_sk);
                    if(temp == 1){
                        check = true;
                    }
                    // if(i==0){
                    //     printf("i == 0: recv x = %llu ,ipmt = %d\n",pads[i * (dimension / side_length) + j ], temp);
                    // }
                }
                if(check == 1){
                    // printf("!!!! %d th == 1   **", i);
                    result.pushBack(1);
                }else{
                    //printf("!!!! %d th == 0\n", i);
                    result.pushBack(0);
                }
            }

            printf("Intersection Set Size:%d\n", result.hammingWeight());

            //std::cout << "fmat_paillier_recv_online: run_ot_receiver begin" << std::endl;
            auto ot_result = OT_for_FPSI::run_ot_receiver(*channel, result, send_set_size);

            return;

        }


        void fpsi_hamming_send_online(coproto::LocalAsyncSocket* channel,
        std::vector<BitVector>* sender_elements,
        std::stack<BitVector>* masks, std::stack<std::vector<std::vector<block>>>* masks_ciphers_block,
        u64 dimension, u64 delta, u32 side_length,
        pubkey_t* gm_pubkey
        ){
            PRNG prng(oc::sysRandomSeed());

            u64 paxos_mSize, keys_size;

            coproto::sync_wait((*channel).flush());
            coproto::sync_wait((*channel).recvResize(paxos_mSize));
            coproto::sync_wait((*channel).flush());
            coproto::sync_wait((*channel).recvResize(keys_size));

            std::vector<std::vector<block>> codeWords(paxos_mSize);

            for(u64 i = 0;i < paxos_mSize; i++){
                coproto::sync_wait((*channel).flush());
                coproto::sync_wait((*channel).recvResize(codeWords[i]));
            }

            RBOKVS paxos;
            paxos.init(keys_size, 0.1, lambda, seed);

            std::vector<BitVector> masked_elements;
            std::vector<block> masked_val;

            for(u64 i = 0; i < (*sender_elements).size();i++){
                for(u64 j = 0; j < (dimension / side_length); j++){
                    auto send_key = sender_key_hamming((*sender_elements)[i], j, dimension, side_length);
                    auto send_val = paxos.decode(codeWords, send_key, GM_CIPHER_LENGTH_BLOCKS * dimension);

                    masked_elements.push_back(sender_add_mask_hamming((*sender_elements)[i], send_val, masked_val, (*masks).top(), (*masks_ciphers_block).top(), dimension, side_length, gm_pubkey));
                    (*masks).pop();
                    (*masks_ciphers_block).pop();
                }
            }

            // BitVector choices;
            
            // receiver_get_choice_hamming(masked_val, choices, gm_prikey);

            // printf("recv:\n");
            // for(u64 i = 0; i < dimension; i++){
            //     printf("%d ", (choices[i] == 1));
            // }
            // printf("\n");

            coproto::sync_wait((*channel).flush());
            coproto::sync_wait((*channel).send(masked_val));

            coproto::sync_wait((*channel).flush());
            coproto::sync_wait((*channel).send((*sender_elements).size()));

            // printf("send:\n");
            // for(u64 i = 0; i < dimension; i++){
            //     printf("%d ", (masked_elements[0][i] == 1));
            // }
            // printf("\n");

            u64 send_pad_num = masked_elements.size() * dimension;
            u64 pad, pad_plus_one, sum;

            printf("OT num = %d\n", send_pad_num);

            std::vector<u64> pads;

            std::vector<std::array<osuCrypto::block, 2UL>> sendMsg(send_pad_num);
            for(u64 i = 0; i < masked_elements.size(); i++){
                sum = 0;
                for(u64 j = 0; j < dimension ; j++){
                    pad = (prng.get<u64>() % (((u64)1) << 54));
                    pad_plus_one = ((pad + 1) % (((u64)1) << 54));
                    
                    sendMsg[i * dimension + j][(masked_elements[i][j] == 1)] = block( 0,pad);
                    sendMsg[i * dimension + j][(masked_elements[i][j] == 0)] = block( 0,pad_plus_one);
                    // if((i == 0)&(j < 2)){
                    //     std:: cout << sendMsg[i][0] << std::endl;
                    //     std:: cout << sendMsg[i][1] << std::endl;
                    // }
                    sum += pad;
                }
                pads.push_back(sum);
                
            }

            // printf("send:\n");
            // for(u64 j = 0; j < 2; j++){
            //     std:: cout << sendMsg[j][0] << std::endl;
            //     std:: cout << sendMsg[j][1] << std::endl;
            // }

            run_ot_sender(*channel, sendMsg);


            // printf("send:\n");
            // for(u64 i = 0; i < delta + 1; i++){
            //     printf("%llu ", pads[i]);
            // }
            // printf("\n");


            DH25519_number send_sk(prng);

            for(u64 i =0; i < (*sender_elements).size(); i ++){
                for(u64 j = 0 ; j < (dimension / side_length) ; j++){
                    //printf("j = %d\n", j);
                    run_ipmt_sender(*channel, pads[i * (dimension / side_length) + j ], pads[i * (dimension / side_length) + j ] + delta, send_sk);
                    // if(i==0){
                    //     printf("i == 0: send a = %llu\n", pads[i * (dimension / side_length) + j ]);
                    // }
                }
                    
            }

            std::vector<std::array<block, 2UL>> send_msg((*sender_elements).size());
            for(u64 i = 0; i < (*sender_elements).size(); i++){
                send_msg[i][1] = block((*sender_elements)[i].data()[0], (*sender_elements)[i].data()[1], (*sender_elements)[i].data()[2], (*sender_elements)[i].data()[3],
                                        (*sender_elements)[i].data()[4], (*sender_elements)[i].data()[5], (*sender_elements)[i].data()[6], (*sender_elements)[i].data()[7],
                                        (*sender_elements)[i].data()[8], (*sender_elements)[i].data()[9], (*sender_elements)[i].data()[10], (*sender_elements)[i].data()[11],
                                        (*sender_elements)[i].data()[12], (*sender_elements)[i].data()[13], (*sender_elements)[i].data()[14], (*sender_elements)[i].data()[15]);
            }

            OT_for_FPSI::run_ot_sender(*channel, send_msg);

        }

    }

}