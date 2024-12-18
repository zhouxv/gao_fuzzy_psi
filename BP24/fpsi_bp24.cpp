#include "fpsi_bp24.h"

namespace osuCrypto
{
    namespace bp24_ec{
        void u64_to_vector_bit(const u64& x, std::vector<u64>& x_bit, const u64& dimension){
            u64 x_temp(x);
            for(u64 i = 0; i < dimension; i++){
                x_bit.push_back(((x_temp & 1) != 0));
                x_temp = x_temp >> 1;
            }
            return;
        }

        void traversal_active_grid(const std::vector<u64>& bottom_grid, std::vector<std::vector<u64>>& grids, const u64& dimension){
            grids.push_back(bottom_grid);
            for(u64 i = 1; i < u64(pow(2, dimension)); i++){
                std::vector<u64> grid_temp;
                u64_to_vector_bit(i, grid_temp, dimension);
                for(u64 j = 0; j < dimension; j++){
                    grid_temp[j] = grid_temp[j] + bottom_grid[j];
                }
                grids.push_back(grid_temp);
            }
            return;
        }

        std::vector<u64> get_grid(const std::vector<u64>& element, const u64& dimension, const i32& side_length){
            std::vector<u64> grid(dimension);
            for(u64 i = 0; i < dimension; i++){
                grid[i] = (element[i] / side_length);
            }
            return grid;
        }

        std::vector<u64> get_bottom_grid(const std::vector<u64>& element, const u64& dimension, const u64& delta, const i32& side_length){
            std::vector<u64> bottom_grid(dimension);
            for(u64 i = 0; i < dimension; i++){
                bottom_grid[i] = ((element[i] - delta) / side_length);
            }
            return bottom_grid;
        }

        std::vector<std::vector<u64>> receiver_get_traversal_active_grid(const std::vector<u64>& element, const u64& dimension, const u64& delta, const u64& side_length){
            std::vector<std::vector<u64>> grids;
            std::vector<u64> bottom_grid = get_bottom_grid(element, dimension, delta, side_length);
            traversal_active_grid(bottom_grid, grids, dimension);
            return grids;
        }

        block get_key_from_grid_d_x(const std::vector<u64>& grid, const u64& d, const u64& x){
            blake3_hasher hasher;
            block hash_out;
            blake3_hasher_init(&hasher);
            for(auto iter : grid){
                blake3_hasher_update(&hasher, &iter, sizeof(iter));
            }
            blake3_hasher_update(&hasher, &d, sizeof(d));
            blake3_hasher_update(&hasher, &x, sizeof(x));
            blake3_hasher_finalize(&hasher, hash_out.data(), 16);
            return hash_out;
        }


        // side_length = 2 * delta
        void receiver_precomp_vals_ec_lp(const std::size_t& elements_size,
                                std::vector<std::vector<Rist25519_number>>& vals,
                                const u64& dimension, const u64& delta, const u64& side_length, const u64& p, const FM25519_number& sk){
            if(side_length != 2 * delta){
                throw std::runtime_error("side_length should be 2 * delta");
            }
            std::vector<FM25519_number> temp_val(EC_CIPHER_SIZE_IN_NUMBER);
            FM25519_number hj;
            PRNG prng(oc::sysRandomSeed());
            for(u64 i = 0; i < elements_size ; i++){
                for(u64 j = 0; j < (u64)pow(2, dimension); j++){
                    for(u64 k = 0; k < dimension; k++){
                        for(u64 l = 0; l < side_length; l++){
                            hj = FM25519_number(prng);
                            temp_val[0] = hj;
                            temp_val[1] = sk * hj;
                            vals.push_back(temp_val);
                        }
                    }
                }
            }

            return;
        }

        void receiver_precomp_vals_ec_linfty(const std::size_t& elements_size,
                                std::vector<std::vector<Rist25519_number>>& vals,
                                const u64& dimension, const u64& delta, const u64& side_length, const FM25519_number& sk){
            if(side_length != 2 * delta){
                throw std::runtime_error("side_length should be 2 * delta");
            }
            std::vector<FM25519_number> temp_val(EC_CIPHER_SIZE_IN_NUMBER);
            FM25519_number hj;
            PRNG prng(oc::sysRandomSeed());
            for(u64 i = 0; i < elements_size ; i++){
                for(u64 j = 0; j < (u64)pow(2, dimension); j++){
                    for(u64 k = 0; k < dimension; k++){
                        for(u64 l = 0; l < side_length; l++){
                            hj = FM25519_number(prng);
                            temp_val[0] = hj;
                            temp_val[1] = sk * hj;
                            vals.push_back(temp_val);
                        }
                    }
                }
            }

            return;
        }


        void sender_mask_ec_lp(const std::size_t& elements_size,
                            std::vector<FM25519_point>& vec_G_pow_a_H_pow_c,
                            std::vector<FM25519_number>& vec_b,
                            std::vector<FM25519_point>& vec_G_pow_c,
                            std::vector<std::vector<FM25519_point>>& vec_G_pow_a_bj,
                            const u64& delta, const u64& p,
                            const FM25519_point& G, const FM25519_point& H){
            PRNG prng(oc::sysRandomSeed());
            
            FM25519_number a, b, c;
            u64 j_max(pow(delta, p));
            std::vector<FM25519_point> G_pow_a_bj(j_max + 1);

            for(u64 i = 0; i < elements_size; i++){
                a = FM25519_number(prng);
                b = FM25519_number(prng);
                c = FM25519_number(prng);

                vec_G_pow_a_H_pow_c.push_back(a * G + c * H);
                vec_b.push_back(b);
                vec_G_pow_c.push_back(c * G);

                for(u64 j = 0; j <= j_max; j++){
                    G_pow_a_bj[j] = (a + b * j) * G;
                }
                //coproto::shuffle()
                std::shuffle(G_pow_a_bj.begin(), G_pow_a_bj.end(), prng);
                vec_G_pow_a_bj.push_back(G_pow_a_bj);
            }
            return;
        }

        void sender_mask_ec_linfty(const std::size_t& elements_size,
                            std::vector<FM25519_point>& vec_G_pow_a,
                            std::vector<FM25519_number>& vec_b,
                            std::vector<FM25519_point>& vec_H_pow_a,
                            const FM25519_point& G, const FM25519_point& H){
            PRNG prng(oc::sysRandomSeed());
            
            FM25519_number a, b;

            for(u64 i = 0; i < elements_size; i++){
                a = FM25519_number(prng);
                b = FM25519_number(prng);

                vec_G_pow_a.push_back(a * G);
                vec_b.push_back(b);
                vec_H_pow_a.push_back(a * H);

                //coproto::shuffle()
            }
            return;
        }


        void receiver_w_to_key_ec_lp(const std::vector<std::vector<u64>>& elements,
                                    std::vector<block>& keys, std::vector<std::vector<FM25519_number>>& vals,
                                    const u64& dimension, const u64& delta, const u64& side_length, const u64& p){
            u64 vals_cnt = 0;
            for(u64 i = 0; i < elements.size() ; i++){
                std::vector<std::vector<u64>> grids = receiver_get_traversal_active_grid(elements[i], dimension, delta, side_length);
                for(u64 j = 0; j < grids.size(); j++){
                    for(u64 k = 0; k < dimension; k++){
                        for(u64 l = grids[j][k] * side_length; l < grids[j][k] * side_length + side_length; l++){
                            keys.push_back(get_key_from_grid_d_x(grids[j], k, l));
                            vals[vals_cnt][1] = vals[vals_cnt][1] + FM25519_number((u64)pow(abs((i64)l - (i64)elements[i][k]), p));

                            vals_cnt ++;
                        }
                    }
                }
            }
            return;
        }

        void receiver_w_to_key_ec_linfty(const std::vector<std::vector<u64>>& elements,
                                    std::vector<block>& keys, std::vector<std::vector<FM25519_number>>& vals,
                                    const u64& dimension, const u64& delta, const u64& side_length){
            u64 vals_cnt = 0;
            for(u64 i = 0; i < elements.size() ; i++){
                std::vector<std::vector<u64>> grids = receiver_get_traversal_active_grid(elements[i], dimension, delta, side_length);
                for(u64 j = 0; j < grids.size(); j++){
                    for(u64 k = 0; k < dimension; k++){
                        for(u64 l = grids[j][k] * side_length; l < grids[j][k] * side_length + side_length; l++){
                            keys.push_back(get_key_from_grid_d_x(grids[j], k, l));
                            vals[vals_cnt][1] = vals[vals_cnt][1] + FM25519_number((u64)((abs((i64)l - (i64)elements[i][k])) > delta));

                            vals_cnt ++;
                        }
                    }
                }
            }
            return;
        }

        void sender_q_to_masked_distance_ec_lp(const std::vector<std::vector<u64>>& elements,
                                                const std::vector<std::vector<Rist25519_point>>& codeWords,
                                                const std::vector<FM25519_point>& vec_G_pow_a_H_pow_c,
                                                const std::vector<FM25519_number>& vec_b,
                                                const std::vector<FM25519_point>& vec_G_pow_c,
                                                std::vector<FM25519_point>& vec_F_star, std::vector<FM25519_point>& vec_H_star,
                                                const u64& dimension, const u64& side_length, const u64& okvs_n){
            
            RBOKVS_rist rb_okvs;
            rb_okvs.init(okvs_n, 0.1, lambda, seed);
            FM25519_point F_star, H_star;
            FM25519_point temp_U, temp_V;


            for(u64 i = 0; i < elements.size(); i++){
                std::vector<u64> grid = get_grid(elements[i], dimension, side_length);
                std::vector<Rist25519_point> value = rb_okvs.decode(codeWords, get_key_from_grid_d_x(grid, 0, elements[i][0]), EC_CIPHER_SIZE_IN_NUMBER);
                F_star = value[0];
                H_star = value[1];

                for(u64 j = 1; j < dimension; j++){
                    std::vector<Rist25519_point> value = rb_okvs.decode(codeWords, get_key_from_grid_d_x(grid, j, elements[i][j]), EC_CIPHER_SIZE_IN_NUMBER);
                    temp_U = value[0];
                    temp_V = value[1];

                    F_star = F_star + temp_U;
                    H_star = H_star + temp_V;
                }

                F_star = F_star * vec_b[i] + vec_G_pow_c[i];
                H_star = H_star * vec_b[i] + vec_G_pow_a_H_pow_c[i];
                vec_F_star.push_back(F_star);
                vec_H_star.push_back(H_star);
            }
            return;
        }

        void sender_q_to_masked_distance_ec_linfty(const std::vector<std::vector<u64>>& elements,
                                                const std::vector<std::vector<Rist25519_point>>& codeWords,
                                                const std::vector<FM25519_point>& vec_G_pow_a,
                                                const std::vector<FM25519_number>& vec_b,
                                                const std::vector<FM25519_point>& vec_H_pow_a,
                                                std::vector<FM25519_point>& vec_F_star, std::vector<FM25519_point>& vec_H_star,
                                                const u64& dimension, const u64& side_length, const u64& okvs_n){
            
            RBOKVS_rist rb_okvs;
            rb_okvs.init(okvs_n, 0.1, lambda, seed);
            FM25519_point F_star, H_star;
            FM25519_point temp_U, temp_V;


            for(u64 i = 0; i < elements.size(); i++){
                std::vector<u64> grid = get_grid(elements[i], dimension, side_length);
                std::vector<Rist25519_point> value = rb_okvs.decode(codeWords, get_key_from_grid_d_x(grid, 0, elements[i][0]), EC_CIPHER_SIZE_IN_NUMBER);
                F_star = value[0];
                H_star = value[1];

                for(u64 j = 1; j < dimension; j++){
                    std::vector<Rist25519_point> value = rb_okvs.decode(codeWords, get_key_from_grid_d_x(grid, j, elements[i][j]), EC_CIPHER_SIZE_IN_NUMBER);
                    temp_U = value[0];
                    temp_V = value[1];

                    F_star = F_star + temp_U;
                    H_star = H_star + temp_V;
                }

                F_star = F_star * vec_b[i] + vec_G_pow_a[i];
                H_star = H_star * vec_b[i] + vec_H_pow_a[i];
                vec_F_star.push_back(F_star);
                vec_H_star.push_back(H_star);
            }
            return;
        }


        void receiver_result(const std::vector<FM25519_point>& vec_F_star, const std::vector<FM25519_point>& vec_H_star, const std::vector<std::vector<FM25519_point>>& vec_G_pow_a_bj,
                            std::vector<bool>& result,
                            const FM25519_number& sk){
            bool temp;
            for(u64 i = 0; i < vec_F_star.size(); i++){
                temp = false;
                auto it_find = find(vec_G_pow_a_bj[i].begin(), vec_G_pow_a_bj[i].end(), vec_H_star[i] - sk * vec_F_star[i]);
                if(it_find != vec_G_pow_a_bj[i].end()){
                    temp = true;
                }
                
                result.push_back(temp);
            }

            return;
        }      

       void receiver_result_lp(const std::vector<FM25519_point>& vec_F_star, const std::vector<FM25519_point>& vec_H_star, const std::vector<std::vector<FM25519_point>>& vec_G_pow_a_bj,
                            BitVector& result,
                            const FM25519_number& sk){
            bool temp;
            for(u64 i = 0; i < vec_F_star.size(); i++){
                temp = false;
                auto it_find = find(vec_G_pow_a_bj[i].begin(), vec_G_pow_a_bj[i].end(), vec_H_star[i] - sk * vec_F_star[i]);
                if(it_find != vec_G_pow_a_bj[i].end()){
                    temp = true;
                }
                
                if(temp == 1){
                    result.pushBack(1);
                }else{
                    result.pushBack(0);
                }
            }

            return;
        }

       void receiver_result_linfty(const std::vector<FM25519_point>& vec_F_star, const std::vector<FM25519_point>& vec_H_star,
                            BitVector& result,
                            const FM25519_number& sk){
            bool temp;
            for(u64 i = 0; i < vec_F_star.size(); i++){
                temp = false;
                if(vec_H_star[i] == sk * vec_F_star[i]){
                    temp = true;
                }
                
                if(temp == 1){
                    result.pushBack(1);
                }else{
                    result.pushBack(0);
                }
            }

            return;
        }

        void bp24_lp_low_dim_recv_online(coproto::LocalAsyncSocket* channel,
        std::vector<std::vector<u64>>* receiver_elements,
        std::vector<std::vector<Rist25519_number>>* fmat_vals,
        u64 dimension, u64 delta, u64 side_length, u64 p,
        FM25519_number recv_sk, FM25519_point G){
            Timer time;

            std::vector<element> fmat_keys;
            receiver_w_to_key_ec_lp(*receiver_elements, fmat_keys, *fmat_vals, dimension, delta, side_length, p);

            RBOKVS_rist rb_okvs;
            rb_okvs.init(fmat_keys.size(), 0.1, lambda, seed);
            std::vector<std::vector<FM25519_point>> codeWords_fmat(rb_okvs.num_columns, std::vector<FM25519_point>(EC_CIPHER_SIZE_IN_NUMBER));

            //rb_okvs.encode(fmat_keys, *fmat_vals, EC_CIPHER_SIZE_IN_NUMBER, codeWords_fmat, G);
            rb_okvs.encode(fmat_keys, *fmat_vals, EC_CIPHER_SIZE_IN_NUMBER, codeWords_fmat);

            std::vector<FM25519_point> codeWords_fmat_net(rb_okvs.num_columns * EC_CIPHER_SIZE_IN_NUMBER);

            for(u64 i = 0;i < rb_okvs.num_columns; i++){
                for(u64 j = 0; j < EC_CIPHER_SIZE_IN_NUMBER; j++){
                    codeWords_fmat_net[i * EC_CIPHER_SIZE_IN_NUMBER + j] = codeWords_fmat[i][j];
                }
            }

            coproto::sync_wait((*channel).flush());
            coproto::sync_wait((*channel).send(codeWords_fmat_net));
            coproto::sync_wait((*channel).flush());
            coproto::sync_wait((*channel).send(fmat_keys.size()));

            std::vector<FM25519_point> vec_F_star, vec_H_star;
            coproto::sync_wait((*channel).flush());
            coproto::sync_wait((*channel).recvResize(vec_F_star));
            coproto::sync_wait((*channel).flush());
            coproto::sync_wait((*channel).recvResize(vec_H_star));

            std::vector<std::vector<FM25519_point>> vec_G_pow_a_bj(vec_F_star.size());
            for(u64 i = 0; i < vec_F_star.size(); i++){
                coproto::sync_wait((*channel).flush());
                coproto::sync_wait((*channel).recvResize(vec_G_pow_a_bj[i]));
            }

            osuCrypto::BitVector result;
            receiver_result_lp(vec_F_star, vec_H_star, vec_G_pow_a_bj, result, recv_sk);

            printf("FPSI-CA:%d\n", result.hammingWeight());

            return;
        }

        void bp24_lp_low_dim_send_online(coproto::LocalAsyncSocket* channel,
        std::vector<std::vector<u64>>* sender_elements,
        std::vector<FM25519_point>* vec_G_pow_a_H_pow_c, std::vector<FM25519_number>* vec_b, std::vector<FM25519_point>* vec_G_pow_c,
        std::vector<std::vector<FM25519_point>>* vec_G_pow_a_bj,
        u64 dimension, u64 delta, u64 side_length
        ){
            std::vector<FM25519_point> codeWords_fmat_net;
            size_t fmat_keys_size;
            coproto::sync_wait((*channel).flush());
            coproto::sync_wait((*channel).recvResize(codeWords_fmat_net));
            coproto::sync_wait((*channel).flush());
            coproto::sync_wait((*channel).recvResize(fmat_keys_size));

            std::vector<std::vector<FM25519_point>> codeWords_fmat(codeWords_fmat_net.size() / EC_CIPHER_SIZE_IN_NUMBER, std::vector<FM25519_point>(EC_CIPHER_SIZE_IN_NUMBER));
            
            for(u64 i = 0;i < (codeWords_fmat_net.size() / EC_CIPHER_SIZE_IN_NUMBER); i++){
                for(u64 j = 0; j < EC_CIPHER_SIZE_IN_NUMBER; j++){
                    codeWords_fmat[i][j] = codeWords_fmat_net[i * EC_CIPHER_SIZE_IN_NUMBER + j];
                }
            }

            std::vector<FM25519_point> vec_F_star, vec_H_star;
            sender_q_to_masked_distance_ec_lp(*sender_elements, codeWords_fmat, *vec_G_pow_a_H_pow_c, *vec_b, *vec_G_pow_c, vec_F_star, vec_H_star, dimension, side_length, fmat_keys_size);

            coproto::sync_wait((*channel).flush());
            coproto::sync_wait((*channel).send(vec_F_star));
            coproto::sync_wait((*channel).flush());
            coproto::sync_wait((*channel).send(vec_H_star));

            for(u64 i = 0; i < sender_elements->size(); i++){
                coproto::sync_wait((*channel).flush());
                coproto::sync_wait((*channel).send((*vec_G_pow_a_bj)[i]));
            }

            return;
        }


        void bp24_linfty_low_dim_recv_online(coproto::LocalAsyncSocket* channel,
        std::vector<std::vector<u64>>* receiver_elements,
        std::vector<std::vector<Rist25519_number>>* fmat_vals,
        u64 dimension, u64 delta, u64 side_length,
        FM25519_number recv_sk, FM25519_point G){
            std::vector<element> fmat_keys;
            receiver_w_to_key_ec_linfty(*receiver_elements, fmat_keys, *fmat_vals, dimension, delta, side_length);

            RBOKVS_rist rb_okvs;
            rb_okvs.init(fmat_keys.size(), 0.1, lambda, seed);
            std::vector<std::vector<FM25519_point>> codeWords_fmat(rb_okvs.num_columns, std::vector<FM25519_point>(EC_CIPHER_SIZE_IN_NUMBER));

            // rb_okvs.encode(fmat_keys, *fmat_vals, EC_CIPHER_SIZE_IN_NUMBER, codeWords_fmat, G);
            rb_okvs.encode(fmat_keys, *fmat_vals, EC_CIPHER_SIZE_IN_NUMBER, codeWords_fmat);

            std::vector<FM25519_point> codeWords_fmat_net(rb_okvs.num_columns * EC_CIPHER_SIZE_IN_NUMBER);

            for(u64 i = 0;i < rb_okvs.num_columns; i++){
                for(u64 j = 0; j < EC_CIPHER_SIZE_IN_NUMBER; j++){
                    codeWords_fmat_net[i * EC_CIPHER_SIZE_IN_NUMBER + j] = codeWords_fmat[i][j];
                }
            }

            coproto::sync_wait((*channel).flush());
            coproto::sync_wait((*channel).send(codeWords_fmat_net));
            coproto::sync_wait((*channel).flush());
            coproto::sync_wait((*channel).send(fmat_keys.size()));

            std::vector<FM25519_point> vec_F_star, vec_H_star;
            coproto::sync_wait((*channel).flush());
            coproto::sync_wait((*channel).recvResize(vec_F_star));
            coproto::sync_wait((*channel).flush());
            coproto::sync_wait((*channel).recvResize(vec_H_star));

            osuCrypto::BitVector result;
            receiver_result_linfty(vec_F_star, vec_H_star, result, recv_sk);
            
            printf("FPSI-CA:%d\n", result.hammingWeight());

            return;
        }

        void bp24_linfty_low_dim_send_online(coproto::LocalAsyncSocket* channel,
        std::vector<std::vector<u64>>* sender_elements,
        std::vector<FM25519_point>* vec_G_pow_a, std::vector<FM25519_number>* vec_b, std::vector<FM25519_point>* vec_H_pow_a,
        u64 dimension, u64 delta, u64 side_length
        ){
            std::vector<FM25519_point> codeWords_fmat_net;
            size_t fmat_keys_size;
            coproto::sync_wait((*channel).flush());
            coproto::sync_wait((*channel).recvResize(codeWords_fmat_net));
            coproto::sync_wait((*channel).flush());
            coproto::sync_wait((*channel).recvResize(fmat_keys_size));

            std::vector<std::vector<FM25519_point>> codeWords_fmat(codeWords_fmat_net.size() / EC_CIPHER_SIZE_IN_NUMBER, std::vector<FM25519_point>(EC_CIPHER_SIZE_IN_NUMBER));
            
            for(u64 i = 0;i < (codeWords_fmat_net.size() / EC_CIPHER_SIZE_IN_NUMBER); i++){
                for(u64 j = 0; j < EC_CIPHER_SIZE_IN_NUMBER; j++){
                    codeWords_fmat[i][j] = codeWords_fmat_net[i * EC_CIPHER_SIZE_IN_NUMBER + j];
                }
            }

            std::vector<FM25519_point> vec_F_star, vec_H_star;
            sender_q_to_masked_distance_ec_linfty(*sender_elements, codeWords_fmat, *vec_G_pow_a, *vec_b, *vec_H_pow_a, vec_F_star, vec_H_star, dimension, side_length, fmat_keys_size);

            coproto::sync_wait((*channel).flush());
            coproto::sync_wait((*channel).send(vec_F_star));
            coproto::sync_wait((*channel).flush());
            coproto::sync_wait((*channel).send(vec_H_star));

            return;
        }


    }

    namespace bp24_high_dim{


        block get_key_from_sepdim_ele_j_ele(const u64& separate_dim, const u64& prim, const u64& j, const u64& sub){
            blake3_hasher hasher;
            block hash_out;
            blake3_hasher_init(&hasher);
            blake3_hasher_update(&hasher, &separate_dim, sizeof(separate_dim));
            blake3_hasher_update(&hasher, &prim, sizeof(prim));
            blake3_hasher_update(&hasher, &j, sizeof(j));
            blake3_hasher_update(&hasher, &sub, sizeof(sub));
            blake3_hasher_finalize(&hasher, hash_out.data(), 16);
            return hash_out;
        }


        // side_length = 2 * delta
        void receiver_vals_ec(const std::size_t& elements_size,
                                std::vector<std::vector<Rist25519_number>>& vals,
                                const u64& dimension, const u64& delta, const FM25519_number& sk){
            std::vector<FM25519_number> temp_val(EC_CIPHER_SIZE_IN_NUMBER);
            FM25519_number hj;
            PRNG prng(oc::sysRandomSeed());
            for(u64 i = 0; i < elements_size ; i++){
                for(u64 j = 0; j < dimension; j++){
                    for(u64 prim = - delta; prim <= delta; prim++){
                        for(u64 sub = - delta; sub <= delta; sub++){
                            hj = FM25519_number(prng);
                            temp_val[0] = hj;
                            temp_val[1] = sk * hj;
                            vals.push_back(temp_val);
                        }
                    }
                }
            }

            return;
        }

        void receiver_w_to_key_ec(const std::vector<std::vector<u64>>& elements, const std::vector<u64>& separate_dims,
                                    std::vector<block>& keys, std::vector<std::vector<FM25519_number>>& vals,
                                    const u64& dimension, const u64& delta, const u64& side_length, const u64& p){
            // u64 vals_cnt = 0;
            for(u64 i = 0; i < elements.size() ; i++){
                u64 separate_dim = separate_dims[i];
                u64 ele_separate_dim = elements[i][separate_dim];
                for(u64 j = 0; j < dimension; j++){
                    for(u64 prim = ele_separate_dim - delta; prim <= ele_separate_dim + delta; prim++){
                        for(u64 sub = elements[i][j] - delta; sub <= elements[i][j] + delta; sub++){
                            keys.push_back(get_key_from_sepdim_ele_j_ele(separate_dim, prim, j, sub));
                            // vals[vals_cnt][1] = vals[vals_cnt][1] + FM25519_number((u64)pow(abs((i64)l - (i64)elements[i][k]), p));

                            // vals_cnt ++;
                        }
                    }
                }
            }
            return;
        }

        void sender_q_to_distance_ec(const std::vector<std::vector<u64>>& elements,
                                                const std::vector<std::vector<Rist25519_point>>& codeWords,
                                                std::vector<std::vector<FM25519_point>>& vec_F_star, std::vector<std::vector<FM25519_point>>& vec_H_star,
                                                const u64& dimension, const u64& okvs_n){
            
            RBOKVS_rist rb_okvs;
            rb_okvs.init(okvs_n, 0.1, lambda, seed);
            std::vector<FM25519_point> F_star(dimension), H_star(dimension);
            FM25519_point temp_U, temp_V;


            for(u64 i = 0; i < elements.size(); i++){
                for(u64 j = 0; j < dimension; j++){
                    std::vector<Rist25519_point> value = rb_okvs.decode(codeWords, get_key_from_sepdim_ele_j_ele(j, elements[i][j], 0, elements[i][0]), EC_CIPHER_SIZE_IN_NUMBER);
                    F_star[j] = value[0];
                    H_star[j] = value[1];
                    for(u64 k = 1; k < dimension; k++){
                        std::vector<Rist25519_point> value = rb_okvs.decode(codeWords, get_key_from_sepdim_ele_j_ele(j, elements[i][j], k, elements[i][k]), EC_CIPHER_SIZE_IN_NUMBER);
                        temp_U = value[0];
                        temp_V = value[1];

                        F_star[j] = F_star[j] + temp_U;
                        H_star[j] = H_star[j] + temp_V;
                    }

                }
                vec_F_star.push_back(F_star);
                vec_H_star.push_back(H_star);
            }
            return;
        }

        void receiver_result(const std::vector<std::vector<FM25519_point>>& vec_F_star, const std::vector<std::vector<FM25519_point>>& vec_H_star,
                            std::vector<bool>& result,
                            const FM25519_number& sk){
            bool temp;
            for(u64 i = 0; i < vec_F_star.size(); i++){
                temp = false;
                for(u64 j = 0; j < vec_F_star[0].size(); j++){
                    auto it_find = find(vec_H_star[i].begin(), vec_H_star[i].end(), sk * vec_F_star[i][j]);
                    if(it_find != vec_H_star[i].end()){
                        temp = true;
                    }
                }
                
                result.push_back(temp);
            }

            return;
        }

        block H_gamma_dim_component(const u64& dim, const u64& component){
            return block(dim, component);
        }

        u64 dec_H_gamma_dim_component(const u64& dim, const u64& component, const u64& width_band, const block& rand_band){
            block input = H_gamma_dim_component(dim, component);
            u64 output = 0;
            u64 width_band_in_byte = divCeil(width_band, 8);
            u8 hashOut[width_band_in_byte];
            blake3_hasher hasher;
            blake3_hasher_init(&hasher);
            blake3_hasher_update(&hasher, &rand_band, sizeof(rand_band));
            blake3_hasher_update(&hasher, &input, sizeof(input));
            blake3_hasher_finalize(&hasher, hashOut, width_band_in_byte);

            u64 i(0);
            for(i = 0; i < width_band_in_byte - 1; i++){
                output += u64(bool(hashOut[i] & 0b10000000));
                output += u64(bool(hashOut[i] & 0b01000000));
                output += u64(bool(hashOut[i] & 0b00100000));
                output += u64(bool(hashOut[i] & 0b00010000));
                output += u64(bool(hashOut[i] & 0b00001000));
                output += u64(bool(hashOut[i] & 0b00000100));
                output += u64(bool(hashOut[i] & 0b00000010));
                output += u64(bool(hashOut[i] & 0b00000001));
            }

            u64 j(0);
            if((width_band % 8) == 0){
                for(j = 0; j < 8; j++){
                    output += u64(bool(hashOut[i] & (((u8)1)<< (7 - j))));
                }
            }else{
                for(j = 0; j < (width_band % 8); j++){
                    output += u64(bool(hashOut[i] & (((u8)1)<< (7 - j))));
                }
            }
            
            return output;
        }

        std::vector<FM25519_point> two_dim_to_one_dim(const std::vector<std::vector<FM25519_point>>& codewords){
            std::vector<FM25519_point> result;
            for(auto iter : codewords){
                for(auto iterator : iter){
                    result.push_back(iterator);
                }
            }
            return result;
        }

        std::vector<FM25519_number> two_dim_to_one_dim(const std::vector<std::vector<FM25519_number>>& codewords){
            std::vector<FM25519_number> result;
            for(auto iter : codewords){
                for(auto iterator : iter){
                    result.push_back(iterator);
                }
            }
            return result;
        }

        std::vector<std::vector<FM25519_point>> one_dim_to_two_dim(const std::vector<FM25519_point>& a_vector, const u64& ele_num_per_row){
            std::vector<std::vector<FM25519_point>> result((a_vector.size() / ele_num_per_row), std::vector<FM25519_point>(ele_num_per_row));
            for(u64 i = 0; i < (a_vector.size() / ele_num_per_row); i++){
                for(u64 j = 0; j < ele_num_per_row; j++){
                    result[i][j] = a_vector[i * ele_num_per_row + j];
                }
            }
            return result;
        }

        void receiver_precomp_vals_ec_linfty(const std::size_t& elements_size,
                                std::stack<std::vector<Rist25519_number>>& vals_candidate,
                                const u64& dimension, const i64& delta, const FM25519_number& sk){

            std::vector<FM25519_number> temp_val(EC_CIPHER_SIZE_IN_NUMBER);
            FM25519_number hj;
            PRNG prng(oc::sysRandomSeed());
            RBOKVS_rist inter_okvs;
            inter_okvs.init((2 * delta + 1) * dimension, 0.1, lambda, seed);

            for(u64 k = 0; k < elements_size; k++){
                for(u64 i = 0; i < dimension; i++){
                    for(i64 j = -delta; j <= delta; j++){
                        for(u64 i_dot = 0; i_dot < inter_okvs.num_columns; i_dot ++){
                            hj = FM25519_number(prng);
                            temp_val[0] = hj;
                            temp_val[1] = sk * hj;
                            vals_candidate.push(temp_val);
                        }
                        
                    }
                }
            }

            return;
        }

        void sender_mask_ec_linfty(const std::size_t& elements_size,
                            std::vector<FM25519_point>& vec_G_pow_a,
                            std::vector<FM25519_number>& vec_b,
                            std::vector<FM25519_point>& vec_H_pow_a,
                            const FM25519_point& G, const FM25519_point& H){
            PRNG prng(oc::sysRandomSeed());
            
            FM25519_number a, b;

            for(u64 i = 0; i < elements_size; i++){
                a = FM25519_number(prng);
                b = FM25519_number(prng);

                vec_G_pow_a.push_back(a * G);
                vec_b.push_back(b);
                vec_H_pow_a.push_back(a * H);

                //coproto::shuffle()
            }
            return;
        }

        std::vector<std::vector<std::vector<FM25519_point>>> receiver_get_E(const std::vector<std::vector<u64>>& elements, const std::vector<u64>& separate_dims,
        std::stack<std::vector<Rist25519_number>>& vals_candidate,
        const u64& dimension, const i64& delta, const FM25519_point& G){
            std::vector<std::vector<std::vector<FM25519_point>>> E(dimension);
            std::vector<std::vector<block>> list_keys(dimension);
            std::vector<std::vector<std::vector<FM25519_number>>> list_vals(dimension);
            RBOKVS_rist inter_okvs;
            RBOKVS_rist outer_okvs;
            inter_okvs.init((2 * delta + 1) * dimension, 0.1, lambda, seed);
            outer_okvs.init((2 * delta + 1) * elements.size(), 0.1, lambda, seed);
            PRNG prng(oc::sysRandomSeed());

            FM25519_number zeta(prng);
            
            for(u64 k = 0; k < elements.size(); k++){
                for(u64 i = 0; i < dimension; i++){
                    for(i64 j = -delta; j <= delta; j++){
                        std::vector<std::vector<FM25519_number>> inter_codewords(inter_okvs.num_columns, std::vector<FM25519_number>(EC_CIPHER_SIZE_IN_NUMBER));
                        if(i == separate_dims[k]){
                            std::vector<block> inter_keys;
                            std::vector<std::vector<FM25519_number>> inter_vals;
                            std::vector<FM25519_number> inter_val_temp(EC_CIPHER_SIZE_IN_NUMBER);
                            for(u64 i_dot = 0; i_dot < dimension; i_dot ++){
                                for(i64 j_dot = -delta; j_dot <= delta; j_dot++){
                                    inter_keys.push_back(H_gamma_dim_component(i_dot, elements[k][i_dot] + j_dot));
                                    inter_val_temp[0] = vals_candidate.top()[0];
                                    auto x = (dimension - 1) * (dec_H_gamma_dim_component(i_dot, elements[k][i_dot] + j_dot, inter_okvs.width_band, inter_okvs.rand_band));
                                    inter_val_temp[1] = (vals_candidate.top()[1] - zeta * x);
                                    inter_vals.push_back(inter_val_temp);
                                    vals_candidate.pop();
                                }
                            }
                            inter_okvs.encode(inter_keys, inter_vals, EC_CIPHER_SIZE_IN_NUMBER, inter_codewords);
                        }else{
                            for(u64 i_dot = 0; i_dot < inter_okvs.num_columns; i_dot ++){
                                inter_codewords[i_dot][0] = vals_candidate.top()[0];
                                inter_codewords[i_dot][1] = vals_candidate.top()[1] + zeta;
                                vals_candidate.pop();
                            }
                        }

                        auto key_temp = H_gamma_dim_component(i, elements[k][i] + j);
                        if(find(list_keys[i].begin(), list_keys[i].end(), key_temp) != list_keys[i].end()){
                            printf("collusion: ele = %d\n   dim = %d\n----------------------------------\n", k, i);
                            key_temp = prng.get<block>();
                        }
                        list_keys[i].push_back(key_temp);
                        
                        list_vals[i].push_back(two_dim_to_one_dim(inter_codewords));
                    }
                }
            }

            std::vector<std::vector<FM25519_point>> E_i(outer_okvs.num_columns, std::vector<FM25519_point>(EC_CIPHER_SIZE_IN_NUMBER * inter_okvs.num_columns));
            
            // printf("E_i init done\n E val size = %d\n", list_vals[0][0].size());
            // printf("E val num = %d\n E key num = %d\n", list_vals[0].size(), list_keys[0].size());
            // printf("E val size real = %d\n", EC_CIPHER_SIZE_IN_NUMBER * inter_okvs.num_columns);

            for(u64 i = 0; i < dimension; i++){
                // outer_okvs.encode(list_keys[i], list_vals[i], EC_CIPHER_SIZE_IN_NUMBER * inter_okvs.num_columns, E_i, G);
                outer_okvs.encode(list_keys[i], list_vals[i], EC_CIPHER_SIZE_IN_NUMBER * inter_okvs.num_columns, E_i);
                E[i] = E_i;
            }

            return E;
        }

        void sender_q_to_masked_distance_ec_linfty(const std::vector<std::vector<u64>>& elements,
                                                const std::vector<std::vector<std::vector<FM25519_point>>>& E,
                                                const std::vector<FM25519_point>& vec_G_pow_a,
                                                const std::vector<FM25519_number>& vec_b,
                                                const std::vector<FM25519_point>& vec_H_pow_a,
                                                std::vector<FM25519_point>& vec_F_star, std::vector<FM25519_point>& vec_H_star,
                                                const u64& dimension, const u64& delta, const u64& outer_okvs_n){

                                                    RBOKVS_rist inter_okvs;
                                                    RBOKVS_rist outer_okvs;
                                                    inter_okvs.init((2 * delta + 1) * dimension, 0.1, lambda, seed);
                                                    outer_okvs.init(outer_okvs_n, 0.1, lambda, seed);

                                                    FM25519_point F_star, H_star;
                                                    std::vector<FM25519_point> value_temp(EC_CIPHER_SIZE_IN_NUMBER);

                                                    for(u64 k = 0; k < elements.size(); k++){
                                                        F_star = ZERO_POINT;
                                                        H_star = ZERO_POINT;
                                                        for(u64 i = 0; i < dimension; i++){
                                                            auto e_i = outer_okvs.decode(E[i], H_gamma_dim_component(i, elements[k][i]), EC_CIPHER_SIZE_IN_NUMBER * inter_okvs.num_columns);
                                                            auto e_i_codewords = one_dim_to_two_dim(e_i, EC_CIPHER_SIZE_IN_NUMBER);
                                                            for(u64 j = 0; j < dimension; j++){
                                                                value_temp = (inter_okvs.decode(e_i_codewords, H_gamma_dim_component(j, elements[k][j]), EC_CIPHER_SIZE_IN_NUMBER));
                                                                F_star += value_temp[0];
                                                                H_star += value_temp[1];
                                                            }
                                                        
                                                        }
                                                        F_star = F_star * vec_b[k] + vec_G_pow_a[k];
                                                        H_star = H_star * vec_b[k] + vec_H_pow_a[k];
                                                        vec_F_star.push_back(F_star);
                                                        vec_H_star.push_back(H_star);
                                                    }
                                                    return;
                                                }

       void receiver_result_linfty(const std::vector<FM25519_point>& vec_F_star, const std::vector<FM25519_point>& vec_H_star,
                            BitVector& result,
                            const FM25519_number& sk){
            bool temp;
            for(u64 i = 0; i < vec_F_star.size(); i++){
                temp = false;
                if(vec_H_star[i] == sk * vec_F_star[i]){
                    temp = true;
                }

                if(temp == 1){
                    result.pushBack(1);
                }else{
                    result.pushBack(0);
                }
            }
        printf("\n");

            return;
        }


        void bp24_linfty_high_dim_recv_online(coproto::LocalAsyncSocket* channel,
        std::vector<std::vector<u64>>* receiver_elements, std::vector<osuCrypto::u64>* separate_dims,
        std::stack<std::vector<Rist25519_number>>* vals_candidate,
        u64 dimension, u64 delta,
        FM25519_number recv_sk, FM25519_point G){

            std::vector<std::vector<std::vector<FM25519_point>>> E = receiver_get_E(*receiver_elements, *separate_dims, *vals_candidate, dimension, delta, G);

            coproto::sync_wait((*channel).flush());
            coproto::sync_wait((*channel).send(E[0][0].size()));

            coproto::sync_wait((*channel).flush());
            coproto::sync_wait((*channel).send((2 * delta + 1) * (*receiver_elements).size()));

            for(u64 i = 0; i < dimension; i++){
                coproto::sync_wait((*channel).flush());
                coproto::sync_wait((*channel).send(two_dim_to_one_dim(E[i])));
            }

            std::vector<FM25519_point> vec_F_star, vec_H_star;
            coproto::sync_wait((*channel).flush());
            coproto::sync_wait((*channel).recvResize(vec_F_star));
            coproto::sync_wait((*channel).flush());
            coproto::sync_wait((*channel).recvResize(vec_H_star));

            osuCrypto::BitVector result;
            receiver_result_linfty(vec_F_star, vec_H_star, result, recv_sk);
            
            printf("FPSI-CA:%d\n", result.hammingWeight());

            return;
        }

        void bp24_linfty_high_dim_send_online(coproto::LocalAsyncSocket* channel,
        std::vector<std::vector<u64>>* sender_elements,
        std::vector<FM25519_point>* vec_G_pow_a, std::vector<FM25519_number>* vec_b, std::vector<FM25519_point>* vec_H_pow_a,
        u64 dimension, u64 delta){
            std::vector<std::vector<std::vector<FM25519_point>>> E(dimension);
            

            size_t outer_okvs_n;
            size_t ele_num_per_row_in_E_i;

            coproto::sync_wait((*channel).flush());
            coproto::sync_wait((*channel).recvResize(ele_num_per_row_in_E_i));

            coproto::sync_wait((*channel).flush());
            coproto::sync_wait((*channel).recvResize(outer_okvs_n));

            for(u64 i = 0; i < dimension; i++){
                std::vector<FM25519_point> E_i_net;
                coproto::sync_wait((*channel).flush());
                coproto::sync_wait((*channel).recvResize(E_i_net));
                E[i] = one_dim_to_two_dim(E_i_net, ele_num_per_row_in_E_i);
            }

            std::vector<FM25519_point> vec_F_star, vec_H_star;
            sender_q_to_masked_distance_ec_linfty(*sender_elements, E, *vec_G_pow_a, *vec_b, *vec_H_pow_a, vec_F_star, vec_H_star, dimension, delta, outer_okvs_n);

            coproto::sync_wait((*channel).flush());
            coproto::sync_wait((*channel).send(vec_F_star));
            coproto::sync_wait((*channel).flush());
            coproto::sync_wait((*channel).send(vec_H_star));

            return;
        }

        void receiver_precomp_ec_lp(const std::size_t& recv_set_size,
                                std::vector<std::vector<block>>& keys,
                                std::vector<std::vector<std::vector<Rist25519_number>>>& vals,
                                const u64& dimension, const i64& delta, const FM25519_number& sk){
            PRNG prng(oc::sysRandomSeed());

            double kappa = 40;
            double rho = 0.365;
            // rho = 0.5;
            double log_e = 1.4427;
            double N = recv_set_size;

            u64 L = (u64)(((kappa) / log_e) * pow(N, rho));

            u64 num_per_okvs = (2 * delta + 1) * dimension * recv_set_size;

            printf("%d okvs, per num = %d\n", L, num_per_okvs);

            block key;
            std::vector<Rist25519_number> val_temp(EC_CIPHER_SIZE_IN_NUMBER);
            for(u64 i = 0; i < L; i ++){
                std::vector<block> keys_temp;
                std::vector<std::vector<Rist25519_number>> vals_temp;
                for(u64 j = 0; j < num_per_okvs; j++){
                    key = prng.get<block>();
                    keys_temp.push_back(key);

                    val_temp[0] = Rist25519_number(prng);
                    val_temp[1] = sk * val_temp[0];
                    vals_temp.push_back(val_temp);
                }
                keys.push_back(keys_temp);
                vals.push_back(vals_temp);
            }

            return;
        }

        void sender_precomp_ec_lp(const std::size_t& send_set_size, const std::size_t& recv_set_size,
                            std::vector<std::vector<block>>& keys,
                            std::vector<FM25519_point>& vec_G_pow_a,
                            std::vector<FM25519_number>& vec_b,
                            std::vector<FM25519_point>& vec_H_pow_a,
                            const FM25519_point& G, const FM25519_point& H, const u64 &dimension){
            PRNG prng(oc::sysRandomSeed());
            
            FM25519_number a, b;

            for(u64 i = 0; i < send_set_size; i++){
                a = FM25519_number(prng);
                b = FM25519_number(prng);

                vec_G_pow_a.push_back(a * G);
                vec_b.push_back(b);
                vec_H_pow_a.push_back(a * H);

                //coproto::shuffle()
            }
            
            double kappa = 40;
            double rho = 0.365;
            double log_e = 1.4427;
            double N = recv_set_size;
            u64 M = send_set_size;
            u64 L = (u64)(((kappa) / log_e) * pow(N, rho));
            u64 T = (u64)(((2 + ((kappa) / log_e)) * log2(N))/(log2(log2(N))));

            block key;
            for(u64 i = 0; i < L; i ++){
                std::vector<block> keys_temp;
                for(u64 j = 0; j < M * T * dimension; j ++){
                    key = prng.get<block>();
                    keys_temp.push_back(key);
                }
                keys.push_back(keys_temp);
            }

            return;
        }

        void bp24_lp_high_dim_recv_online(coproto::LocalAsyncSocket* channel,
        std::vector<std::vector<block>>* keys, std::vector<std::vector<std::vector<Rist25519_number>>>* vals,
        u64 dimension, u64 delta,
        std::size_t send_set_size, std::size_t recv_set_size,
        FM25519_number recv_sk, FM25519_point G){

            double kappa = 40;
            double rho = 0.365;
            double log_e = 1.4427;
            double N = recv_set_size;

            u64 L = (u64)(((kappa) / log_e) * pow(N, rho));
            u64 T = (u64)(((2 + ((kappa) / log_e)) * log2(N))/(log2(log2(N))));

            printf("per_okvs_keysize = %d\n", (*keys)[0].size());
            printf("L = %d\n", L);
            printf("T = %d\n", T);

            RBOKVS_rist okvs;
            okvs.init((*keys)[0].size(), 0.1, lambda, seed);


            std::vector<std::vector<FM25519_point>> E(L);
            for(u64 i = 0; i < L ; i++){
                std::vector<std::vector<FM25519_point>> E_i(okvs.num_columns, std::vector<FM25519_point>(EC_CIPHER_SIZE_IN_NUMBER));
                okvs.encode((*keys)[i], (*vals)[i], EC_CIPHER_SIZE_IN_NUMBER, E_i);
                E[i] = (two_dim_to_one_dim(E_i));
            }

            for(u64 i = 0; i < L; i++){
                coproto::sync_wait((*channel).flush());
                coproto::sync_wait((*channel).send(E[i]));
            }

            coproto::sync_wait((*channel).flush());
            coproto::sync_wait((*channel).send((*keys)[0].size()));

        }

        void bp24_lp_high_dim_send_online(coproto::LocalAsyncSocket* channel,
        std::vector<std::vector<block>>* keys,
        std::vector<FM25519_point>* vec_G_pow_a, std::vector<FM25519_number>* vec_b, std::vector<FM25519_point>* vec_H_pow_a,
        std::size_t send_set_size, std::size_t recv_set_size,
        u64 dimension, u64 delta){

            double kappa = 40;
            double rho = 0.365;
            double log_e = 1.4427;
            double N = recv_set_size;
            u64 M = send_set_size;
            u64 L = (u64)(((kappa) / log_e) * pow(N, rho));
            u64 T = (u64)(((2 + ((kappa) / log_e)) * log2(N))/(log2(log2(N))));

            std::vector<std::vector<std::vector<FM25519_point>>> E(L);


            for(u64 i = 0; i < L; i++){
                std::vector<FM25519_point> E_temp;
                coproto::sync_wait((*channel).flush());
                coproto::sync_wait((*channel).recvResize(E_temp));
                E[i] = one_dim_to_two_dim(E_temp, EC_CIPHER_SIZE_IN_NUMBER);
            }

            size_t okvs_n;
            coproto::sync_wait((*channel).flush());
            coproto::sync_wait((*channel).recvResize(okvs_n));

            printf("decode cnt = %d\n", L*M*T);

            RBOKVS_rist okvs;
            okvs.init(okvs_n, 0.1, lambda, seed);
            std::vector<std::vector<std::vector<FM25519_point>>> values(L, std::vector<std::vector<FM25519_point>>(M * T));
            for(u64 i = 0; i < L; i ++){
                std::vector<block> keys_temp;
                for(u64 j = 0; j < M * T * dimension; j ++){
                    values[i][j] = okvs.decode(E[i], (*keys)[i][j], EC_CIPHER_SIZE_IN_NUMBER);
                }
            }

            u64 cnt(0);
            for(u64 i = 0; i < L; i ++){
                std::vector<block> keys_temp;
                for(u64 j = 0; j < M * T * dimension; j ++){
                    if((values[i][j][0] + values[i][j][1]) != ((*vec_G_pow_a)[j / T] + (*vec_H_pow_a)[j / T])){
                        cnt++;
                    }
                }
            }

            return;
        }

    }

}