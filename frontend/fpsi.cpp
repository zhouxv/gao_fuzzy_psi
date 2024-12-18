///////////////////////////

#include "fpsi.h"
#include <unistd.h>
#include <thread>

#include "gm_crypto.h"
#include "fm.h"
#include "fuzzy_mapping.h"
#include "Hamming.h"
#include "fpsi_bp24.h"

namespace osuCrypto
{
/////our protocols///////////
    void test_our_lp_paillier_fpsi(const CLP& cmd){

        std::cout << "test_our_lp_paillier_fpsi ----------------------------" << std::endl;

        PRNG prng(oc::sysRandomSeed());

        const u64 dimension = cmd.getOr("d", 2);
        const u64 delta = cmd.getOr("delta", 10);
        const u64 side_length = 1;
        const u64 p = cmd.getOr("p", 2);
        const u64 recv_set_size = 1ull << cmd.getOr("r", 10);
        const u64 send_set_size = 1ull << cmd.getOr("s", 10);
        const u64 intersection_size = cmd.getOr("i", 32);
        if((intersection_size > recv_set_size) | (intersection_size > send_set_size)){
            printf("intersection_size should not be greater than set_size\n");
            return;
        }

        std::cout << "recv_set_size: " << recv_set_size << std::endl;
        std::cout << "send_set_size: " << send_set_size << std::endl;
        std::cout << "dimension    : " << dimension << std::endl;
        std::cout << "delta        : " << delta << std::endl;
        std::cout << "distance     : l_" << p << std::endl;

        std::vector<std::vector<u64>> receiver_elements(recv_set_size, std::vector<u64>(dimension, 0));
        std::vector<std::vector<u64>> sender_elements(send_set_size, std::vector<u64>(dimension, 0));

        std::cout << "data init start" << std::endl;
        for(u64 i = 0; i < recv_set_size; i++){
            for(u64 j = 0; j < dimension; j++){
                receiver_elements[i][j] = (prng.get<u64>()) % ((0xffff'ffff'ffff'ffff) - 3 * delta) + 1.5 * delta;
            }
        }

        for(u64 i = 0; i < send_set_size; i++){
            for(u64 j = 0; j < dimension; j++){
                sender_elements[i][j] = (prng.get<u64>()) % ((0xffff'ffff'ffff'ffff) - 3 * delta) + 1.5 * delta;
            }
        }


        u64 base_pos = (prng.get<u64>()) % (send_set_size - intersection_size - 1);
        for(u64 i = base_pos; i < base_pos + intersection_size; i++){
            for(u64 j = 0; j < dimension; j++){
                sender_elements[i][j] = receiver_elements[i - base_pos][j];
            }
            for(u64 j = 0; j < 1; j++){
                sender_elements[i][j] += ((i8)((prng.get<u8>()) % (delta - 1)) - delta / 2);
            }
        }

        std::cout << "data init done" << std::endl;

        ///////////////////////////////////////////////////////////////////////////////////////
        // key generate //////////////////////////////////////////////////////////////////////////////
        Rist25519_number recv_sk(prng);
        std::array<Rist25519_point, 2> recv_pk;
        recv_pk[0] = Rist25519_point(prng);
        recv_pk[1] = recv_sk * recv_pk[0];

        Rist25519_number send_sk(prng);
        std::array<Rist25519_point, 2> send_pk;
        send_pk[0] = Rist25519_point(prng);
        send_pk[1] = send_sk * send_pk[0];

        Rist25519_number recv_dh_sk(prng);
        Rist25519_number send_dh_sk(prng);

        ipcl::initializeContext("QAT");
        ipcl::KeyPair paillier_key = ipcl::generateKeypair(2048, true);
        ipcl::setHybridMode(ipcl::HybridMode::OPTIMAL);

        DH25519_number recv_dh_k(prng);
        DH25519_number send_dh_k(prng);
///////////////////////////////////////
        Timer time;
        ///////////////////////////////////////////////////////////////////////////////////////
        // offline //////////////////////////////////////////////////////////////////////////////
        time.setTimePoint("Start");
        std::stack<Rist25519_number> recv_vals_candidate_r;
        std::stack<Rist25519_number> recv_vals_candidate_skr;
        std::vector<std::vector<Rist25519_number>> recv_values;
        fmap::assign_segments(recv_set_size, recv_values, recv_vals_candidate_r, recv_vals_candidate_skr, dimension, delta, side_length, recv_sk);
        std::stack<Rist25519_number> send_vals_candidate_r;
        std::stack<Rist25519_number> send_vals_candidate_skr;
        std::vector<std::vector<Rist25519_number>> send_values;
        fmap::assign_segments(send_set_size, send_values, send_vals_candidate_r, send_vals_candidate_skr, dimension, delta, side_length, send_sk);
        std::vector<Rist25519_number> recv_masks;
        std::vector<Rist25519_number> recv_masks_inv;
        fmap::get_mask_cipher(recv_set_size, recv_masks, recv_masks_inv, recv_pk);   
        std::vector<Rist25519_number> send_masks;
        std::vector<Rist25519_number> send_masks_inv;
        fmap::get_mask_cipher(send_set_size, send_masks, send_masks_inv, send_pk);
        std::cout << "fmap offline done" << std::endl;

        std::vector<std::vector<block>> fmat_vals;
        fm_paillier::receiver_value_paillier_lp(recv_set_size, fmat_vals, dimension, delta, p, paillier_key);

        std::vector<u32> masks;
        ipcl::CipherText vec_mask_ct;
        fm_paillier::sender_mask_paillier_lp(send_set_size, masks, vec_mask_ct, paillier_key.pub_key);
        std::vector<std::vector<block>> send_prefixes;
        std::vector<std::vector<DH25519_point>> send_prefixes_k;
        u64 max_prefix_num = fm_paillier::sender_get_prefixes(masks, send_prefixes, delta, p);
        fm_paillier::prefixes_pow_sk(send_prefixes, send_prefixes_k, send_dh_k);

        std::vector<DH25519_point> send_prefixes_k_net;
        fm_paillier::pad_send_prefixes_k(send_prefixes_k, send_prefixes_k_net, max_prefix_num);


        //fm_paillier::pad_prefixes_k(send_prefixes_k, delta, p);
        std::cout << "fmat offline done" << std::endl;
        time.setTimePoint("offline");
// ///////////////////////////////////////
        
	    auto sockets = coproto::LocalAsyncSocket::makePair();

        std::vector<Rist25519_point> recv_vec_dhkk_seedsum(recv_set_size);
        std::vector<Rist25519_point> send_vec_dhkk_seedsum(send_set_size);

        std::cout << "fmap online begin" << std::endl;
		std::thread thread_fmap_recv(fmap::fmap_recv_online, &sockets[0],
        &receiver_elements,
        &recv_values,
        &recv_vals_candidate_r, &recv_vals_candidate_skr,
        &recv_masks, &recv_masks_inv,
        &recv_vec_dhkk_seedsum, 
        dimension, delta, side_length,
        recv_sk, recv_pk, recv_dh_sk);
		std::thread thread_fmap_send(fmap::fmap_send_online, &sockets[1],
        &sender_elements,
        &send_values,
        &send_vals_candidate_r, &send_vals_candidate_skr,
        &send_masks, &send_masks_inv,
        &send_vec_dhkk_seedsum,
        dimension, delta, side_length,
        send_sk, send_pk, send_dh_sk);

		thread_fmap_recv.join();
		thread_fmap_send.join();

        std::cout << "fmap online done" << std::endl;
        time.setTimePoint("fmap done");

        // if(recv_vec_dhkk_seedsum[369] == send_vec_dhkk_seedsum[369]){
        //     printf("pass map\n");
        // }else{
        //     printf("wrong map\n");

        // }

        // print_vec_point(recv_vec_dhkk_seedsum);
        // print_vec_point(send_vec_dhkk_seedsum);

		std::thread thread_fmat_recv(fm_paillier::fmat_paillier_recv_online, &sockets[0],
        &receiver_elements, &recv_vec_dhkk_seedsum,
        &fmat_vals,
        dimension, delta, p,
        paillier_key, recv_dh_k);

		std::thread thread_fmat_send(fm_paillier::fmat_paillier_send_online, &sockets[1],
        &sender_elements, &send_vec_dhkk_seedsum,
        &send_prefixes_k_net, &vec_mask_ct,
        dimension, delta, p,
        paillier_key.pub_key, send_dh_k);

		thread_fmat_recv.join();
		thread_fmat_send.join();
        time.setTimePoint("fmat done");
        time.setTimePoint("online done");


        ipcl::setHybridOff();
        ipcl::terminateContext();

        std::cout << (time) << std::endl;

		auto recv_bytes_present = sockets[0].bytesSent();
		auto send_bytes_present = sockets[1].bytesSent();
        std::cout << "[our_lp] recv sends:  "<< (recv_bytes_present) / 1024.0 / 1024 << "MB" << std::endl;
		std::cout << "[our_lp] send sends:  "<< (send_bytes_present) / 1024.0 / 1024 << "MB" << std::endl;
		std::cout << "[our_lp] comm total:  "<< ((recv_bytes_present) + (send_bytes_present)) / 1024.0 / 1024 << "MB" << std::endl;

        // sockets[0].close();
        // sockets[1].close();

        std::cout << std::endl;

        const bool out_to_file = cmd.isSet("file");
        if(out_to_file){
            std::string filename = "test_our_lp_paillier_fpsi_m_"+std::to_string(send_set_size)
                                    +"_n_"+std::to_string(recv_set_size)
                                    +"_d_"+std::to_string(dimension)
                                    +"_delta_"+std::to_string(delta)
                                    +"_p_"+std::to_string(p)+".txt";
            std::ofstream mycout(filename, std::ios::app);
            mycout << std::endl << "test_our_lp_paillier_fpsi ----------------------------" << std::endl;
            mycout << "recv_set_size: " << recv_set_size << std::endl;
            mycout << "send_set_size: " << send_set_size << std::endl;
            mycout << "dimension:     " << dimension << std::endl;
            mycout << "delta:         " << delta << std::endl;
            mycout << "l_p:           " << p << std::endl;
            mycout << "[our_lp] recv sends:  "<< (recv_bytes_present) / 1024.0 / 1024 << "MB" << std::endl;
		    mycout << "[our_lp] send sends:  "<< (send_bytes_present) / 1024.0 / 1024 << "MB" << std::endl;
		    mycout << "[our_lp] comm total:  "<< ((recv_bytes_present) + (send_bytes_present)) / 1024.0 / 1024 << "MB" << std::endl;
            mycout << time << std::endl << std::endl;
            mycout.close();
        }
        return;
    }

    void test_our_linfty_paillier_fpsi(const CLP& cmd){
        std::cout << "test_our_linfty_paillier_fpsi ----------------------------" << std::endl;
        PRNG prng(oc::sysRandomSeed());

        const u64 dimension = cmd.getOr("d", 2);
        const u64 delta = cmd.getOr("delta", 10);
        const u64 side_length = 1;
        const u64 p = 0;
        const u64 recv_set_size = 1ull << cmd.getOr("r", 10);
        const u64 send_set_size = 1ull << cmd.getOr("s", 10);
        const u64 intersection_size = cmd.getOr("i", 32);
        if((intersection_size > recv_set_size) | (intersection_size > send_set_size)){
            printf("intersection_size should not be greater than set_size\n");
            return;
        }


        std::cout << "recv_set_size: " << recv_set_size << std::endl;
        std::cout << "send_set_size: " << send_set_size << std::endl;
        std::cout << "dimension    : " << dimension << std::endl;
        std::cout << "delta        : " << delta << std::endl;
        std::cout << "distance     : l_infty" << std::endl;

        std::vector<std::vector<u64>> receiver_elements(recv_set_size, std::vector<u64>(dimension, 0));
        std::vector<std::vector<u64>> sender_elements(send_set_size, std::vector<u64>(dimension, 0));
        
        std::cout << "data init begin" << std::endl;

        for(u64 i = 0; i < recv_set_size; i++){
            for(u64 j = 0; j < dimension; j++){
                receiver_elements[i][j] = (prng.get<u64>()) % ((0xffff'ffff'ffff'ffff) - 3 * delta) + 1.5 * delta;
            }
        }

        for(u64 i = 0; i < send_set_size; i++){
            for(u64 j = 0; j < dimension; j++){
                sender_elements[i][j] = (prng.get<u64>()) % ((0xffff'ffff'ffff'ffff) - 3 * delta) + 1.5 * delta;
            }
        }

        u64 base_pos = (prng.get<u64>()) % (send_set_size - intersection_size - 1);
        //u64 base_pos = 0;
        for(u64 i = base_pos; i < base_pos + intersection_size; i++){
            for(u64 j = 0; j < dimension; j++){
                sender_elements[i][j] = receiver_elements[i - base_pos][j];
            }
            for(u64 j = 0; j < 2; j++){
                sender_elements[i][j] += ((i8)((prng.get<u8>()) % (delta - 1)) - delta / 2);
            }
        }
        std::cout << "data init done" << std::endl;

        ///////////////////////////////////////////////////////////////////////////////////////
        // key generate //////////////////////////////////////////////////////////////////////////////
        Rist25519_number recv_sk(prng);
        std::array<Rist25519_point, 2> recv_pk;
        recv_pk[0] = Rist25519_point(prng);
        recv_pk[1] = recv_sk * recv_pk[0];

        Rist25519_number send_sk(prng);
        std::array<Rist25519_point, 2> send_pk;
        send_pk[0] = Rist25519_point(prng);
        send_pk[1] = send_sk * send_pk[0];

        Rist25519_number recv_dh_sk(prng);
        Rist25519_number send_dh_sk(prng);


        ipcl::initializeContext("QAT");
        ipcl::KeyPair paillier_key = ipcl::generateKeypair(2048, true);
        ipcl::setHybridMode(ipcl::HybridMode::OPTIMAL);


///////////////////////////////////////
        Timer time;
        ///////////////////////////////////////////////////////////////////////////////////////
        // offline //////////////////////////////////////////////////////////////////////////////
        time.setTimePoint("Start");
        std::stack<Rist25519_number> recv_vals_candidate_r;
        std::stack<Rist25519_number> recv_vals_candidate_skr;
        std::vector<std::vector<Rist25519_number>> recv_values;
        fmap::assign_segments(recv_set_size, recv_values, recv_vals_candidate_r, recv_vals_candidate_skr, dimension, delta, side_length, recv_sk);
        std::stack<Rist25519_number> send_vals_candidate_r;
        std::stack<Rist25519_number> send_vals_candidate_skr;
        std::vector<std::vector<Rist25519_number>> send_values;
        fmap::assign_segments(send_set_size, send_values, send_vals_candidate_r, send_vals_candidate_skr, dimension, delta, side_length, send_sk);
        std::vector<Rist25519_number> recv_masks;
        std::vector<Rist25519_number> recv_masks_inv;
        fmap::get_mask_cipher(recv_set_size, recv_masks, recv_masks_inv, recv_pk);   
        std::vector<Rist25519_number> send_masks;
        std::vector<Rist25519_number> send_masks_inv;
        fmap::get_mask_cipher(send_set_size, send_masks, send_masks_inv, send_pk);
        std::cout << "fmap offline done" << std::endl;

        std::vector<std::vector<block>> fmat_vals;
        fm_paillier::receiver_value_paillier_linfty(recv_set_size, fmat_vals, dimension, delta, paillier_key);
        std::cout << "fmat offline done" << std::endl;
        time.setTimePoint("offline");
// ///////////////////////////////////////
        
	    auto sockets = coproto::LocalAsyncSocket::makePair();

        std::vector<Rist25519_point> recv_vec_dhkk_seedsum(recv_set_size);
        std::vector<Rist25519_point> send_vec_dhkk_seedsum(send_set_size);

        std::cout << "fmap online begin" << std::endl;
		std::thread thread_fmap_recv(fmap::fmap_recv_online, &sockets[0],
        &receiver_elements,
        &recv_values,
        &recv_vals_candidate_r, &recv_vals_candidate_skr,
        &recv_masks, &recv_masks_inv,
        &recv_vec_dhkk_seedsum, 
        dimension, delta, side_length,
        recv_sk, recv_pk, recv_dh_sk);
		std::thread thread_fmap_send(fmap::fmap_send_online, &sockets[1],
        &sender_elements,
        &send_values,
        &send_vals_candidate_r, &send_vals_candidate_skr,
        &send_masks, &send_masks_inv,
        &send_vec_dhkk_seedsum,
        dimension, delta, side_length,
        send_sk, send_pk, send_dh_sk);

		thread_fmap_recv.join();
		thread_fmap_send.join();
        
        auto recv_bytes_present_fmap = sockets[0].bytesSent();
        auto send_bytes_present_fmap = sockets[1].bytesSent();

        std::cout << "fmap online done" << std::endl;
        time.setTimePoint("fmap done");
        // print_vec_point(recv_vec_dhkk_seedsum);
        // print_vec_point(send_vec_dhkk_seedsum);

		std::thread thread_fmat_recv(fm_paillier::fmat_paillier_linfty_recv_online, &sockets[0],
        &receiver_elements, &recv_vec_dhkk_seedsum,
        &fmat_vals,
        dimension, delta,
        paillier_key);

		std::thread thread_fmat_send(fm_paillier::fmat_paillier_linfty_send_online, &sockets[1],
        &sender_elements, &send_vec_dhkk_seedsum,
        dimension, delta,
        paillier_key.pub_key);

		thread_fmat_recv.join();
		thread_fmat_send.join();
        time.setTimePoint("fmat done");
        time.setTimePoint("online done");

        std::cout << (time) << std::endl;

		auto recv_bytes_present = sockets[0].bytesSent();
		auto send_bytes_present = sockets[1].bytesSent();
        std::cout << "[our_linfty] recv sends:  "<< (recv_bytes_present) / 1024.0 / 1024 << "MB" << std::endl;
		std::cout << "[our_linfty] send sends:  "<< (send_bytes_present) / 1024.0 / 1024 << "MB" << std::endl;
		std::cout << "[our_linfty] comm total:  "<< ((recv_bytes_present) + (send_bytes_present)) / 1024.0 / 1024 << "MB" << std::endl;
        std::cout << "[our_fmap] recv sends:  "<< (recv_bytes_present_fmap) / 1024.0 / 1024 << "MB" << std::endl;
		std::cout << "[our_fmap] send sends:  "<< (send_bytes_present_fmap) / 1024.0 / 1024 << "MB" << std::endl;
		std::cout << "[our_fmap] comm total:  "<< ((recv_bytes_present_fmap) + (send_bytes_present_fmap)) / 1024.0 / 1024 << "MB" << std::endl;


        // sockets[0].close();
        // sockets[1].close();

        std::cout << std::endl;


        const bool out_to_file = cmd.isSet("file");
        if(out_to_file){
            std::string filename = "test_our_linfty_paillier_fpsi_m_"+std::to_string(send_set_size)
                                    +"_n_"+std::to_string(recv_set_size)
                                    +"_d_"+std::to_string(dimension)
                                    +"_delta_"+std::to_string(delta)
                                    +"_p_infty"+".txt";
            std::ofstream mycout(filename, std::ios::app);
            mycout << std::endl << "test_our_linfty_paillier_fpsi ----------------------------" << std::endl;
            mycout << "recv_set_size: " << recv_set_size << std::endl;
            mycout << "send_set_size: " << send_set_size << std::endl;
            mycout << "dimension:     " << dimension << std::endl;
            mycout << "delta:         " << delta << std::endl;
            mycout << "distance:      l_infty" << std::endl;
            mycout << "[our_linfty] recv sends:  "<< (recv_bytes_present) / 1024.0 / 1024 << "MB" << std::endl;
		    mycout << "[our_linfty] send sends:  "<< (send_bytes_present) / 1024.0 / 1024 << "MB" << std::endl;
		    mycout << "[our_linfty] comm total:  "<< ((recv_bytes_present) + (send_bytes_present)) / 1024.0 / 1024 << "MB" << std::endl;
            mycout << time << std::endl << std::endl;
            mycout.close();
        }

        return;
    }

    void test_gm_fpsi_hamming(const CLP& cmd){
        std::cout << "test_gm_fpsi_hamming ----------------------------" << std::endl;
        PRNG prng(oc::sysRandomSeed());

        const u64 dimension = cmd.getOr("hamd", 128);
        const u64 delta = cmd.getOr("hamdelta", 4);
        const u64 side_length = cmd.getOr("hamside", ((dimension / (delta + 1)) / 8) * 8);
        const u64 recv_set_size = 1ull << cmd.getOr("hamr", 6);
        const u64 send_set_size = 1ull << cmd.getOr("hams", 6);

        u64 i_temp = recv_set_size;
        if(recv_set_size > send_set_size){
            i_temp = send_set_size;
        }

        const u64 intersection_size = cmd.getOr("hami", 7);
        if((intersection_size > recv_set_size) | (intersection_size > send_set_size)){
            printf("intersection_size should not be greater than set_size\n");
            return;
        }
        if((side_length == 0 )){
            printf("dimension should not be less than (threshold + 1) * 8\n");
            return;
        }
        if((side_length > ((dimension / (delta + 1)) / 8) * 8 )){
            printf("side_length should be less than ((dimension / (threshold + 1)) / 8) * 8\n");
            return;
        }
        if((side_length % 8 != 0)){
            printf("side_length mod 8 should be 0\n");
            return;
        }
        if((pow(2, side_length) <= recv_set_size)){
            printf("pow(2, side_length) should be greater than recv_set_size\n");
            return;
        }

        std::cout << "recv_set_size: " << recv_set_size << std::endl;
        std::cout << "send_set_size: " << send_set_size << std::endl;
        std::cout << "dimension    : " << dimension << std::endl;
        std::cout << "delta        : " << delta << std::endl;
        std::cout << "intersec_size: " << intersection_size << std::endl;
        std::cout << "side_length  : " << side_length << std::endl;


        std::vector<BitVector> recv_set;
        std::vector<BitVector> send_set;
        std::vector<std::vector<u64>> unique_components;

        for(u64 i = 0; i< recv_set_size;i++){
            u8 data[dimension/8 + 1];
            prng.get<u8>(data, dimension/8);

            std::vector<u64> unique_component;
            for(u64 j = 0; j< delta +1;j++){
                unique_component.push_back(j);
                u64 temp_i = i;
                for(u64 k = 0; k < (side_length / 8);k++){
                    data[j * (side_length / 8) + k] = temp_i;
                    temp_i >>= 8;
                }
            }
            unique_components.push_back(unique_component);

            BitVector element_temp( data, dimension);
            recv_set.push_back(element_temp);
        }

        for(u64 i  = 0 ; i < intersection_size; i++){
            send_set.push_back(recv_set[i]);
            send_set[i][2] = 1;
        }

        BitVector bitvector_temp(dimension);
        for(u64 i  = 0 ; i < send_set_size - intersection_size; i++){
            bitvector_temp.randomize(prng);
            send_set.push_back(bitvector_temp);
        }

        pubkey_t pbkey;
        privkey_t prkey;

        mpz_init(pbkey.a);
        mpz_init(pbkey.N);
        mpz_init(prkey.p);
        mpz_init(prkey.q);
        gen_keys(&pbkey, &prkey);

        auto sockets = coproto::LocalAsyncSocket::makePair();
        Timer time;

        time.setTimePoint("Start");
        std::cout << "Start" << std::endl;

        std::stack<std::array<std::vector<element>, 2UL>> pre_vals;
        Hamming::receiver_precomp_value_hamming(recv_set_size, pre_vals, dimension, delta, &pbkey);

        std::stack<BitVector> masks;
        std::stack<std::vector<std::vector<block>>> masks_ciphers_block;
        Hamming::sender_precomp_mask_hamming(send_set_size, masks, masks_ciphers_block, dimension, side_length, &pbkey);


        time.setTimePoint("Offline done");
        std::cout << "offline done" << std::endl;

		std::thread thread_fpsi_recv(Hamming::fpsi_hamming_recv_online, &sockets[0],
        &recv_set, &unique_components,
        &pre_vals,
        dimension, delta, side_length,
        &pbkey, &prkey);

		std::thread thread_fpsi_send(Hamming::fpsi_hamming_send_online, &sockets[1],
        &send_set,
        &masks, &masks_ciphers_block,
        dimension, delta, side_length,
        &pbkey);

		thread_fpsi_recv.join();
		thread_fpsi_send.join();
        time.setTimePoint("online done");
        time.setTimePoint("fpsi done");

        std::cout << (time) << std::endl;

		auto recv_bytes_present = sockets[0].bytesSent();
		auto send_bytes_present = sockets[1].bytesSent();
        std::cout << "[fpsi_hamming] recv sends:  "<< (recv_bytes_present) / 1024.0 / 1024 << "MB" << std::endl;
		std::cout << "[fpsi_hamming] send sends:  "<< (send_bytes_present) / 1024.0 / 1024 << "MB" << std::endl;
		std::cout << "[fpsi_hamming] comm total:  "<< ((recv_bytes_present) + (send_bytes_present)) / 1024.0 / 1024 << "MB" << std::endl;

        // sockets[0].close();
        // sockets[1].close();

        std::cout << std::endl;


        mpz_clear(pbkey.a);
        mpz_clear(pbkey.N);
        mpz_clear(prkey.p);
        mpz_clear(prkey.q);

        const bool out_to_file = cmd.isSet("file");
        if(out_to_file){
            std::string filename = "test_Hamming_m_"+std::to_string(send_set_size)
                                    +"_n_"+std::to_string(recv_set_size)
                                    +"_d_"+std::to_string(dimension)
                                    +"_delta_"+std::to_string(delta)
                                    +".txt";
            std::ofstream mycout(filename, std::ios::app);
            mycout << std::endl << "test_Hamming ----------------------------" << std::endl;
            mycout << "recv_set_size: " << recv_set_size << std::endl;
            mycout << "send_set_size: " << send_set_size << std::endl;
            mycout << "dimension:     " << dimension << std::endl;
            mycout << "delta:         " << delta << std::endl;
            mycout << "side_length:   " << side_length << std::endl;
            mycout << "intersec_size: " << intersection_size << std::endl;
		    mycout << "[Hamming] comm:" << ((recv_bytes_present) + (send_bytes_present)) / 1024.0 / 1024 << "MB" << std::endl;
            mycout << "[Hamming] time:" << (time) << std::endl;
            mycout.close();
        }

        return;

    }

// /////bp24 protocols//////////
//     void test_bp24_lp_low_dim(const CLP& cmd){
//         std::cout << "test_bp24_lp_low_dim ----------------------------" << std::endl;
//         PRNG prng(oc::sysRandomSeed());

//         const u64 dimension = cmd.getOr("d", 2);
//         const u64 delta = cmd.getOr("delta", 10);
//         const u64 side_length = delta * 2;
//         const u64 p = cmd.getOr("p", 2);
//         const u64 recv_set_size = 1ull << cmd.getOr("r", 10);
//         const u64 send_set_size = 1ull << cmd.getOr("s", 10);
//         const u64 intersection_size = cmd.getOr("i", 32);
//         if((intersection_size > recv_set_size) | (intersection_size > send_set_size)){
//             printf("intersection_size should not be greater than set_size\n");
//             return;
//         }

//         std::cout << "recv_set_size: " << recv_set_size << std::endl;
//         std::cout << "send_set_size: " << send_set_size << std::endl;
//         std::cout << "dimension    : " << dimension << std::endl;
//         std::cout << "delta        : " << delta << std::endl;
//         std::cout << "side_length  : " << side_length << std::endl;
//         std::cout << "l_p          : l_" << p << std::endl;


//         std::vector<std::vector<u64>> receiver_elements(recv_set_size, std::vector<u64>(dimension, 0));
//         std::vector<std::vector<u64>> sender_elements(send_set_size, std::vector<u64>(dimension, 0));


//         std::cout << "data init begin" << std::endl;
//         for(u64 i = 0; i < recv_set_size; i++){
//             for(u64 j = 0; j < dimension; j++){
//                 receiver_elements[i][j] = (6 * delta + 1) * (i + 1);
//             }
//         }

//         for(u64 i = 0; i < send_set_size; i++){
//             for(u64 j = 0; j < dimension; j++){
//                 sender_elements[i][j] = (prng.get<u64>()) % ((0xffff'ffff'ffff'ffff) - 3 * delta) + 1.5 * delta;
//             }
//         }

//         for(u64 i = 0; i < intersection_size; i++){
//             for(u64 j = 0; j < dimension; j++){
//                 sender_elements[i][j] = receiver_elements[i][j];
//             }
//             sender_elements[i][1] += 1;
//         }
//         std::cout << "data init done" << std::endl;

//         ///////////////////////////////////////////////////////////////////////////////////////
//         // key generate //////////////////////////////////////////////////////////////////////////////
//         Rist25519_number recv_sk(prng);
//         std::array<Rist25519_point, 2> recv_pk;
//         recv_pk[0] = Rist25519_point::mulGenerator(1);
//         recv_pk[1] = recv_sk * recv_pk[0];

// ///////////////////////////////////////
//         Timer time;
//         ///////////////////////////////////////////////////////////////////////////////////////
//         // offline //////////////////////////////////////////////////////////////////////////////
//         time.setTimePoint("Start");
//         std::vector<std::vector<FM25519_number>> fmat_vals;
//         bp24_ec::receiver_precomp_vals_ec_lp(recv_set_size, fmat_vals, dimension, delta, side_length, p, recv_sk);

//         std::vector<FM25519_point> vec_G_pow_a_H_pow_c;
//         std::vector<FM25519_number> vec_b;
//         std::vector<FM25519_point> vec_G_pow_c;
//         std::vector<std::vector<FM25519_point>> vec_G_pow_a_bj;
//         bp24_ec::sender_mask_ec_lp(send_set_size, vec_G_pow_a_H_pow_c, vec_b, vec_G_pow_c, vec_G_pow_a_bj, delta, p, recv_pk[0], recv_pk[1]);

//         std::cout << "fmat offline done" << std::endl;
//         time.setTimePoint("offline");
// // ///////////////////////////////////////
        
// 	    auto sockets = coproto::LocalAsyncSocket::makePair();

// 		std::thread thread_fmat_recv(bp24_ec::bp24_lp_low_dim_recv_online, &sockets[0],
//         &receiver_elements,
//         &fmat_vals,
//         dimension, delta, side_length, p,
//         recv_sk, recv_pk[0]);

// 		std::thread thread_fmat_send(bp24_ec::bp24_lp_low_dim_send_online, &sockets[1],
//         &sender_elements,
//         &vec_G_pow_a_H_pow_c, &vec_b, &vec_G_pow_c,
//         &vec_G_pow_a_bj,
//         dimension, delta, side_length);

// 		thread_fmat_recv.join();
// 		thread_fmat_send.join();
//         time.setTimePoint("fmat done");
//         time.setTimePoint("online done");

//         std::cout << (time) << std::endl;

// 		auto recv_bytes_present = sockets[0].bytesSent();
// 		auto send_bytes_present = sockets[1].bytesSent();
//         std::cout << "[bp24_lp] recv sends:  "<< (recv_bytes_present) / 1024.0 / 1024 << "MB" << std::endl;
// 		std::cout << "[bp24_lp] send sends:  "<< (send_bytes_present) / 1024.0 / 1024 << "MB" << std::endl;
// 		std::cout << "[bp24_lp] comm total:  "<< ((recv_bytes_present) + (send_bytes_present)) / 1024.0 / 1024 << "MB" << std::endl;

//         // sockets[0].close();
//         // sockets[1].close();

//         std::cout << std::endl;

//         const bool out_to_file = cmd.isSet("file");
//         if(out_to_file){
//             std::string filename = "test_bp24_lp_low_dim_m_"+std::to_string(send_set_size)
//                                     +"_n_"+std::to_string(recv_set_size)
//                                     +"_d_"+std::to_string(dimension)
//                                     +"_delta_"+std::to_string(delta)
//                                     +"_p_"+std::to_string(p)+".txt";
//             std::ofstream mycout(filename, std::ios::app);
//             mycout << std::endl << "test_bp24_lp_low_dim ----------------------------" << std::endl;
//             mycout << "recv_set_size: " << recv_set_size << std::endl;
//             mycout << "send_set_size: " << send_set_size << std::endl;
//             mycout << "dimension:     " << dimension << std::endl;
//             mycout << "delta:         " << delta << std::endl;
//             mycout << "side_length:   " << side_length << std::endl;
//             mycout << "l_p:           " << p << std::endl;
//             mycout << "[bp24_lp] recv sends:  "<< (recv_bytes_present) / 1024.0 / 1024 << "MB" << std::endl;
// 		    mycout << "[bp24_lp] send sends:  "<< (send_bytes_present) / 1024.0 / 1024 << "MB" << std::endl;
// 		    mycout << "[bp24_lp] comm total:  "<< ((recv_bytes_present) + (send_bytes_present)) / 1024.0 / 1024 << "MB" << std::endl;
//             mycout << time << std::endl << std::endl;
//             mycout.close();
//         }
//         return;
//     }

//     void test_bp24_linfty_low_dim(const CLP& cmd){
//         std::cout << "test_bp24_linfty_low_dim ----------------------------" << std::endl;
//         PRNG prng(oc::sysRandomSeed());

//         const u64 dimension = cmd.getOr("d", 2);
//         const u64 delta = cmd.getOr("delta", 10);
//         const u64 side_length = delta * 2;
//         const u64 p = 0;
//         const u64 recv_set_size = 1ull << cmd.getOr("r", 10);
//         const u64 send_set_size = 1ull << cmd.getOr("s", 10);
//         const u64 intersection_size = cmd.getOr("i", 32);
//         if((intersection_size > recv_set_size) | (intersection_size > send_set_size)){
//             printf("intersection_size should not be greater than set_size\n");
//             return;
//         }


//         std::cout << "recv_set_size: " << recv_set_size << std::endl;
//         std::cout << "send_set_size: " << send_set_size << std::endl;
//         std::cout << "dimension    : " << dimension << std::endl;
//         std::cout << "delta        : " << delta << std::endl;
//         std::cout << "side_length  : " << side_length << std::endl;
//         std::cout << "distance     : l_infty" << std::endl;

//         std::vector<std::vector<u64>> receiver_elements(recv_set_size, std::vector<u64>(dimension, 0));
//         std::vector<std::vector<u64>> sender_elements(send_set_size, std::vector<u64>(dimension, 0));

//         std::cout << "data init begin" << std::endl;
//         for(u64 i = 0; i < recv_set_size; i++){
//             for(u64 j = 0; j < dimension; j++){
//                 receiver_elements[i][j] = (6 * delta + 1) * (i + 1);
//             }
//         }

//         for(u64 i = 0; i < send_set_size; i++){
//             for(u64 j = 0; j < dimension; j++){
//                 sender_elements[i][j] = (prng.get<u64>()) % ((0xffff'ffff'ffff'ffff) - 3 * delta) + 1.5 * delta;
//             }
//         }

//         for(u64 i = 0; i < intersection_size; i++){
//             for(u64 j = 0; j < dimension; j++){
//                 sender_elements[i][j] = receiver_elements[i][j];
//             }
//             sender_elements[i][1] += 1;
//         }
//         std::cout << "data init done" << std::endl;

//         ///////////////////////////////////////////////////////////////////////////////////////
//         // key generate //////////////////////////////////////////////////////////////////////////////
//         Rist25519_number recv_sk(prng);
//         std::array<Rist25519_point, 2> recv_pk;
//         recv_pk[0] = Rist25519_point(prng);
//         recv_pk[1] = recv_sk * recv_pk[0];

// ///////////////////////////////////////
//         Timer time;
//         ///////////////////////////////////////////////////////////////////////////////////////
//         // offline //////////////////////////////////////////////////////////////////////////////
//         time.setTimePoint("Start");

//         std::vector<std::vector<FM25519_number>> fmat_vals;
//         bp24_ec::receiver_precomp_vals_ec_linfty(recv_set_size, fmat_vals, dimension, delta, side_length, recv_sk);

//         std::vector<FM25519_point> vec_G_pow_a;
//         std::vector<FM25519_number> vec_b;
//         std::vector<FM25519_point> vec_H_pow_a;
//         bp24_ec::sender_mask_ec_linfty(send_set_size, vec_G_pow_a, vec_b, vec_H_pow_a, recv_pk[0], recv_pk[1]);
//         std::cout << "fmat offline done" << std::endl;
//         time.setTimePoint("offline");
// // ///////////////////////////////////////
        
// 	    auto sockets = coproto::LocalAsyncSocket::makePair();

// 		std::thread thread_fmat_recv(bp24_ec::bp24_linfty_low_dim_recv_online, &sockets[0],
//         &receiver_elements,
//         &fmat_vals,
//         dimension, delta, side_length,
//         recv_sk, recv_pk[0]);

// 		std::thread thread_fmat_send(bp24_ec::bp24_linfty_low_dim_send_online, &sockets[1],
//         &sender_elements,
//         &vec_G_pow_a, &vec_b, &vec_H_pow_a,
//         dimension, delta, side_length);

// 		thread_fmat_recv.join();
// 		thread_fmat_send.join();
//         time.setTimePoint("fmat done");
//         time.setTimePoint("online done");

//         std::cout << (time) << std::endl;

// 		auto recv_bytes_present = sockets[0].bytesSent();
// 		auto send_bytes_present = sockets[1].bytesSent();
//         std::cout << "[bp24_linfty] recv sends:  "<< (recv_bytes_present) / 1024.0 / 1024 << "MB" << std::endl;
// 		std::cout << "[bp24_linfty] send sends:  "<< (send_bytes_present) / 1024.0 / 1024 << "MB" << std::endl;
// 		std::cout << "[bp24_linfty] comm total:  "<< ((recv_bytes_present) + (send_bytes_present)) / 1024.0 / 1024 << "MB" << std::endl;

//         // sockets[0].close();
//         // sockets[1].close();

//         std::cout << std::endl;

//         const bool out_to_file = cmd.isSet("file");
//         if(out_to_file){
//             std::string filename = "test_bp24_linfty_low_dim_m_"+std::to_string(send_set_size)
//                                     +"_n_"+std::to_string(recv_set_size)
//                                     +"_d_"+std::to_string(dimension)
//                                     +"_delta_"+std::to_string(delta)
//                                     +"_p_infty"+".txt";
//             std::ofstream mycout(filename, std::ios::app);
//             mycout << std::endl << "test_bp24_linfty_low_dim ----------------------------" << std::endl;
//             mycout << "recv_set_size: " << recv_set_size << std::endl;
//             mycout << "send_set_size: " << send_set_size << std::endl;
//             mycout << "dimension:     " << dimension << std::endl;
//             mycout << "delta:         " << delta << std::endl;
//             mycout << "side_length:   " << side_length << std::endl;
//             mycout << "distance:      l_infty" << std::endl;
//             mycout << "[bp24_linfty] recv sends:  "<< (recv_bytes_present) / 1024.0 / 1024 << "MB" << std::endl;
// 		    mycout << "[bp24_linfty] send sends:  "<< (send_bytes_present) / 1024.0 / 1024 << "MB" << std::endl;
// 		    mycout << "[bp24_linfty] comm total:  "<< ((recv_bytes_present) + (send_bytes_present)) / 1024.0 / 1024 << "MB" << std::endl;
//             mycout << time << std::endl << std::endl;
//             mycout.close();
//         }

//         return;
//     }

//     void test_bp24_lp_high_dim(const CLP& cmd){
//         std::cout << "test_bp24_lp_high_dim ----------------------------" << std::endl;
//         PRNG prng(oc::sysRandomSeed());

//         const u64 dimension = cmd.getOr("d", 2);
//         const u64 delta = cmd.getOr("delta", 10);
//         const u64 side_length = delta * 2;
//         const u64 p = cmd.getOr("p", 2);
//         const u64 recv_set_size = 1ull << cmd.getOr("r", 10);
//         const u64 send_set_size = 1ull << cmd.getOr("s", 10);

//         std::cout << "recv_set_size: " << recv_set_size << std::endl;
//         std::cout << "send_set_size: " << send_set_size << std::endl;
//         std::cout << "dimension    : " << dimension << std::endl;
//         std::cout << "delta        : " << delta << std::endl;
//         std::cout << "side_length  : " << side_length << std::endl;
//         std::cout << "l_p          : l_" << p << std::endl;

//         double kappa = 40;
//         double rho = 0.365;
//         if(p == 1){
//             rho = 0.5;
//         }
//         double log_e = 1.4427;
//         double N = recv_set_size;
//         u64 M = send_set_size;
//         u64 L = (u64)(((kappa) / log_e) * pow(N, rho));
//         u64 T = (u64)(((2 + ((kappa) / log_e)) * log2(N))/(log2(log2(N))));

//         double time = (N * L * (2 * delta + 1) * dimension * 40 + M * L * T * dimension) * 10 * 0.001;
//         double comm = N * L * (2 * delta + 1) * dimension * EC_CIPHER_SIZE_IN_BLOCK * 16 / 1024.0 / 1024;

//         std::cout << "rho          : " << rho << std::endl;

// 		std::cout << "[bp24_lp_high] comm lower bound:  " << comm << "MB" << std::endl;
//         std::cout << "[bp24_lp_high] time lower bound:  " << time << "ms" << std::endl << std::endl;

//         std::cout << std::endl;

//         const bool out_to_file = cmd.isSet("file");
//         if(out_to_file){
//             std::string filename = "test_bp24_lp_high_dim_m_"+std::to_string(send_set_size)
//                                     +"_n_"+std::to_string(recv_set_size)
//                                     +"_d_"+std::to_string(dimension)
//                                     +"_delta_"+std::to_string(delta)
//                                     +"_p_"+std::to_string(p)+".txt";
//             std::ofstream mycout(filename, std::ios::app);
//             mycout << std::endl << "test_bp24_lp_high_dim ----------------------------" << std::endl;
//             mycout << "recv_set_size: " << recv_set_size << std::endl;
//             mycout << "send_set_size: " << send_set_size << std::endl;
//             mycout << "dimension:     " << dimension << std::endl;
//             mycout << "delta:         " << delta << std::endl;
//             mycout << "side_length:   " << side_length << std::endl;
//             mycout << "l_p:           " << p << std::endl;
// 		    mycout << "[bp24_lp_high] comm lower bound:  " << comm << "MB" << std::endl;
//             mycout << "[bp24_lp_high] time lower bound:  " << time << "ms" << std::endl << std::endl;
//             mycout.close();
//         }

//         return;
//     }

//     void test_bp24_linfty_high_dim(const CLP& cmd){
//         std::cout << "test_bp24_linfty_high_dim ----------------------------" << std::endl;
//         PRNG prng(oc::sysRandomSeed());

//         const u64 dimension = cmd.getOr("d", 2);
//         const u64 delta = cmd.getOr("delta", 10);
//         const u64 side_length = delta * 2;
//         const u64 p = 0;
//         const u64 recv_set_size = 1ull << cmd.getOr("r", 10);
//         const u64 send_set_size = 1ull << cmd.getOr("s", 10);
//         const u64 intersection_size = cmd.getOr("i", 32);
//         if((intersection_size > recv_set_size) | (intersection_size > send_set_size)){
//             printf("intersection_size should not be greater than set_size\n");
//             return;
//         }

//         std::cout << "recv_set_size: " << recv_set_size << std::endl;
//         std::cout << "send_set_size: " << send_set_size << std::endl;
//         std::cout << "dimension    : " << dimension << std::endl;
//         std::cout << "delta        : " << delta << std::endl;
//         std::cout << "side_length  : " << side_length << std::endl;
//         std::cout << "distance     : l_infty" << std::endl;


//         std::vector<std::vector<u64>> receiver_elements(recv_set_size, std::vector<u64>(dimension, 0));
//         std::vector<u64> separate_dims(recv_set_size);

//         std::vector<std::vector<u64>> sender_elements(send_set_size, std::vector<u64>(dimension, 0));

//         printf("data init start\n");
//         for(u64 i = 0; i < recv_set_size; i++){
//             for(u64 j = 0; j < dimension; j++){
//                 receiver_elements[i][j] = (3 * delta + 1) * (i + 1);
//             }
//             separate_dims[i] = 0;
//         }

//         for(u64 i = 0; i < send_set_size; i++){
//             for(u64 j = 0; j < dimension; j++){
//                 sender_elements[i][j] = (prng.get<u64>()) % ((0xffff'ffff'ffff'ffff) - 3 * delta) + 1.5 * delta;
//             }
//         }

//         for(u64 i = 0; i < intersection_size; i++){
//             for(u64 j = 0; j < dimension; j++){
//                 sender_elements[i][j] = receiver_elements[i][j];
//             }
//             sender_elements[i][1] += 1;
//         }
//         std::cout << "data init done" << std::endl;

//         ///////////////////////////////////////////////////////////////////////////////////////
//         // key generate //////////////////////////////////////////////////////////////////////////////
//         Rist25519_number recv_sk(prng);
//         std::array<Rist25519_point, 2> recv_pk;
//         recv_pk[0] = Rist25519_point(prng);
//         recv_pk[1] = recv_sk * recv_pk[0];

// ///////////////////////////////////////
//         Timer time;
//         ///////////////////////////////////////////////////////////////////////////////////////
//         // offline //////////////////////////////////////////////////////////////////////////////
//         time.setTimePoint("Start");

//         std::stack<std::vector<FM25519_number>> vals_candidate;
//         bp24_high_dim::receiver_precomp_vals_ec_linfty(recv_set_size, vals_candidate, dimension, delta, recv_sk);

//         std::vector<FM25519_point> vec_G_pow_a;
//         std::vector<FM25519_number> vec_b;
//         std::vector<FM25519_point> vec_H_pow_a;
//         bp24_high_dim::sender_mask_ec_linfty(send_set_size, vec_G_pow_a, vec_b, vec_H_pow_a, recv_pk[0], recv_pk[1]);

//         std::cout << "fmat offline done" << std::endl;
//         time.setTimePoint("offline");
// // ///////////////////////////////////////
        
// 	    auto sockets = coproto::LocalAsyncSocket::makePair();

// 		std::thread thread_fmat_recv(bp24_high_dim::bp24_linfty_high_dim_recv_online, &sockets[0],
//         &receiver_elements, &separate_dims,
//         &vals_candidate,
//         dimension, delta,
//         recv_sk, recv_pk[0]);

// 		std::thread thread_fmat_send(bp24_high_dim::bp24_linfty_high_dim_send_online, &sockets[1],
//         &sender_elements,
//         &vec_G_pow_a, &vec_b, &vec_H_pow_a,
//         dimension, delta);

// 		thread_fmat_recv.join();
// 		thread_fmat_send.join();
//         time.setTimePoint("fmat done");
//         time.setTimePoint("online done");

//         std::cout << (time) << std::endl;

// 		auto recv_bytes_present = sockets[0].bytesSent();
// 		auto send_bytes_present = sockets[1].bytesSent();
//         std::cout << "[bp24_linfty_high] recv sends:  "<< (recv_bytes_present) / 1024.0 / 1024 << "MB" << std::endl;
// 		std::cout << "[bp24_linfty_high] send sends:  "<< (send_bytes_present) / 1024.0 / 1024 << "MB" << std::endl;
// 		std::cout << "[bp24_linfty_high] comm total:  "<< ((recv_bytes_present) + (send_bytes_present)) / 1024.0 / 1024 << "MB" << std::endl;

//         // sockets[0].close();
//         // sockets[1].close();

//         std::cout << std::endl;

//         const bool out_to_file = cmd.isSet("file");
//         if(out_to_file){
//             std::string filename = "test_bp24_linfty_high_dim_m_"+std::to_string(send_set_size)
//                                     +"_n_"+std::to_string(recv_set_size)
//                                     +"_d_"+std::to_string(dimension)
//                                     +"_delta_"+std::to_string(delta)
//                                     +"_p_infty"+".txt";
//             std::ofstream mycout(filename, std::ios::app);
//             mycout << std::endl << "test_bp24_linfty_high_dim ----------------------------" << std::endl;
//             mycout << "recv_set_size: " << recv_set_size << std::endl;
//             mycout << "send_set_size: " << send_set_size << std::endl;
//             mycout << "dimension:     " << dimension << std::endl;
//             mycout << "delta:         " << delta << std::endl;
//             mycout << "side_length:   " << side_length << std::endl;
//             mycout << "distance:      l_infty" << std::endl;
//             mycout << "[bp24_linfty_high] recv sends:  "<< (recv_bytes_present) / 1024.0 / 1024 << "MB" << std::endl;
// 		    mycout << "[bp24_linfty_high] send sends:  "<< (send_bytes_present) / 1024.0 / 1024 << "MB" << std::endl;
// 		    mycout << "[bp24_linfty_high] comm total:  "<< ((recv_bytes_present) + (send_bytes_present)) / 1024.0 / 1024 << "MB" << std::endl;
//             mycout << time << std::endl << std::endl;
//             mycout.close();
//         }

//         return;
//     }


    bool test_fpsi(const CLP& clp){
        
        bool lp_our = clp.isSet("t11");
        bool linfty_paillier_our = clp.isSet("t12");
        bool hamming_gm_our = clp.isSet("t13");

        bool lp_bp = clp.isSet("t21");
        bool linfty_bp = clp.isSet("t22");
        
        bool lp_bp_high = clp.isSet("t23");
        bool linfty_bp_high = clp.isSet("t24");

        if(lp_our){
            test_our_lp_paillier_fpsi(clp);
        }
        if(linfty_paillier_our){
            test_our_linfty_paillier_fpsi(clp);
        }
        if(hamming_gm_our){
            test_gm_fpsi_hamming(clp);
        }

        
        // if(lp_bp){
        //     test_bp24_lp_low_dim(clp);
        // }
        // if(linfty_bp){
        //     test_bp24_linfty_low_dim(clp);
        // }

        // if(lp_bp_high){
        //     test_bp24_lp_high_dim(clp);
        // }
        // if(linfty_bp_high){
        //     test_bp24_linfty_high_dim(clp);
        // }


        return 1;
    }

}