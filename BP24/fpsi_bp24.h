#include "fm.h"

namespace osuCrypto
{
    namespace bp24_ec{

        // side_length = 2 * delta
        void receiver_precomp_vals_ec_lp(const std::size_t& elements_size,
                                std::vector<std::vector<Rist25519_number>>& vals,
                                const u64& dimension, const u64& delta, const u64& side_length, const u64& p, const FM25519_number& sk);

        void receiver_precomp_vals_ec_linfty(const std::size_t& elements_size,
                                std::vector<std::vector<Rist25519_number>>& vals,
                                const u64& dimension, const u64& delta, const u64& side_length, const FM25519_number& sk);

        void sender_mask_ec_lp(const std::size_t& elements_size,
                            std::vector<FM25519_point>& vec_G_pow_a_H_pow_c,
                            std::vector<FM25519_number>& vec_b,
                            std::vector<FM25519_point>& vec_G_pow_c,
                            std::vector<std::vector<FM25519_point>>& vec_G_pow_a_bj,
                            const u64& delta, const u64& p,
                            const FM25519_point& G, const FM25519_point& H);

        void sender_mask_ec_linfty(const std::size_t& elements_size,
                            std::vector<FM25519_point>& vec_G_pow_a,
                            std::vector<FM25519_number>& vec_b,
                            std::vector<FM25519_point>& vec_H_pow_a,
                            const FM25519_point& G, const FM25519_point& H);

        void bp24_lp_low_dim_recv_online(coproto::LocalAsyncSocket* channel,
        std::vector<std::vector<u64>>* receiver_elements,
        std::vector<std::vector<Rist25519_number>>* fmat_vals,
        u64 dimension, u64 delta, u64 side_length, u64 p,
        FM25519_number recv_sk, FM25519_point G);

        void bp24_lp_low_dim_send_online(coproto::LocalAsyncSocket* channel,
        std::vector<std::vector<u64>>* sender_elements,
        std::vector<FM25519_point>* vec_G_pow_a_H_pow_c, std::vector<FM25519_number>* vec_b, std::vector<FM25519_point>* vec_G_pow_c,
        std::vector<std::vector<FM25519_point>>* vec_G_pow_a_bj,
        u64 dimension, u64 delta, u64 side_length);


        void bp24_linfty_low_dim_recv_online(coproto::LocalAsyncSocket* channel,
        std::vector<std::vector<u64>>* receiver_elements,
        std::vector<std::vector<Rist25519_number>>* fmat_vals,
        u64 dimension, u64 delta, u64 side_length,
        FM25519_number recv_sk, FM25519_point G);

        void bp24_linfty_low_dim_send_online(coproto::LocalAsyncSocket* channel,
        std::vector<std::vector<u64>>* sender_elements,
        std::vector<FM25519_point>* vec_G_pow_a, std::vector<FM25519_number>* vec_b, std::vector<FM25519_point>* vec_H_pow_a,
        u64 dimension, u64 delta, u64 side_length);

    }

    namespace bp24_high_dim{
        void receiver_precomp_vals_ec_linfty(const std::size_t& elements_size,
                            std::stack<std::vector<Rist25519_number>>& vals_candidate,
                            const u64& dimension, const i64& delta, const FM25519_number& sk);

        void sender_mask_ec_linfty(const std::size_t& elements_size,
                            std::vector<FM25519_point>& vec_G_pow_a,
                            std::vector<FM25519_number>& vec_b,
                            std::vector<FM25519_point>& vec_H_pow_a,
                            const FM25519_point& G, const FM25519_point& H);

        std::vector<std::vector<std::vector<FM25519_point>>> receiver_get_E(const std::vector<std::vector<u64>>& elements, const std::vector<u64>& separate_dims,
        std::stack<std::vector<Rist25519_number>>& vals_candidate,
        const u64& dimension, const i64& delta, const FM25519_point& G);

        void bp24_linfty_high_dim_recv_online(coproto::LocalAsyncSocket* channel,
        std::vector<std::vector<u64>>* receiver_elements, std::vector<osuCrypto::u64>* separate_dims,
        std::stack<std::vector<Rist25519_number>>* vals_candidate,
        u64 dimension, u64 delta,
        FM25519_number recv_sk, FM25519_point G);

        void bp24_linfty_high_dim_send_online(coproto::LocalAsyncSocket* channel,
        std::vector<std::vector<u64>>* sender_elements,
        std::vector<FM25519_point>* vec_G_pow_a, std::vector<FM25519_number>* vec_b, std::vector<FM25519_point>* vec_H_pow_a,
        u64 dimension, u64 delta);




    }


}