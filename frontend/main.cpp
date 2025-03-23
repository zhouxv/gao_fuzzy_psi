#include <iostream>

#include "fpsi.h"

using namespace oc;

int main(int argc, char **argv)
{
    CLP cmd;
    cmd.parse(argc, argv);

    if (cmd.isSet("fpsi"))
    {
        oc::test_fpsi(cmd);
        return 0;
    }

    if (cmd.isSet("phe"))
    {
        oc::test_paillier_performance(cmd);
        return 0;
    }

    if (true)
    {

        std::cout
            << "#######################################################\n"
            << "#                  - FPSI from Fmap -                 #\n"
            << "#               A library for performing              #\n"
            << "#                         FPSI.                       #\n"
            << "#                                                     #\n"
            << "#######################################################\n"
            << std::endl;

        std::cout
            << "  -fpsi   " << ": to run the FPSI protocols.                                                     " << "\n"
            << "\n"
            << "Protocols:\n"
            << "  -  our protocols   --------------------" << "\n"
            << "  -t11   " << ": to run the test of FPSI for L_p distance from SAS Fmap.                         " << "\n"
            << "  -t12   " << ": to run the test of FPSI for L_infty distance from SAS Fmap.                     " << "\n"
            << "  -t13   " << ": to run the test of FPSI for Hamming distance from UC Fmap.                      " << "\n"
            // << "  -[BP24]'s protocols--------------------" << "\n"
            // << "  -t21   " << ": to run the test of [BP24]'s FPSI for L_p distance in low-dimension space.       " << "\n"
            // << "  -t22   " << ": to run the test of [BP24]'s FPSI for L_infty distance in low-dimension space.   " << "\n"
            // << "  -t23   " << ": to run the estimation of [BP24]'s FPSI for L_p distance in high-dimension space." << "\n"
            // << "  -t24   " << ": to run the test of [BP24]'s FPSI for L_infty distance in high-dimension space.  " << "\n"
            << "\n"
            << "Options for L_{p \\ in [1, infty]}:\n"
            << "   -d    " << ": to choose the dimension, default = 2.                                           " << "\n"
            << " -delta  " << ": to choose the threshold, default = 10.                                          " << "\n"
            << "   -s    " << ": to choose the log_2 of sender's input size, default m = 2^10.                   " << "\n"
            << "   -r    " << ": to choose the log_2 of receiver's input size, default n = 2^10.                 " << "\n"
            << "   -i    " << ": to choose the intersection size, default i = 32.                                " << "\n"
            << "   -p    " << ": to choose the p for L_p distance, default = 2.                                  " << "\n"
            << "\n"
            << "Options for Hamming:\n"
            << "Considering UniqC assamption, successful execution of our protocol for Hamming distance needs:   " << "\n"
            << "              1. the dimension is large enough;                                                  " << "\n"
            << "              2. the threshold is much smaller than the dimension. (d > 8 * delta + 8)           " << "\n"
            // << " -hamd   " << ": to choose the dimension, default = 128.                                         " << "\n"
            << "-hamdelta" << ": to choose the threshold, default = 4.                                           " << "\n"
            << " -hams   " << ": to choose the log_2 of sender's input size, default m = 2^6.                    " << "\n"
            << " -hamr   " << ": to choose the log_2 of receiver's input size, default n = 2^6.                  " << "\n"
            << " -hami   " << ": to choose the intersection size, default hami = 7.                              " << "\n"
            // << "-hamside " << ": to choose the bitsize of super-component, default hamside = ((dimension / (delta + 1)) / 8) * 8." << "\n"
            ;

        return 0;
    }
}
