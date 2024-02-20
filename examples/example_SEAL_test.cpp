#include "seal/seal.h"
#include <iostream>
#include <ringsnark/zk_proof_systems/groth16/groth16.hpp>

using namespace std;
using namespace seal;

int main() {

    seal::EncryptionParameters parms(seal::scheme_type::bgv);
    size_t poly_modulus_degree = 4096;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(seal::CoeffModulus::Create(poly_modulus_degree, { 30, 30, 30 }));
    parms.set_plain_modulus(1024);

    // auto context = seal::SEALContext::Create(parms);
    // auto context = std::make_shared<seal::SEALContext>(parms);
    SEALContext context(parms);


    seal::KeyGenerator keygen(context);

    // seal::KeyGenerator keygen(context);
    // seal::PublicKey public_key = keygen.public_key();
    seal::PublicKey public_key;
    keygen.create_public_key(public_key);
    seal::SecretKey secret_key = keygen.secret_key();

    seal::Encryptor encryptor(context, public_key);
    seal::Evaluator evaluator(context);
    seal::Decryptor decryptor(context, secret_key);


    // seal::Plaintext x0_plain("x0"), x1_plain("x1"), x2_plain("x2"), x3_plain("x3");
    seal::Plaintext x0_plain("2"), x1_plain("3"), x2_plain("4"), x3_plain("5");
    seal::Ciphertext x0_encrypted, x1_encrypted, x2_encrypted, x3_encrypted;

    auto start = clock_start();
    encryptor.encrypt(x0_plain, x0_encrypted);
    encryptor.encrypt(x1_plain, x1_encrypted);
    encryptor.encrypt(x2_plain, x2_encrypted);
    encryptor.encrypt(x3_plain, x3_encrypted);
    long long t = time_from(start);
    cout << "\033[32m" <<"Encode time:\t" << t / (1000.0) << " ms" << "\033[0m" << endl;

    start = clock_start();
    seal::Ciphertext temp1, temp2, x4_encrypted;

    // Compute (x0 + x1)
    evaluator.add(x0_encrypted, x1_encrypted, temp1);

    // Compute (x2 * x3)
    evaluator.multiply(x2_encrypted, x3_encrypted, temp2);

    // Compute (x0 + x1) * (x2 * x3)
    evaluator.multiply(temp1, temp2, x4_encrypted);
    t = time_from(start);
    cout << "\033[32m" <<"Compute time:\t" << t / (1000.0) << " ms" << "\033[0m" << endl;

    start = clock_start();
    seal::Plaintext x4_plain;
    decryptor.decrypt(x4_encrypted, x4_plain);
    t = time_from(start);
    cout << "\033[32m" <<"decode time time:\t" << t / (1000.0) << " ms" << "\033[0m" << endl;
    // std::cout << "Result: " << x4_plain.to_string() << std::endl;

    // Convert the result to an integer (assuming the result is a single integer)
    int result;
    std::istringstream iss(x4_plain.to_string());
    iss >> result;
    std::cout << "Result as integer: " << result << std::endl;

    // std::cout << "SEAL version: " << SEAL_VERSION << std::endl;

}