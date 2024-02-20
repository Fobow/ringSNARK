#include <iostream>
#include <ringsnark/gadgetlib/protoboard.hpp>
#include <ringsnark/seal/seal_ring.hpp>
#include <ringsnark/seal/seal_util.hpp>
#include <ringsnark/zk_proof_systems/groth16/groth16.hpp>
#include <ringsnark/zk_proof_systems/rinocchio/rinocchio.hpp>
#include <string>

#include "poly_arith.h"
#include "seal/seal.h"
// #include "utils.h"

using namespace std;
using namespace seal;

int main(int argc, char *argv[]) {
  // length of square matrix side
  const size_t length = std::stoi(argv[1]);
  EncryptionParameters params(scheme_type::bgv);
  auto poly_modulus_degree = 4096;
  auto inner_poly_modulus_degree = 4 * poly_modulus_degree;
  // auto poly_modulus_degree = 1024;
  // auto inner_poly_modulus_degree = 8 * poly_modulus_degree;

  params.set_poly_modulus_degree(poly_modulus_degree);
  params.set_coeff_modulus(default_double_batching_modulus(
      poly_modulus_degree, inner_poly_modulus_degree));
  params.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 60));
  SEALContext context(params);

  print_params(params);

  typedef ringsnark::seal::RingElem R;
  typedef ringsnark::seal::EncodingElem E;

#define USE_MODSWITCH_IN_INNER_PRODUCT
    R::set_context(context);
    E::set_context(inner_poly_modulus_degree);

    const size_t N = context.get_context_data(context.first_parms_id())
                        ->parms()
                        .poly_modulus_degree();

    // define the scale of computation
    const size_t n = length*3+1;
    ringsnark::protoboard<R> pb;

    // Set public values
    ringsnark::pb_variable_array<R> vars(n, ringsnark::pb_variable<R>());
    vars.allocate(pb, n, "x");
    pb.set_input_sizes(n-1);  // the last variable is private (output)
    
    // Set constraints
    // vector mult
    for(size_t i=0; i<length; i++){
      pb.add_r1cs_constraint(ringsnark::r1cs_constraint<R>(vars[i], vars[i+length], vars[i+2*length]));
    }
    ringsnark::linear_combination<R> A,B,C;
    for(size_t i = 0; i<length; i++){
      A.add_term(vars[i+2*length], 1);
    }
    B.add_term(0, 1);
    C.add_term(vars[3*length], 1);

    pb.add_r1cs_constraint(ringsnark::r1cs_constraint<R>(A, B, C));

    // Set values
  vector<ringsnark::seal::RingElem> values(n);
  {
    auto timer = clock_start();
    auto encoder = BatchEncoder(context);
    auto tables = context.get_context_data(context.first_parms_id())->small_ntt_tables();

    vector<uint64_t> vs(N);
    Plaintext ptxt;
    vector<::polytools::SealPoly> polys(n, ::polytools::SealPoly(context));
    for(size_t i=0; i<length; i++){
        vs[i] = i+2;
        encoder.encode(vs, ptxt);
        auto poly = polytools::SealPoly(context, ptxt, &(context.first_parms_id()));
        poly.ntt_inplace(tables);
        polys[i] = poly;
        values[i] = ringsnark::seal::RingElem(poly);

        vs[i+length] = i+1;
        encoder.encode(vs, ptxt);
        poly = polytools::SealPoly(context, ptxt, &(context.first_parms_id()));
        poly.ntt_inplace(tables);
        polys[i+length] = poly;
        values[i+length] = ringsnark::seal::RingElem(poly);
    }

    long long end = time_from(timer);
    cout << "\033[32m" <<"encode time:\t" << end / (1000.0) << " ms" << "\033[0m" << endl;

    // 2. intermediate results
    timer = clock_start();
    // Intermediate values

    for(size_t i=0; i<length; i++){
        vs[i+2*length] = vs[i] *  vs[i+length];
        // vs[i+2*length] = vs[i] + vs[i+length];
        auto poly = polytools::SealPoly(polys[i]);
        poly.multiply_inplace(polys[i+length]);
        // poly.add_inplace(polys[i+length]);
        polys[i+2*length] = poly;
        values[i+2*length] = ringsnark::seal::RingElem(poly);
    }

    auto poly = polytools::SealPoly(polys[2*length]);
    for(size_t i=0; i<length; i++){
        vs[length*3] += vs[i+2*length];
        if(i!=0){
            poly.add_inplace(polys[i+2*length]);
        }
    }
    polys[length*3] = poly;
    values[length*3] = ringsnark::seal::RingElem(poly);

    end = time_from(timer);
    cout << "\033[32m" <<"compute time:\t" << end / (1000.0) << " ms" << "\033[0m" << endl;

  }
  for (size_t i = 0; i < n; i++) {
    pb.val(vars[i]) = values[i];
  }
  cout << "#Inputs\t" << pb.num_inputs() << endl;
  cout << "#Variables\t" << pb.num_variables() << endl;
  cout << "#Constraints\t" << pb.num_constraints() << endl;
  cout << "R1CS satisfied: " << std::boolalpha << pb.is_satisfied() << endl;
  cout << endl;

  //only evaluate on groth16, because pinnochio is too slow
  {
    cout << "=============" << endl;
    cout << "=== RingGroth16 ===" << endl;
    auto start = clock_start();
    const auto keypair =
        ringsnark::groth16::generator<R, E>(pb.get_constraint_system());
    long long t = time_from(start);
    cout << "\033[32m" <<"Setup time:\t" << t / (1000.0) << " ms" << "\033[0m" << endl;
    cout << "Size of pk:\t" << keypair.pk.size_in_bits() << " bits" << endl;
    cout << "Size of vk:\t" << keypair.vk.size_in_bits() << " bits" << endl;

    start = clock_start();
    const auto proof = ringsnark::groth16::prover(
        keypair.pk, pb.primary_input(), pb.auxiliary_input());
    t = time_from(start);
    cout << "\033[32m" <<"Prove time:\t" << t / (1000.0) << " ms" << "\033[0m" << endl;
    cout << "Size of proof:\t" << proof.size_in_bits() << " bits" << endl;

    start = clock_start();
    const bool verif =
        ringsnark::groth16::verifier(keypair.vk, pb.primary_input(), proof);
    t = time_from(start);
    cout << "\033[32m" <<"Verify time:\t" << t / (1000.0) << " ms" << "\033[0m" << endl;
    cout << "Verification passed: " << std::boolalpha << verif << endl;
  }

}