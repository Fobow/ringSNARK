#include <iostream>

#include "seal/seal.h"
#include "ringsnark/zk_proof_systems/rinocchio/rinocchio.hpp"
#include "poly_arith.h"
#include <ringsnark/seal/seal_ring.hpp>
#include <ringsnark/gadgetlib/protoboard.hpp>

using namespace std;
using namespace seal;

int main() {
    EncryptionParameters params(scheme_type::bgv);
    auto poly_modulus_degree = (size_t) pow(2, 12);
    params.set_poly_modulus_degree(poly_modulus_degree);
    params.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    params.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));
    SEALContext context(params);

    typedef ringsnark::seal::RingElem R;
    typedef ringsnark::seal::EncodingElem E;

    R::set_context(context);
    E::set_context(context);

    const size_t N = context.get_context_data(context.first_parms_id())->parms().poly_modulus_degree();
    const size_t n = 5;
    ringsnark::protoboard<R> pb;

    // Set public values
    vector<ringsnark::pb_variable<R>> vars(n);
    for (int i = 0; i < vars.size(); i++) {
        vars[i].allocate(pb, "x" + std::to_string(i));
    }
    pb.set_input_sizes(n);

    // Set private values
    // TODO: no private values in this simple example

    // Set constraints
    pb.add_r1cs_constraint(ringsnark::r1cs_constraint<R>(vars[0], vars[1], vars[4]));

    // Generate CRS
    const auto keypair = ringsnark::rinocchio::generator<R, E>(pb.get_constraint_system());

    // Set values
    vector<ringsnark::seal::RingElem> values;
    values.reserve(n);
    {
        auto encoder = BatchEncoder(context);
        auto tables = context.get_context_data(context.first_parms_id())->small_ntt_tables();

        vector<uint64_t> vs(N);
        vector<Plaintext> xs(n);

        // Inputs
        vs[0] = 2;
        encoder.encode(vs, xs[0]);
        auto poly = polytools::SealPoly(context, xs[0], &(context.first_parms_id()));
        poly.ntt_inplace(tables);
        values[0] = ringsnark::seal::RingElem(poly);

        vs[1] = 3;
        encoder.encode(vs, xs[1]);
        poly = polytools::SealPoly(context, xs[1], &(context.first_parms_id()));
        poly.ntt_inplace(tables);
        values[1] = ringsnark::seal::RingElem(poly);

        vs[2] = 4;
        encoder.encode(vs, xs[2]);
        poly = polytools::SealPoly(context, xs[2], &(context.first_parms_id()));
        poly.ntt_inplace(tables);
        values[2] = ringsnark::seal::RingElem(poly);

        // Intermediate values
        vs[4] = 2 * 3;
        poly = polytools::SealPoly(*values[0].poly);
        poly.multiply_inplace(*values[1].poly);
        values[4] = ringsnark::seal::RingElem(poly);

        // Outputs
        vs[3] = 2 * 3 * 4;
        poly = polytools::SealPoly(*values[4].poly);
        poly.multiply_inplace(*values[2].poly);
        values[3] = ringsnark::seal::RingElem(poly);
    }
    for (size_t i = 0; i < n; i++) {
        pb.val(vars[i]) = values[i];
    }
    cout << "#Inputs\t" << pb.num_inputs() << endl;
    cout << "#Variables\t" << pb.num_variables() << endl;
    cout << "#Constraints\t" << pb.num_constraints() << endl;
    assert(pb.is_satisfied());

    const auto proof = ringsnark::rinocchio::prover(keypair.pk, pb.primary_input(), pb.auxiliary_input());

    const bool verif = ringsnark::rinocchio::verifier(keypair.vk, pb.primary_input(), proof);
    cout << "verification status: " << verif << endl;
}