#include <set>
#include <string>

namespace ringsnark::seal {
RingElem::RingElem() : value((Scalar)0) {}

RingElem::RingElem(Scalar value) : value(value) {}

RingElem::RingElem(const polytools::SealPoly &poly)
    : value(polytools::SealPoly(poly)) {}

[[nodiscard]] size_t RingElem::size_in_bits() const {
  if (is_scalar()) {
    return 8 * sizeof(Scalar);
  } else if (is_poly()) {
    size_t size = 0;
    for (const auto &q_i : get_poly().get_coeff_modulus()) {
      size += q_i.bit_count() * get_poly().get_coeff_count();
    }
    return size;
  } else {
    throw invalid_ring_elem_types();
  }
}

bool RingElem::is_zero() const {
  if (is_scalar()) {
    return get_scalar() == 0;
  } else if (is_poly()) {
    return get_poly().is_zero();
  } else {
    throw invalid_ring_elem_types();
  }
}

bool RingElem::fast_is_zero() const {
  if (is_scalar()) {
    return get_scalar() == 0;
  } else {
    return false;
  }
}

bool RingElem::is_poly() const { return std::holds_alternative<Poly>(value); }

bool RingElem::is_scalar() const {
  return std::holds_alternative<Scalar>(value);
}

RingElem::Poly RingElem::get_poly() const { return std::get<Poly>(value); }

RingElem::Poly &RingElem::get_poly() { return *std::get_if<Poly>(&value); }

RingElem::Scalar &RingElem::get_scalar() {
  return *std::get_if<Scalar>(&value);
}

RingElem::Scalar RingElem::get_scalar() const {
  return std::get<Scalar>(value);
}

void RingElem::negate_inplace() {
  if (is_scalar()) {
    // TODO: make more efficient
    this->to_poly_inplace();
    get_poly().negate_inplace();
  } else if (is_poly()) {
    get_poly().negate_inplace();
  } else {
    throw invalid_ring_elem_types();
  }
}

bool RingElem::is_invertible() const noexcept {
  if (is_scalar()) {
    bool success = to_poly().get_poly().invert_inplace();
    return success;
  } else if (is_poly()) {
    bool success = get_poly().invert_inplace();
    return success;
  } else {
    //            throw invalid_ring_elem_types();
    return false;
  }
}

void RingElem::invert_inplace() {
  if (is_scalar()) {
    // TODO: make more efficient
    this->to_poly_inplace();
    bool success = get_poly().invert_inplace();
    if (!success) {
      throw std::invalid_argument("element is not invertible in ring");
    }
  } else if (is_poly()) {
    bool success = get_poly().invert_inplace();
    if (!success) {
      throw std::invalid_argument("element is not invertible in ring");
    }
  } else {
    throw invalid_ring_elem_types();
  }
}

RingElem &RingElem::operator+=(const RingElem &other) {
  if (is_poly()) {
    if (other.is_poly()) {
      get_poly().add_inplace(other.get_poly());
    } else if (other.is_scalar()) {
      if (other.get_scalar() == 0) {
        return *this;
      }
      get_poly().add_scalar_inplace(other.get_scalar());
    } else {
      throw invalid_ring_elem_types();
    }
  } else if (is_scalar()) {
    if (get_scalar() == 0) {
      this->value = other.value;
      return *this;
    }
    if (other.is_poly()) {
      Scalar scalar = this->get_scalar();
      value = polytools::SealPoly(other.get_poly());
      get_poly().add_scalar_inplace(scalar);
    } else if (other.is_scalar()) {
      size_t this_bitsize = 1 + std::floor(std::log2(this->get_scalar()));
      size_t other_bitsize = 1 + std::floor(std::log2(other.get_scalar()));
      size_t res_bitsize = (this_bitsize == other_bitsize)
                               ? this_bitsize + 1
                               : std::max(this_bitsize, other_bitsize);
      size_t q1 = get_context()
                      .first_context_data()
                      ->parms()
                      .coeff_modulus()[0]
                      .value();
      size_t q1_bitsize = 1 + std::floor(std::log2(q1));
      if (res_bitsize < q1_bitsize) {
        this->get_scalar() += other.get_scalar();
      } else {
        // Computing result requires switching to RNS representation, so we use
        // polytools to take care of it
        // TODO: store a custom RNS representation of scalar instead for
        // efficiency?
        this->to_poly_inplace();
        this->operator+=(other);
      }
    } else {
      throw invalid_ring_elem_types();
    }
  } else {
    throw invalid_ring_elem_types();
  }
  return *this;
}

RingElem &RingElem::operator-=(const RingElem &other) {
  if (is_poly()) {
    if (other.is_poly()) {
      get_poly().subtract_inplace(other.get_poly());
    } else if (other.is_scalar()) {
      if (other.get_scalar() == 0) {
        return *this;
      }
      get_poly().subtract_scalar_inplace(other.get_scalar());
    } else {
      throw invalid_ring_elem_types();
    }
  } else if (is_scalar()) {
    if (other.is_poly()) {
      Scalar scalar = this->get_scalar();
      value = polytools::SealPoly(other.get_poly());
      get_poly().negate_inplace();
      get_poly().add_scalar_inplace(scalar);
    } else if (other.is_scalar()) {
      // TODO: optimize
      this->to_poly_inplace();
      get_poly().subtract_scalar_inplace(other.get_scalar());
    } else {
      throw invalid_ring_elem_types();
    }
  } else {
    throw invalid_ring_elem_types();
  }
  return *this;
}

RingElem &RingElem::operator*=(const RingElem &other) {
  if (is_poly()) {
    if (other.is_poly()) {
      get_poly().multiply_inplace(other.get_poly());
    } else if (other.is_scalar()) {
      if (other.get_scalar() == 1) {
        return *this;
      }
      if (other.get_scalar() == 0) {
        value = (uint64_t)0;
        return *this;
      }
      get_poly().multiply_scalar_inplace(other.get_scalar());
    } else {
      throw invalid_ring_elem_types();
    }
  } else if (is_scalar()) {
    if (get_scalar() == 1) {
      this->value = other.value;
      return *this;
    }
    if (get_scalar() == 0) {
      return *this;
    }
    if (other.fast_is_zero()) {
      value = (uint64_t)0;
      return *this;
    }
    if (other.is_poly()) {
      Scalar scalar = this->get_scalar();
      value = polytools::SealPoly(other.get_poly());
      get_poly().multiply_scalar_inplace(scalar);
    } else if (other.is_scalar()) {
      size_t this_bitsize = 1 + std::floor(std::log2(this->get_scalar()));
      size_t other_bitsize = 1 + std::floor(std::log2(other.get_scalar()));
      size_t res_bitsize = this_bitsize + other_bitsize;
      size_t q1 = get_context()
                      .first_context_data()
                      ->parms()
                      .coeff_modulus()[0]
                      .value();
      size_t q1_bitsize = 1 + std::floor(std::log2(q1));
      if (res_bitsize < q1_bitsize) {
        this->get_scalar() *= other.get_scalar();
      } else {
        // Computing result requires switching to RNS representation, so we use
        // polytools to take care of it
        // TODO: store a custom RNS representation of scalar instead for
        // efficiency?
        this->to_poly_inplace();
        this->operator*=(other);
      }
    } else {
      throw invalid_ring_elem_types();
    }
  } else {
    throw invalid_ring_elem_types();
  }
  return *this;
}

bool operator==(const RingElem &lhs, const RingElem &rhs) {
  if (lhs.is_scalar() && rhs.is_scalar()) {
    return lhs.get_scalar() == rhs.get_scalar();
  } else if (lhs.is_poly() && rhs.is_poly()) {
    return lhs.get_poly().is_equal(rhs.get_poly());
  } else if (lhs.is_scalar() &&
             rhs.is_poly()) {  // TODO: cast down to scalar instead?
    return lhs.to_poly().get_poly().is_equal(rhs.get_poly());
  } else if (lhs.is_poly() &&
             rhs.is_scalar()) {  // TODO: cast down to scalar instead?
    return lhs.get_poly().is_equal(rhs.to_poly().get_poly());
  } else {
    throw RingElem::invalid_ring_elem_types();
  }
}

RingElem &RingElem::to_poly_inplace() {
  if (is_scalar()) {
    Scalar scalar = this->get_scalar();
    value = polytools::SealPoly(get_context());
    get_poly().add_scalar_inplace(scalar);
    assert(get_poly().is_ntt_form());
    return *this;
  } else if (is_poly()) {
    return *this;
  } else {
    throw invalid_ring_elem_types();
  }
}

size_t RingElem::hash() const {
  if (is_scalar()) {
    return this->get_scalar();
  } else if (is_poly()) {
    size_t hash = 0;
    for (size_t i = 0; i < get_poly().get_coeff_count(); i++) {
      for (const auto &v : get_poly().get_coefficient_rns(i)) {
        hash ^= v;
      }
    }
    return hash;
  } else {
    throw invalid_ring_elem_types();
  }
}

std::ostream &operator<<(std::ostream &out, const RingElem &elem) {
  if (elem.is_scalar()) {
    return out << elem.get_scalar();
  } else if (elem.is_poly()) {
    return out << elem.get_poly().to_json();
  } else {
    throw RingElem::invalid_ring_elem_types();
  }
}

size_t EncodingElem::size_in_bits() const {
  size_t size = 0;
  for (size_t i = 0; i < ciphertexts.size(); i++) {
    auto c = ciphertexts[i];
    auto params = get_contexts()[i].get_context_data(c.parms_id())->parms();
    for (const auto &q_i : params.coeff_modulus()) {
      size += params.poly_modulus_degree() * c.size() * q_i.bit_count();
    }
  }
  return size;
}

EncodingElem &EncodingElem::modswitch_inplace() {
  for (size_t i = 0; i < ciphertexts.size(); i++) {
    evaluators[i]->mod_switch_to_next_inplace(ciphertexts[i]);
  }
  return *this;
}

std::vector<EncodingElem> EncodingElem::encode(
    const SecretKey &sk, const std::vector<RingElem> &rs) {
  assert(get_contexts().size() == sk.size());
  std::vector<EncodingElem> encs(rs.size());

  // Reuse encryptors for all elements
  vector<::seal::Encryptor *> encryptors;
  encryptors.reserve(get_contexts().size());
  for (size_t i = 0; i < get_contexts().size(); i++) {
    encryptors.push_back(new ::seal::Encryptor(get_contexts()[i], sk[i]));
  }

#pragma omp parallel for default(none) \
    shared(rs, encs, encryptors, ::seal::parms_id_zero)
  for (int i = 0; i < rs.size(); i++) {
    const auto &r = rs[i];
    ::seal::Plaintext ptxt;
    std::vector<::seal::Ciphertext> ctxts(get_contexts().size());

    ::polytools::SealPoly poly =
        (r.is_scalar()) ? r.to_poly().get_poly() : r.get_poly();

    // TODO: handle case where number of moduli differs, e.g., after
    // mod-switching on the ring
    assert(poly.get_coeff_modulus_count() == ctxts.size());
    for (size_t i = 0; i < get_contexts().size(); i++) {
      // TODO: encode() silently writes only up to the vector size. Could this
      // cause problems down the line?
      encoders[i]->encode(poly.get_limb(i), ptxt);
      encryptors[i]->encrypt_symmetric(ptxt, ctxts[i]);
    }

    encs[i] = EncodingElem(ctxts);
  }
  return encs;
}

EncodingElem EncodingElem::inner_product(
    vector<EncodingElem>::const_iterator a_start,
    vector<EncodingElem>::const_iterator a_end,
    vector<RingElem>::const_iterator b_start,
    vector<RingElem>::const_iterator b_end) {
  size_t num_moduli = EncodingElem::get_contexts()[0]
                          .first_context_data()
                          ->parms()
                          .coeff_modulus()
                          .size();
#ifdef RINGSNARK_DEBUG
  assert(a_end - a_start > 0 &&
         "cannot compute inner product of empty vectors");
  assert(a_end - a_start == b_end - b_start &&
         "cannot compute inner product of vectors with mismatched sizes");
  for (size_t i = 1; i < EncodingElem::get_contexts().size(); i++) {
    assert(EncodingElem::get_contexts()[i]
               .first_context_data()
               ->parms()
               .coeff_modulus()
               .size() == num_moduli);
  }
#endif

  const size_t num_modswitches =
      (num_moduli > 2) ? num_moduli - 2
                       : 0;  // Number of modswitches during the sum
  set<size_t> checkpoints;
  size_t max_num_its = 0;
  vector<bool> is_zero(a_end - a_start);
  for (int i = 0; i < is_zero.size(); ++i) {
    is_zero[i] = (b_start + i)->is_zero();
    if (!is_zero[i]) {
      max_num_its++;
    }
  }

  if (num_modswitches == 1) {
    checkpoints.insert(max_num_its / 2);
  } else if (num_modswitches > 1) {
    size_t delta = (a_end - a_start) / num_modswitches;
    for (int i = 0; i < num_modswitches - 1; ++i) {
      checkpoints.insert(delta * (i + 1));
    }
    checkpoints.insert(max_num_its);
  }
  assert(checkpoints.size() <= num_modswitches);
  if (max_num_its > num_modswitches) {
    assert(checkpoints.size() == num_modswitches);
  }

  EncodingElem res;
  EncodingElem tmp;
  size_t curr_it_count = 0;
  for (int i = 0; i < (a_end - a_start); i++) {
    if (!is_zero[i]) {
      tmp = (*(a_start + i)) * (*(b_start + i));
#ifdef USE_MODSWITCH_IN_INNER_PRODUCT
      if (num_moduli > 1) {
        tmp.modswitch_inplace();
      }
#endif
      res += tmp;
#ifdef USE_MODSWITCH_IN_INNER_PRODUCT
      curr_it_count++;
      if (checkpoints.count(curr_it_count) == 1) {
        res.modswitch_inplace();
      }
#endif
    }
  }
  return res;
}

RingElem EncodingElem::decode(const SecretKey &sk, const EncodingElem &e) {
  ::seal::Plaintext ptxt;
  auto parms = RingElem::get_context().first_context_data()->parms();
  std::vector<uint64_t> coeffs;

  assert(e.ciphertexts.size() == get_contexts().size());
  for (size_t i = 0; i < e.ciphertexts.size(); i++) {
    ::seal::Decryptor decryptor(get_contexts()[i], sk[i]);
    vector<uint64_t> curr_limb(parms.poly_modulus_degree());

    try {
      if (decryptor.invariant_noise_budget(e.ciphertexts[i]) <= 0) {
        // This indicates that either the parameters of the encoding scheme were
        // set to be too small, or that the prover used more budget (i.e.,
        // performed more operations) than required.
        throw decoding_error(
            "ciphertext #" + to_string(i) + " has remaining noise budget " +
            to_string(decryptor.invariant_noise_budget(e.ciphertexts[i])) +
            " <= 0");
      }
      decryptor.decrypt(e.ciphertexts[i], ptxt);
      encoders[i]->decode(ptxt, curr_limb);
    } catch (std::invalid_argument &invalid_arg) {
      if (std::string(invalid_arg.what()) == "encrypted is empty") {
        // TODO: can we handle this case more explicitly to prevent confusion,
        // e.g., have a dedicated
        //  flag/subclass for the "0" ciphertext?
        // This should only really be an issue when the SNARK is used in non-ZK
        // mode; with ZK, the noise terms prevent the ctxt from being zero
        // w.h.p. Do nothing, curr_limb already holds all zeros.
      } else {
        throw invalid_arg;
      }
    }

    curr_limb.resize(parms.poly_modulus_degree());  // Get rid of 0-padding
    coeffs.insert(coeffs.end(), curr_limb.begin(), curr_limb.end());
  }
  assert(coeffs.size() ==
         parms.poly_modulus_degree() * parms.coeff_modulus().size());
  return RingElem(
      polytools::SealPoly(RingElem::get_context(), coeffs, &parms.parms_id()));
}

EncodingElem &EncodingElem::operator+=(const EncodingElem &other) {
  // TODO: handle case where number of ciphertexts differ (and are > 1), e.g.,
  // in mod-switching cases?
  if (other.is_empty()) {
    return *this;
  }
  if (this->is_empty()) {
    this->ciphertexts = other.ciphertexts;
    return *this;
  }
  assert(this->ciphertexts.size() == other.ciphertexts.size());
  assert(this->ciphertexts.size() == get_contexts().size());
  for (size_t i = 0; i < this->ciphertexts.size(); i++) {
    const bool was_ntt = this->ciphertexts[i].is_ntt_form();
    try {
      evaluators[i]->add_inplace(this->ciphertexts[i], other.ciphertexts[i]);
    } catch (std::logic_error &e) {
      if (std::string(e.what()) == "result ciphertext is transparent") {
        // Explicitly assign a zero-ciphertext
        this->ciphertexts[i] = ::seal::Ciphertext(
            get_contexts()[i], get_contexts()[i].first_parms_id());
        this->ciphertexts[i].is_ntt_form() = was_ntt;
      } else {
        throw e;
      }
    }
  }
  return *this;
}

EncodingElem &EncodingElem::operator*=(const RingElem &r) {
  ::seal::Plaintext ptxt;

  // Handle zero case explicitly, to prevent a "transparent ciphertext"
  // logic_error from SEAL
  if (r.is_zero()) {
    ciphertexts.resize(get_contexts().size());
    for (size_t i = 0; i < get_contexts().size(); i++) {
      auto context = get_contexts()[i];
      const bool was_ntt = ciphertexts[i].is_ntt_form();
      ciphertexts[i] = ::seal::Ciphertext(context, context.first_parms_id());
      ciphertexts[i].is_ntt_form() = was_ntt;
    }
    return *this;
  }

  if (r.is_scalar()) {
    if (r.get_scalar() == 1) {
      return *this;
    }
    return this->operator*=(r.to_poly());
  } else if (r.is_poly()) {
    assert(r.get_poly().get_coeff_modulus_count() == this->ciphertexts.size());

    for (size_t i = 0; i < this->ciphertexts.size(); i++) {
      encoders[i]->encode(r.get_poly().get_limb(i), ptxt);
      try {
        evaluators[i]->multiply_plain_inplace(this->ciphertexts[i], ptxt);
      } catch (std::logic_error err) {
        if (std::string(err.what()) == "result ciphertext is transparent") {
        } else {
          throw err;
        }
      }
    }
    return *this;
  } else {
    throw RingElem::invalid_ring_elem_types();
  }
}
}  // namespace ringsnark::seal