use std::{borrow::Borrow, marker::PhantomData};

use ark_ec::CurveGroup;
use ark_ff::{Field, PrimeField, Zero};
use ark_r1cs_std::{uint8::UInt8, prelude::{AllocVar, AllocationMode, CurveVar, EqGadget, Boolean}, ToBitsGadget};
use ark_relations::r1cs::{Namespace, SynthesisError};
use ark_serialize::CanonicalSerialize;

use crate::gadgets::public_encryptions::constraints::AsymmetricEncryptionGadget;

use super::*;

#[derive(Clone)]
pub struct RandomnessVar<F: Field>(pub Vec<UInt8<F>>);

impl<C, F> AllocVar<Randomness<C>, F> for RandomnessVar<F>
where
    C: CurveGroup,
    F: PrimeField,
{
    fn new_variable<T: Borrow<Randomness<C>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let mut r = Vec::new();
        let _ = &f()
            .map(|b| b.borrow().0)
            .unwrap_or(C::ScalarField::zero())
            .serialize_compressed(&mut r)
            .unwrap();
        match mode {
            AllocationMode::Constant => Ok(Self(UInt8::constant_vec(&r))),
            AllocationMode::Input => UInt8::new_input_vec(cs, &r).map(Self),
            AllocationMode::Witness => UInt8::new_witness_vec(cs, &r).map(Self),
        }
    }
}

#[derive(Clone)]
pub struct ParametersVar<C: CurveGroup, GG: CurveVar<C, C::BaseField>>
{
    pub generator: GG,
    pub _curve: PhantomData<C>,
}

impl<C, GG> AllocVar<Parameters<C>, C::BaseField> for ParametersVar<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, C::BaseField>,
{
    fn new_variable<T: Borrow<Parameters<C>>>(
        cs: impl Into<Namespace<C::BaseField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let generator = GG::new_variable(cs, || f().map(|g| g.borrow().generator), mode)?;
        Ok(Self {
            generator,
            _curve: PhantomData,
        })
    }
}

#[derive(Clone)]
pub struct PlaintextVar<C: CurveGroup, GG: CurveVar<C, C::BaseField>>
{
    pub plaintext: GG,
    pub _curve: PhantomData<C>,
}

impl<C, GG> AllocVar<Plaintext<C>, C::BaseField> for PlaintextVar<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, C::BaseField>,
{
    fn new_variable<T: Borrow<Plaintext<C>>>(
        cs: impl Into<Namespace<C::BaseField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let plaintext = GG::new_variable(cs, f, mode)?;
        Ok(Self {
            plaintext,
            _curve: PhantomData,
        })
    }
}

#[derive(Clone)]
pub struct PublicKeyVar<C: CurveGroup, GG: CurveVar<C, C::BaseField>>
{
    pub pk: GG,
    pub _curve: PhantomData<C>,
}

impl<C, GG> AllocVar<PublicKey<C>, C::BaseField> for PublicKeyVar<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, C::BaseField>,
{
    fn new_variable<T: Borrow<PublicKey<C>>>(
        cs: impl Into<Namespace<C::BaseField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let pk = GG::new_variable(cs, f, mode)?;
        Ok(Self {
            pk,
            _curve: PhantomData,
        })
    }
}

#[derive(Clone)]
pub struct OutputVar<C: CurveGroup, GG: CurveVar<C, C::BaseField>>
{
    pub c1: GG,
    pub c2: GG,
    pub _curve: PhantomData<C>,
}

impl<C, GG> AllocVar<Ciphertext<C>, C::BaseField> for OutputVar<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, C::BaseField>,
{
    fn new_variable<T: Borrow<Ciphertext<C>>>(
        cs: impl Into<Namespace<C::BaseField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let prep = f().map(|g| *g.borrow());
        let c1 = GG::new_variable(cs.clone(), || prep.map(|g| g.borrow().0), mode)?;
        let c2 = GG::new_variable(cs.clone(), || prep.map(|g| g.borrow().1), mode)?;
        Ok(Self {
            c1,
            c2,
            _curve: PhantomData,
        })
    }
}

impl<C, GC> EqGadget<C::BaseField> for OutputVar<C, GC>
where
    C: CurveGroup,
    GC: CurveVar<C, C::BaseField>,
{
    #[inline]
    fn is_eq(&self, other: &Self) -> Result<Boolean<C::BaseField>, SynthesisError> {
        self.c1.is_eq(&other.c1)?.and(&self.c2.is_eq(&other.c2)?)
    }
}


#[derive(Clone)]
pub struct ElGamalEncGadget<C: CurveGroup, GG: CurveVar<C, C::BaseField>>
{
    #[doc(hidden)]
    _curve: PhantomData<*const C>,
    _group_var: PhantomData<*const GG>,
}

impl<C, GG> AsymmetricEncryptionGadget<ElGamal<C>, C::BaseField> for ElGamalEncGadget<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, C::BaseField>,
    C::BaseField: PrimeField,
{
    type OutputVar = OutputVar<C, GG>;
    type ParametersVar = ParametersVar<C, GG>;
    type PlaintextVar = PlaintextVar<C, GG>;
    type PublicKeyVar = PublicKeyVar<C, GG>;
    type RandomnessVar = RandomnessVar<C::BaseField>;

    fn encrypt(
        parameters: &Self::ParametersVar,
        message: &Self::PlaintextVar,
        randomness: &Self::RandomnessVar,
        public_key: &Self::PublicKeyVar,
    ) -> Result<Self::OutputVar, SynthesisError> {
        // flatten randomness to little-endian bit vector
        let randomness = randomness
            .0
            .iter()
            .flat_map(|b| b.to_bits_le().unwrap())
            .collect::<Vec<_>>();

        // compute s = randomness*pk
        let s = public_key.pk.clone().scalar_mul_le(randomness.iter())?;

        // compute c1 = randomness*generator
        let c1 = parameters
            .generator
            .clone()
            .scalar_mul_le(randomness.iter())?;

        // compute c2 = m + s
        let c2 = message.plaintext.clone() + s;

        Ok(Self::OutputVar {
            c1,
            c2,
            _curve: PhantomData,
        })
    }
}

#[cfg(test)]
mod test {
    use ark_std::{test_rng, UniformRand};

    use ark_ed_on_bn254::{constraints::EdwardsVar, EdwardsProjective, Fq};

    use crate::gadgets::public_encryptions::constraints::AsymmetricEncryptionGadget;
    use crate::gadgets::public_encryptions::elgamal::{constraints::ElGamalEncGadget, ElGamal, Randomness};
    use crate::gadgets::public_encryptions::AsymmetricEncryptionScheme;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_r1cs_std::R1CSVar;
    use ark_r1cs_std::alloc::AllocVar;
    use ark_r1cs_std::eq::EqGadget;

    #[test]
    fn test_elgamal_gadget() {
        let rng = &mut test_rng();

        type MyEnc = ElGamal<EdwardsProjective>;
        type MyGadget = ElGamalEncGadget<EdwardsProjective, EdwardsVar>;

        // compute primitive result
        let parameters = MyEnc::setup(rng).unwrap();
        let (pk, _) = MyEnc::keygen(&parameters, rng).unwrap();
        let msg = EdwardsProjective::rand(rng).into();
        let randomness = Randomness::rand(rng);
        let primitive_result = MyEnc::encrypt(&parameters, &pk, &msg, &randomness).unwrap();

        // construct constraint system
        let cs = ConstraintSystem::<Fq>::new_ref();
        let randomness_var =
            <MyGadget as AsymmetricEncryptionGadget<MyEnc, Fq>>::RandomnessVar::new_witness(
                ark_relations::ns!(cs, "gadget_randomness"),
                || Ok(&randomness),
            )
            .unwrap();
        let parameters_var =
            <MyGadget as AsymmetricEncryptionGadget<MyEnc, Fq>>::ParametersVar::new_constant(
                ark_relations::ns!(cs, "gadget_parameters"),
                &parameters,
            )
            .unwrap();
        let msg_var =
            <MyGadget as AsymmetricEncryptionGadget<MyEnc, Fq>>::PlaintextVar::new_witness(
                ark_relations::ns!(cs, "gadget_message"),
                || Ok(&msg),
            )
            .unwrap();
        let pk_var =
            <MyGadget as AsymmetricEncryptionGadget<MyEnc, Fq>>::PublicKeyVar::new_witness(
                ark_relations::ns!(cs, "gadget_public_key"),
                || Ok(&pk),
            )
            .unwrap();

        // use gadget
        let result_var =
            MyGadget::encrypt(&parameters_var, &msg_var, &randomness_var, &pk_var).unwrap();

        // check that result equals expected ciphertext in the constraint system
        let expected_var =
            <MyGadget as AsymmetricEncryptionGadget<MyEnc, Fq>>::OutputVar::new_input(
                ark_relations::ns!(cs, "gadget_expected"),
                || Ok(&primitive_result),
            )
            .unwrap();
        expected_var.enforce_equal(&result_var).unwrap();

        assert_eq!(primitive_result.0, result_var.c1.value().unwrap());
        assert_eq!(primitive_result.1, result_var.c2.value().unwrap());
        assert!(cs.is_satisfied().unwrap());
    }
}
