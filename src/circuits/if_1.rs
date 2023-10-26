use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::AllocVar;
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_relations::r1cs::ConstraintSystemRef;
use ark_relations::r1cs::SynthesisError;

// is age greater than 19?
#[derive(Clone)]
pub struct IfV1<F: PrimeField> {
    // statement
    age: Option<F>,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for IfV1<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let age = FpVar::new_input(cs.clone(), || self.age.ok_or(SynthesisError::AssignmentMissing))?;
        
        let age19 = F::from_str("19").unwrap_or_default();
        let age19 = FpVar::new_constant(cs.clone(), age19)?;

        age.enforce_cmp(&age19, std::cmp::Ordering::Greater, false)?;

        Ok(())
    }
}

#[cfg(test)]
pub mod test {
    use std::str::FromStr;

    use ark_bn254::Fr;
    use ark_ff::Fp;
    use ark_relations::r1cs::ConstraintSynthesizer;

    use crate::circuits::if_1::IfV1;

    #[test]
    fn test_mul() {
        let age: Fr = Fp::from_str("20").unwrap();

        let test_circuit = IfV1 {age: Some(age)};
        let cs = ark_relations::r1cs::ConstraintSystem::new_ref();

        test_circuit.clone().generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }
}
